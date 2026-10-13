"""
BrandSentinel Scanning & Evidence Analysis Pipeline
===================================================
Pipeline Stage Architecture:
  Source adapter (or validated JSON import)
    → normalized candidate
    → exact official-asset check
    → evidence analysis (Unicode, leet swaps, added words, publisher, payment language)
    → assessment (official match, likely impersonation, inconclusive, unrelated)
    → stored result (Candidate & Detection records with evidence, timestamps, provenance)

Design Principles:
- Strict zero-trust on external text (sanitization, control-character neutralization).
- Exact source-scoped identifier matching for official identity. Never establish official status from name/logo alone.
- Stricter matching for short or common names to prevent false positive collisions.
- Multiple corroborating signals required for likely impersonation; do not equate similarity alone with confirmed fraud.
- Unknown publisher alone MUST NOT establish impersonation.
- Logo similarity reported as None (not performed) unless actual image analysis is executed.
- Live sources and demo scans are strictly segregated; never silently substitute demo results on live source failure.
"""

import re
import json
import time
import unicodedata
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set

from connectors import NormalizedCandidate

DETECTOR_VERSION = "2.1.0"

# Assessment Constants
ASSESSMENT_OFFICIAL_MATCH = "official_match"
ASSESSMENT_LIKELY_IMPERSONATION = "likely_impersonation"
ASSESSMENT_INCONCLUSIVE = "inconclusive"
ASSESSMENT_UNRELATED = "unrelated"

# Identity Status Constants (aligned with database enum/conventions)
IDENTITY_VERIFIED_OFFICIAL = "verified_official"
IDENTITY_UNAUTHORIZED_IMPERSONATOR = "unauthorized_impersonator"
IDENTITY_INCONCLUSIVE = "inconclusive"
IDENTITY_UNRELATED = "unrelated"

# Deceptive modifier words commonly added to impersonate brands
DECEPTIVE_MODIFIERS: Set[str] = {
    "support", "rewards", "reward", "helpdesk", "help", "claim",
    "official", "security", "portal", "login", "verify", "verification",
    "giveaway", "airdrop", "bonus", "promo", "promotion", "service",
    "care", "desk", "team", "global", "alerts", "hotline", "customer",
    "billing", "token", "gift", "auth", "direct", "agent", "app",
    "account", "desk", "center", "centre", "live", "assist"
}

# Suspicious payment, crypto, or credential-harvesting phrases
SUSPICIOUS_PAYMENT_PATTERNS = [
    re.compile(r"\b(send|transfer|deposit)\s+([\d\.]+\s+)?(btc|eth|crypto|sol|usdt|bitcoin|ethereum|funds|money)\b", re.I),
    re.compile(r"\b(crypto|token|coin|reward)\s+(giveaway|airdrop|reward)\b", re.I),
    re.compile(r"\bconnect\s+(your\s+)?(wallet|metamask|phantom|trustwallet)\b", re.I),
    re.compile(r"\b(claim|receive|win)\b.*?\b(airdrop|rewards?|tokens?|bonus|gift\s*card)\b", re.I),
    re.compile(r"\b(verify|confirm|unlock)\s+(your\s+)?(account|wallet|pin|password|seed\s*phrase)\b", re.I),
    re.compile(r"\b(enter|provide)\s+(your\s+)?(seed\s*phrase|private\s*key|recovery\s*phrase)\b", re.I),
    re.compile(r"\b(urgent|immediate)\s+(payment|wire|action\s+required)\b", re.I),
    re.compile(r"\b(paypal|cashapp|venmo|zelle)\s+(deposit|payment|fee)\b", re.I),
    re.compile(r"\b(100%|guaranteed)\s+(double|return|profit|multiplier)\b", re.I),
    re.compile(r"\b(airdrop|giveaway)\b", re.I),
]

# Leet-speak character mappings (homoglyphs / typoglycemia substitutions)
LEET_CHAR_MAP: Dict[str, str] = {
    "0": "o",
    "1": "i",
    "!": "i",
    "|": "i",
    "3": "e",
    "4": "a",
    "@": "a",
    "5": "s",
    "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "9": "g"
}

# Cyrillic and Greek lookalike homoglyphs mapped to Latin ASCII
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "к": "k",
    "т": "t", "м": "m", "в": "b", "н": "h",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "ν": "v"
}

# High-frequency dictionary words where short name collisions are common
COMMON_DICTIONARY_WORDS: Set[str] = {
    "star", "cloud", "nova", "ace", "one", "pay", "bank", "alpha", "blue",
    "net", "safe", "hub", "point", "shield", "core", "link", "trust", "sky"
}


# ==============================================================================
# 1. TEXT NORMALIZATION & UNTRUSTED DATA SANITIZATION
# ==============================================================================

def sanitize_untrusted_text(text: Optional[str], max_length: int = 1000) -> str:
    """
    Sanitizes untrusted input text from external APIs, scraping, or JSON imports.
    - Neutralizes null bytes and C0/C1 control characters (except newline, tab).
    - Strips leading/trailing whitespace.
    - Limits string length to prevent memory exhaustion.
    """
    if text is None:
        return ""
    # Strip null bytes and control chars
    clean = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(text))
    clean = clean.strip()
    return clean[:max_length]


def normalize_unicode(text: str) -> str:
    """
    Normalizes Unicode text via NFKC decomposition, strips combining marks,
    and resolves visual homoglyphs (Cyrillic/Greek lookalikes) to Latin base letters.
    """
    if not text:
        return ""
    # NFKC normalizes compatibility characters (e.g. fullwidth, fractions, ligature forms)
    norm = unicodedata.normalize("NFKC", text)
    # Strip combining accents/diacritics
    decomp = unicodedata.normalize("NFD", norm)
    without_accents = "".join(c for c in decomp if unicodedata.category(c) != "Mn")
    
    # Map lookalike homoglyphs
    homo_resolved = []
    for char in without_accents:
        lower_char = char.lower()
        if lower_char in HOMOGLYPH_MAP:
            mapped = HOMOGLYPH_MAP[lower_char]
            homo_resolved.append(mapped.upper() if char.isupper() else mapped)
        else:
            homo_resolved.append(char)

    return "".join(homo_resolved)


def normalize_text_for_matching(text: str) -> str:
    """
    Produces a canonical matching representation:
    - Unicode normalized & accent stripped
    - Lowercase
    - Punctuation stripped
    - Consecutive whitespace collapsed
    """
    if not text:
        return ""
    unicode_norm = normalize_unicode(text).lower()
    # Replace common separators with spaces
    spaced = re.sub(r"[\._\-\–—/\\:;,\(\)\[\]\{\}\*#~`\"']", " ", unicode_norm)
    # Collapse whitespace
    return re.sub(r"\s+", " ", spaced).strip()


def remove_all_separators(text: str) -> str:
    """Strips all spaces and punctuation for compact substring comparisons."""
    norm = normalize_text_for_matching(text)
    return re.sub(r"\s+", "", norm)


# ==============================================================================
# 2. CHARACTER SWAP & LEET-SPEAK ANALYSIS
# ==============================================================================

def detect_character_swaps(candidate_name: str, brand_name: str) -> Dict[str, Any]:
    """
    Detects whether candidate utilizes intentional leet-speak character substitutions
    to imitate the protected brand (e.g. 'N0rthstar' vs 'Northstar', 'Northst@r').
    """
    cand_compact = remove_all_separators(candidate_name)
    brand_compact = remove_all_separators(brand_name)

    if not cand_compact or not brand_compact:
        return {
            "detected": False,
            "swapped_string": cand_compact,
            "matched_brand": False,
            "swaps": []
        }

    # Perform leet substitution reverse mapping
    # Also resolve multi-character swaps: 'vv' -> 'w', 'rn' -> 'm'
    resolved_chars = []
    swaps_found = []

    i = 0
    while i < len(cand_compact):
        # Check two-character substitutions
        if i + 1 < len(cand_compact):
            pair = cand_compact[i:i+2]
            if pair == "vv":
                resolved_chars.append("w")
                swaps_found.append(("vv", "w", i))
                i += 2
                continue
            elif pair == "rn" and brand_compact.find("m") != -1:
                resolved_chars.append("m")
                swaps_found.append(("rn", "m", i))
                i += 2
                continue

        c = cand_compact[i]
        if c in LEET_CHAR_MAP:
            mapped = LEET_CHAR_MAP[c]
            resolved_chars.append(mapped)
            swaps_found.append((c, mapped, i))
        else:
            resolved_chars.append(c)
        i += 1

    unleeted_string = "".join(resolved_chars)
    
    # Check if the unleeted string matches the brand or contains the brand
    brand_matched = False
    if unleeted_string == brand_compact:
        brand_matched = True
    elif brand_compact in unleeted_string and brand_compact not in cand_compact:
        # The brand was obfuscated by leet characters!
        brand_matched = True

    return {
        "detected": len(swaps_found) > 0 and brand_matched,
        "swapped_string": unleeted_string,
        "matched_brand": brand_matched,
        "swaps": swaps_found
    }


# ==============================================================================
# 3. ADDED WORDS & DECEPTIVE MODIFIER DETECTION
# ==============================================================================

def detect_added_words(candidate_text: str, brand_name: str) -> List[str]:
    """
    Identifies high-risk added words (Support, Rewards, Security, Login, etc.)
    commonly used in social or app squatting schemes alongside the brand name.
    """
    clean_cand = normalize_text_for_matching(candidate_text)
    clean_brand = normalize_text_for_matching(brand_name)

    if not clean_cand or not clean_brand:
        return []

    tokens = clean_cand.split()
    brand_tokens = set(clean_brand.split())

    # Find candidate tokens that are NOT in the brand name
    extra_tokens = [t for t in tokens if t not in brand_tokens]

    matched_modifiers = []
    for token in extra_tokens:
        if token in DECEPTIVE_MODIFIERS:
            matched_modifiers.append(token)
        else:
            # Check if token ends with or starts with a modifier (e.g. "northstarsupport")
            for mod in DECEPTIVE_MODIFIERS:
                if len(token) > len(mod) + 2:
                    if token.endswith(mod) or token.startswith(mod):
                        matched_modifiers.append(mod)

    # If the text is a single compound string (e.g. "northstarsupport" handle)
    compact_cand = remove_all_separators(candidate_text)
    compact_brand = remove_all_separators(brand_name)
    if compact_brand in compact_cand:
        residual = compact_cand.replace(compact_brand, "")
        for mod in DECEPTIVE_MODIFIERS:
            if mod in residual and mod not in matched_modifiers:
                matched_modifiers.append(mod)

    return sorted(list(set(matched_modifiers)))


# ==============================================================================
# 4. NAME SIMILARITY & EDIT DISTANCE (STRICT ON SHORT/COMMON NAMES)
# ==============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if len(s1) == 0:
        return len(s2)
    if len(s2) == 0:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0 = v1[:]

    return v0[len(s2)]


def calculate_name_similarity(
    candidate_name: str,
    brand_name: str,
    aliases: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Calculates robust name similarity between candidate name and brand name/aliases.
    Enforces strict matching thresholds for short or common dictionary names.
    """
    cand_norm = normalize_text_for_matching(candidate_name)
    cand_compact = remove_all_separators(candidate_name)

    names_to_check = [brand_name] + (aliases or [])
    best_match = {
        "similarity_score": 0.0,
        "matched_name": brand_name,
        "is_exact_match": False,
        "is_short_or_common": False,
        "edit_distance": 999
    }

    for target in names_to_check:
        if not target:
            continue
        target_norm = normalize_text_for_matching(target)
        target_compact = remove_all_separators(target)

        if not target_compact or not cand_compact:
            continue

        # Check if target is short (<= 4 chars) or common word
        is_short_or_common = (len(target_compact) <= 4) or (target_compact in COMMON_DICTIONARY_WORDS)

        # 1. Exact match check
        if cand_compact == target_compact or cand_norm == target_norm:
            return {
                "similarity_score": 1.0,
                "matched_name": target,
                "is_exact_match": True,
                "is_short_or_common": is_short_or_common,
                "edit_distance": 0
            }

        # 2. Leet swap check
        leet_res = detect_character_swaps(candidate_name, target)
        if leet_res["detected"] and leet_res["matched_brand"]:
            score = 0.96
            if score > best_match["similarity_score"]:
                best_match = {
                    "similarity_score": score,
                    "matched_name": target,
                    "is_exact_match": False,
                    "is_short_or_common": is_short_or_common,
                    "edit_distance": 1,
                    "character_swap": True
                }
            continue

        # 3. Normalized Levenshtein ratio
        dist = levenshtein_distance(cand_compact, target_compact)
        max_len = max(len(cand_compact), len(target_compact))
        raw_ratio = 1.0 - (dist / max_len) if max_len > 0 else 0.0

        # Substring / Token containment
        cand_tokens = set(cand_norm.split())
        target_tokens = set(target_norm.split())
        token_overlap = len(cand_tokens.intersection(target_tokens)) / len(target_tokens) if target_tokens else 0.0

        # Short/Common name penalty & thresholding
        effective_score = raw_ratio
        if is_short_or_common:
            # CRITICAL RULE: For short or common words, single letter differences (e.g. Star vs Stan)
            # are usually coincidental. Require exact token presence for positive similarity.
            if target_compact not in cand_tokens and target_compact != cand_compact:
                effective_score = min(raw_ratio * 0.5, 0.49)
            else:
                effective_score = max(raw_ratio, token_overlap)
        else:
            # If target brand is fully contained as a token or prefix in candidate
            if target_compact in cand_compact:
                effective_score = max(effective_score, 0.88)
            elif token_overlap >= 0.8:
                effective_score = max(effective_score, token_overlap)

        if effective_score > best_match["similarity_score"]:
            best_match = {
                "similarity_score": round(effective_score, 3),
                "matched_name": target,
                "is_exact_match": False,
                "is_short_or_common": is_short_or_common,
                "edit_distance": dist
            }

    return best_match


# ==============================================================================
# 5. PUBLISHER MISMATCH & PAYMENT LANGUAGE EVIDENCE
# ==============================================================================

def analyze_publisher_evidence(
    candidate_publisher_id: Optional[str],
    candidate_publisher_name: Optional[str],
    official_publisher_ids: List[str],
    official_publisher_names: List[str]
) -> Dict[str, Any]:
    """
    Evaluates publisher consistency.
    CORE SECURITY RULE: Unknown publisher alone MUST NOT establish impersonation.
    """
    cand_id = (candidate_publisher_id or "").strip()
    cand_name = (candidate_publisher_name or "").strip()

    # Rule: Unknown publisher alone is NOT an impersonation signal!
    if not cand_id and not cand_name:
        return {
            "is_known": False,
            "is_mismatch": False,
            "is_match": False,
            "status": "unknown_publisher",
            "rationale": "Candidate has no explicit publisher identifier. Unknown publisher alone does not establish impersonation."
        }

    # If official brand has registered authorized publishers
    clean_official_ids = [p.strip().lower() for p in official_publisher_ids if p and p.strip()]
    clean_official_names = [p.strip().lower() for p in official_publisher_names if p and p.strip()]

    if not clean_official_ids and not clean_official_names:
        return {
            "is_known": True,
            "is_mismatch": False,
            "is_match": False,
            "status": "official_publisher_unconfigured",
            "candidate_publisher": cand_name or cand_id,
            "rationale": "No authorized publisher configured on official brand registry."
        }

    # Check match against official publishers
    matches_id = cand_id.lower() in clean_official_ids if cand_id else False
    matches_name = cand_name.lower() in clean_official_names if cand_name else False

    if matches_id or matches_name:
        return {
            "is_known": True,
            "is_mismatch": False,
            "is_match": True,
            "status": "authorized_publisher_match",
            "candidate_publisher": cand_name or cand_id,
            "rationale": f"Publisher '{cand_name or cand_id}' matches official authorized publisher."
        }
    else:
        # Explicit publisher is known, but MISMATCHES the official authorized publisher!
        # This is a strong corroborating signal for app stores.
        return {
            "is_known": True,
            "is_mismatch": True,
            "is_match": False,
            "status": "publisher_mismatch",
            "candidate_publisher": cand_name or cand_id,
            "official_publishers": clean_official_names or clean_official_ids,
            "rationale": f"Publisher mismatch: candidate publisher '{cand_name or cand_id}' does not match authorized publishers ({', '.join(clean_official_names or clean_official_ids)})."
        }


def detect_suspicious_payment_language(text: Optional[str]) -> Dict[str, Any]:
    """
    Detects scam, giveaway, wallet connection, or deceptive payment keywords.
    """
    if not text:
        return {"detected": False, "matched_terms": []}

    clean_text = normalize_unicode(text)
    matched_terms = []

    for pattern in SUSPICIOUS_PAYMENT_PATTERNS:
        match = pattern.search(clean_text)
        if match:
            matched_terms.append(match.group(0).strip())

    return {
        "detected": len(matched_terms) > 0,
        "matched_terms": list(set(matched_terms))
    }


# ==============================================================================
# 6. EXACT OFFICIAL ASSET IDENTIFIER CHECK
# ==============================================================================

def check_exact_official_match(
    candidate: NormalizedCandidate,
    official_assets: List[Any]
) -> Tuple[bool, Optional[str], str]:
    """
    Stage 2 Check: Validates candidate strictly against registered official assets.
    Returns: (is_official_match, matched_asset_id, match_reason)
    """
    cand_prov = (candidate.provider or "").strip().lower()
    cand_ext_id = (candidate.external_id or "").strip()
    cand_handle = (candidate.handle_or_package or "").strip().lower()
    cand_pub = (candidate.publisher_id or "").strip()

    # Filter official assets belonging to the same platform family
    relevant_officials = [
        a for a in official_assets
        if (getattr(a, "source_platform", "") or "").strip().lower() == cand_prov
        or (cand_prov in ["apple_app_store", "google_play"] and getattr(a, "source_platform", "") in ["apple_app_store", "google_play", "apps"])
    ]

    for asset in relevant_officials:
        asset_id = getattr(asset, "id", None)
        off_exact = (getattr(asset, "exact_identifier", "") or "").strip().lower()
        off_stable = (getattr(asset, "stable_id", "") or "").strip()
        off_pub = (getattr(asset, "authorized_publisher_id", "") or "").strip()

        # Domain matching
        if cand_prov in ["domain", "domain_registry", "web"]:
            if cand_handle == off_exact or cand_handle.endswith(f".{off_exact}"):
                return True, asset_id, f"Exact official domain match for '{off_exact}'"

        # App store matching: requires package/app ID match AND (if configured) publisher match
        elif cand_prov in ["google_play", "apple_app_store"]:
            app_id_matches = (cand_handle == off_exact) or (cand_ext_id and cand_ext_id == off_stable)
            pub_matches = True
            if off_pub:
                pub_matches = (cand_pub.lower() == off_pub.lower())
            
            if app_id_matches and pub_matches:
                return True, asset_id, f"Exact app identifier & authorized publisher match on {cand_prov}"

        # Social accounts: requires exact stable ID match
        else:
            if cand_ext_id and off_stable and cand_ext_id == off_stable:
                return True, asset_id, f"Exact platform stable ID match ('{off_stable}') on {cand_prov}"

    return False, None, "No exact source-scoped official identifier match."


# ==============================================================================
# 7. EVIDENCE ANALYSIS & ASSESSMENT STAGE
# ==============================================================================

def analyze_and_assess_candidate(
    candidate: NormalizedCandidate,
    brand_name: str,
    brand_aliases: Optional[List[str]] = None,
    official_assets: Optional[List[Any]] = None
) -> Dict[str, Any]:
    """
    Executes Stages 2, 3, and 4 of the Scanning Pipeline:
    - Stage 2: Exact official-asset check.
    - Stage 3: Forensic evidence extraction across untrusted text.
    - Stage 4: Multi-signal assessment formulation.
    """
    official_assets = official_assets or []
    brand_aliases = brand_aliases or []

    # Sanitize untrusted text
    safe_display = sanitize_untrusted_text(candidate.display_name)
    safe_handle = sanitize_untrusted_text(candidate.handle_or_package)
    safe_desc = sanitize_untrusted_text(candidate.description)
    safe_pub_name = sanitize_untrusted_text(candidate.publisher_name)
    safe_pub_id = sanitize_untrusted_text(candidate.publisher_id)

    # --------------------------------------------------------------------------
    # STAGE 2: EXACT OFFICIAL ASSET CHECK
    # --------------------------------------------------------------------------
    is_official, matched_asset_id, official_reason = check_exact_official_match(candidate, official_assets)
    if is_official:
        return {
            "assessment": ASSESSMENT_OFFICIAL_MATCH,
            "identity_status": IDENTITY_VERIFIED_OFFICIAL,
            "risk_level": "none",
            "risk_score": 0,
            "detection_type": "Official Brand Asset",
            "match_score": "100% Verified Official Identifier",
            "corroborating_signals": ["exact_official_identifier_match"],
            "rationale": official_reason,
            "is_official": True,
            "matched_official_asset_id": matched_asset_id,
            "evidence": {
                "detector_version": DETECTOR_VERSION,
                "source_identifier": safe_handle or safe_display,
                "stable_source_id": candidate.external_id,
                "official_asset_matched": True,
                "matched_asset_id": matched_asset_id
            }
        }

    # --------------------------------------------------------------------------
    # STAGE 3: EVIDENCE ANALYSIS
    # --------------------------------------------------------------------------
    all_brand_names = [brand_name] + brand_aliases

    # 1. Name Similarity
    sim_display = calculate_name_similarity(safe_display, brand_name, brand_aliases)
    sim_handle = calculate_name_similarity(safe_handle, brand_name, brand_aliases)
    best_sim = sim_display if sim_display["similarity_score"] >= sim_handle["similarity_score"] else sim_handle

    # 2. Character Swaps / Leet Analysis across brand name and aliases
    character_swap_detected = False
    swaps_list = []
    for b_target in all_brand_names:
        sw_disp = detect_character_swaps(safe_display, b_target)
        sw_hand = detect_character_swaps(safe_handle, b_target)
        if sw_disp["detected"] or sw_hand["detected"]:
            character_swap_detected = True
            swaps_list.extend(sw_disp["swaps"] + sw_hand["swaps"])
    if best_sim.get("character_swap"):
        character_swap_detected = True

    # 3. Added Deceptive Words
    added_words = []
    for b_target in all_brand_names:
        for w in detect_added_words(f"{safe_display} {safe_handle}", b_target):
            if w not in added_words:
                added_words.append(w)

    # 4. Publisher Mismatch Analysis
    off_pub_ids = [getattr(a, "authorized_publisher_id", "") for a in official_assets if getattr(a, "authorized_publisher_id", "")]
    off_pub_names = [getattr(a, "authorized_publisher_name", "") for a in official_assets if getattr(a, "authorized_publisher_name", "")]
    pub_analysis = analyze_publisher_evidence(safe_pub_id, safe_pub_name, off_pub_ids, off_pub_names)

    # 5. Suspicious Payment / Scam Language
    payment_evidence = detect_suspicious_payment_language(f"{safe_display} {safe_desc}")

    # 6. Logo Similarity: Explicit disclosure of honesty rule
    logo_evidence = {
        "status": "not_performed",
        "similarity_score": None,
        "reason": "Actual image computer vision analysis not performed; visual match percentage not claimed."
    }

    # Compile Corroborating Signals
    corroborating_signals: List[str] = []
    
    # Signal 1: Name match or leet swap
    has_high_name_sim = best_sim["similarity_score"] >= 0.85
    if character_swap_detected:
        corroborating_signals.append("character_swap_detected")
    if best_sim["is_exact_match"]:
        corroborating_signals.append("exact_brand_name_in_title")
    elif has_high_name_sim and not character_swap_detected:
        corroborating_signals.append("high_name_similarity")

    # Signal 2: Deceptive added words
    if added_words:
        corroborating_signals.append(f"added_deceptive_words:{','.join(added_words[:3])}")

    # Signal 3: Publisher mismatch (only if publisher is explicitly known and differs!)
    if pub_analysis.get("is_mismatch"):
        corroborating_signals.append("unauthorized_publisher_mismatch")

    # Signal 4: Suspicious payment / credential harvesting text
    if payment_evidence.get("detected"):
        corroborating_signals.append("suspicious_payment_language")

    # --------------------------------------------------------------------------
    # STAGE 4: ASSESSMENT FORMULATION
    # Rules:
    # - Likely impersonation requires MULTIPLE corroborating signals.
    # - Do not equate similarity with confirmed fraud.
    # - Unknown publisher alone must NOT establish impersonation.
    # - Stricter matching for short/common names.
    # --------------------------------------------------------------------------
    sim_score = best_sim["similarity_score"]
    is_short_common = best_sim["is_short_or_common"]

    # Disqualification for short/common names without exact token
    if is_short_common and not best_sim["is_exact_match"] and not character_swap_detected:
        if sim_score < 0.90:
            return {
                "assessment": ASSESSMENT_UNRELATED,
                "identity_status": IDENTITY_UNRELATED,
                "risk_level": "none",
                "risk_score": 5,
                "detection_type": "Benign / Common Name Collision",
                "match_score": f"{int(sim_score * 100)}% Common Word Overlap",
                "corroborating_signals": [],
                "rationale": "Short/common brand word collision with non-infringing third party. Evaluated as benign.",
                "is_official": False,
                "matched_official_asset_id": None,
                "evidence": _build_evidence_dict(
                    candidate, best_sim, character_swap_detected, swaps_list,
                    added_words, pub_analysis, payment_evidence, logo_evidence,
                    corroborating_signals, "Short/common name threshold applied"
                )
            }

    # Low similarity -> Unrelated
    if sim_score < 0.60 and not character_swap_detected and not added_words:
        return {
            "assessment": ASSESSMENT_UNRELATED,
            "identity_status": IDENTITY_UNRELATED,
            "risk_level": "low",
            "risk_score": int(sim_score * 30),
            "detection_type": "Unrelated Asset",
            "match_score": f"{int(sim_score * 100)}% Similarity",
            "corroborating_signals": [],
            "rationale": "Name similarity below threat threshold. No brand infringement detected.",
            "is_official": False,
            "matched_official_asset_id": None,
            "evidence": _build_evidence_dict(
                candidate, best_sim, character_swap_detected, swaps_list,
                added_words, pub_analysis, payment_evidence, logo_evidence,
                corroborating_signals, "Negligible similarity score"
            )
        }

    # Assessment Condition 1: LIKELY IMPERSONATION (Multiple corroborating signals)
    # At least two distinct threat signals required!
    # Examples:
    # - High name similarity + Added deceptive words ('Northstar Support')
    # - Character swap + Added words / Payment text ('N0rthstar Rewards')
    # - High name similarity + Unauthorized publisher mismatch (Counterfeit mobile app)
    # - Brand name match + Suspicious payment/airdrop language
    has_name_signal = (has_high_name_sim or best_sim["is_exact_match"] or character_swap_detected)
    has_deceptive_signal = bool(added_words)
    has_pub_mismatch = bool(pub_analysis.get("is_mismatch"))
    has_payment_signal = bool(payment_evidence.get("detected"))

    threat_signal_count = sum([
        1 if has_name_signal else 0,
        1 if has_deceptive_signal else 0,
        1 if has_pub_mismatch else 0,
        1 if has_payment_signal else 0
    ])

    if threat_signal_count >= 2 and (has_name_signal or character_swap_detected):
        # Determine risk level
        if has_payment_signal or (has_pub_mismatch and candidate.provider in ["google_play", "apple_app_store"]):
            risk_level = "critical"
            risk_score = 92
            detection_type = "High-Risk Impersonation & Scam Intent" if has_payment_signal else "Counterfeit Publisher Distribution"
        else:
            risk_level = "high"
            risk_score = 82
            detection_type = "Suspected Brand Impersonation"

        match_label = f"{int(sim_score * 100)}% Target Match"
        if character_swap_detected:
            match_label += " (Character Swap / Leet)"

        rationale = f"Likely impersonation established via {threat_signal_count} corroborating signals: {', '.join(corroborating_signals)}."

        return {
            "assessment": ASSESSMENT_LIKELY_IMPERSONATION,
            "identity_status": IDENTITY_UNAUTHORIZED_IMPERSONATOR,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "detection_type": detection_type,
            "match_score": match_label,
            "corroborating_signals": corroborating_signals,
            "rationale": rationale,
            "is_official": False,
            "matched_official_asset_id": None,
            "evidence": _build_evidence_dict(
                candidate, best_sim, character_swap_detected, swaps_list,
                added_words, pub_analysis, payment_evidence, logo_evidence,
                corroborating_signals, rationale
            )
        }

    # Assessment Condition 2: INCONCLUSIVE (Insufficient or single isolated signal)
    # Rule: Do not equate similarity alone with confirmed fraud!
    # Rule: Unknown publisher alone does NOT establish impersonation!
    inconclusive_rationale = (
        "Similarity detected, but lacking multiple corroborating signals of deceptive intent. "
        "Marked inconclusive for human analyst verification."
    )
    if pub_analysis.get("status") == "unknown_publisher":
        inconclusive_rationale += " (Unknown publisher alone does not establish impersonation)."

    return {
        "assessment": ASSESSMENT_INCONCLUSIVE,
        "identity_status": IDENTITY_INCONCLUSIVE,
        "risk_level": "medium",
        "risk_score": max(45, int(sim_score * 65)),
        "detection_type": "Inconclusive Brand Similarity",
        "match_score": f"{int(sim_score * 100)}% Similarity (Unverified Intent)",
        "corroborating_signals": corroborating_signals,
        "rationale": inconclusive_rationale,
        "is_official": False,
        "matched_official_asset_id": None,
        "evidence": _build_evidence_dict(
            candidate, best_sim, character_swap_detected, swaps_list,
            added_words, pub_analysis, payment_evidence, logo_evidence,
            corroborating_signals, inconclusive_rationale
        )
    }


def _build_evidence_dict(
    candidate: NormalizedCandidate,
    sim_data: Dict[str, Any],
    character_swap: bool,
    swaps_list: List[Any],
    added_words: List[str],
    pub_analysis: Dict[str, Any],
    payment_evidence: Dict[str, Any],
    logo_evidence: Dict[str, Any],
    signals: List[str],
    rationale: str
) -> Dict[str, Any]:
    """Builds a structured evidence snapshot dictionary for forensic auditing."""
    return {
        "detector_version": DETECTOR_VERSION,
        "assessment_rationale": rationale,
        "corroborating_signals": signals,
        "name_similarity": {
            "score": sim_data.get("similarity_score", 0.0),
            "matched_brand_target": sim_data.get("matched_name"),
            "is_exact": sim_data.get("is_exact_match", False),
            "is_short_or_common": sim_data.get("is_short_or_common", False)
        },
        "character_swap_analysis": {
            "detected": character_swap,
            "swaps": [f"{s[0]}->{s[1]}" for s in swaps_list]
        },
        "added_deceptive_words": added_words,
        "publisher_analysis": pub_analysis,
        "payment_language_analysis": payment_evidence,
        "logo_analysis": logo_evidence,
        "missing_evidence_indicators": candidate.missing_evidence_indicators or [
            "Logo image analysis not performed"
        ],
        "timestamps": {
            "collected_at": candidate.collected_at,
            "analyzed_at": datetime.utcnow().isoformat() + "Z"
        },
        "provenance": candidate.provenance or {
            "provider": candidate.provider,
            "source_url": candidate.source_url
        }
    }


# ==============================================================================
# 8. PIPELINE EXECUTION & RESULT STORAGE (STAGE 5)
# ==============================================================================

def process_candidate_pipeline(
    candidate: NormalizedCandidate,
    brand_id: str,
    brand_name: str,
    brand_aliases: List[str],
    official_assets: List[Any],
    organization_id: str,
    db_session: Any,
    scan_id: Optional[str] = None,
    is_sample: bool = False
) -> Dict[str, Any]:
    """
    Executes the full pipeline for a single candidate and persists the result:
    Candidate (sanitized) + Detection (evidence, timestamps, provenance, detector version).
    """
    from db.models import Candidate as CandidateModel, Detection as DetectionModel

    # Analyze & assess
    assessment = analyze_and_assess_candidate(
        candidate=candidate,
        brand_name=brand_name,
        brand_aliases=brand_aliases,
        official_assets=official_assets
    )

    # Sanitize untrusted input fields for storage
    safe_identifier = sanitize_untrusted_text(candidate.handle_or_package or candidate.external_id)
    safe_display = sanitize_untrusted_text(candidate.display_name or candidate.handle_or_package)
    safe_pub_id = sanitize_untrusted_text(candidate.publisher_id)

    # 1. Upsert Candidate Row
    existing_cand = db_session.query(CandidateModel).filter(
        CandidateModel.organization_id == organization_id,
        CandidateModel.source_platform == candidate.provider,
        CandidateModel.candidate_identifier == safe_identifier
    ).first()

    cand_meta = {
        "collected_at": candidate.collected_at,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "description": sanitize_untrusted_text(candidate.description, 500),
        "source_url": candidate.source_url,
        "provenance": candidate.provenance,
        "missing_evidence_indicators": candidate.missing_evidence_indicators
    }

    if existing_cand:
        existing_cand.display_name = safe_display
        existing_cand.stable_source_id = candidate.external_id
        existing_cand.publisher_identifier = safe_pub_id
        existing_cand.metadata_json = json.dumps(cand_meta)
        cand_record = existing_cand
    else:
        cand_record = CandidateModel(
            organization_id=organization_id,
            scan_id=scan_id,
            source_platform=candidate.provider,
            candidate_identifier=safe_identifier,
            stable_source_id=candidate.external_id,
            publisher_identifier=safe_pub_id,
            display_name=safe_display,
            metadata_json=json.dumps(cand_meta),
            is_sample=is_sample
        )
        db_session.add(cand_record)
        db_session.flush()

    # 2. Upsert Detection Row
    # If the candidate is an official match, set status to whitelisted
    det_status = "whitelisted" if assessment["is_official"] else "flagged"
    if assessment["assessment"] == ASSESSMENT_INCONCLUSIVE:
        det_status = "under_review"
    elif assessment["assessment"] == ASSESSMENT_UNRELATED:
        det_status = "dismissed"

    existing_det = db_session.query(DetectionModel).filter(
        DetectionModel.organization_id == organization_id,
        DetectionModel.brand_id == brand_id,
        DetectionModel.candidate_id == cand_record.id
    ).first()

    evidence_json = json.dumps(assessment["evidence"])

    if existing_det:
        existing_det.risk_level = assessment["risk_level"]
        existing_det.risk_score = assessment["risk_score"]
        existing_det.detection_type = assessment["detection_type"]
        existing_det.match_score = assessment["match_score"]
        existing_det.identity_status = assessment["identity_status"]
        existing_det.similarity_details_json = evidence_json
        existing_det.status = det_status
        det_record = existing_det
    else:
        det_record = DetectionModel(
            organization_id=organization_id,
            brand_id=brand_id,
            candidate_id=cand_record.id,
            risk_level=assessment["risk_level"],
            risk_score=assessment["risk_score"],
            detection_type=assessment["detection_type"],
            match_score=assessment["match_score"],
            identity_status=assessment["identity_status"],
            similarity_details_json=evidence_json,
            status=det_status,
            is_sample=is_sample
        )
        db_session.add(det_record)
        db_session.flush()

    return {
        "candidate_id": cand_record.id,
        "detection_id": det_record.id,
        "assessment": assessment["assessment"],
        "identity_status": assessment["identity_status"],
        "risk_level": assessment["risk_level"],
        "risk_score": assessment["risk_score"],
        "detection_type": assessment["detection_type"],
        "is_official": assessment["is_official"],
        "corroborating_signals": assessment["corroborating_signals"],
        "rationale": assessment["rationale"],
        "evidence": assessment["evidence"]
    }


# ==============================================================================
# 9. VALIDATED JSON IMPORT PARSER
# ==============================================================================

def validate_and_parse_import_json(
    raw_payload: Any
) -> Tuple[bool, List[NormalizedCandidate], Optional[str]]:
    """
    Validates external JSON candidate import payloads against NormalizedCandidate schema.
    Returns: (is_valid, candidates_list, error_message)
    """
    if raw_payload is None:
        return False, [], "Missing JSON payload."

    items = []
    if isinstance(raw_payload, list):
        items = raw_payload
    elif isinstance(raw_payload, dict):
        if "candidates" in raw_payload and isinstance(raw_payload["candidates"], list):
            items = raw_payload["candidates"]
        elif "items" in raw_payload and isinstance(raw_payload["items"], list):
            items = raw_payload["items"]
        else:
            items = [raw_payload]
    else:
        return False, [], "Import payload must be a JSON array or object containing 'candidates'."

    if not items:
        return False, [], "JSON candidate list is empty."

    candidates = []
    for idx, it in enumerate(items):
        if not isinstance(it, dict):
            return False, [], f"Candidate record at index {idx} must be a JSON object."

        provider = (it.get("provider") or it.get("source_platform") or it.get("platform") or "").strip().lower()
        if not provider:
            return False, [], f"Candidate record at index {idx} missing required field 'source_platform'."

        handle = (it.get("handle_or_package") or it.get("candidate_identifier") or it.get("handle") or "").strip()
        display = (it.get("display_name") or it.get("title") or handle or "").strip()
        ext_id = str(it.get("external_id") or it.get("stable_source_id") or handle or f"import_{idx}_{int(time.time())}").strip()

        if not handle and not display:
            return False, [], f"Candidate record at index {idx} must have 'candidate_identifier' or 'display_name'."

        asset_type = it.get("asset_type") or ("mobile_app" if provider in ["google_play", "apple_app_store"] else "social_account")
        desc = it.get("description") or ""
        pub_id = it.get("publisher_id")
        pub_name = it.get("publisher_name")
        src_url = it.get("source_url") or f"https://{provider}.example.com/{handle}"

        cand = NormalizedCandidate(
            provider=provider,
            external_id=ext_id,
            asset_type=asset_type,
            display_name=display or handle,
            handle_or_package=handle or display,
            description=desc,
            logo_url=it.get("logo_url"),
            publisher_id=pub_id,
            publisher_name=pub_name,
            source_url=src_url,
            provenance={
                "input_type": "validated_json_import",
                "imported_at": datetime.utcnow().isoformat() + "Z",
                "batch_index": idx
            },
            missing_evidence_indicators=it.get("missing_evidence_indicators") or [
                "JSON import mode: External API telemetry not verified by direct connection"
            ]
        )
        candidates.append(cand)

    return True, candidates, None
