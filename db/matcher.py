"""
Exact Source-Scoped Official Asset Matching Engine for BrandSentinel.

CRITICAL SECURITY RULE:
Use exact source-scoped identifiers for official-asset matching.
Never establish official identity from a similar name or logo alone.
"""

import json
import re
from typing import List, Tuple, Optional, Dict, Any

IDENTITY_VERIFIED_OFFICIAL = "verified_official"
IDENTITY_UNAUTHORIZED_IMPERSONATOR = "unauthorized_impersonator"
IDENTITY_SUSPICIOUS_CANDIDATE = "suspicious_candidate"
IDENTITY_INCONCLUSIVE = "inconclusive"
IDENTITY_UNRELATED = "unrelated"

ASSESSMENT_OFFICIAL_MATCH = "official_match"
ASSESSMENT_LIKELY_IMPERSONATION = "likely_impersonation"
ASSESSMENT_INCONCLUSIVE = "inconclusive"
ASSESSMENT_UNRELATED = "unrelated"

def evaluate_candidate_identity(
    source_platform: str,
    candidate_identifier: str,
    stable_source_id: Optional[str],
    display_name: str,
    publisher_identifier: Optional[str] = None,
    name_similarity_score: float = 0.0,
    logo_similarity_score: float = 0.0,
    official_assets: Optional[List[Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates whether a candidate asset is verified official or an infringing suspect.
    
    Guarantees:
    - Never establishes official identity from similar name or logo alone.
    - Requires exact source-scoped identifiers and stable platform IDs.
    """
    official_assets = official_assets or []
    platform_norm = (source_platform or "").strip().lower()
    cand_id_norm = (candidate_identifier or "").strip().lower()
    stable_id_norm = (stable_source_id or "").strip()
    pub_id_norm = (publisher_identifier or "").strip()

    # Filter official assets matching the same source platform family
    platform_officials = [
        a for a in official_assets
        if (a.source_platform or "").strip().lower() == platform_norm
        or (platform_norm in ["google_play", "apple_app_store"] and (a.source_platform or "").strip().lower() in ["google_play", "apple_app_store", "apps"])
    ]

    has_high_similarity = (name_similarity_score >= 0.70) or (logo_similarity_score >= 0.70)

    # 1. DOMAIN MATCHING
    if platform_norm in ["domain", "domain_registry", "web"]:
        for official in platform_officials:
            off_domain = (official.exact_identifier or "").strip().lower()
            if cand_id_norm == off_domain or cand_id_norm.endswith(f".{off_domain}"):
                return {
                    "identity_status": IDENTITY_VERIFIED_OFFICIAL,
                    "is_official": True,
                    "matched_asset_id": official.id,
                    "match_reason": f"Exact domain match against authorized asset '{off_domain}'",
                    "risk_level": "none",
                    "recommended_verdict": "whitelisted",
                    "assessment": ASSESSMENT_OFFICIAL_MATCH
                }
        
        # Not an exact domain match. If name or logo is similar, it is a high-risk candidate
        return {
            "identity_status": IDENTITY_UNAUTHORIZED_IMPERSONATOR if has_high_similarity else IDENTITY_SUSPICIOUS_CANDIDATE,
            "is_official": False,
            "matched_asset_id": None,
            "match_reason": "Domain identifier not in registered official domains list (Name/logo similarity alone does NOT establish official identity)",
            "risk_level": "critical" if has_high_similarity else "medium",
            "recommended_verdict": "flagged",
            "assessment": ASSESSMENT_LIKELY_IMPERSONATION if has_high_similarity else ASSESSMENT_INCONCLUSIVE
        }

    # 2. SOCIAL PLATFORM MATCHING
    if platform_norm in ["instagram", "twitter_x", "tiktok", "linkedin", "facebook", "youtube", "telegram", "discord"]:
        for official in platform_officials:
            off_stable = (official.stable_id or "").strip()
            off_handle = (official.exact_identifier or "").strip().lower()

            # Exact stable ID match on the same platform
            if stable_id_norm and off_stable and stable_id_norm == off_stable:
                return {
                    "identity_status": IDENTITY_VERIFIED_OFFICIAL,
                    "is_official": True,
                    "matched_asset_id": official.id,
                    "match_reason": f"Exact platform stable ID match ('{off_stable}') on {platform_norm}",
                    "risk_level": "none",
                    "recommended_verdict": "whitelisted",
                    "assessment": ASSESSMENT_OFFICIAL_MATCH
                }

        # If stable ID does not match, similarity in name or logo proves potential impersonation, NEVER official status!
        return {
            "identity_status": IDENTITY_UNAUTHORIZED_IMPERSONATOR if has_high_similarity else IDENTITY_SUSPICIOUS_CANDIDATE,
            "is_official": False,
            "matched_asset_id": None,
            "match_reason": "No match on stable platform channel ID. High visual/name similarity classified as potential impersonation.",
            "risk_level": "high" if has_high_similarity else "medium",
            "recommended_verdict": "flagged",
            "assessment": ASSESSMENT_LIKELY_IMPERSONATION if has_high_similarity else ASSESSMENT_INCONCLUSIVE
        }

    # 3. APP STORE MATCHING
    if platform_norm in ["google_play", "apple_app_store", "apps"]:
        for official in platform_officials:
            off_stable = (official.stable_id or "").strip()
            off_exact = (official.exact_identifier or "").strip().lower()
            off_pub = (official.authorized_publisher_id or "").strip()

            # Check exact stable package/app ID
            matches_app_id = (cand_id_norm == off_exact) or (stable_id_norm and stable_id_norm == off_stable)
            
            # If official specified an authorized publisher ID, candidate must match it
            matches_publisher = True
            if off_pub:
                matches_publisher = (pub_id_norm == off_pub)

            if matches_app_id and matches_publisher:
                return {
                    "identity_status": IDENTITY_VERIFIED_OFFICIAL,
                    "is_official": True,
                    "matched_asset_id": official.id,
                    "match_reason": f"Exact store identifier & authorized publisher match on {platform_norm}",
                    "risk_level": "none",
                    "recommended_verdict": "whitelisted",
                    "assessment": ASSESSMENT_OFFICIAL_MATCH
                }

        return {
            "identity_status": IDENTITY_UNAUTHORIZED_IMPERSONATOR if has_high_similarity else IDENTITY_SUSPICIOUS_CANDIDATE,
            "is_official": False,
            "matched_asset_id": None,
            "match_reason": "Package identifier or publisher signature does not match official registered application assets.",
            "risk_level": "critical" if has_high_similarity else "medium",
            "recommended_verdict": "flagged",
            "assessment": ASSESSMENT_LIKELY_IMPERSONATION if has_high_similarity else ASSESSMENT_INCONCLUSIVE
        }

    # Default fallback
    return {
        "identity_status": IDENTITY_SUSPICIOUS_CANDIDATE,
        "is_official": False,
        "matched_asset_id": None,
        "match_reason": "Unrecognized platform or unmatched identifier.",
        "risk_level": "medium",
        "recommended_verdict": "flagged",
        "assessment": ASSESSMENT_INCONCLUSIVE
    }


# ==============================================================================
# EXACT YOUTUBE CHANNEL VERIFICATION EVALUATION
# ==============================================================================

VERDICT_OFFICIAL = "Official"
VERDICT_SUSPECTED_IMPERSONATION = "Suspected impersonation"
VERDICT_UNRELATED = "Unrelated"
VERDICT_INCONCLUSIVE = "Inconclusive"

DECEPTIVE_AUTHORITY_KEYWORDS = [
    "official", "support", "customer support", "customer care", "helpdesk",
    "help desk", "service", "care", "security", "rewards", "reward",
    "billing", "verify", "verification", "headquarters", "authorized",
    "corporate", "team", "global", "channel"
]

DECEPTIVE_DESCRIPTION_CLAIMS = [
    "official account", "official youtube", "official channel", "official support",
    "contact support", "customer care", "customer service", "help center",
    "authorized representative", "rewards claim", "dm for support", "whatsapp support",
    "telegram support", "official representative", "official page"
]

FAN_COMMENTARY_DISCLOSURES = [
    "fan", "fans", "fanpage", "fan page", "fan club", "fan account",
    "tribute", "unofficial", "not affiliated", "fan community",
    "commentary", "review", "reviews", "critique", "critiques",
    "analysis", "reaction", "reactions", "news", "discussion",
    "breakdown", "parody", "satire", "spoof", "meme", "memes",
    "comedy", "joke"
]


def evaluate_youtube_channel_verification(
    channel_data: Dict[str, Any],
    brand: Any,
    official_assets: Optional[List[Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates an exact resolved YouTube channel against the brand's registered official assets.

    Verdicts:
    - Official: Exact channel ID matches a registered official account.
    - Suspected impersonation: Different ID with meaningful evidence of impersonating the selected brand.
    - Unrelated: Available evidence indicates no meaningful relationship to that brand.
    - Inconclusive: Missing official identity or insufficient/ambiguous evidence.

    CRITICAL RULES:
    1. A different ID or similar name alone must never mean "fake" or impersonator.
    2. A legitimate unrelated channel must not be labelled an impersonator.
    3. Fan, commentary, review, and parody channels must be accounted for and not falsely accused.
    4. Exact match displays: "Official — Channel ID matches the brand’s registered official account."
    5. No invented percentages or fabricated evidence.
    """
    official_assets = official_assets or []
    channel_id = str(channel_data.get("channel_id") or channel_data.get("id") or "").strip()
    title = str(channel_data.get("title") or "").strip()
    description = str(channel_data.get("description") or "").strip()
    custom_url = str(channel_data.get("custom_url") or "").strip()
    canonical_url = str(channel_data.get("canonical_url") or f"https://www.youtube.com/channel/{channel_id}").strip()

    brand_name = getattr(brand, "name", str(brand)).strip()
    brand_name_lower = brand_name.lower()

    # 1. Collect registered official YouTube channel IDs for the selected brand
    official_yt_assets = [
        a for a in official_assets
        if (getattr(a, "source_platform", "") or "").strip().lower() == "youtube"
        or (
            (getattr(a, "asset_type", "") or "").strip().lower() == "social_account"
            and (getattr(a, "source_platform", "") or "").strip().lower() == "youtube"
        )
    ]

    official_stable_ids = []
    for a in official_yt_assets:
        s_id = str(getattr(a, "stable_id", "") or "").strip()
        if s_id and s_id not in official_stable_ids:
            official_stable_ids.append(s_id)
        e_id = str(getattr(a, "exact_identifier", "") or "").strip()
        if e_id.startswith("UC") and e_id not in official_stable_ids:
            official_stable_ids.append(e_id)

    # 2. Check for EXACT official channel match
    if channel_id and channel_id in official_stable_ids:
        return {
            "verdict": VERDICT_OFFICIAL,
            "channel_name": title,
            "channel_url": canonical_url,
            "stable_channel_id": channel_id,
            "summary": "Official — Channel ID matches the brand’s registered official account.",
            "is_official": True,
            "reasons": [
                "Official — Channel ID matches the brand’s registered official account.",
                f"Resolved channel ID '{channel_id}' matches registered official YouTube identity for '{brand_name}'.",
                "Identity confirmed through exact stable channel ID match against verified brand registry."
            ],
            "evidence": {
                "resolved_channel_id": channel_id,
                "matched_official_id": channel_id,
                "registered_official_channel_ids": official_stable_ids,
                "brand_name": brand_name,
                "verification_method": "Exact stable channel ID comparison",
                "identity_match": True,
                "scope_note": "Official confirms a registered identity match, not that every video or message is safe."
            }
        }

    # 3. Check for missing official brand baseline
    if not official_stable_ids:
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "channel_name": title,
            "channel_url": canonical_url,
            "stable_channel_id": channel_id,
            "summary": f"Inconclusive — Missing official identity for '{brand_name}'.",
            "is_official": False,
            "reasons": [
                f"The selected brand '{brand_name}' does not have a registered official YouTube channel ID.",
                "Official status cannot be established without a registered baseline channel ID to compare against.",
                "Please register the official YouTube channel in Brand Profile to enable exact matching."
            ],
            "evidence": {
                "resolved_channel_id": channel_id,
                "registered_official_channel_ids": [],
                "brand_name": brand_name,
                "missing_official_identity": True
            }
        }

    # 4. Parse brand aliases and tokens for content evaluation
    aliases = []
    aliases_json = getattr(brand, "aliases_json", "[]")
    if aliases_json:
        try:
            parsed_aliases = json.loads(aliases_json)
            if isinstance(parsed_aliases, list):
                aliases = [str(a).strip().lower() for a in parsed_aliases if a]
        except Exception:
            pass

    brand_terms = {brand_name_lower} | set(aliases)
    primary_token = brand_name_lower.split()[0] if brand_name_lower else ""

    title_lower = title.lower()
    desc_lower = description.lower()
    handle_lower = custom_url.lower()
    combined_text = f"{title_lower} {handle_lower} {desc_lower}"

    brand_mentioned = any(term in combined_text for term in brand_terms if len(term) >= 3)
    if not brand_mentioned:
        combined_compact = re.sub(r"[\s_-]+", "", combined_text)
        for term in brand_terms:
            t_compact = re.sub(r"[\s_-]+", "", term)
            if len(t_compact) >= 4 and t_compact in combined_compact:
                brand_mentioned = True
                break
        if not brand_mentioned and primary_token and len(primary_token) >= 4:
            brand_mentioned = primary_token in combined_text or primary_token in combined_compact

    # 5. Check if Unrelated: No brand relationship found
    if not brand_mentioned:
        return {
            "verdict": VERDICT_UNRELATED,
            "channel_name": title,
            "channel_url": canonical_url,
            "stable_channel_id": channel_id,
            "summary": f"Unrelated — Available evidence indicates no meaningful relationship to {brand_name}.",
            "is_official": False,
            "reasons": [
                f"Available evidence indicates no meaningful relationship to {brand_name}.",
                f"Channel title ('{title}'), handle ('{custom_url}'), and description do not reference the brand or its registered aliases.",
                f"Resolved channel ID '{channel_id}' is distinct from the brand's registered account ({', '.join(official_stable_ids)})."
            ],
            "evidence": {
                "resolved_channel_id": channel_id,
                "registered_official_channel_ids": official_stable_ids,
                "brand_name": brand_name,
                "brand_terms_evaluated": list(brand_terms),
                "relationship_found": False
            }
        }

    # 6. Check for Fan, Commentary, Review, or Parody Disclosures
    detected_disclosures = []
    for disc in FAN_COMMENTARY_DISCLOSURES:
        pattern = r"\b" + re.escape(disc) + r"\b"
        if re.search(pattern, combined_text):
            detected_disclosures.append(disc)

    if detected_disclosures:
        return {
            "verdict": VERDICT_INCONCLUSIVE,
            "channel_name": title,
            "channel_url": canonical_url,
            "stable_channel_id": channel_id,
            "summary": f"Inconclusive — Channel references {brand_name} with fan/commentary/parody indicators.",
            "is_official": False,
            "reasons": [
                f"Channel references '{brand_name}' but contains disclosure indicators ({', '.join(detected_disclosures[:3])}).",
                "Channel ID differs from the registered official account, but context indicates fan, commentary, review, or parody activity rather than deceptive impersonation.",
                "Legitimate fan, commentary, and parody channels must not be categorized as impersonators."
            ],
            "evidence": {
                "resolved_channel_id": channel_id,
                "registered_official_channel_ids": official_stable_ids,
                "brand_name": brand_name,
                "detected_disclosures": detected_disclosures,
                "deception_intent_established": False
            }
        }

    # 7. Check for Meaningful Impersonation Evidence
    impersonation_evidence = []

    # Check authority/official keywords combined with brand in title or handle
    for kw in DECEPTIVE_AUTHORITY_KEYWORDS:
        kw_pattern = r"\b" + re.escape(kw) + r"\b"
        if re.search(kw_pattern, title_lower) or kw in handle_lower:
            impersonation_evidence.append(f"Channel uses authority/official modifier: '{kw}'")
            break

    # Check deceptive claims in description
    for claim in DECEPTIVE_DESCRIPTION_CLAIMS:
        if claim in desc_lower:
            impersonation_evidence.append(f"Channel description claims official status or support: '{claim}'")
            break

    # Check direct name copy: title or handle exactly mirrors brand name without registration
    clean_title = re.sub(r"[^\w\s]", "", title_lower).strip()
    clean_brand = re.sub(r"[^\w\s]", "", brand_name_lower).strip()
    if clean_title == clean_brand or handle_lower in [f"@{clean_brand}", f"@{primary_token}"]:
        impersonation_evidence.append(f"Channel title directly mirrors brand name '{brand_name}' under an unregistered ID")

    if impersonation_evidence:
        return {
            "verdict": VERDICT_SUSPECTED_IMPERSONATION,
            "channel_name": title,
            "channel_url": canonical_url,
            "stable_channel_id": channel_id,
            "summary": f"Suspected impersonation — Different channel ID with meaningful evidence of impersonating {brand_name}.",
            "is_official": False,
            "reasons": [
                f"Channel ID '{channel_id}' does not match registered official account ({', '.join(official_stable_ids)}).",
                f"Meaningful evidence of impersonating {brand_name} detected.",
                *impersonation_evidence,
                "No official authorization found and channel lacks fan or parody disclaimers."
            ],
            "evidence": {
                "resolved_channel_id": channel_id,
                "registered_official_channel_ids": official_stable_ids,
                "brand_name": brand_name,
                "impersonation_indicators": impersonation_evidence,
                "absence_of_disclosure": True
            }
        }

    # 8. Ambiguous / Insufficient Evidence -> Inconclusive
    return {
        "verdict": VERDICT_INCONCLUSIVE,
        "channel_name": title,
        "channel_url": canonical_url,
        "stable_channel_id": channel_id,
        "summary": f"Inconclusive — Channel mentions terms related to {brand_name} without proof of impersonation.",
        "is_official": False,
        "reasons": [
            f"Channel ID '{channel_id}' does not match registered official account ({', '.join(official_stable_ids)}).",
            f"Channel contains terms overlapping with '{brand_name}', but evidence is insufficient or ambiguous.",
            "A different ID or similar name alone does not constitute proof of impersonation."
        ],
        "evidence": {
            "resolved_channel_id": channel_id,
            "registered_official_channel_ids": official_stable_ids,
            "brand_name": brand_name,
            "ambiguity_reason": "Name similarity without deceptive authority claims or impersonation indicators"
        }
    }
