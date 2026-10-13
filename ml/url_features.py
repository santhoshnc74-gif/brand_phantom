"""
ml/url_features.py
Deterministic, reproducible URL lexical feature extractor for BrandSentinel Phishing URL Detection.
Computes features strictly from raw URL strings without network requests, DNS queries, or page fetching.
Shared 100% identically between dataset training and live inference.
"""

import re
import math
from urllib.parse import urlparse, unquote

FEATURE_EXTRACTOR_VERSION = "1.0.0"

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "is_https",
    "is_ip",
    "num_dots_url",
    "num_dots_host",
    "num_hyphens_url",
    "num_hyphens_host",
    "num_underscores_url",
    "num_slashes_url",
    "num_question_marks",
    "num_equals",
    "num_ampersands",
    "num_percent",
    "num_at_symbols",
    "num_tildes",
    "num_digits_url",
    "digit_ratio_url",
    "num_letters_url",
    "letter_ratio_url",
    "special_char_ratio_url",
    "num_subdomains",
    "tld_length",
    "has_port",
    "suspicious_keyword_count",
    "char_entropy_url",
    "char_entropy_host",
    "max_consecutive_char",
]

IP_V4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IP_V6_PATTERN = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "confirmation", "banking", "bank", "password", "credential",
    "wallet", "authenticate", "auth", "recover", "recovery", "webscr", "ebayisapi",
    "support", "service", "billing", "invoice", "payment", "session", "appleid"
)

# Common two-part public suffixes for domain grouping without network calls
TWO_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "com.sg", "edu.sg", "gov.sg",
    "co.za", "org.za", "web.za",
    "gc.ca", "asso.fr", "com.de", "co.kr"
}

def normalize_url(raw_url: str) -> str:
    """
    Normalizes URL deterministically:
    - Strips leading/trailing whitespace
    - Adds https:// scheme if missing for parsing
    - Lowercases hostname
    - Strips fragment identifier (#...)
    - Preserves path and query parameter case and semantics
    """
    if not raw_url:
        return ""
    
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        # Lowercase only hostname
        host = (parsed.hostname or "").lower()
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"
        
        # Build URL without fragment
        scheme = parsed.scheme.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        # Fallback to simple strip of fragment
        return url.split("#")[0]

def extract_domain_and_registrable(url: str):
    """
    Extracts the hostname and registrable domain (for leak-free grouping).
    Returns (hostname, registrable_domain).
    """
    normalized = normalize_url(url)
    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower().strip()
    except Exception:
        host = ""

    if not host:
        return "", ""

    # Check IP host
    if IP_V4_PATTERN.match(host) or IP_V6_PATTERN.match(host):
        return host, host

    parts = host.split(".")
    if len(parts) <= 2:
        return host, host

    # Check two-part TLD
    last_two = ".".join(parts[-2:])
    if last_two in TWO_PART_TLDS and len(parts) >= 3:
        registrable = ".".join(parts[-3:])
    else:
        registrable = ".".join(parts[-2:])

    return host, registrable

def _shannon_entropy(s: str) -> float:
    """Computes Shannon entropy of string."""
    if not s:
        return 0.0
    length = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def _max_consecutive_run(s: str) -> int:
    """Length of longest consecutive identical character run."""
    if not s:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    return max_run

def extract_features_dict(url: str) -> dict:
    """
    Extracts dictionary of lexical URL features.
    Deterministic, offline, safe for single URL or full batch.
    """
    normalized = normalize_url(url)
    try:
        parsed = urlparse(normalized)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().strip()
        path = parsed.path or ""
        query = parsed.query or ""
        has_custom_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
    except Exception:
        scheme = "https"
        host = ""
        path = ""
        query = ""
        has_custom_port = 0

    url_len = len(normalized)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)

    is_https = 1 if scheme == "https" else 0
    is_ip = 1 if (IP_V4_PATTERN.match(host) or IP_V6_PATTERN.match(host)) else 0

    num_dots_url = normalized.count(".")
    num_dots_host = host.count(".")
    num_hyphens_url = normalized.count("-")
    num_hyphens_host = host.count("-")
    num_underscores_url = normalized.count("_")
    num_slashes_url = normalized.count("/")
    num_question_marks = normalized.count("?")
    num_equals = normalized.count("=")
    num_ampersands = normalized.count("&")
    num_percent = normalized.count("%")
    num_at_symbols = normalized.count("@")
    num_tildes = normalized.count("~")

    # Character counts
    num_digits = sum(1 for c in normalized if c.isdigit())
    num_letters = sum(1 for c in normalized if c.isalpha())
    digit_ratio = num_digits / max(url_len, 1)
    letter_ratio = num_letters / max(url_len, 1)
    special_ratio = max(0, url_len - num_letters - num_digits) / max(url_len, 1)

    # Subdomain and TLD
    host_parts = host.split(".") if host else []
    if is_ip or len(host_parts) <= 1:
        num_subdomains = 0
        tld_len = 0
    else:
        # Registrable domain usually takes 1 or 2 parts, rest are subdomains
        last_two = ".".join(host_parts[-2:])
        domain_parts_count = 3 if last_two in TWO_PART_TLDS and len(host_parts) >= 3 else 2
        num_subdomains = max(0, len(host_parts) - domain_parts_count)
        tld_len = len(host_parts[-1])

    # Suspicious keywords in path and query
    path_query_lower = (path + " " + query).lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in path_query_lower)

    # Entropy
    entropy_url = _shannon_entropy(normalized)
    entropy_host = _shannon_entropy(host)

    # Longest repeating char run
    max_run = _max_consecutive_run(normalized)

    return {
        "url_length": float(url_len),
        "host_length": float(host_len),
        "path_length": float(path_len),
        "query_length": float(query_len),
        "is_https": float(is_https),
        "is_ip": float(is_ip),
        "num_dots_url": float(num_dots_url),
        "num_dots_host": float(num_dots_host),
        "num_hyphens_url": float(num_hyphens_url),
        "num_hyphens_host": float(num_hyphens_host),
        "num_underscores_url": float(num_underscores_url),
        "num_slashes_url": float(num_slashes_url),
        "num_question_marks": float(num_question_marks),
        "num_equals": float(num_equals),
        "num_ampersands": float(num_ampersands),
        "num_percent": float(num_percent),
        "num_at_symbols": float(num_at_symbols),
        "num_tildes": float(num_tildes),
        "num_digits_url": float(num_digits),
        "digit_ratio_url": float(digit_ratio),
        "num_letters_url": float(num_letters),
        "letter_ratio_url": float(letter_ratio),
        "special_char_ratio_url": float(special_ratio),
        "num_subdomains": float(num_subdomains),
        "tld_length": float(tld_len),
        "has_port": float(has_custom_port),
        "suspicious_keyword_count": float(keyword_count),
        "char_entropy_url": float(entropy_url),
        "char_entropy_host": float(entropy_host),
        "max_consecutive_char": float(max_run),
    }

def extract_features_vector(url: str) -> list:
    """Extracts ordered list of features matching FEATURE_NAMES."""
    feat_dict = extract_features_dict(url)
    return [feat_dict[k] for k in FEATURE_NAMES]
