import re
import json

SUPPORTED_SOCIAL_PLATFORMS = {"instagram", "twitter_x", "tiktok", "linkedin", "facebook", "youtube"}
SUPPORTED_APP_STORES = {"google_play", "apple_app_store"}
VALID_REVIEW_VERDICTS = {
    "new", "flagged", "in_review", "under_review",
    "confirmed", "takedown_requested", "takedown_sent",
    "whitelisted", "dismissed", "escalated"
}

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
ANDROID_PACKAGE_REGEX = re.compile(
    r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$'
)
APPLE_ID_REGEX = re.compile(
    r'^(?:id)?([0-9]{7,12})$'
)

class ValidationError(Exception):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.message = message
        self.field = field

def validate_org_scope(expected_org_id, target_org_id):
    if not expected_org_id or not target_org_id:
        raise ValidationError("Missing organization scope identifier.", field="organization_id")
    if str(expected_org_id) != str(target_org_id):
        raise ValidationError("Cross-organization operation unauthorized.", field="organization_id")

def validate_brand_name(name):
    if not name or not isinstance(name, str) or not name.strip():
        raise ValidationError("Brand name is required and cannot be empty.", field="name")
    cleaned = name.strip()
    if len(cleaned) < 2 or len(cleaned) > 255:
        raise ValidationError("Brand name must be between 2 and 255 characters.", field="name")
    return cleaned

def validate_aliases(aliases):
    if aliases is None:
        return []
    if isinstance(aliases, str):
        try:
            aliases = json.loads(aliases)
        except Exception:
            aliases = [a.strip() for a in aliases.split(",") if a.strip()]
    if not isinstance(aliases, list):
        raise ValidationError("Aliases must be a list of strings.", field="aliases")
    cleaned_aliases = []
    for a in aliases:
        if isinstance(a, str) and a.strip():
            cleaned_aliases.append(a.strip())
    return cleaned_aliases

def validate_domain(domain_str):
    if not domain_str or not isinstance(domain_str, str):
        raise ValidationError("Domain name is required.", field="domain")
    d = domain_str.strip().lower()
    
    # Strip any protocol or paths if user accidentally typed them
    if d.startswith("http://") or d.startswith("https://"):
        raise ValidationError(
            "Domain must be a fully qualified domain name (e.g. 'northstar-tech.io') without 'http://' or 'https://'.",
            field="domain"
        )
    if "/" in d or ":" in d:
        raise ValidationError("Domain must not contain URL paths, slashes, or port numbers.", field="domain")
    
    if not DOMAIN_REGEX.match(d):
        raise ValidationError(f"'{d}' is not a valid fully-qualified domain name (FQDN).", field="domain")
    return d

def validate_social_asset(platform, handle, stable_account_id):
    if not platform or platform.lower() not in SUPPORTED_SOCIAL_PLATFORMS:
        raise ValidationError(
            f"Unsupported social platform '{platform}'. Supported: {', '.join(sorted(SUPPORTED_SOCIAL_PLATFORMS))}",
            field="source_platform"
        )
    platform_clean = platform.lower()

    if not handle or not isinstance(handle, str) or not handle.strip():
        raise ValidationError("Social handle or account path is required.", field="exact_identifier")
    handle_clean = handle.strip()

    if not stable_account_id or not isinstance(stable_account_id, str) or not stable_account_id.strip():
        raise ValidationError(
            "Exact stable account/channel ID is required for official social assets (e.g. platform internal user/channel ID).",
            field="stable_id"
        )
    stable_clean = stable_account_id.strip()

    return platform_clean, handle_clean, stable_clean

def validate_app_asset(store, exact_id, stable_app_id, authorized_publisher_id=None):
    if not store or store.lower() not in SUPPORTED_APP_STORES:
        raise ValidationError(
            f"Unsupported app store '{store}'. Supported: {', '.join(sorted(SUPPORTED_APP_STORES))}",
            field="source_platform"
        )
    store_clean = store.lower()

    if not exact_id or not isinstance(exact_id, str) or not exact_id.strip():
        raise ValidationError("App identifier / package name is required.", field="exact_identifier")
    exact_clean = exact_id.strip()

    if not stable_app_id or not isinstance(stable_app_id, str) or not stable_app_id.strip():
        raise ValidationError("Exact stable app identifier is required for official app assets.", field="stable_id")
    stable_clean = stable_app_id.strip()

    if store_clean == "google_play":
        if not ANDROID_PACKAGE_REGEX.match(exact_clean):
            raise ValidationError(
                f"Google Play package name '{exact_clean}' must follow standard reverse-DNS notation (e.g. 'com.northstar.mobile').",
                field="exact_identifier"
            )
    elif store_clean == "apple_app_store":
        match = APPLE_ID_REGEX.match(exact_clean)
        if not match:
            raise ValidationError(
                f"Apple App Store ID '{exact_clean}' must be a numeric ID (e.g. '158932014' or 'id158932014').",
                field="exact_identifier"
            )
        exact_clean = match.group(1)

    pub_clean = authorized_publisher_id.strip() if authorized_publisher_id else None
    return store_clean, exact_clean, stable_clean, pub_clean

def validate_review_verdict(verdict):
    if not verdict or verdict.lower() not in VALID_REVIEW_VERDICTS:
        raise ValidationError(
            f"Invalid review verdict '{verdict}'. Allowed verdicts: {', '.join(sorted(VALID_REVIEW_VERDICTS))}",
            field="verdict"
        )
    return verdict.lower()
