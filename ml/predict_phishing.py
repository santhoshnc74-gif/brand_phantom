"""
ml/predict_phishing.py
Safe official-identity verification and phishing risk prediction service for BrandSentinel.
Enforces domain security checks, prevents suffix attacks (e.g. official.example.attacker.example),
and caches the trusted active model in memory per organization/version.
"""

import os
import re
import json
import logging
from urllib.parse import urlparse
import joblib

from ml.url_features import (
    normalize_url,
    extract_domain_and_registrable,
    extract_features_vector,
)
# Ensure class definition is in namespace for joblib unpickling
from ml.train_phishing import PhishingModelBundle

logger = logging.getLogger("ml.predict_phishing")

_ACTIVE_MODEL_CACHE = {}

SOCIAL_AND_APP_DOMAINS = {
    "youtube.com": "YouTube channel identity must be checked using the Exact YouTube Channel Verification tool below.",
    "youtu.be": "YouTube channel identity must be checked using the Exact YouTube Channel Verification tool below.",
    "instagram.com": "Website URL analysis cannot verify Instagram account authenticity or ownership.",
    "t.me": "Website URL analysis cannot verify Telegram channel or bot authenticity.",
    "telegram.me": "Website URL analysis cannot verify Telegram channel or bot authenticity.",
    "play.google.com": "Website URL analysis cannot verify Google Play developer or app integrity.",
    "apps.apple.com": "Website URL analysis cannot verify Apple App Store developer credentials."
}

def verify_official_identity(url: str, brand_id: str, official_assets: list) -> dict:
    """
    Verifies whether the given URL matches a registered official domain for the selected brand.
    Enforces safe hostname matching:
    - Rejects lookalike suffixes: 'official.example.attacker.example' is REJECTED when official is 'official.example'.
    - Accepts exact match: 'brand.com' == 'brand.com'
    - Accepts legitimate subdomains: 'auth.brand.com' ends with '.brand.com'
    
    Returns {
        "status": "Official" | "Not verified as official" | "Unable to verify",
        "description": str,
        "matched_asset": dict or None
    }
    """
    if not brand_id or not official_assets:
        return {
            "status": "Unable to verify",
            "description": "No official domain assets registered for the selected brand.",
            "matched_asset": None
        }

    try:
        norm_url = normalize_url(url)
        parsed = urlparse(norm_url)
        submitted_host = (parsed.hostname or "").lower().strip()
    except Exception:
        return {
            "status": "Unable to verify",
            "description": "Could not parse submitted website hostname.",
            "matched_asset": None
        }

    if not submitted_host:
        return {
            "status": "Unable to verify",
            "description": "Invalid URL without a valid hostname.",
            "matched_asset": None
        }

    # Search registered official assets for this brand
    # Assets can have asset_type == 'domain' or 'website' or specific asset records
    registered_domains = []
    for asset in official_assets:
        # Extract registered domain/identifier
        ident = (asset.get("identifier") or asset.get("domain") or asset.get("value") or "").lower().strip()
        if not ident:
            continue
        # Strip scheme if stored with https://
        if "://" in ident:
            try:
                ident = urlparse(ident).hostname or ident
            except Exception:
                pass
        ident = ident.split("/")[0].split(":")[0].strip()
        if ident:
            registered_domains.append((ident, asset))

    if not registered_domains:
        return {
            "status": "Unable to verify",
            "description": "No official domains registered in the selected brand's asset registry.",
            "matched_asset": None
        }

    # Safe comparison:
    # submitted_host must EQUAL registered_domain OR end with '.' + registered_domain
    for reg_domain, asset_obj in registered_domains:
        if submitted_host == reg_domain or submitted_host.endswith("." + reg_domain):
            return {
                "status": "Official",
                "description": f"Domain matches the brand's registered official domain ({reg_domain}).",
                "matched_asset": {
                    "id": asset_obj.get("id"),
                    "domain": reg_domain,
                    "label": asset_obj.get("label") or reg_domain
                }
            }

    return {
        "status": "Not verified as official",
        "description": "No match in the selected brand's official registry.",
        "matched_asset": None
    }

def get_platform_limitation_note(url: str) -> str:
    """Returns limitation note if URL points to YouTube, Instagram, Telegram, or App Stores."""
    try:
        norm = normalize_url(url)
        host = (urlparse(norm).hostname or "").lower()
        for dom, note in SOCIAL_AND_APP_DOMAINS.items():
            if host == dom or host.endswith("." + dom):
                return note
    except Exception:
        pass
    return None

def load_cached_model_bundle(artifact_path: str, model_version: str):
    """Loads and caches the model bundle from disk."""
    global _ACTIVE_MODEL_CACHE
    if model_version in _ACTIVE_MODEL_CACHE:
        return _ACTIVE_MODEL_CACHE[model_version]

    if not os.path.exists(artifact_path):
        raise FileNotFoundError(f"Model artifact not found at {artifact_path}")

    bundle = joblib.load(artifact_path)
    _ACTIVE_MODEL_CACHE[model_version] = bundle
    return bundle

def clear_model_cache():
    """Clears in-memory model cache."""
    global _ACTIVE_MODEL_CACHE
    _ACTIVE_MODEL_CACHE.clear()

def predict_url_risk(url: str, bundle: PhishingModelBundle) -> dict:
    """
    Computes phishing probability and verdict for a URL using the active model bundle.
    Returns:
    {
        "status": "Likely phishing" | "Likely legitimate" | "Unable to assess",
        "probability": float (0.0 to 1.0),
        "threshold": float,
        "description": str
    }
    """
    if not url or not url.strip():
        return {
            "status": "Unable to assess",
            "probability": None,
            "threshold": 0.5,
            "description": "Empty URL provided."
        }

    try:
        norm_url = normalize_url(url)
        parsed = urlparse(norm_url)
        if not parsed.scheme or not parsed.hostname:
            return {
                "status": "Unable to assess",
                "probability": None,
                "threshold": 0.5,
                "description": "Invalid or unparseable website URL."
            }

        if parsed.scheme.lower() not in ("http", "https"):
            return {
                "status": "Unable to assess",
                "probability": None,
                "threshold": 0.5,
                "description": f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are supported."
            }

        # Extract features identically to training
        features = extract_features_vector(norm_url)
        phish_proba = float(bundle.predict_phishing_proba([features])[0])
        threshold = float(getattr(bundle, "threshold", 0.5))

        verdict = "Likely phishing" if phish_proba >= threshold else "Likely legitimate"
        desc = "Model prediction based on URL features."

        return {
            "status": verdict,
            "probability": round(phish_proba, 4),
            "threshold": threshold,
            "description": desc
        }
    except Exception as e:
        logger.error(f"Error evaluating URL phishing risk: {e}", exc_info=True)
        return {
            "status": "Unable to assess",
            "probability": None,
            "threshold": 0.5,
            "description": f"Model inference error: {str(e)}"
        }
