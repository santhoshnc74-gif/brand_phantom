"""
BrandSentinel Credential Vault
==============================
Provides AES-128-CBC + HMAC-SHA256 authenticated symmetric encryption
using Fernet from the cryptography library.

Managed encryption keys are kept strictly separate from the database.
Stored credentials in relational tables contain only encrypted ciphertext.
Cleartext secrets are never returned to clients.
"""

import os
import json
import base64
import hashlib
import logging
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("brandsentinel.vault")

class CredentialVaultError(Exception):
    """Base exception for Credential Vault failures."""
    pass

class CredentialDecryptionError(CredentialVaultError):
    """Raised when ciphertext cannot be decrypted or key is invalid."""
    pass

def derive_vault_key(raw_key: Optional[str] = None) -> bytes:
    """
    Derives a valid 32-byte urlsafe base64 key suitable for Fernet.
    If raw_key is already a valid 32-byte urlsafe base64 string, it is used directly.
    Otherwise, a deterministic 32-byte key is derived via SHA-256.
    """
    if not raw_key:
        raw_key = os.getenv("CREDENTIAL_ENCRYPTION_KEY")
    if not raw_key:
        # Fall back to server SECRET_KEY in development/test
        raw_key = os.getenv("SECRET_KEY", "dev-insecure-key-only-change-in-prod-min32chars")

    try:
        raw_bytes = raw_key.encode("utf-8")
        decoded = base64.urlsafe_b64decode(raw_bytes)
        if len(decoded) == 32:
            return raw_bytes
    except Exception:
        pass

    # Derive 32-byte key using SHA-256
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_credentials(data: Dict[str, Any], custom_key: Optional[str] = None) -> str:
    """
    Encrypts a dictionary of credentials into a Fernet ciphertext token.
    Never returns unencrypted credentials.
    """
    if not data:
        return ""
    try:
        fernet_key = derive_vault_key(custom_key)
        f = Fernet(fernet_key)
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        encrypted_token = f.encrypt(json_bytes)
        return encrypted_token.decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to encrypt credentials: {type(e).__name__}")
        raise CredentialVaultError("Failed to encrypt credentials in secure vault.") from e

def decrypt_credentials(ciphertext: Optional[str], custom_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Decrypts a Fernet ciphertext token back into a dictionary of credentials.
    Raises CredentialDecryptionError if ciphertext is invalid, corrupted, or key is wrong.
    """
    if not ciphertext or not ciphertext.strip():
        return {}
    try:
        fernet_key = derive_vault_key(custom_key)
        f = Fernet(fernet_key)
        decrypted_bytes = f.decrypt(ciphertext.strip().encode("utf-8"))
        return json.loads(decrypted_bytes.decode("utf-8"))
    except InvalidToken as e:
        logger.warning("Decryption failed: Invalid cipher token or mismatched encryption key.")
        raise CredentialDecryptionError("Unable to decrypt credentials. Key mismatch or data corrupted.") from e
    except Exception as e:
        logger.error(f"Unexpected decryption error: {type(e).__name__}")
        raise CredentialDecryptionError("Credential decryption failed.") from e

def sanitize_credential_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively replaces sensitive values in dictionary with '[REDACTED]'.
    Safe for logging, auditing, and debugging without leaking secrets.
    """
    sanitized = {}
    sensitive_keys = {"api_key", "secret", "private_key", "password", "token", "credential", "client_secret", "key"}
    for k, v in payload.items():
        if isinstance(v, dict):
            sanitized[k] = sanitize_credential_payload(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_credential_payload(i) if isinstance(i, dict) else "[REDACTED]"
                for i in v
            ]
        elif any(s in k.lower() for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized
