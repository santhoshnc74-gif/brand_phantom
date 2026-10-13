import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from functools import wraps
from flask import request, jsonify, g, make_response
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
import pyotp

from db.models import User, UserSession, AuthToken, RateLimitRecord, AuditEvent

# Password Hasher with Argon2id parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

SESSION_COOKIE_NAME = "brandsentinel_session"
CSRF_COOKIE_NAME = "brandsentinel_csrf"
IDLE_TIMEOUT = timedelta(hours=2)
ABSOLUTE_TIMEOUT = timedelta(days=7)

PASSWORD_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&_\-#])[A-Za-z\d@$!%*?&_\-#]{10,}$'
)

class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

# -----------------------------------------------------------------------------
# 1. PASSWORD SECURITY & COMPLEXITY
# -----------------------------------------------------------------------------
def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    if not password_hash or not plain_password:
        return False
    try:
        return ph.verify(password_hash, plain_password)
    except (VerifyMismatchError, InvalidHash):
        return False

def validate_password_complexity(password: str) -> None:
    if not password or len(password) < 10:
        raise AuthError("Password must be at least 10 characters long.", 400)
    if not re.search(r'[A-Z]', password):
        raise AuthError("Password must contain at least one uppercase letter.", 400)
    if not re.search(r'[a-z]', password):
        raise AuthError("Password must contain at least one lowercase letter.", 400)
    if not re.search(r'\d', password):
        raise AuthError("Password must contain at least one number.", 400)
    if not re.search(r'[@$!%*?&_\-#]', password):
        raise AuthError("Password must contain at least one special character (@, $, !, %, *, ?, &, _, -, #).", 400)

# -----------------------------------------------------------------------------
# 2. CRYPTOGRAPHIC TOKEN MANAGEMENT (Single-Use SHA-256 Hashing)
# -----------------------------------------------------------------------------
def generate_token_pair() -> Tuple[str, str]:
    """Generates a raw URL-safe token for the user and its SHA-256 hash for DB storage."""
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash

def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def create_auth_token(db, user_id: str, token_type: str, lifetime_minutes: int = 60) -> str:
    raw_token, token_hash = generate_token_pair()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = now + timedelta(minutes=lifetime_minutes)

    token_rec = AuthToken(
        user_id=user_id,
        token_type=token_type,
        token_hash=token_hash,
        created_at=now,
        expires_at=expires_at,
        is_used=False
    )
    db.add(token_rec)
    db.commit()
    return raw_token

def consume_auth_token(db, raw_token: str, token_type: str) -> Optional[User]:
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    token_rec = db.query(AuthToken).filter(
        AuthToken.token_hash == token_hash,
        AuthToken.token_type == token_type,
        AuthToken.is_used == False,
        AuthToken.expires_at > now
    ).first()

    if not token_rec:
        return None

    token_rec.is_used = True
    user = db.query(User).filter(User.id == token_rec.user_id).first()
    db.commit()
    return user

def peek_auth_token(db, raw_token: str, token_type: str) -> Optional[Tuple[AuthToken, User]]:
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    token_rec = db.query(AuthToken).filter(
        AuthToken.token_hash == token_hash,
        AuthToken.token_type == token_type,
        AuthToken.is_used == False,
        AuthToken.expires_at > now
    ).first()

    if not token_rec:
        return None

    user = db.query(User).filter(User.id == token_rec.user_id).first()
    return token_rec, user

# -----------------------------------------------------------------------------
# 3. SERVER-VALIDATED SESSIONS, EXPIRATION, ROTATION, REVOCATION
# -----------------------------------------------------------------------------
def create_session(db, user: User, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Tuple[UserSession, str, str]:
    raw_token, token_hash = generate_token_pair()
    csrf_token = secrets.token_hex(32)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        csrf_token=csrf_token,
        created_at=now,
        last_activity_at=now,
        expires_at=now + ABSOLUTE_TIMEOUT,
        is_revoked=False
    )
    db.add(session)
    db.commit()
    return session, raw_token, csrf_token

def validate_session(db, raw_token: str) -> Optional[UserSession]:
    if not raw_token:
        return None
    token_hash = hash_token(raw_token)
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    session = db.query(UserSession).filter(
        UserSession.token_hash == token_hash,
        UserSession.is_revoked == False
    ).first()

    if not session:
        return None

    # Check absolute expiration
    if session.expires_at <= now:
        session.is_revoked = True
        db.commit()
        return None

    # Check idle timeout
    if session.last_activity_at + IDLE_TIMEOUT <= now:
        session.is_revoked = True
        db.commit()
        return None

    # Update activity timestamp
    session.last_activity_at = now
    db.commit()
    return session

def rotate_session(db, old_session: UserSession, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Tuple[UserSession, str, str]:
    """Rotates session token on privilege change to prevent session fixation attacks."""
    old_session.is_revoked = True
    user = old_session.user
    db.commit()
    return create_session(db, user, ip_address, user_agent)

def revoke_session(db, raw_token: str) -> bool:
    if not raw_token:
        return False
    token_hash = hash_token(raw_token)
    session = db.query(UserSession).filter(UserSession.token_hash == token_hash).first()
    if session:
        session.is_revoked = True
        db.commit()
        return True
    return False

def revoke_all_user_sessions(db, user_id: str) -> int:
    """Revokes all active sessions for a user (e.g. on password reset or account recovery)."""
    count = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.is_revoked == False
    ).update({"is_revoked": True})
    db.commit()
    return count

def set_auth_cookies(response, raw_token: str, csrf_token: str, is_production: bool = False):
    """
    Sets HttpOnly, SameSite=Lax, and Secure session cookies.
    Session tokens are NEVER stored in localStorage.
    """
    # HttpOnly Session Cookie
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        secure=is_production,
        samesite="Lax",
        max_age=int(ABSOLUTE_TIMEOUT.total_seconds()),
        path="/"
    )
    # Accessible CSRF Cookie for double-submit / header validation
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        httponly=False,
        secure=is_production,
        samesite="Lax",
        max_age=int(ABSOLUTE_TIMEOUT.total_seconds()),
        path="/"
    )
    return response

def clear_auth_cookies(response):
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return response

# -----------------------------------------------------------------------------
# 4. MULTI-FACTOR AUTHENTICATION (TOTP / RFC 6238)
# -----------------------------------------------------------------------------
def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def get_mfa_uri(secret: str, email: str, issuer: str = "BrandSentinel") -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=issuer)

def verify_mfa_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    clean_code = re.sub(r'\s+', '', code)
    if not re.match(r'^\d{6}$', clean_code):
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_code, valid_window=1)

# -----------------------------------------------------------------------------
# 5. AUTHENTICATION RATE LIMITING
# -----------------------------------------------------------------------------
def check_rate_limit(db, key: str, max_attempts: int = 5, window_seconds: int = 900, block_seconds: int = 900) -> Tuple[bool, int, Optional[int]]:
    """
    Rate limiter for sign-in, recovery, and registration attempts.
    Returns (is_allowed, remaining_attempts, retry_after_seconds).
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    record = db.query(RateLimitRecord).filter(RateLimitRecord.key == key).first()

    if not record:
        return True, max_attempts, None

    # Check if currently blocked
    if record.blocked_until and record.blocked_until > now:
        retry_after = int((record.blocked_until - now).total_seconds())
        return False, 0, max(1, retry_after)

    # Check if window expired
    if record.first_attempt_at + timedelta(seconds=window_seconds) <= now:
        record.attempts = 0
        record.first_attempt_at = now
        record.blocked_until = None
        db.commit()
        return True, max_attempts, None

    # Check attempt threshold
    if record.attempts >= max_attempts:
        record.blocked_until = now + timedelta(seconds=block_seconds)
        db.commit()
        retry_after = int(block_seconds)
        return False, 0, retry_after

    remaining = max(0, max_attempts - record.attempts)
    return True, remaining, None

def record_rate_limit_attempt(db, key: str, window_seconds: int = 900):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    record = db.query(RateLimitRecord).filter(RateLimitRecord.key == key).first()

    if not record:
        record = RateLimitRecord(
            key=key,
            attempts=1,
            first_attempt_at=now,
            last_attempt_at=now
        )
        db.add(record)
    else:
        record.attempts += 1
        record.last_attempt_at = now
    db.commit()

def clear_rate_limit(db, key: str):
    record = db.query(RateLimitRecord).filter(RateLimitRecord.key == key).first()
    if record:
        db.delete(record)
        db.commit()

# -----------------------------------------------------------------------------
# 6. VALIDATED REDIRECTS (Prevents Open Redirect Vulnerabilities)
# -----------------------------------------------------------------------------
def is_safe_redirect(url: Optional[str]) -> bool:
    if not url:
        return False
    clean = url.strip()
    # Must start with single slash, not protocol-relative (//) and no colons before slash
    if not clean.startswith("/") or clean.startswith("//"):
        return False
    if "\\" in clean or ":" in clean.split("/")[0]:
        return False
    return True

def get_safe_redirect(url: Optional[str], default: str = "/") -> str:
    return url.strip() if is_safe_redirect(url) else default

# -----------------------------------------------------------------------------
# 7. ROUTE DECORATORS & GUARDS
# -----------------------------------------------------------------------------
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db = getattr(g, "db", None)
        if not db:
            return jsonify({"error": "Database session unavailable."}), 500

        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            # Check Bearer authorization header fallback for tests/API clients
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()

        session = validate_session(db, token)
        if not session or not session.user or not session.user.is_active:
            return jsonify({"error": "Authentication required. Please sign in.", "code": "UNAUTHORIZED"}), 401

        g.current_user = session.user
        g.current_session = session
        g.user_id = session.user.id
        return f(*args, **kwargs)
    return decorated_function

def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if not user or user.role not in allowed_roles:
                return jsonify({
                    "error": "Forbidden: Insufficient privileges for this operation.",
                    "code": "FORBIDDEN"
                }), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_csrf(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Only enforce on state-mutating HTTP methods
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            session = getattr(g, "current_session", None)
            if session:
                header_csrf = request.headers.get("X-CSRF-Token") or request.headers.get("X-CSRFToken")
                cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
                expected_csrf = session.csrf_token

                if not header_csrf or header_csrf != expected_csrf:
                    return jsonify({
                        "error": "Invalid or missing CSRF token.",
                        "code": "CSRF_VERIFICATION_FAILED"
                    }), 403
        return f(*args, **kwargs)
    return decorated_function
