import os
import json
import time
import re
import secrets
import csv
import io
from urllib.parse import urlparse
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, g, make_response, Response
from sqlalchemy import func
from sqlalchemy.orm import joinedload

from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, Scan, Candidate, Detection, Review, AuditEvent,
    Dataset, DatasetRecord, MLTrainingJob, MLModelArtifact, URLScan
)
from db.validators import (
    validate_brand_name, validate_aliases, validate_domain,
    validate_social_asset, validate_app_asset, validate_review_verdict,
    validate_org_scope, ValidationError
)
from db.matcher import evaluate_candidate_identity, evaluate_youtube_channel_verification
from db.migrations.migrator import run_migrations
from db.seed import seed_database
from services.dataset_service import (
    validate_and_import_csv, get_dataset_preview, start_training_job,
    get_job_status, get_active_model_info, recover_interrupted_jobs
)
from ml.url_features import normalize_url
from ml.predict_phishing import (
    verify_official_identity, get_platform_limitation_note,
    load_cached_model_bundle, predict_url_risk
)

from auth import (
    hash_password, verify_password, validate_password_complexity,
    create_auth_token, consume_auth_token, peek_auth_token,
    create_session, validate_session, rotate_session, revoke_session, revoke_all_user_sessions,
    set_auth_cookies, clear_auth_cookies,
    generate_mfa_secret, get_mfa_uri, verify_mfa_code,
    check_rate_limit, record_rate_limit_attempt, clear_rate_limit,
    get_safe_redirect, is_safe_redirect,
    require_auth, require_role, validate_csrf,
    AuthError, SESSION_COOKIE_NAME, CSRF_COOKIE_NAME
)
from rbac import (
    require_permission, require_org_role, has_permission,
    get_role_permissions, count_organization_owners, ROLE_PERMISSIONS
)
from config import AppConfig, ConfigurationError, configure_secure_logging
from vault import (
    encrypt_credentials, decrypt_credentials, sanitize_credential_payload,
    CredentialVaultError, CredentialDecryptionError
)
from connectors import (
    YouTubeConnector, AppleAppStoreConnector, GooglePlayConnector, TelegramConnector, FacebookConnector,
    CONNECTOR_CLIENTS, ConnectorRegistry, NormalizedCandidate, ConnectionResult
)
from pipeline import (
    DETECTOR_VERSION,
    ASSESSMENT_OFFICIAL_MATCH,
    ASSESSMENT_LIKELY_IMPERSONATION,
    ASSESSMENT_INCONCLUSIVE,
    ASSESSMENT_UNRELATED,
    analyze_and_assess_candidate,
    process_candidate_pipeline,
    validate_and_parse_import_json,
    sanitize_untrusted_text
)

# Load and validate typed configuration at startup
try:
    app_config = AppConfig.from_env()
    configure_secure_logging(app_config)
except ConfigurationError as ce:
    # Fail safely with sanitized error message without leaking sensitive variables
    import sys
    print(f"CONFIGURATION ERROR: {ce}", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config_obj = app_config
app.secret_key = app_config.secret_key.get_secret_value()
app.config['MAX_CONTENT_LENGTH'] = 120 * 1024 * 1024  # 120 MiB upload limit for large datasets

# Run database migrations and ensure baseline fictional data is seeded on startup
with app.app_context():
    try:
        run_migrations()
        seed_database()
        recover_interrupted_jobs()
    except Exception as e:
        app.logger.info(f"Startup initialization notice: {e}")

@app.before_request
def setup_request_context():
    g.db = SessionLocal()
    g.is_production = (app.config_obj.environment == "production")

    # 1. Resolve session from HttpOnly cookie or Authorization Bearer header
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    session = validate_session(g.db, token) if token else None
    if session and session.user and session.user.is_active:
        g.current_user = session.user
        g.current_session = session
        g.user_id = session.user.id

        # 2. Strict Tenant Isolation & Membership Verification
        # Never trust client-supplied user IDs, roles, or organization IDs!
        requested_org_id = request.headers.get("X-Organization-Id")
        if requested_org_id:
            # Query membership in the explicitly requested organization
            membership = g.db.query(Membership).filter(
                Membership.user_id == session.user.id,
                Membership.organization_id == requested_org_id
            ).first()

            if membership:
                g.org_id = requested_org_id
                g.membership = membership
                g.user_role = membership.role
                g.org_access_denied = False
            else:
                # User is NOT an authorized member of requested organization!
                g.org_id = None
                g.membership = None
                g.user_role = None
                g.org_access_denied = True
        else:
            # Resolve user's primary/active membership
            user_memberships = g.db.query(Membership).filter(
                Membership.user_id == session.user.id
            ).all()

            if user_memberships:
                g.org_id = user_memberships[0].organization_id
                g.membership = user_memberships[0]
                g.user_role = user_memberships[0].role
                g.org_access_denied = False
            else:
                g.org_id = None
                g.membership = None
                g.user_role = None
                g.org_access_denied = False
    else:
        g.current_user = None
        g.current_session = None
        g.membership = None
        g.org_access_denied = False

        requested_org_id = request.headers.get("X-Organization-Id")
        if requested_org_id:
            g.org_id = requested_org_id
            g.user_role = "viewer" if g.is_production else "owner"
        elif not g.is_production:
            # Demo sandbox fallback for unauthenticated preview mode
            sample_org = g.db.query(Organization).filter(Organization.slug == "northstar-tech").first()
            g.org_id = sample_org.id if sample_org else "org-northstar-fictional"
            sample_user = g.db.query(User).filter(User.email == "security@northstar-tech.io").first()
            g.user_id = sample_user.id if sample_user else None
            g.user_role = "owner"
        else:
            g.org_id = None
            g.user_id = None
            g.user_role = None

@app.teardown_request
def teardown_request_context(exception=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()

def log_audit_event(action, entity_type, entity_id, details=None):
    try:
        if not getattr(g, "org_id", None):
            return

        # Sanitize details to guarantee zero secrets, passwords, or tokens in audit logs
        sanitized_details = {}
        if isinstance(details, dict):
            for k, v in details.items():
                if any(secret_term in k.lower() for secret_term in ["password", "secret", "token", "key", "credential", "hash", "auth"]):
                    sanitized_details[k] = "[REDACTED]"
                else:
                    sanitized_details[k] = v
        elif details:
            sanitized_details = {"info": str(details)}

        audit = AuditEvent(
            organization_id=g.org_id,
            user_id=getattr(g, "user_id", None),
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id),
            details_json=json.dumps(sanitized_details),
            ip_address=request.remote_addr or "127.0.0.1"
        )
        g.db.add(audit)
        g.db.commit()
    except Exception as e:
        print(f"Failed to record audit event: {e}")
        g.db.rollback()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/config", methods=["GET"])
def get_public_config():
    """
    Exposes ONLY public, safe metadata to the client.
    Never exposes server secrets, private keys, or API credentials.
    """
    return jsonify(app.config_obj.to_public_dict())

@app.errorhandler(500)
def handle_internal_server_error(e):
    app.logger.error("Internal application error occurred.")
    return jsonify({
        "error": "An internal error occurred. Request telemetry logged securely.",
        "status": 500
    }), 500

def check_production_auth():
    """Enforces authentication in production environments to prevent unauthorized mutations."""
    if g.is_production and not g.current_user:
        return jsonify({
            "error": "Authentication required. Please sign in to perform this operation.",
            "code": "UNAUTHORIZED"
        }), 401
    return None

# ==========================================
# AUTHENTICATION & ACCESS CONTROL API
# ==========================================

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    req = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"

    allowed, _, retry_after = check_rate_limit(
        g.db, f"register:{client_ip}", max_attempts=5, window_seconds=900, block_seconds=900
    )
    if not allowed:
        return jsonify({
            "error": "Too many registration attempts. Please try again later.",
            "retry_after": retry_after,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_after)}

    email = (req.get("email") or "").strip().lower()
    password = req.get("password") or ""
    full_name = (req.get("full_name") or "").strip()
    role = req.get("role", "analyst").strip()

    if not email or "@" not in email or "." not in email:
        return jsonify({"error": "A valid email address is required.", "field": "email"}), 400

    if not full_name:
        return jsonify({"error": "Full name is required.", "field": "full_name"}), 400

    try:
        validate_password_complexity(password)
    except AuthError as ae:
        return jsonify({"error": ae.message, "field": "password"}), 400

    existing_user = g.db.query(User).filter(User.email == email).first()
    if existing_user:
        record_rate_limit_attempt(g.db, f"register:{client_ip}")
        if existing_user.is_verified:
            return jsonify({
                "error": "An account with this email address already exists.",
                "code": "USER_ALREADY_EXISTS"
            }), 409
        else:
            token = create_auth_token(g.db, existing_user.id, "email_verification", lifetime_minutes=60)
            return jsonify({
                "message": "Account already registered but unverified. A new verification token has been issued.",
                "user_id": existing_user.id,
                "email": existing_user.email,
                "verification_token": token,
                "is_verified": False
            }), 200

    pwd_hash = hash_password(password)
    new_user = User(
        email=email,
        full_name=full_name,
        role=role,
        password_hash=pwd_hash,
        is_verified=False,
        is_active=True
    )
    g.db.add(new_user)
    g.db.flush()

    org_name = req.get("organization_name")
    if org_name:
        base_slug = re.sub(r'[^a-z0-9]+', '-', org_name.lower()).strip('-') or "org"
        slug = base_slug
        existing_org = g.db.query(Organization).filter(Organization.slug == slug).first()
        if existing_org:
            slug = f"{base_slug}-{secrets.token_hex(4)}"
        org = Organization(name=org_name, slug=slug, is_sample=False)
        g.db.add(org)
        g.db.flush()
        membership = Membership(organization_id=org.id, user_id=new_user.id, role="owner")
        g.db.add(membership)
    elif g.org_id:
        membership = Membership(organization_id=g.org_id, user_id=new_user.id, role=role)
        g.db.add(membership)

    token = create_auth_token(g.db, new_user.id, "email_verification", lifetime_minutes=60)
    g.db.commit()

    log_audit_event("auth.register", "user", new_user.id, {"email": email, "role": role})

    return jsonify({
        "message": "Registration successful. Please verify your email before signing in.",
        "user_id": new_user.id,
        "email": new_user.email,
        "verification_token": token,
        "is_verified": False
    }), 201

@app.route("/api/auth/verify-email", methods=["POST"])
def auth_verify_email():
    req = request.get_json(silent=True) or {}
    token = (req.get("token") or "").strip()
    client_ip = request.remote_addr or "127.0.0.1"

    allowed, _, retry_after = check_rate_limit(
        g.db, f"verify:{client_ip}", max_attempts=10, window_seconds=600, block_seconds=600
    )
    if not allowed:
        return jsonify({
            "error": "Too many verification attempts. Please wait before retrying.",
            "retry_after": retry_after,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_after)}

    if not token:
        return jsonify({"error": "Verification token is required.", "field": "token"}), 400

    user = consume_auth_token(g.db, token, "email_verification")
    if not user:
        record_rate_limit_attempt(g.db, f"verify:{client_ip}")
        return jsonify({
            "error": "Invalid, expired, or already used verification token.",
            "code": "INVALID_TOKEN"
        }), 400

    user.is_verified = True
    g.db.commit()

    log_audit_event("auth.verify_email", "user", user.id, {"email": user.email})

    return jsonify({
        "message": "Email verified successfully. You may now sign in.",
        "email": user.email,
        "is_verified": True
    }), 200

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    req = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"
    email = (req.get("email") or "").strip().lower()
    password = req.get("password") or ""
    next_url = req.get("next")

    # Rate limit check on client IP
    allowed_ip, _, retry_ip = check_rate_limit(
        g.db, f"login:ip:{client_ip}", max_attempts=5, window_seconds=900, block_seconds=900
    )
    if not allowed_ip:
        return jsonify({
            "error": "Too many sign-in attempts from this IP address. Account lock enforced.",
            "retry_after": retry_ip,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_ip)}

    # Rate limit check on target account
    if email:
        allowed_acc, _, retry_acc = check_rate_limit(
            g.db, f"login:acc:{email}", max_attempts=5, window_seconds=900, block_seconds=900
        )
        if not allowed_acc:
            return jsonify({
                "error": "Too many failed sign-in attempts for this account. Account locked temporarily.",
                "retry_after": retry_acc,
                "code": "RATE_LIMITED"
            }), 429, {"Retry-After": str(retry_acc)}

    if not email or not password:
        return jsonify({"error": "Email and password are required.", "code": "MISSING_CREDENTIALS"}), 400

    user = g.db.query(User).filter(User.email == email).first()

    if not user or not user.password_hash or not verify_password(password, user.password_hash):
        record_rate_limit_attempt(g.db, f"login:ip:{client_ip}")
        if email:
            record_rate_limit_attempt(g.db, f"login:acc:{email}")
        return jsonify({
            "error": "Invalid email or password.",
            "code": "INVALID_CREDENTIALS"
        }), 401

    if not user.is_active:
        return jsonify({
            "error": "Account has been deactivated. Please contact an administrator.",
            "code": "ACCOUNT_DISABLED"
        }), 403

    if not user.is_verified:
        return jsonify({
            "error": "Email verification required before sign-in.",
            "code": "UNVERIFIED_EMAIL"
        }), 403

    # Clear failed attempt counters on successful credential verification
    clear_rate_limit(g.db, f"login:ip:{client_ip}")
    clear_rate_limit(g.db, f"login:acc:{email}")

    # Multi-Factor Authentication requirement
    is_privileged = user.role in ["security_lead", "admin", "owner"]
    if user.is_mfa_enabled:
        # MFA ticket issuance for 2nd factor challenge
        mfa_ticket = create_auth_token(g.db, user.id, "mfa_login", lifetime_minutes=5)
        return jsonify({
            "mfa_required": True,
            "mfa_ticket": mfa_ticket,
            "message": "Multi-factor authentication code required.",
            "email": user.email
        }), 200

    mfa_setup_needed = is_privileged and not user.is_mfa_enabled

    # Create server-validated session
    session, raw_token, csrf_token = create_session(
        g.db, user, ip_address=client_ip, user_agent=request.user_agent.string
    )

    safe_redirect = get_safe_redirect(next_url, default="/")
    log_audit_event("auth.login", "user", user.id, {
        "email": user.email,
        "mfa_used": False,
        "mfa_setup_needed": mfa_setup_needed
    })

    resp = make_response(jsonify({
        "message": "Sign-in successful.",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_verified": user.is_verified,
            "is_mfa_enabled": user.is_mfa_enabled,
            "mfa_setup_needed": mfa_setup_needed
        },
        "csrf_token": csrf_token,
        "redirect_url": safe_redirect
    }))

    set_auth_cookies(resp, raw_token, csrf_token, is_production=g.is_production)
    return resp

@app.route("/api/auth/mfa/verify", methods=["POST"])
def auth_mfa_verify():
    req = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"
    ticket = (req.get("mfa_ticket") or "").strip()
    code = (req.get("code") or "").strip()

    allowed, _, retry_after = check_rate_limit(
        g.db, f"mfa:{client_ip}", max_attempts=5, window_seconds=300, block_seconds=300
    )
    if not allowed:
        return jsonify({
            "error": "Too many failed MFA verification attempts. Please wait.",
            "retry_after": retry_after,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_after)}

    if not ticket or not code:
        return jsonify({"error": "MFA ticket and 6-digit verification code are required."}), 400

    res = peek_auth_token(g.db, ticket, "mfa_login")
    if not res:
        record_rate_limit_attempt(g.db, f"mfa:{client_ip}")
        return jsonify({
            "error": "Invalid, expired, or already used MFA session ticket.",
            "code": "INVALID_MFA_TICKET"
        }), 401

    token_rec, user = res

    if not user.mfa_secret or not verify_mfa_code(user.mfa_secret, code):
        record_rate_limit_attempt(g.db, f"mfa:{client_ip}")
        return jsonify({
            "error": "Invalid multi-factor authentication code.",
            "code": "INVALID_MFA_CODE"
        }), 401

    # Mark ticket consumed upon successful factor verification
    token_rec.is_used = True
    g.db.commit()

    clear_rate_limit(g.db, f"mfa:{client_ip}")

    session, raw_token, csrf_token = create_session(
        g.db, user, ip_address=client_ip, user_agent=request.user_agent.string
    )

    log_audit_event("auth.mfa_login", "user", user.id, {"email": user.email, "mfa_verified": True})

    resp = make_response(jsonify({
        "message": "Multi-factor authentication verified. Sign-in successful.",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_verified": user.is_verified,
            "is_mfa_enabled": user.is_mfa_enabled
        },
        "csrf_token": csrf_token,
        "redirect_url": "/"
    }))

    set_auth_cookies(resp, raw_token, csrf_token, is_production=g.is_production)
    return resp

@app.route("/api/auth/mfa/setup", methods=["POST"])
@require_auth
def auth_mfa_setup():
    secret = generate_mfa_secret()
    uri = get_mfa_uri(secret, g.current_user.email, issuer="BrandSentinel")

    g.current_user.mfa_secret = secret
    g.db.commit()

    return jsonify({
        "message": "MFA secret generated. Scan QR code or enter secret into authenticator app.",
        "secret": secret,
        "otpauth_url": uri
    })

@app.route("/api/auth/mfa/enable", methods=["POST"])
@require_auth
def auth_mfa_enable():
    req = request.get_json(silent=True) or {}
    code = (req.get("code") or "").strip()

    if not code:
        return jsonify({"error": "Verification code is required."}), 400

    if not g.current_user.mfa_secret or not verify_mfa_code(g.current_user.mfa_secret, code):
        return jsonify({"error": "Invalid verification code. Multi-factor authentication was not enabled."}), 400

    g.current_user.is_mfa_enabled = True
    g.db.commit()

    new_session, new_token, new_csrf = rotate_session(
        g.db, g.current_session, ip_address=request.remote_addr, user_agent=request.user_agent.string
    )

    log_audit_event("auth.mfa_enabled", "user", g.current_user.id, {"email": g.current_user.email})

    resp = make_response(jsonify({
        "message": "Multi-factor authentication has been successfully enabled.",
        "is_mfa_enabled": True,
        "csrf_token": new_csrf
    }))
    set_auth_cookies(resp, new_token, new_csrf, is_production=g.is_production)
    return resp

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

    if token:
        revoke_session(g.db, token)

    if getattr(g, "current_user", None):
        log_audit_event("auth.logout", "user", g.current_user.id, {"email": g.current_user.email})

    resp = make_response(jsonify({"message": "Successfully signed out."}))
    clear_auth_cookies(resp)
    return resp

@app.route("/api/auth/logout-all", methods=["POST"])
@require_auth
def auth_logout_all():
    revoked_count = revoke_all_user_sessions(g.db, g.current_user.id)
    log_audit_event("auth.logout_all", "user", g.current_user.id, {"revoked_sessions": revoked_count})

    resp = make_response(jsonify({
        "message": "All active sessions have been revoked.",
        "revoked_count": revoked_count
    }))
    clear_auth_cookies(resp)
    return resp

@app.route("/api/auth/forgot-password", methods=["POST"])
def auth_forgot_password():
    req = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"
    email = (req.get("email") or "").strip().lower()

    allowed, _, retry_after = check_rate_limit(
        g.db, f"forgot:{client_ip}", max_attempts=5, window_seconds=900, block_seconds=900
    )
    if not allowed:
        return jsonify({
            "error": "Too many password recovery requests. Please try again later.",
            "retry_after": retry_after,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_after)}

    if not email:
        return jsonify({"error": "Email address is required."}), 400

    token = None
    user = g.db.query(User).filter(User.email == email).first()
    if user and user.is_active:
        token = create_auth_token(g.db, user.id, "password_reset", lifetime_minutes=15)
        log_audit_event("auth.forgot_password", "user", user.id, {"email": email})

    return jsonify({
        "message": "If that email address is registered, password reset instructions have been dispatched.",
        "reset_token": token
    }), 200

@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    req = request.get_json(silent=True) or {}
    client_ip = request.remote_addr or "127.0.0.1"
    token = (req.get("token") or "").strip()
    new_password = req.get("new_password") or ""

    allowed, _, retry_after = check_rate_limit(
        g.db, f"reset:{client_ip}", max_attempts=5, window_seconds=900, block_seconds=900
    )
    if not allowed:
        return jsonify({
            "error": "Too many password reset attempts. Please try again later.",
            "retry_after": retry_after,
            "code": "RATE_LIMITED"
        }), 429, {"Retry-After": str(retry_after)}

    if not token or not new_password:
        return jsonify({"error": "Reset token and new password are required."}), 400

    try:
        validate_password_complexity(new_password)
    except AuthError as ae:
        return jsonify({"error": ae.message, "field": "new_password"}), 400

    user = consume_auth_token(g.db, token, "password_reset")
    if not user:
        record_rate_limit_attempt(g.db, f"reset:{client_ip}")
        return jsonify({
            "error": "Invalid, expired, or already used password reset token.",
            "code": "INVALID_TOKEN"
        }), 400

    user.password_hash = hash_password(new_password)
    revoked_count = revoke_all_user_sessions(g.db, user.id)
    g.db.commit()

    log_audit_event("auth.reset_password", "user", user.id, {
        "email": user.email,
        "revoked_sessions": revoked_count
    })

    return jsonify({
        "message": "Password reset successful. All active sessions have been revoked. Please sign in with your new credentials."
    }), 200

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def auth_me():
    user = g.current_user
    session = g.current_session

    orgs = []
    for m in user.memberships:
        orgs.append({
            "organization_id": m.organization_id,
            "organization_name": m.organization.name if m.organization else None,
            "role": m.role
        })

    active_org_dict = None
    if getattr(g, "org_id", None):
        active_org_dict = {
            "id": g.org_id,
            "role": getattr(g, "user_role", None),
            "permissions": get_role_permissions(getattr(g, "user_role", None))
        }

    return jsonify({
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "is_verified": user.is_verified,
            "is_mfa_enabled": user.is_mfa_enabled,
            "organizations": orgs
        },
        "active_organization": active_org_dict,
        "session": {
            "id": session.id,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "last_activity_at": session.last_activity_at.isoformat() if session.last_activity_at else None,
            "expires_at": session.expires_at.isoformat() if session.expires_at else None
        },
        "csrf_token": session.csrf_token
    })

# ==========================================
# ORGANIZATION MEMBERSHIP MANAGEMENT API
# ==========================================

@app.route("/api/organizations/members", methods=["GET"])
@require_permission("member:read")
def list_organization_members():
    """
    Lists all members within the authorized organization.
    Permitted strictly for Owner.
    """
    memberships = g.db.query(Membership).options(
        joinedload(Membership.user)
    ).filter(
        Membership.organization_id == g.org_id
    ).all()

    out = []
    for m in memberships:
        out.append({
            "membership_id": m.id,
            "user_id": m.user.id if m.user else None,
            "email": m.user.email if m.user else None,
            "full_name": m.user.full_name if m.user else None,
            "role": m.role,
            "created_at": m.created_at.isoformat() if m.created_at else None
        })

    return jsonify({
        "organization_id": g.org_id,
        "total_members": len(out),
        "members": out
    })

@app.route("/api/organizations/members", methods=["POST"])
@require_permission("member:invite")
@validate_csrf
def add_organization_member():
    """
    Invites/adds a member to the authorized organization.
    Permitted strictly for Owner.
    """
    req = request.get_json(silent=True) or {}
    email = (req.get("email") or "").strip().lower()
    role = (req.get("role") or "analyst").strip().lower()

    if not email or "@" not in email:
        return jsonify({"error": "A valid user email address is required.", "field": "email"}), 400

    if role not in ROLE_PERMISSIONS:
        return jsonify({
            "error": f"Invalid role '{role}'. Valid roles are: {list(ROLE_PERMISSIONS.keys())}",
            "field": "role"
        }), 400

    user = g.db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            full_name=req.get("full_name", email.split("@")[0].title()),
            role=role,
            is_verified=False,
            is_active=True
        )
        g.db.add(user)
        g.db.flush()

    existing_mem = g.db.query(Membership).filter(
        Membership.organization_id == g.org_id,
        Membership.user_id == user.id
    ).first()
    if existing_mem:
        return jsonify({
            "error": "User is already an active member of this organization.",
            "code": "ALREADY_MEMBER"
        }), 409

    membership = Membership(
        organization_id=g.org_id,
        user_id=user.id,
        role=role
    )
    g.db.add(membership)
    g.db.commit()

    log_audit_event("member.add", "membership", membership.id, {
        "target_user_id": user.id,
        "email": user.email,
        "assigned_role": role
    })

    return jsonify({
        "message": f"User {user.email} added to organization with role '{role}'.",
        "membership": {
            "membership_id": membership.id,
            "user_id": user.id,
            "email": user.email,
            "role": membership.role
        }
    }), 201

@app.route("/api/organizations/members/<membership_id>", methods=["PATCH", "PUT"])
@require_permission("member:update_role")
@validate_csrf
def update_member_role(membership_id):
    """
    Updates role of a member in the authorized organization.
    - Prevents self-modification.
    - Prevents removal/demotion of last owner.
    - Enforces role changes against existing sessions immediately.
    """
    req = request.get_json(silent=True) or {}
    new_role = (req.get("role") or "").strip().lower()

    if new_role not in ROLE_PERMISSIONS:
        return jsonify({
            "error": f"Invalid role '{new_role}'. Valid roles are: {list(ROLE_PERMISSIONS.keys())}",
            "field": "role"
        }), 400

    target_mem = g.db.query(Membership).filter(
        Membership.id == membership_id,
        Membership.organization_id == g.org_id
    ).first()

    if not target_mem:
        return jsonify({"error": "Membership not found in active organization"}), 404

    # 1. Prevent self-promotion or self-demotion
    if target_mem.user_id == g.current_user.id:
        return jsonify({
            "error": "Forbidden: You cannot modify your own organization role.",
            "code": "SELF_MODIFICATION_FORBIDDEN"
        }), 403

    # 2. Prevent demotion of the last remaining owner
    if target_mem.role == "owner" and new_role != "owner":
        remaining_owners = count_organization_owners(g.db, g.org_id, exclude_membership_id=target_mem.id)
        if remaining_owners == 0:
            return jsonify({
                "error": "Forbidden: Cannot demote the last remaining owner of the organization.",
                "code": "LAST_OWNER_PROTECTION"
            }), 403

    old_role = target_mem.role
    target_mem.role = new_role

    # 3. Enforce role changes against existing sessions immediately
    revoked_count = revoke_all_user_sessions(g.db, target_mem.user_id)
    g.db.commit()

    log_audit_event("member.update_role", "membership", target_mem.id, {
        "target_user_id": target_mem.user_id,
        "old_role": old_role,
        "new_role": new_role,
        "revoked_sessions": revoked_count
    })

    return jsonify({
        "message": f"Member role updated to '{new_role}'. Active sessions revoked for policy enforcement.",
        "membership_id": target_mem.id,
        "old_role": old_role,
        "new_role": new_role
    }), 200

@app.route("/api/organizations/members/<membership_id>", methods=["DELETE"])
@require_permission("member:remove")
@validate_csrf
def remove_organization_member(membership_id):
    """
    Removes a member from the authorized organization.
    - Prevents self-removal.
    - Prevents removal of the last owner.
    - Enforces membership revocation against existing sessions immediately.
    """
    target_mem = g.db.query(Membership).filter(
        Membership.id == membership_id,
        Membership.organization_id == g.org_id
    ).first()

    if not target_mem:
        return jsonify({"error": "Membership not found in active organization"}), 404

    # 1. Prevent self-removal
    if target_mem.user_id == g.current_user.id:
        return jsonify({
            "error": "Forbidden: You cannot remove yourself from the organization.",
            "code": "SELF_REMOVAL_FORBIDDEN"
        }), 403

    # 2. Prevent removal of the last remaining owner
    if target_mem.role == "owner":
        remaining_owners = count_organization_owners(g.db, g.org_id, exclude_membership_id=target_mem.id)
        if remaining_owners == 0:
            return jsonify({
                "error": "Forbidden: Cannot remove the last remaining owner of the organization.",
                "code": "LAST_OWNER_PROTECTION"
            }), 403

    target_user_id = target_mem.user_id
    g.db.delete(target_mem)

    # 3. Invalidate active sessions immediately upon membership revocation
    revoked_count = revoke_all_user_sessions(g.db, target_user_id)
    g.db.commit()

    log_audit_event("member.remove", "membership", membership_id, {
        "target_user_id": target_user_id,
        "revoked_sessions": revoked_count
    })

    return jsonify({
        "message": "Member removed from organization successfully. Active sessions revoked.",
        "membership_id": membership_id
    }), 200

# ==========================================
# REPORTS & EXPORTS API
# ==========================================

@app.route("/api/reports", methods=["GET"])
@require_permission("report:view")
def get_reports_summary():
    """
    Returns aggregated KPI metrics for the authorized organization.
    Permitted for Viewer, Analyst, Admin, Owner.
    """
    total_brands = g.db.query(Brand).filter(Brand.organization_id == g.org_id).count()
    total_assets = g.db.query(OfficialAsset).filter(OfficialAsset.organization_id == g.org_id).count()
    total_detections = g.db.query(Detection).filter(Detection.organization_id == g.org_id).count()
    critical_detections = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.risk_level == "critical"
    ).count()
    high_detections = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.risk_level == "high"
    ).count()
    pending_reviews = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status.in_(["new", "flagged"])
    ).count()

    return jsonify({
        "organization_id": g.org_id,
        "metrics": {
            "total_brands": total_brands,
            "total_official_assets": total_assets,
            "total_threat_detections": total_detections,
            "critical_threats": critical_detections,
            "high_threats": high_detections,
            "pending_reviews": pending_reviews
        },
        "report_generated_at": datetime.now(timezone.utc).isoformat()
    })

def sanitize_csv_cell(value: Any) -> str:
    """
    Mitigates CSV Formula Injection (CWE-1236 / Spreadsheet Macro Injection).
    If a cell value starts with =, +, -, @, \t, \r, %, or |, prepend a single quote (')
    to instruct spreadsheet applications (Excel, Google Sheets, LibreOffice Calc)
    to treat the field strictly as literal text rather than an executable formula or command.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r", "%", "|"):
        return "'" + s
    return s

@app.route("/api/reports/export", methods=["GET"])
def export_report():
    """
    Explicit Report Export Permissions:
    - type=summary   -> export:summary   (Permitted for Viewer, Analyst, Admin, Owner)
    - type=telemetry -> export:telemetry (Permitted for Analyst, Admin, Owner; Denied to Viewer)
    Supports format=json (default) and format=csv (protected against formula injection).
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    export_type = request.args.get("type", "summary").lower()
    fmt = request.args.get("format", "json").lower()

    if export_type == "summary":
        if not has_permission(getattr(g, "user_role", None), "export:summary"):
            return jsonify({
                "error": "Forbidden: Insufficient privileges to export report summary.",
                "code": "FORBIDDEN"
            }), 403

        detections = g.db.query(Detection).filter(
            Detection.organization_id == g.org_id
        ).all()

        report_rows = []
        for d in detections:
            report_rows.append({
                "detection_id": d.id,
                "target_identifier": d.candidate.candidate_identifier if d.candidate else "N/A",
                "risk_level": d.risk_level,
                "status": d.status,
                "created_at": d.created_at.isoformat() if d.created_at else None
            })

        if fmt == "csv":
            out_buf = io.StringIO()
            writer = csv.writer(out_buf, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(["Detection ID", "Target Identifier", "Risk Level", "Status", "Created At"])
            for r in report_rows:
                writer.writerow([
                    sanitize_csv_cell(r["detection_id"]),
                    sanitize_csv_cell(r["target_identifier"]),
                    sanitize_csv_cell(r["risk_level"]),
                    sanitize_csv_cell(r["status"]),
                    sanitize_csv_cell(r["created_at"])
                ])
            log_audit_event("export.summary_csv", "report", g.org_id, {"format": "csv", "count": len(report_rows)})
            return Response(
                out_buf.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="brandsentinel_summary_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv"',
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )

        log_audit_event("export.summary", "report", g.org_id, {"export_type": "summary", "count": len(report_rows)})

        return jsonify({
            "organization_id": g.org_id,
            "export_type": "summary",
            "count": len(report_rows),
            "data": report_rows
        })

    elif export_type in ["telemetry", "raw"]:
        if not has_permission(getattr(g, "user_role", None), "export:telemetry"):
            return jsonify({
                "error": "Forbidden: Role lacks permission to export raw forensic telemetry.",
                "code": "FORBIDDEN",
                "required_permission": "export:telemetry"
            }), 403

        detections = g.db.query(Detection).options(
            joinedload(Detection.candidate)
        ).filter(
            Detection.organization_id == g.org_id
        ).all()

        telemetry_rows = []
        for d in detections:
            c = d.candidate
            meta = {}
            if c and c.metadata_json:
                try:
                    meta = json.loads(c.metadata_json)
                except Exception:
                    meta = {}
            telemetry_rows.append({
                "detection_id": d.id,
                "candidate_identifier": c.candidate_identifier if c else "N/A",
                "stable_source_id": c.stable_source_id if c else "N/A",
                "risk_score": d.risk_score,
                "match_score": d.match_score,
                "identity_status": d.identity_status,
                "violations": meta.get("violations", []),
                "host_telemetry": meta.get("host_telemetry", ""),
                "visual_comparison": meta.get("visual_comparison", {}),
                "status": d.status
            })

        if fmt == "csv":
            out_buf = io.StringIO()
            writer = csv.writer(out_buf, quoting=csv.QUOTE_MINIMAL)
            writer.writerow([
                "Detection ID", "Candidate Identifier", "Stable Source ID", "Risk Score",
                "Match Score", "Identity Status", "Violations", "Host Telemetry", "Status"
            ])
            for r in telemetry_rows:
                violations_str = "; ".join(r["violations"]) if isinstance(r["violations"], list) else str(r["violations"])
                writer.writerow([
                    sanitize_csv_cell(r["detection_id"]),
                    sanitize_csv_cell(r["candidate_identifier"]),
                    sanitize_csv_cell(r["stable_source_id"]),
                    sanitize_csv_cell(r["risk_score"]),
                    sanitize_csv_cell(r["match_score"]),
                    sanitize_csv_cell(r["identity_status"]),
                    sanitize_csv_cell(violations_str),
                    sanitize_csv_cell(r["host_telemetry"]),
                    sanitize_csv_cell(r["status"])
                ])
            log_audit_event("export.telemetry_csv", "report", g.org_id, {"format": "csv", "count": len(telemetry_rows)})
            return Response(
                out_buf.getvalue(),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="brandsentinel_telemetry_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv"',
                    "Content-Type": "text/csv; charset=utf-8"
                }
            )

        log_audit_event("export.telemetry", "report", g.org_id, {"export_type": "telemetry", "count": len(telemetry_rows)})

        return jsonify({
            "organization_id": g.org_id,
            "export_type": "telemetry",
            "count": len(telemetry_rows),
            "data": telemetry_rows
        })
    else:
        return jsonify({"error": f"Invalid export type '{export_type}'. Options: 'summary', 'telemetry'."}), 400

@app.route("/api/audit/export", methods=["GET"])
@require_permission("audit:export")
def export_audit_log():
    """
    Exports full compliance audit log for the organization.
    Permitted strictly for Owner only.
    """
    events = g.db.query(AuditEvent).filter(
        AuditEvent.organization_id == g.org_id
    ).order_by(AuditEvent.created_at.desc()).all()

    out = []
    for e in events:
        details = {}
        try:
            details = json.loads(e.details_json) if e.details_json else {}
        except Exception:
            details = {}
        out.append({
            "id": e.id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "user_id": e.user_id,
            "details": details,
            "ip_address": e.ip_address,
            "created_at": e.created_at.isoformat() if e.created_at else None
        })

    log_audit_event("audit.export", "audit_log", g.org_id, {"event_count": len(out)})

    return jsonify({
        "organization_id": g.org_id,
        "total_events": len(out),
        "audit_events": out
    })

# ==========================================
# BRANDS & OFFICIAL ASSETS API
# ==========================================

@app.route("/api/brands", methods=["GET"])
@require_permission("brand:read")
def list_brands():
    include_samples = request.args.get("include_samples", "true").lower() == "true"
    query = g.db.query(Brand).filter(Brand.organization_id == g.org_id)
    if not include_samples:
        query = query.filter(Brand.is_sample == False)
    
    brands = query.all()
    out = []
    for b in brands:
        aliases = []
        try:
            aliases = json.loads(b.aliases_json) if b.aliases_json else []
        except Exception:
            aliases = []
            
        threat_count = g.db.query(Detection).filter(
            Detection.brand_id == b.id,
            Detection.status != "whitelisted"
        ).count()
        
        out.append({
            "id": b.id,
            "organization_id": b.organization_id,
            "name": b.name,
            "aliases": aliases,
            "logo_url": b.logo_url,
            "industry": b.industry,
            "status": b.status,
            "is_sample": b.is_sample,
            "active_threats": threat_count
        })
    return jsonify(out)

@app.route("/api/brands/<brand_id>", methods=["GET"])
@require_permission("brand:read")
def get_brand(brand_id):
    brand = g.db.query(Brand).filter(
        Brand.id == brand_id,
        Brand.organization_id == g.org_id
    ).first()
    if not brand:
        return jsonify({"error": "Brand not found in active organization"}), 404

    aliases = []
    try:
        aliases = json.loads(brand.aliases_json) if brand.aliases_json else []
    except Exception:
        aliases = []

    assets = g.db.query(OfficialAsset).filter(
        OfficialAsset.brand_id == brand.id,
        OfficialAsset.organization_id == g.org_id
    ).all()

    assets_out = []
    for a in assets:
        meta = {}
        try:
            meta = json.loads(a.metadata_json) if a.metadata_json else {}
        except Exception:
            meta = {}
        assets_out.append({
            "id": a.id,
            "asset_type": a.asset_type,
            "source_platform": a.source_platform,
            "exact_identifier": a.exact_identifier,
            "stable_id": a.stable_id,
            "authorized_publisher_id": a.authorized_publisher_id,
            "authorized_publisher_name": a.authorized_publisher_name,
            "display_name": a.display_name,
            "verified": a.verified,
            "metadata": meta,
            "is_sample": a.is_sample
        })

    return jsonify({
        "id": brand.id,
        "organization_id": brand.organization_id,
        "name": brand.name,
        "aliases": aliases,
        "logo_url": brand.logo_url,
        "industry": brand.industry,
        "status": brand.status,
        "is_sample": brand.is_sample,
        "official_assets": assets_out
    })

@app.route("/api/brands", methods=["POST"])
@validate_csrf
@require_permission("brand:create")
def create_brand():
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    req = request.get_json(silent=True) or {}
    try:
        name = validate_brand_name(req.get("name"))
        aliases = validate_aliases(req.get("aliases"))
        logo_url = req.get("logo_url")
        industry = req.get("industry", "General Enterprise")
        is_sample = bool(req.get("is_sample", False))

        # If brand already exists in this organization, return existing record
        existing_brand = g.db.query(Brand).filter(
            Brand.organization_id == g.org_id,
            func.lower(Brand.name) == name.lower()
        ).first()

        if existing_brand:
            existing_aliases = []
            try:
                existing_aliases = json.loads(existing_brand.aliases_json) if existing_brand.aliases_json else []
            except Exception:
                existing_aliases = []

            return jsonify({
                "message": f"Brand '{existing_brand.name}' already exists in organization.",
                "brand": {
                    "id": existing_brand.id,
                    "name": existing_brand.name,
                    "aliases": existing_aliases,
                    "industry": existing_brand.industry,
                    "is_sample": existing_brand.is_sample,
                    "organization_id": existing_brand.organization_id,
                    "logo_url": existing_brand.logo_url
                },
                "already_exists": True
            }), 200

        new_brand = Brand(
            organization_id=g.org_id,
            name=name,
            aliases_json=json.dumps(aliases),
            logo_url=logo_url,
            industry=industry,
            is_sample=is_sample
        )
        g.db.add(new_brand)
        g.db.commit()

        log_audit_event("brand.create", "brand", new_brand.id, {"name": name, "aliases": aliases})

        return jsonify({
            "message": "Brand created successfully",
            "brand": {
                "id": new_brand.id,
                "name": new_brand.name,
                "aliases": aliases,
                "industry": new_brand.industry,
                "is_sample": new_brand.is_sample,
                "organization_id": new_brand.organization_id,
                "logo_url": new_brand.logo_url
            }
        }), 201
    except ValidationError as ve:
        return jsonify({"error": ve.message, "field": ve.field}), 400
    except Exception as e:
        g.db.rollback()
        return jsonify({"error": f"Internal error creating brand: {str(e)}"}), 500

@app.route("/api/brands/<brand_id>", methods=["PUT", "PATCH"])
@validate_csrf
@require_permission("brand:update")
def update_brand(brand_id):
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    brand = g.db.query(Brand).filter(
        Brand.id == brand_id,
        Brand.organization_id == g.org_id
    ).first()
    if not brand:
        return jsonify({"error": "Brand not found in active organization"}), 404

    req = request.get_json(silent=True) or {}
    try:
        changes = {}
        if "name" in req:
            brand.name = validate_brand_name(req["name"])
            changes["name"] = brand.name
        if "aliases" in req:
            aliases = validate_aliases(req["aliases"])
            brand.aliases_json = json.dumps(aliases)
            changes["aliases"] = aliases
        if "logo_url" in req:
            brand.logo_url = req["logo_url"]
            changes["logo_url"] = brand.logo_url
        if "industry" in req:
            brand.industry = req["industry"]
            changes["industry"] = brand.industry

        g.db.commit()
        log_audit_event("brand.update", "brand", brand.id, changes)

        return jsonify({
            "message": "Brand updated successfully",
            "brand": {
                "id": brand.id,
                "name": brand.name,
                "aliases": json.loads(brand.aliases_json),
                "logo_url": brand.logo_url,
                "industry": brand.industry
            }
        })
    except ValidationError as ve:
        return jsonify({"error": ve.message, "field": ve.field}), 400
    except Exception as e:
        g.db.rollback()
        return jsonify({"error": f"Failed to update brand: {str(e)}"}), 500

# Add Official Asset to a Brand
@app.route("/api/brands/<brand_id>/assets", methods=["POST"])
@validate_csrf
@require_permission("asset:create")
def add_brand_official_asset(brand_id):
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    brand = g.db.query(Brand).filter(
        Brand.id == brand_id,
        Brand.organization_id == g.org_id
    ).first()
    if not brand:
        return jsonify({"error": "Brand not found"}), 404

    req = request.get_json(silent=True) or {}
    asset_type = req.get("asset_type", "").lower()
    
    try:
        if asset_type == "domain":
            domain = validate_domain(req.get("domain") or req.get("exact_identifier"))
            asset = OfficialAsset(
                organization_id=g.org_id,
                brand_id=brand.id,
                asset_type="domain",
                source_platform="domain",
                exact_identifier=domain,
                stable_id=domain,
                display_name=req.get("display_name", domain),
                verified=True,
                is_sample=brand.is_sample
            )
        elif asset_type == "social_account":
            platform, handle, stable_id = validate_social_asset(
                req.get("source_platform"),
                req.get("exact_identifier") or req.get("handle"),
                req.get("stable_id") or req.get("stable_account_id")
            )
            asset = OfficialAsset(
                organization_id=g.org_id,
                brand_id=brand.id,
                asset_type="social_account",
                source_platform=platform,
                exact_identifier=handle,
                stable_id=stable_id,
                display_name=req.get("display_name", handle),
                verified=True,
                is_sample=brand.is_sample
            )
        elif asset_type == "mobile_app":
            store, exact_id, stable_id, pub_id = validate_app_asset(
                req.get("source_platform"),
                req.get("exact_identifier") or req.get("package_or_app_id"),
                req.get("stable_id") or req.get("stable_app_id"),
                req.get("authorized_publisher_id")
            )
            asset = OfficialAsset(
                organization_id=g.org_id,
                brand_id=brand.id,
                asset_type="mobile_app",
                source_platform=store,
                exact_identifier=exact_id,
                stable_id=stable_id,
                authorized_publisher_id=pub_id,
                authorized_publisher_name=req.get("authorized_publisher_name"),
                display_name=req.get("display_name", exact_id),
                verified=True,
                is_sample=brand.is_sample
            )
        else:
            return jsonify({
                "error": f"Invalid asset_type '{asset_type}'. Must be 'domain', 'social_account', or 'mobile_app'."
            }), 400

        g.db.add(asset)
        g.db.commit()

        log_audit_event("asset.create", "official_asset", asset.id, {
            "brand_id": brand.id,
            "asset_type": asset.asset_type,
            "source_platform": asset.source_platform,
            "exact_identifier": asset.exact_identifier,
            "stable_id": asset.stable_id
        })

        return jsonify({
            "message": f"Official asset '{asset.exact_identifier}' registered successfully with exact stable ID.",
            "asset": {
                "id": asset.id,
                "asset_type": asset.asset_type,
                "source_platform": asset.source_platform,
                "exact_identifier": asset.exact_identifier,
                "stable_id": asset.stable_id,
                "authorized_publisher_id": asset.authorized_publisher_id,
                "display_name": asset.display_name
            }
        }), 201

    except ValidationError as ve:
        return jsonify({"error": ve.message, "field": ve.field}), 400
    except Exception as e:
        g.db.rollback()
        return jsonify({"error": f"Failed to add official asset: {str(e)}"}), 500

@app.route("/api/brands/<brand_id>/assets/<asset_id>", methods=["DELETE"])
@validate_csrf
@require_permission("asset:delete")
def delete_brand_official_asset(brand_id, asset_id):
    asset = g.db.query(OfficialAsset).filter(
        OfficialAsset.id == asset_id,
        OfficialAsset.brand_id == brand_id,
        OfficialAsset.organization_id == g.org_id
    ).first()
    if not asset:
        return jsonify({"error": "Official asset not found in organization"}), 404

    exact_ident = asset.exact_identifier
    g.db.delete(asset)
    g.db.commit()

    log_audit_event("asset.delete", "official_asset", asset_id, {"exact_identifier": exact_ident})

    return jsonify({"message": f"Official asset '{exact_ident}' removed successfully."})

# ==========================================
# FINDINGS & DETECTIONS API
# ==========================================

SOCIAL_PLATFORMS = {"instagram", "twitter_x", "tiktok", "linkedin", "facebook", "youtube", "telegram", "social_media"}
APPS_PLATFORMS = {"google_play", "apple_app_store", "apps", "domain", "domain_registry", "web", "darkweb_feed", "threat_intel"}

@app.route("/api/findings", methods=["GET"])
@require_permission("detection:read")
def get_findings():
    category = request.args.get("category", "all").lower()
    search = request.args.get("q", "").lower().strip()
    risk = request.args.get("risk", "all").lower()
    status_filter = request.args.get("status", "all").lower().strip()
    sort_param = request.args.get("sort", "risk_desc").lower().strip()

    # Multi-tenant query scoped to organization
    query = g.db.query(Detection).join(Candidate).filter(
        Detection.organization_id == g.org_id
    )

    brand_id = request.args.get("brand_id")
    if brand_id:
        query = query.filter(Detection.brand_id == brand_id)

    if category == "social":
        query = query.filter(Candidate.source_platform.in_(list(SOCIAL_PLATFORMS)))
    elif category == "apps":
        query = query.filter(Candidate.source_platform.in_(list(APPS_PLATFORMS)))

    if risk != "all":
        query = query.filter(Detection.risk_level == risk)

    if status_filter == "new":
        query = query.filter(Detection.status.in_(["new", "flagged"]))
    elif status_filter in ["in_review", "under_review"]:
        query = query.filter(Detection.status.in_(["in_review", "under_review"]))
    elif status_filter == "confirmed":
        query = query.filter(Detection.status.in_(["confirmed", "takedown_requested", "takedown_sent", "escalated"]))
    elif status_filter == "dismissed":
        query = query.filter(Detection.status == "dismissed")
    elif status_filter == "whitelisted":
        query = query.filter(Detection.status == "whitelisted")
    elif status_filter != "all":
        query = query.filter(Detection.status == status_filter)

    # Sorting
    if sort_param == "risk_asc":
        query = query.order_by(Detection.risk_score.asc(), Detection.created_at.desc())
    elif sort_param == "date_desc":
        query = query.order_by(Detection.created_at.desc())
    elif sort_param == "date_asc":
        query = query.order_by(Detection.created_at.asc())
    elif sort_param == "score_desc":
        query = query.order_by(Detection.risk_score.desc(), Detection.created_at.desc())
    elif sort_param == "name_asc":
        query = query.order_by(Candidate.candidate_identifier.asc())
    elif sort_param == "name_desc":
        query = query.order_by(Candidate.candidate_identifier.desc())
    else:  # risk_desc (default)
        query = query.order_by(Detection.risk_score.desc(), Detection.created_at.desc())

    detections = query.all()

    # Organization-wide counts for tabs and status filters
    count_all = g.db.query(Detection).join(Candidate).filter(Detection.organization_id == g.org_id).count()
    count_social = g.db.query(Detection).join(Candidate).filter(
        Detection.organization_id == g.org_id,
        Candidate.source_platform.in_(list(SOCIAL_PLATFORMS))
    ).count()
    count_apps = g.db.query(Detection).join(Candidate).filter(
        Detection.organization_id == g.org_id,
        Candidate.source_platform.in_(list(APPS_PLATFORMS))
    ).count()
    count_new = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status.in_(["new", "flagged"])
    ).count()
    count_in_review = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status.in_(["in_review", "under_review"])
    ).count()
    count_confirmed = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status.in_(["confirmed", "takedown_requested", "takedown_sent", "escalated"])
    ).count()
    count_dismissed = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status == "dismissed"
    ).count()
    count_whitelisted = g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.status == "whitelisted"
    ).count()
    count_flagged = count_all - count_whitelisted - count_dismissed

    # Live scan check
    live_scan_count = g.db.query(Scan).filter(
        Scan.organization_id == g.org_id,
        Scan.is_sample == False,
        Scan.status.in_(["completed", "partial_success"])
    ).count()
    has_live_scans = (live_scan_count > 0)
    is_sample_dataset = not has_live_scans or (count_all > 0 and g.db.query(Detection).filter(
        Detection.organization_id == g.org_id,
        Detection.is_sample == False
    ).count() == 0)

    findings_out = []
    for d in detections:
        c = d.candidate
        meta = {}
        try:
            meta = json.loads(c.metadata_json) if c.metadata_json else {}
        except Exception:
            meta = {}

        ev = {}
        try:
            ev = json.loads(d.similarity_details_json) if d.similarity_details_json else {}
        except Exception:
            ev = {}

        # Search filter
        if search:
            target_str = (c.candidate_identifier + " " + d.detection_type + " " + c.source_platform + " " + (c.display_name or "") + " " + (d.status or "")).lower()
            if search not in target_str:
                continue

        # Map platform icon
        platform_icon = "globe"
        p_lower = (c.source_platform or "").lower()
        if "insta" in p_lower:
            platform_icon = "instagram"
        elif "twit" in p_lower or p_lower == "x":
            platform_icon = "twitter"
        elif "play" in p_lower:
            platform_icon = "playstore"
        elif "apple" in p_lower:
            platform_icon = "appstore"
        elif "tik" in p_lower:
            platform_icon = "tiktok"
        elif "youtube" in p_lower or "yt" in p_lower:
            platform_icon = "youtube"
        elif "telegram" in p_lower or "tg" in p_lower:
            platform_icon = "telegram"
        elif "face" in p_lower or "meta" in p_lower:
            platform_icon = "facebook"
        elif "link" in p_lower:
            platform_icon = "linkedin"

        category_name = "Social" if p_lower in SOCIAL_PLATFORMS else "Apps"

        # Normalized Status
        raw_status = (d.status or "flagged").lower()
        if raw_status in ["new", "flagged"]:
            status_display = "New"
        elif raw_status in ["in_review", "under_review"]:
            status_display = "In Review"
        elif raw_status in ["confirmed", "takedown_requested", "takedown_sent", "escalated"]:
            status_display = "Confirmed"
        elif raw_status == "dismissed":
            status_display = "Dismissed"
        elif raw_status == "whitelisted":
            status_display = "Whitelisted"
        else:
            status_display = raw_status.replace("_", " ").title()

        # Source URL
        source_url = meta.get("source_url") or ev.get("provenance", {}).get("source_url")
        if not source_url:
            clean_handle = c.candidate_identifier.lstrip("@")
            if platform_icon == "telegram":
                source_url = f"https://t.me/{clean_handle}"
            elif platform_icon == "youtube":
                source_url = f"https://youtube.com/{c.candidate_identifier}"
            elif platform_icon == "facebook":
                source_url = f"https://facebook.com/{clean_handle}"
            elif platform_icon == "appstore":
                source_url = f"https://apps.apple.com/app/id{clean_handle}"
            elif platform_icon == "playstore":
                source_url = f"https://play.google.com/store/apps/details?id={clean_handle}"
            elif "." in clean_handle and not clean_handle.startswith("com."):
                source_url = f"https://{clean_handle}"
            else:
                source_url = f"https://{c.source_platform}.example.com/{clean_handle}"

        # Violations
        violations = meta.get("violations") or []
        if not violations and ev.get("assessment_rationale"):
            violations = [ev.get("assessment_rationale")]
        if not violations:
            violations = [
                f"Candidate '{c.candidate_identifier}' flagged under assessment: {d.detection_type}",
                "Unauthorized brand trademark/logo similarity pattern"
            ]

        # Assessment explanation & missing evidence
        assessment_rationale = ev.get("assessment_rationale") or f"Evaluated under detector v{DETECTOR_VERSION}. Risk score: {d.risk_score}."
        corroborating_signals = ev.get("corroborating_signals") or []
        missing_evidence = ev.get("missing_evidence_indicators") or meta.get("missing_evidence_indicators") or [
            "Logo analysis not performed: Computer vision image analysis not executed; visual match percentage not claimed."
        ]
        logo_analysis = ev.get("logo_analysis") or {
            "status": "not_performed",
            "similarity_score": None,
            "reason": "Actual image computer vision analysis not performed; visual match percentage not claimed."
        }
        is_official = bool(d.identity_status == "verified_official" or raw_status == "whitelisted")

        # Persistent Review Audit History
        reviews_query = g.db.query(Review).options(joinedload(Review.reviewer)).filter(
            Review.detection_id == d.id,
            Review.organization_id == g.org_id
        ).order_by(Review.created_at.desc()).all()

        reviews_out = [
            {
                "id": r.id,
                "verdict": r.verdict,
                "verdict_label": "New" if r.verdict in ["new", "flagged"] else ("In Review" if r.verdict in ["in_review", "under_review"] else ("Confirmed" if r.verdict in ["confirmed", "takedown_requested", "takedown_sent", "escalated"] else r.verdict.replace("_", " ").title())),
                "notes": r.notes or "",
                "reviewer_id": r.reviewer_user_id,
                "reviewer_name": r.reviewer.full_name if r.reviewer else "Analyst",
                "created_at": r.created_at.strftime("%b %d, %Y, %I:%M %p") if r.created_at else ""
            }
            for r in reviews_query
        ]

        findings_out.append({
            "id": d.id,
            "brand_id": d.brand_id,
            "target_name": c.candidate_identifier,
            "display_name": c.display_name or c.candidate_identifier,
            "category": category_name,
            "platform": c.source_platform.replace("_", " ").title(),
            "platform_icon": platform_icon,
            "risk_level": d.risk_level.title(),
            "risk_score": d.risk_score,
            "detection_type": d.detection_type,
            "match_score": d.match_score,
            "identity_status": d.identity_status,
            "status": status_display,
            "raw_status": raw_status,
            "is_sample": d.is_sample,
            "is_official": is_official,
            "source_url": source_url,
            "detected_at": d.created_at.strftime("%b %d, %Y, %I:%M %p") if d.created_at else "Recently",
            "created_at_iso": d.created_at.isoformat() if d.created_at else None,
            "evidence": {
                "target_handle": c.candidate_identifier,
                "official_counterpart": meta.get("official_counterpart", "@northstar_tech (Official Asset)"),
                "audience": meta.get("audience", meta.get("followers", "Simulated reach")),
                "official_audience": "248K verified enterprise followers",
                "account_age": meta.get("account_age", "Recent"),
                "violations": violations,
                "source_url": source_url,
                "assessment_rationale": assessment_rationale,
                "corroborating_signals": corroborating_signals,
                "missing_evidence_indicators": missing_evidence,
                "host_telemetry": meta.get("host_telemetry", "Direct cloud proxy relay"),
                "visual_comparison": meta.get("visual_comparison", {
                    "logo_similarity": d.match_score,
                    "color_palette": "Deep navy and cobalt accent match"
                }),
                "logo_analysis": logo_analysis,
                "timestamps": ev.get("timestamps", {
                    "collected_at": meta.get("collected_at", d.created_at.isoformat() if d.created_at else ""),
                    "analyzed_at": d.created_at.isoformat() if d.created_at else ""
                }),
                "provenance": ev.get("provenance", meta.get("provenance", {"collector": "scanner", "source": c.source_platform})),
                "detector_version": ev.get("detector_version", DETECTOR_VERSION),
                "reviews": reviews_out
            },
            "reviews": reviews_out
        })

    # Pagination logic
    page_param = request.args.get("page")
    per_page_param = request.args.get("per_page")
    
    total_matching = len(findings_out)
    if per_page_param and per_page_param.isdigit() and int(per_page_param) > 0:
        per_page = int(per_page_param)
        page = int(page_param) if page_param and page_param.isdigit() else 1
        total_pages = max(1, (total_matching + per_page - 1) // per_page)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        findings_page = findings_out[start_idx:end_idx]
    else:
        page = 1
        per_page = total_matching
        total_pages = 1
        findings_page = findings_out

    return jsonify({
        "total": total_matching,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "category": category,
        "counts": {
            "all": count_all,
            "social": count_social,
            "apps": count_apps,
            "new": count_new,
            "in_review": count_in_review,
            "confirmed": count_confirmed,
            "dismissed": count_dismissed,
            "whitelisted": count_whitelisted,
            "flagged": count_flagged
        },
        "has_live_scans": has_live_scans,
        "is_sample_dataset": is_sample_dataset,
        "findings": findings_page
    })

@app.route("/api/findings/<detection_id>", methods=["GET", "POST", "PATCH"])
@validate_csrf
def manage_finding(detection_id):
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    if request.method in ["POST", "PATCH"]:
        if not has_permission(getattr(g, "user_role", None), "detection:review"):
            return jsonify({
                "error": f"Forbidden: Role '{getattr(g, 'user_role', None)}' lacks required permission 'detection:review'.",
                "code": "FORBIDDEN"
            }), 403
    else:
        if not has_permission(getattr(g, "user_role", None), "detection:read"):
            return jsonify({
                "error": f"Forbidden: Role '{getattr(g, 'user_role', None)}' lacks required permission 'detection:read'.",
                "code": "FORBIDDEN"
            }), 403

    detection = g.db.query(Detection).filter(
        Detection.id == detection_id,
        Detection.organization_id == g.org_id
    ).first()
    if not detection:
        return jsonify({"error": "Detection not found in organization"}), 404

    if request.method in ["POST", "PATCH"]:
        auth_err = check_production_auth()
        if auth_err:
            return auth_err
        req = request.get_json(silent=True) or {}
        new_status = req.get("status", "").lower().replace(" ", "_").strip()
        try:
            verdict = validate_review_verdict(new_status)
            detection.status = verdict

            notes_text = req.get("notes") or f"Status updated to '{verdict}' via analyst review."

            # Record Review in DB
            review = Review(
                organization_id=g.org_id,
                detection_id=detection.id,
                reviewer_user_id=getattr(g, "user_id", None),
                verdict=verdict,
                notes=notes_text
            )
            g.db.add(review)
            g.db.commit()

            log_audit_event("detection.review", "detection", detection.id, {
                "verdict": verdict,
                "notes": notes_text,
                "candidate": detection.candidate.candidate_identifier if detection.candidate else ""
            })

            reviewer_name = g.current_user.full_name if getattr(g, "current_user", None) else "Analyst"

            return jsonify({
                "message": f"Detection status updated to '{verdict}'",
                "detection_id": detection.id,
                "status": detection.status,
                "review": {
                    "id": review.id,
                    "verdict": review.verdict,
                    "notes": review.notes,
                    "reviewer_name": reviewer_name,
                    "created_at": review.created_at.strftime("%b %d, %Y, %I:%M %p") if review.created_at else ""
                }
            })
        except ValidationError as ve:
            return jsonify({"error": ve.message, "field": ve.field}), 400
        except Exception as e:
            g.db.rollback()
            return jsonify({"error": f"Failed to record review: {str(e)}"}), 500

    # GET response with full details and review history
    c = detection.candidate
    reviews_query = g.db.query(Review).options(joinedload(Review.reviewer)).filter(
        Review.detection_id == detection.id,
        Review.organization_id == g.org_id
    ).order_by(Review.created_at.desc()).all()

    reviews_out = [
        {
            "id": r.id,
            "verdict": r.verdict,
            "verdict_label": "New" if r.verdict in ["new", "flagged"] else ("In Review" if r.verdict in ["in_review", "under_review"] else ("Confirmed" if r.verdict in ["confirmed", "takedown_requested", "takedown_sent", "escalated"] else r.verdict.replace("_", " ").title())),
            "notes": r.notes or "",
            "reviewer_id": r.reviewer_user_id,
            "reviewer_name": r.reviewer.full_name if r.reviewer else "Analyst",
            "created_at": r.created_at.strftime("%b %d, %Y, %I:%M %p") if r.created_at else ""
        }
        for r in reviews_query
    ]

    return jsonify({
        "id": detection.id,
        "status": detection.status,
        "risk_level": detection.risk_level,
        "risk_score": detection.risk_score,
        "detection_type": detection.detection_type,
        "match_score": detection.match_score,
        "candidate": {
            "id": c.id if c else None,
            "identifier": c.candidate_identifier if c else "N/A",
            "display_name": c.display_name if c else "N/A",
            "platform": c.source_platform if c else "N/A"
        },
        "reviews": reviews_out
    })

@app.route("/api/findings/bulk", methods=["POST"])
@validate_csrf
@require_permission("detection:review")
def bulk_manage_findings():
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    payload = request.get_json(silent=True) or {}
    ids = payload.get("ids") or payload.get("detection_ids") or []
    status_str = (payload.get("status") or "").lower().replace(" ", "_").strip()
    notes_str = payload.get("notes") or f"Bulk review updated to '{status_str}'."

    if not ids or not isinstance(ids, list):
        return jsonify({"error": "List of detection IDs is required.", "code": "INVALID_PAYLOAD"}), 400

    try:
        verdict = validate_review_verdict(status_str)
    except ValidationError as ve:
        return jsonify({"error": ve.message, "field": ve.field}), 400

    updated_count = 0
    for det_id in ids:
        det = g.db.query(Detection).filter(
            Detection.id == det_id,
            Detection.organization_id == g.org_id
        ).first()
        if det:
            det.status = verdict
            rev = Review(
                organization_id=g.org_id,
                detection_id=det.id,
                reviewer_user_id=getattr(g, "user_id", None),
                verdict=verdict,
                notes=notes_str
            )
            g.db.add(rev)
            updated_count += 1

    g.db.commit()

    log_audit_event("detection.bulk_review", "detection", g.org_id, {
        "verdict": verdict,
        "count": updated_count
    })

    return jsonify({
        "message": f"Updated {updated_count} findings to '{verdict}'.",
        "updated_count": updated_count,
        "verdict": verdict
    })

# ==========================================
# SCAN SIMULATION WITH EXACT IDENTITY MATCHER
# ==========================================

@app.route("/api/scan", methods=["POST"])
@validate_csrf
@require_permission("scan:run")
def run_scan():
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    req = request.get_json(silent=True) or {}
    query = (req.get("query") or "@northstar_alert").strip()
    source = req.get("source", "All Sources")

    # Get active brand
    active_brand = g.db.query(Brand).filter(
        Brand.organization_id == g.org_id
    ).first()
    if not active_brand:
        return jsonify({"error": "No brand configured for organization"}), 400

    # Fetch official assets for this brand
    official_assets = g.db.query(OfficialAsset).filter(
        OfficialAsset.brand_id == active_brand.id,
        OfficialAsset.organization_id == g.org_id
    ).all()

    # Determine platform
    is_app = any(x in query.lower() for x in ["app", "apk", "mobile", "ios", "com."])
    if is_app:
        platform = "google_play"
    elif "insta" in source.lower():
        platform = "instagram"
    elif "twit" in source.lower() or "x " in source.lower():
        platform = "twitter_x"
    elif "tik" in source.lower():
        platform = "tiktok"
    elif "." in query and not query.startswith("@"):
        platform = "domain"
    else:
        platform = "instagram"

    # Simulated candidate identifiers
    candidate_identifier = query if query.startswith("@") or "." in query else f"@{query.replace(' ', '_').lower()}"
    # Generate a candidate with a SIMILAR NAME & LOGO, but an UNMATCHED STABLE ID to test the core security rule!
    stable_source_id = f"unverified_simulated_{int(time.time())}"

    # Evaluate using Exact Source-Scoped Identity Matcher
    # CRITICAL: Even if logo/name similarity is high, never establish official identity without exact stable ID!
    evaluation = evaluate_candidate_identity(
        source_platform=platform,
        candidate_identifier=candidate_identifier,
        stable_source_id=stable_source_id,
        display_name=query,
        name_similarity_score=0.92,
        logo_similarity_score=0.95,
        official_assets=official_assets
    )

    try:
        # Create persistent Scan record
        scan = Scan(
            organization_id=g.org_id,
            brand_id=active_brand.id,
            target_query=query,
            source_platform=platform,
            status="completed",
            initiated_by_user_id=g.user_id,
            candidates_found=1,
            detections_flagged=1,
            is_sample=True,
            completed_at=datetime.utcnow()
        )
        g.db.add(scan)
        g.db.flush()

        # Create Candidate record
        candidate = Candidate(
            organization_id=g.org_id,
            scan_id=scan.id,
            source_platform=platform,
            candidate_identifier=candidate_identifier,
            stable_source_id=stable_source_id,
            display_name=f"Suspect Account ({query})",
            metadata_json=json.dumps({
                "audience": "Simulated audience reach",
                "violations": [
                    f"Similarity scan against '{query}' flagged unauthorized brand mark reproduction",
                    evaluation["match_reason"]
                ],
                "host_telemetry": "Simulated scanner telemetry (Sandbox Mock Mode)",
                "visual_comparison": {
                    "logo_similarity": "95.0% Simulated Asset Match",
                    "color_palette": "Deep navy & electric blue palette match"
                }
            }),
            is_sample=True
        )
        g.db.add(candidate)
        g.db.flush()

        # Create Detection record
        detection = Detection(
            organization_id=g.org_id,
            brand_id=active_brand.id,
            candidate_id=candidate.id,
            risk_level=evaluation["risk_level"],
            risk_score=92,
            detection_type="Suspicious Name & Asset Squatting",
            match_score="95% Pattern Match",
            identity_status=evaluation["identity_status"], # Enforced by matcher
            status="flagged",
            is_sample=True
        )
        g.db.add(detection)
        g.db.commit()

        log_audit_event("scan.complete", "scan", scan.id, {
            "query": query,
            "platform": platform,
            "identity_status": evaluation["identity_status"],
            "detection_id": detection.id
        })

        # Format output finding
        platform_icon = "playstore" if is_app else ("instagram" if "insta" in platform else "twitter")
        new_finding = {
            "id": detection.id,
            "target_name": candidate.candidate_identifier,
            "category": "Apps" if is_app else "Social",
            "platform": platform.replace("_", " ").title(),
            "platform_icon": platform_icon,
            "risk_level": detection.risk_level.title(),
            "risk_score": detection.risk_score,
            "detection_type": detection.detection_type,
            "match_score": detection.match_score,
            "detected_at": "Just now",
            "status": "Flagged",
            "evidence": {
                "target_handle": candidate.candidate_identifier,
                "official_counterpart": "@northstar_tech (Official)",
                "audience": "Simulated reach",
                "official_audience": "248K verified enterprise followers",
                "account_age": "New pattern detected",
                "violations": [
                    f"Candidate '{candidate.candidate_identifier}' flagged by exact identifier scanner",
                    evaluation["match_reason"]
                ],
                "host_telemetry": "Direct sandbox proxy telemetry",
                "visual_comparison": {
                    "logo_similarity": "95.0% Vector Match",
                    "color_palette": "Navy & Electric Blue overlap"
                }
            }
        }

        return jsonify({
            "status": "success",
            "simulated": True,
            "message": f"Scan completed for '{query}'. 1 threat flagged by source-scoped identity matcher.",
            "query": query,
            "source": source,
            "new_finding": new_finding,
            "identity_status": evaluation["identity_status"],
            "disclaimer": "Fictional sample telemetry. Scans in this demo phase are simulated without live external scrapers or stored credentials."
        })

    except Exception as e:
        g.db.rollback()
        return jsonify({"error": f"Scan execution failed: {str(e)}"}), 500

# ==========================================
# SOURCE CONNECTIONS API
# ==========================================

@app.route("/api/sources", methods=["GET", "POST"])
@validate_csrf
def manage_sources():
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    if request.method == "POST":
        auth_err = check_production_auth()
        if auth_err:
            return auth_err
        if not has_permission(getattr(g, "user_role", None), "source:manage"):
            return jsonify({
                "error": f"Forbidden: Role '{getattr(g, 'user_role', None)}' lacks required permission 'source:manage'.",
                "code": "FORBIDDEN"
            }), 403
        req = request.get_json(silent=True) or {}
        source_id = req.get("id")
        action = req.get("action", "toggle")

        alt_id = source_id.replace("source-", "src-") if source_id else ""
        source = g.db.query(SourceConnection).filter(
            (SourceConnection.id == source_id) | (SourceConnection.id == alt_id),
            SourceConnection.organization_id == g.org_id
        ).first()

        if not source:
            return jsonify({"error": "Source connector not found"}), 404

        if action == "connect":
            source.connection_status = "connected"
            source.test_status = "connected"
            source.last_sync_at = datetime.utcnow()
        elif action == "disconnect":
            source.connection_status = "unconfigured"
            source.test_status = "unconfigured"
        else:
            source.connection_status = "unconfigured" if source.connection_status == "connected" else "connected"
            source.test_status = source.connection_status
            if source.connection_status == "connected":
                source.last_sync_at = datetime.utcnow()

        g.db.commit()
        log_audit_event("source.toggle", "source_connection", source.id, {"status": source.connection_status})

        return jsonify({
            "message": f"Source {source.name} connection updated",
            "source": {
                "id": source.id,
                "name": source.name,
                "platform": source.platform,
                "connected": source.connection_status == "connected",
                "status": "Connected" if source.connection_status == "connected" else "Unconfigured"
            }
        })

    # GET sources
    if not has_permission(getattr(g, "user_role", None), "source:read"):
        return jsonify({
            "error": f"Forbidden: Role '{getattr(g, 'user_role', None)}' lacks required permission 'source:read'.",
            "code": "FORBIDDEN"
        }), 403

    sources = g.db.query(SourceConnection).filter(
        SourceConnection.organization_id == g.org_id
    ).all()

    icon_map = {
        "youtube": "youtube",
        "instagram": "instagram",
        "twitter_x": "twitter",
        "apple_app_store": "appstore",
        "google_play": "playstore",
        "tiktok": "tiktok",
        "domain_registry": "globe"
    }

    out = []
    for s in sources:
        # Determine configured state (org supplied or deployment fallback)
        is_cfg = bool(s.is_configured)
        key_src = s.key_source or "none"
        if not is_cfg and s.platform in app_config.connectors:
            dep_conn = app_config.connectors[s.platform]
            if dep_conn.enabled:
                is_cfg = True
                key_src = "deployment_configured"

        is_connected = (s.test_status == "connected")
        if is_connected:
            status_text = "Connected"
        elif s.test_status == "error":
            status_text = "Error"
        elif s.test_status == "ready_to_connect":
            status_text = "Ready to Connect"
        else:
            status_text = "Unconfigured"

        out.append({
            "id": s.id,
            "name": s.name,
            "platform": s.platform,
            "status": status_text,
            "connected": is_connected,
            "test_status": s.test_status or "unconfigured",
            "is_configured": is_cfg,
            "key_source": key_src,
            "last_tested_at": s.last_tested_at.isoformat() + "Z" if s.last_tested_at else None,
            "error_type": s.error_type,
            "status_message": s.status_message or "",
            "icon": icon_map.get(s.platform, "globe"),
            "rate_limit": s.rate_limit_info,
            "is_sample": s.is_sample,
            "description": f"Monitoring feed for {s.name}"
        })
    return jsonify(out)

# ==============================================================================
# SOURCE CREDENTIAL MANAGEMENT ENDPOINTS (Owner-Authorized, Encrypted, Secret-Safe)
# ==============================================================================

@app.route("/api/sources/<source_id>/credentials", methods=["POST", "PUT"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def save_source_credentials(source_id):
    """
    Saves and encrypts provider credentials for an organization source connection.
    - Owner-authorized only.
    - Encrypted via Fernet with managed key kept separate from database.
    - Bound strictly to active organization.
    - Runs immediate connection test.
    - Never returns stored secret.
    """
    if not getattr(g, "current_user", None):
        return jsonify({"error": "Authentication required. Please sign in.", "code": "UNAUTHORIZED"}), 401

    alt_id = source_id.replace("source-", "src-") if source_id else ""
    source = g.db.query(SourceConnection).filter(
        (SourceConnection.id == source_id) | (SourceConnection.id == alt_id),
        SourceConnection.organization_id == g.org_id
    ).first()

    if not source:
        return jsonify({"error": "Source connector not found in organization", "code": "NOT_FOUND"}), 404

    payload = request.get_json(silent=True) or {}
    api_key = payload.get("api_key", "").strip()
    service_account = payload.get("service_account")
    credentials_dict = payload.get("credentials") or {}

    if not api_key and not service_account and not credentials_dict:
        return jsonify({
            "error": "Credential value (api_key or service_account) is required.",
            "code": "MISSING_CREDENTIALS"
        }), 400

    cred_data = {}
    if api_key:
        cred_data["api_key"] = api_key
    if service_account:
        cred_data["service_account"] = service_account
    if credentials_dict:
        cred_data.update(credentials_dict)

    # 1. Encrypt credentials with managed vault key
    try:
        encrypted_token = encrypt_credentials(cred_data)
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}", "code": "ENCRYPTION_ERROR"}), 500

    source.encrypted_credentials = encrypted_token
    source.is_configured = True
    source.key_source = "org_supplied"

    # 2. Run server-side connection test
    test_res = None
    if source.platform == "youtube":
        test_res = YouTubeConnector.test_connection(api_key or cred_data.get("api_key"))
    elif source.platform == "apple_app_store":
        test_res = AppleAppStoreConnector.test_connection()
    elif source.platform == "google_play":
        test_res = GooglePlayConnector.test_connection(sa_credentials=service_account or cred_data.get("service_account"))
    else:
        connector_cls = CONNECTOR_CLIENTS.get(source.platform)
        if connector_cls and hasattr(connector_cls, "test_connection"):
            test_res = connector_cls.test_connection()
        else:
            test_res = ConnectionResult(
                success=False,
                status="unconfigured",
                error_type="NOT_IMPLEMENTED",
                status_message=f"{source.name} integration pending official implementation."
            )

    source.test_status = test_res.status
    source.connection_status = test_res.status
    source.error_type = test_res.error_type
    source.status_message = test_res.status_message
    if test_res.rate_limit_info:
        source.rate_limit_info = test_res.rate_limit_info
    source.last_tested_at = datetime.utcnow()

    g.db.commit()

    # 3. Audit without logging secrets
    log_audit_event("source.credentials_save", "source_connection", source.id, {
        "platform": source.platform,
        "key_source": "org_supplied",
        "test_status": source.test_status,
        "error_type": source.error_type
    })

    return jsonify({
        "message": f"Credentials for {source.name} saved and tested.",
        "source": {
            "id": source.id,
            "name": source.name,
            "platform": source.platform,
            "is_configured": True,
            "connected": source.test_status == "connected",
            "status": "Connected" if source.test_status == "connected" else ("Error" if source.test_status == "error" else "Unconfigured"),
            "test_status": source.test_status,
            "error_type": source.error_type,
            "status_message": source.status_message,
            "rate_limit": source.rate_limit_info,
            "key_source": "org_supplied",
            "last_tested_at": source.last_tested_at.isoformat() + "Z" if source.last_tested_at else None
        }
    })

@app.route("/api/sources/<source_id>/credentials", methods=["DELETE"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def delete_source_credentials(source_id):
    """
    Deletes stored provider credentials without revealing them.
    Owner-authorized only.
    """
    if not getattr(g, "current_user", None):
        return jsonify({"error": "Authentication required. Please sign in.", "code": "UNAUTHORIZED"}), 401

    alt_id = source_id.replace("source-", "src-") if source_id else ""
    source = g.db.query(SourceConnection).filter(
        (SourceConnection.id == source_id) | (SourceConnection.id == alt_id),
        SourceConnection.organization_id == g.org_id
    ).first()

    if not source:
        return jsonify({"error": "Source connector not found in organization", "code": "NOT_FOUND"}), 404

    source.encrypted_credentials = None
    source.is_configured = False
    source.key_source = "none"
    source.connection_status = "unconfigured"
    source.test_status = "unconfigured"
    source.error_type = None
    source.status_message = "Credentials deleted by organization owner."
    source.last_tested_at = None

    g.db.commit()

    log_audit_event("source.credentials_delete", "source_connection", source.id, {
        "platform": source.platform
    })

    return jsonify({
        "message": f"Stored credentials for {source.name} deleted.",
        "source": {
            "id": source.id,
            "name": source.name,
            "platform": source.platform,
            "is_configured": False,
            "connected": False,
            "status": "Unconfigured",
            "test_status": "unconfigured",
            "key_source": "none",
            "status_message": "Credentials deleted by organization owner."
        }
    })

@app.route("/api/sources/<source_id>/test", methods=["POST"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def test_source_connection(source_id):
    """
    Executes live provider API connection test from the server.
    Owner-authorized only.
    """
    if not getattr(g, "current_user", None):
        return jsonify({"error": "Authentication required. Please sign in.", "code": "UNAUTHORIZED"}), 401

    alt_id = source_id.replace("source-", "src-") if source_id else ""
    source = g.db.query(SourceConnection).filter(
        (SourceConnection.id == source_id) | (SourceConnection.id == alt_id),
        SourceConnection.organization_id == g.org_id
    ).first()

    if not source:
        return jsonify({"error": "Source connector not found in organization", "code": "NOT_FOUND"}), 404

    # Resolve credentials
    api_key = None
    sa_creds = None
    if source.encrypted_credentials:
        try:
            decrypted = decrypt_credentials(source.encrypted_credentials)
            api_key = decrypted.get("api_key")
            sa_creds = decrypted.get("service_account")
        except Exception as e:
            return jsonify({
                "error": "Failed to decrypt stored credentials. Key mismatch.",
                "code": "DECRYPTION_FAILED"
            }), 500
    elif source.platform in app_config.connectors and app_config.connectors[source.platform].enabled:
        # Fall back to deployment-configured key
        dep_c = app_config.connectors[source.platform]
        api_key = dep_c.credentials.get("api_key", dep_c.credentials.get("client_id")).get_secret_value()
        source.key_source = "deployment_configured"

    # Execute test
    if source.platform == "youtube":
        test_res = YouTubeConnector.test_connection(api_key)
    elif source.platform == "apple_app_store":
        test_res = AppleAppStoreConnector.test_connection()
    elif source.platform == "google_play":
        has_imports = bool(source.connection_metadata_json and source.connection_metadata_json != "{}")
        test_res = GooglePlayConnector.test_connection(sa_credentials=sa_creds, has_imported_packages=has_imports)
    else:
        connector_cls = CONNECTOR_CLIENTS.get(source.platform)
        if connector_cls and hasattr(connector_cls, "test_connection"):
            test_res = connector_cls.test_connection()
        else:
            test_res = ConnectionResult(
                success=False,
                status="unconfigured",
                error_type="NOT_IMPLEMENTED",
                status_message=f"{source.name} integration pending official implementation."
            )

    source.test_status = test_res.status
    source.connection_status = test_res.status
    source.error_type = test_res.error_type
    source.status_message = test_res.status_message
    if test_res.rate_limit_info:
        source.rate_limit_info = test_res.rate_limit_info
    source.last_tested_at = datetime.utcnow()

    g.db.commit()

    log_audit_event("source.test_connection", "source_connection", source.id, {
        "platform": source.platform,
        "test_status": source.test_status,
        "error_type": source.error_type
    })

    return jsonify({
        "message": f"Connection test for {source.name} completed.",
        "result": test_res.to_dict(),
        "source": {
            "id": source.id,
            "name": source.name,
            "platform": source.platform,
            "is_configured": source.is_configured or (source.key_source == "deployment_configured"),
            "connected": source.test_status == "connected",
            "status": "Connected" if source.test_status == "connected" else ("Error" if source.test_status == "error" else "Unconfigured"),
            "test_status": source.test_status,
            "error_type": source.error_type,
            "status_message": source.status_message,
            "rate_limit": source.rate_limit_info,
            "last_tested_at": source.last_tested_at.isoformat() + "Z" if source.last_tested_at else None
        }
    })

@app.route("/api/sources/google-play/import", methods=["POST"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def import_google_play_packages():
    """
    Imports structured Google Play developer package manifests.
    Owner-authorized only.
    """
    if not getattr(g, "current_user", None):
        return jsonify({"error": "Authentication required. Please sign in.", "code": "UNAUTHORIZED"}), 401

    source = g.db.query(SourceConnection).filter(
        SourceConnection.platform == "google_play",
        SourceConnection.organization_id == g.org_id
    ).first()

    if not source:
        return jsonify({"error": "Google Play connector not found in organization", "code": "NOT_FOUND"}), 404

    payload = request.get_json(silent=True) or {}
    packages = payload.get("packages", [])

    if not isinstance(packages, list) or len(packages) == 0:
        return jsonify({
            "error": "A non-empty list of package objects is required for import.",
            "code": "INVALID_IMPORT_PAYLOAD"
        }), 400

    # Validate package structure
    for p in packages:
        pkg_name = p.get("package_name") or p.get("exact_identifier")
        if not pkg_name or not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$', str(pkg_name).strip()):
            return jsonify({
                "error": f"Invalid Android package name: '{pkg_name}'. Must follow com.company.app format.",
                "code": "INVALID_PACKAGE_FORMAT"
            }), 400

    source.connection_metadata_json = json.dumps({"imported_packages": packages})
    source.is_configured = True
    source.key_source = "developer_import"
    source.test_status = "connected"
    source.connection_status = "connected"
    source.error_type = None
    source.status_message = f"Google Play package registry active ({len(packages)} verified packages imported)."
    source.rate_limit_info = "Local Package Manifest Stream"
    source.last_tested_at = datetime.utcnow()

    g.db.commit()

    log_audit_event("source.google_play_import", "source_connection", source.id, {
        "packages_imported": len(packages)
    })

    return jsonify({
        "message": f"Successfully imported {len(packages)} official Google Play packages.",
        "imported_count": len(packages),
        "source": {
            "id": source.id,
            "name": source.name,
            "platform": source.platform,
            "is_configured": True,
            "connected": True,
            "status": "Connected",
            "test_status": "connected",
            "status_message": source.status_message,
            "last_tested_at": source.last_tested_at.isoformat() + "Z"
        }
    })

# ==============================================================================
# PHASE 6: EXPANDABLE MULTI-PLATFORM API CONNECTIONS & MULTI-SOURCE SCANNING
# ==============================================================================

@app.route("/api/connectors/catalog", methods=["GET"])
@require_permission("source:read")
def get_connectors_catalog():
    """
    Returns platform catalog with cards for Telegram, Facebook, YouTube,
    Google Play Store, Apple App Store, and 'Coming later' providers.
    Decorated with current organization connection statuses.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    org_conns = g.db.query(SourceConnection).filter(
        SourceConnection.organization_id == g.org_id
    ).all()

    catalog = ConnectorRegistry.list_catalog(active_connections=org_conns)
    for c in catalog:
        c["id"] = c.get("provider_id")
        c["name"] = c.get("display_name")

    implemented = [c for c in catalog if c.get("is_implemented", False)]
    coming_later = [c for c in catalog if not c.get("is_implemented", False)]

    return jsonify({
        "catalog": catalog,
        "implemented": implemented,
        "coming_later": coming_later,
        "count": len(catalog),
        "organization_id": g.org_id
    })

@app.route("/api/connectors", methods=["GET"])
@require_permission("source:read")
def get_connection_instances():
    """
    Returns all active connection instances for the current organization.
    Supports brand scoping filter. Zero secret exposure.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    brand_id = request.args.get("brand_id")
    connections = g.db.query(SourceConnection).filter(
        SourceConnection.organization_id == g.org_id
    ).all()

    results = []
    for c in connections:
        brand_scopes = []
        try:
            brand_scopes = json.loads(c.enabled_brand_ids_json) if c.enabled_brand_ids_json else []
        except Exception:
            brand_scopes = []

        if brand_id and brand_scopes and brand_id not in brand_scopes:
            continue

        perms = []
        try:
            perms = json.loads(c.granted_permissions_json) if c.granted_permissions_json else []
        except Exception:
            perms = []

        err = c.error_type
        raw_st = c.test_status or "unconfigured"
        if raw_st == "connected":
            status_badge = "connected"
        elif raw_st == "limited_access":
            status_badge = "limited_access"
        elif err in ["QUOTA_EXCEEDED", "RATE_LIMITED"]:
            status_badge = "rate_limited"
        elif err in ["EXPIRED_TOKEN"]:
            status_badge = "expired"
        elif err in ["OUTAGE"]:
            status_badge = "unavailable"
        elif raw_st == "unconfigured":
            status_badge = "unconfigured"
        else:
            status_badge = "error"

        prov_id = c.provider_id or c.platform
        connector_cls = ConnectorRegistry.get(prov_id)
        info_dict = connector_cls.get_info() if connector_cls and hasattr(connector_cls, "get_info") else {}

        results.append({
            "id": c.id,
            "provider_id": prov_id,
            "platform": c.platform,
            "name": c.name,
            "auth_method": c.auth_method or info_dict.get("auth_method", "api_key"),
            "status": status_badge,
            "test_status": c.test_status or "unconfigured",
            "is_configured": bool(c.is_configured),
            "connected": c.test_status in ["connected", "limited_access"],
            "last_tested_at": c.last_tested_at.isoformat() + "Z" if c.last_tested_at else None,
            "last_scan_at": c.last_scan_at.isoformat() + "Z" if c.last_scan_at else None,
            "error_type": c.error_type,
            "status_message": c.status_message or "",
            "rate_limit_info": c.rate_limit_info or info_dict.get("default_rate_limit", "Standard Quota"),
            "enabled_brand_ids": brand_scopes,
            "granted_permissions": perms,
            "key_source": c.key_source or "none",
            "icon": info_dict.get("icon", "globe"),
            "supported_capabilities": info_dict.get("supported_capabilities", []),
            "limitations": info_dict.get("limitations", "")
        })

    return jsonify({"connections": results, "count": len(results)})

@app.route("/api/connectors", methods=["POST"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def create_connection_instance():
    """
    Creates and encrypts a new connection instance for an implemented provider.
    - Owner-authorized only.
    - Encrypted via managed vault key.
    - Bound strictly to active organization.
    - Immediately runs connection test.
    - Supports custom name and brand scoping.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({
            "error": "Forbidden: You are not an authorized member of the requested organization.",
            "code": "ORGANIZATION_ACCESS_DENIED"
        }), 403

    payload = request.get_json(silent=True) or {}
    provider_id = (payload.get("provider_id") or "").strip().lower()
    name = (payload.get("name") or "").strip()
    credentials = payload.get("credentials") or {}
    config_data = payload.get("config") or {}
    brand_ids = payload.get("enabled_brand_ids") or []

    if not provider_id:
        return jsonify({"error": "Field 'provider_id' is required.", "code": "VALIDATION_ERROR"}), 400

    connector_cls = ConnectorRegistry.get(provider_id)
    if not connector_cls:
        return jsonify({"error": f"Unknown provider '{provider_id}'.", "code": "NOT_FOUND"}), 404

    if not getattr(connector_cls, "is_implemented", False):
        return jsonify({
            "error": f"Provider '{provider_id}' is not yet implemented. Marked coming later.",
            "code": "NOT_IMPLEMENTED"
        }), 400

    if not name:
        name = f"{connector_cls.display_name} Connection"

    combined_config = dict(config_data or {})
    if isinstance(credentials, dict):
        combined_config.update(credentials)

    is_valid, val_err = connector_cls.validate_config(combined_config)
    if not is_valid:
        return jsonify({"error": f"Configuration validation failed: {val_err}", "code": "CONFIG_ERROR"}), 400

    # Run immediate server-side test
    test_res = connector_cls.test_connection(credentials=credentials, config=config_data)

    encrypted_token = None
    key_source = "none"
    if credentials:
        try:
            encrypted_token = encrypt_credentials(credentials)
            key_source = "org_supplied"
        except Exception as e:
            return jsonify({"error": f"Credential encryption failed: {str(e)}", "code": "ENCRYPTION_ERROR"}), 500

    granted_perms = test_res.metadata.get("granted_permissions", [])

    new_conn = SourceConnection(
        id=f"conn-{secrets.token_hex(8)}",
        organization_id=g.org_id,
        platform=provider_id,
        provider_id=provider_id,
        auth_method=connector_cls.auth_method,
        name=name,
        connection_status=test_res.status if test_res.success else "error",
        test_status=test_res.status,
        error_type=test_res.error_type,
        status_message=test_res.status_message,
        rate_limit_info=test_res.rate_limit_info or connector_cls.default_rate_limit,
        is_configured=bool(credentials or test_res.success),
        key_source=key_source,
        encrypted_credentials=encrypted_token,
        config_json=json.dumps(config_data),
        enabled_brand_ids_json=json.dumps(brand_ids),
        granted_permissions_json=json.dumps(granted_perms),
        last_tested_at=datetime.utcnow()
    )

    g.db.add(new_conn)
    g.db.commit()

    log_audit_event("connector.create", "source_connection", new_conn.id, {
        "provider_id": provider_id,
        "name": name,
        "test_status": test_res.status,
        "brand_count": len(brand_ids)
    })

    return jsonify({
        "message": f"Connection '{name}' created for {connector_cls.display_name}.",
        "connection": {
            "id": new_conn.id,
            "provider_id": new_conn.provider_id,
            "name": new_conn.name,
            "auth_method": new_conn.auth_method,
            "status": test_res.detailed_status,
            "test_status": new_conn.test_status,
            "connected": test_res.success,
            "is_configured": new_conn.is_configured,
            "status_message": new_conn.status_message,
            "error_type": new_conn.error_type,
            "rate_limit_info": new_conn.rate_limit_info,
            "last_tested_at": new_conn.last_tested_at.isoformat() + "Z",
            "enabled_brand_ids": brand_ids,
            "granted_permissions": granted_perms
        }
    }), 201

@app.route("/api/connectors/<connection_id>", methods=["GET"])
@require_permission("source:read")
def get_connection_instance(connection_id):
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    conn = g.db.query(SourceConnection).filter(
        SourceConnection.id == connection_id,
        SourceConnection.organization_id == g.org_id
    ).first()
    if not conn:
        return jsonify({"error": "Connection not found", "code": "NOT_FOUND"}), 404

    cfg = {}
    try:
        cfg = json.loads(conn.config_json) if conn.config_json else {}
    except Exception:
        pass

    brand_scopes = []
    try:
        brand_scopes = json.loads(conn.enabled_brand_ids_json) if conn.enabled_brand_ids_json else []
    except Exception:
        pass

    perms = []
    try:
        perms = json.loads(conn.granted_permissions_json) if conn.granted_permissions_json else []
    except Exception:
        pass

    prov_id = conn.provider_id or conn.platform
    connector_cls = ConnectorRegistry.get(prov_id)
    info_dict = connector_cls.get_info() if connector_cls and hasattr(connector_cls, "get_info") else {}

    return jsonify({
        "connection": {
            "id": conn.id,
            "provider_id": prov_id,
            "platform": conn.platform,
            "name": conn.name,
            "auth_method": conn.auth_method,
            "status": conn.test_status,
            "test_status": conn.test_status,
            "is_configured": bool(conn.is_configured),
            "connected": conn.test_status in ["connected", "limited_access"],
            "last_tested_at": conn.last_tested_at.isoformat() + "Z" if conn.last_tested_at else None,
            "last_scan_at": conn.last_scan_at.isoformat() + "Z" if conn.last_scan_at else None,
            "error_type": conn.error_type,
            "status_message": conn.status_message or "",
            "rate_limit_info": conn.rate_limit_info,
            "enabled_brand_ids": brand_scopes,
            "granted_permissions": perms,
            "config": cfg,
            "key_source": conn.key_source,
            "icon": info_dict.get("icon", "globe")
        }
    })

@app.route("/api/connectors/<connection_id>", methods=["PUT"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def update_connection_instance(connection_id):
    """
    Updates connection name, brand scoping, config, or replaces credentials.
    Owner-authorized only.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    conn = g.db.query(SourceConnection).filter(
        SourceConnection.id == connection_id,
        SourceConnection.organization_id == g.org_id
    ).first()
    if not conn:
        return jsonify({"error": "Connection not found", "code": "NOT_FOUND"}), 404

    payload = request.get_json(silent=True) or {}
    prov_id = conn.provider_id or conn.platform
    connector_cls = ConnectorRegistry.get(prov_id)

    if "name" in payload and payload["name"]:
        conn.name = payload["name"].strip()

    if "enabled_brand_ids" in payload:
        conn.enabled_brand_ids_json = json.dumps(payload["enabled_brand_ids"])

    config_changed = False
    config_data = {}
    try:
        config_data = json.loads(conn.config_json) if conn.config_json else {}
    except Exception:
        pass

    if "config" in payload and isinstance(payload["config"], dict):
        config_data.update(payload["config"])
        conn.config_json = json.dumps(config_data)
        config_changed = True

    credentials = payload.get("credentials")
    cred_data = None
    if credentials:
        try:
            conn.encrypted_credentials = encrypt_credentials(credentials)
            conn.is_configured = True
            conn.key_source = "org_supplied"
            cred_data = credentials
        except Exception as e:
            return jsonify({"error": f"Credential encryption failed: {str(e)}", "code": "ENCRYPTION_ERROR"}), 500
    elif conn.encrypted_credentials:
        try:
            cred_data = decrypt_credentials(conn.encrypted_credentials)
        except Exception:
            cred_data = None

    # Re-run connection test if credentials or config changed
    if connector_cls and (credentials or config_changed):
        test_res = connector_cls.test_connection(credentials=cred_data, config=config_data)
        conn.test_status = test_res.status
        conn.connection_status = test_res.status if test_res.success else "error"
        conn.error_type = test_res.error_type
        conn.status_message = test_res.status_message
        if test_res.rate_limit_info:
            conn.rate_limit_info = test_res.rate_limit_info
        conn.last_tested_at = datetime.utcnow()
        if "granted_permissions" in test_res.metadata:
            conn.granted_permissions_json = json.dumps(test_res.metadata["granted_permissions"])

    g.db.commit()

    log_audit_event("connector.update", "source_connection", conn.id, {
        "provider_id": prov_id,
        "name": conn.name,
        "test_status": conn.test_status
    })

    return jsonify({
        "message": f"Connection '{conn.name}' updated successfully.",
        "connection": {
            "id": conn.id,
            "provider_id": prov_id,
            "name": conn.name,
            "status": conn.test_status,
            "test_status": conn.test_status,
            "connected": conn.test_status in ["connected", "limited_access"],
            "is_configured": bool(conn.is_configured),
            "status_message": conn.status_message,
            "error_type": conn.error_type,
            "last_tested_at": conn.last_tested_at.isoformat() + "Z" if conn.last_tested_at else None
        }
    })

@app.route("/api/connectors/<connection_id>", methods=["DELETE"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def delete_connection_instance(connection_id):
    """
    Deletes connection instance. Owner-authorized only.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    conn = g.db.query(SourceConnection).filter(
        SourceConnection.id == connection_id,
        SourceConnection.organization_id == g.org_id
    ).first()
    if not conn:
        return jsonify({"error": "Connection not found", "code": "NOT_FOUND"}), 404

    conn_name = conn.name
    prov_id = conn.provider_id or conn.platform

    g.db.delete(conn)
    g.db.commit()

    log_audit_event("connector.delete", "source_connection", connection_id, {
        "provider_id": prov_id,
        "name": conn_name
    })

    return jsonify({
        "message": f"Connection '{conn_name}' deleted.",
        "deleted_id": connection_id
    })

@app.route("/api/connectors/<connection_id>/test", methods=["POST"])
@require_permission("source:manage")
@require_org_role("owner")
@validate_csrf
def test_connection_instance(connection_id):
    """
    Executes live upstream provider test for a connection instance.
    Owner-authorized only.
    """
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    conn = g.db.query(SourceConnection).filter(
        SourceConnection.id == connection_id,
        SourceConnection.organization_id == g.org_id
    ).first()
    if not conn:
        return jsonify({"error": "Connection not found", "code": "NOT_FOUND"}), 404

    prov_id = conn.provider_id or conn.platform
    connector_cls = ConnectorRegistry.get(prov_id)
    if not connector_cls:
        return jsonify({"error": f"Provider '{prov_id}' not found.", "code": "NOT_FOUND"}), 404

    # Resolve credentials
    creds = None
    if conn.encrypted_credentials:
        try:
            creds = decrypt_credentials(conn.encrypted_credentials)
        except Exception:
            return jsonify({"error": "Decryption failed for stored credentials.", "code": "DECRYPTION_FAILED"}), 500

    cfg = {}
    try:
        cfg = json.loads(conn.config_json) if conn.config_json else {}
    except Exception:
        pass

    test_res = connector_cls.test_connection(credentials=creds, config=cfg)

    conn.test_status = test_res.status
    conn.connection_status = test_res.status if test_res.success else "error"
    conn.error_type = test_res.error_type
    conn.status_message = test_res.status_message
    if test_res.rate_limit_info:
        conn.rate_limit_info = test_res.rate_limit_info
    conn.last_tested_at = datetime.utcnow()
    if "granted_permissions" in test_res.metadata:
        conn.granted_permissions_json = json.dumps(test_res.metadata["granted_permissions"])

    g.db.commit()

    log_audit_event("connector.test", "source_connection", conn.id, {
        "provider_id": prov_id,
        "test_status": test_res.status,
        "error_type": test_res.error_type
    })

    return jsonify({
        "message": f"Connection test completed for {conn.name}.",
        "result": test_res.to_dict(),
        "connection": {
            "id": conn.id,
            "provider_id": prov_id,
            "name": conn.name,
            "status": test_res.detailed_status,
            "test_status": conn.test_status,
            "connected": test_res.success,
            "status_message": conn.status_message,
            "error_type": conn.error_type,
            "rate_limit_info": conn.rate_limit_info,
            "last_tested_at": conn.last_tested_at.isoformat() + "Z"
        }
    })

# ==============================================================================
# MULTI-SOURCE SCANNING API
# ==============================================================================

@app.route("/api/scan/multi", methods=["POST"])
@validate_csrf
@require_permission("scan:run")
def run_multi_source_scan():
    """
    Executes scan across one, multiple, or all configured connections.
    - Shows progress and results per source.
    - Deduplicates candidates across sources by provider and external ID.
    - Partial failure resilience: captures and reports failures without discarding valid results.
    - Evaluates exact source-scoped identity against official assets.
    - Returns structured summary: source coverage, candidates examined,
      official assets excluded, impersonation findings, inconclusive results, failed sources.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    payload = request.get_json(silent=True) or {}
    query = (payload.get("query") or "@northstar_alert").strip()
    sources_req = payload.get("sources") or [] # List of provider IDs, connection IDs, or ["all"]
    brand_id_req = payload.get("brand_id")

    # 1. Resolve Brand and Official Assets
    brand_query = g.db.query(Brand).filter(Brand.organization_id == g.org_id)
    if brand_id_req:
        active_brand = brand_query.filter(Brand.id == brand_id_req).first()
    else:
        active_brand = brand_query.first()

    if not active_brand:
        return jsonify({"error": "No brand configured for organization", "code": "NO_BRAND"}), 400

    official_assets = g.db.query(OfficialAsset).filter(
        OfficialAsset.brand_id == active_brand.id,
        OfficialAsset.organization_id == g.org_id
    ).all()

    # 2. Resolve Connections to Scan
    all_org_conns = g.db.query(SourceConnection).filter(
        SourceConnection.organization_id == g.org_id
    ).all()

    selected_conns: List[SourceConnection] = []
    if not sources_req or "all" in [s.lower() for s in sources_req if isinstance(s, str)]:
        # Use all configured/available connections
        selected_conns = [
            c for c in all_org_conns
            if c.is_configured or c.platform == "apple_app_store" or c.test_status in ["connected", "ready_to_connect"]
        ]
        if not selected_conns:
            # Fall back to all org connections if none explicitly configured
            selected_conns = all_org_conns
    else:
        # Match by connection ID or provider_id / platform
        req_set = {str(s).strip().lower() for s in sources_req}
        for c in all_org_conns:
            cid = str(c.id).lower()
            prov = (c.provider_id or c.platform or "").lower()
            if cid in req_set or prov in req_set:
                selected_conns.append(c)

        # Allow querying any registered provider in req_set even if no explicit SourceConnection row exists yet
        found_provs = {(c.provider_id or c.platform or "").lower() for c in selected_conns}
        for prov_req in req_set:
            if prov_req not in found_provs and ConnectorRegistry.get(prov_req):
                c_cls = ConnectorRegistry.get(prov_req)
                existing = g.db.query(SourceConnection).filter(
                    SourceConnection.organization_id == g.org_id,
                    (SourceConnection.platform == prov_req) | (SourceConnection.provider_id == prov_req)
                ).first()
                if existing:
                    selected_conns.append(existing)
                    found_provs.add(prov_req)
                else:
                    temp_conn = SourceConnection(
                        id=f"src-{prov_req}-{secrets.token_hex(6)}",
                        organization_id=g.org_id,
                        platform=prov_req,
                        provider_id=prov_req,
                        auth_method=getattr(c_cls, "auth_method", "api_key"),
                        name=getattr(c_cls, "display_name", prov_req),
                        connection_status="connected" if prov_req == "apple_app_store" else "unconfigured",
                        test_status="connected" if prov_req == "apple_app_store" else "unconfigured",
                        is_configured=(prov_req == "apple_app_store")
                    )
                    g.db.add(temp_conn)
                    g.db.commit()
                    selected_conns.append(temp_conn)
                    found_provs.add(prov_req)

    if not selected_conns:
        return jsonify({
            "error": "No eligible or configured source connections selected for scan.",
            "code": "NO_SOURCES_SELECTED"
        }), 400

    # 3. Execute Discovery Across Sources with Partial Failure Resilience
    source_coverage = []
    failed_sources = []
    skipped_sources = []
    all_candidates: List[NormalizedCandidate] = []

    for conn in selected_conns:
        prov_id = conn.provider_id or conn.platform
        connector_cls = ConnectorRegistry.get(prov_id)

        # Check if provider is implemented
        if not connector_cls or not getattr(connector_cls, "is_implemented", False):
            skipped_sources.append({
                "provider": prov_id,
                "name": conn.name,
                "reason": f"Provider '{prov_id}' is marked Coming later. Live scanning unavailable."
            })
            source_coverage.append({
                "provider": prov_id,
                "name": conn.name,
                "status": "skipped",
                "reason": "Coming later"
            })
            continue

        # Decrypt credentials if available
        creds = None
        if conn.encrypted_credentials:
            try:
                creds = decrypt_credentials(conn.encrypted_credentials)
            except Exception as e:
                failed_sources.append({
                    "provider": prov_id,
                    "name": conn.name,
                    "error_type": "DECRYPTION_ERROR",
                    "message": f"Stored credential decryption failed: {str(e)}"
                })
                source_coverage.append({
                    "provider": prov_id,
                    "name": conn.name,
                    "status": "failed",
                    "reason": "Decryption error"
                })
                continue
        elif prov_id in app_config.connectors and app_config.connectors[prov_id].enabled:
            dep_c = app_config.connectors[prov_id]
            key_val = dep_c.credentials.get("api_key", dep_c.credentials.get("client_id"))
            if key_val:
                creds = {"api_key": key_val.get_secret_value()}

        cfg = {}
        try:
            cfg = json.loads(conn.config_json) if conn.config_json else {}
        except Exception:
            pass

        # Execute candidate discovery
        try:
            discovered = connector_cls.discover_candidates(
                query=query,
                credentials=creds,
                config=cfg,
                limit=10
            )

            all_candidates.extend(discovered)
            conn.last_scan_at = datetime.utcnow()

            source_coverage.append({
                "provider": prov_id,
                "name": conn.name,
                "status": "success",
                "candidates_count": len(discovered)
            })

        except Exception as e:
            app.logger.error("Scan error on source %s (%s): %s", prov_id, conn.name, str(e))
            failed_sources.append({
                "provider": prov_id,
                "name": conn.name,
                "error_type": type(e).__name__,
                "message": f"Discovery failed on {conn.name}: {str(e)}"
            })
            source_coverage.append({
                "provider": prov_id,
                "name": conn.name,
                "status": "failed",
                "reason": str(e)
            })
            # Continue without aborting! Partial failure resilience guarantee.

    g.db.commit()

    # 4. Deduplicate Candidates Across Sources by (provider, external_id)
    seen_keys = set()
    unique_candidates: List[NormalizedCandidate] = []
    for cand in all_candidates:
        key = (cand.provider, cand.external_id)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_candidates.append(cand)

    # 5. Live vs Demo Separation Rule:
    # NEVER silently substitute demo results when a live source fails or returns 0.
    # Keep demo scans explicitly labeled and separate.
    is_explicit_demo = bool(payload.get("is_demo") or payload.get("demo_mode"))
    if is_explicit_demo and not unique_candidates and not failed_sources:
        # Only when explicitly requested as a demo sandbox scan:
        is_app = any(x in query.lower() for x in ["app", "apk", "mobile", "ios", "com."])
        default_prov = "apple_app_store" if is_app else "youtube"
        sim_cand = NormalizedCandidate(
            provider=default_prov,
            external_id=f"demo_sandbox_sim_{int(time.time())}",
            asset_type="mobile_app" if is_app else "social_channel",
            display_name=f"[DEMO SANDBOX] Suspect Account ({query})",
            handle_or_package=query if query.startswith("@") or "." in query else f"@{query.replace(' ', '_').lower()}_demo",
            description=f"Synthetic demo candidate for brand '{query}'. Payment: send btc to claim reward.",
            source_url=f"https://example.com/demo/{query}",
            provenance={"collector": "demo_sandbox", "is_demo": True},
            missing_evidence_indicators=["Sandbox demonstration telemetry"]
        )
        unique_candidates.append(sim_cand)

    # 6. Execute Scanning Pipeline:
    # Source adapter → normalized candidate → exact official-asset check
    # → evidence analysis → assessment → stored result.
    brand_aliases = []
    try:
        brand_aliases = json.loads(active_brand.aliases_json) if active_brand.aliases_json else []
    except Exception:
        brand_aliases = []

    official_assets_excluded = 0
    impersonation_findings = 0
    inconclusive_results = 0
    unrelated_count = 0
    generated_detections = []

    # Determine scan status:
    # If all selected sources failed, status is 'failed'
    # If some failed and some succeeded, status is 'partial_success'
    # If no failures, status is 'completed'
    unavailable_count = len(failed_sources) + len(skipped_sources)
    if unavailable_count == len(selected_conns):
        scan_status = "failed"
    elif unavailable_count:
        scan_status = "partial_success"
    else:
        scan_status = "completed"

    scan_rec = Scan(
        organization_id=g.org_id,
        brand_id=active_brand.id,
        target_query=query,
        source_platform="multi",
        status=scan_status,
        initiated_by_user_id=getattr(g, "user_id", None),
        candidates_found=len(unique_candidates),
        detections_flagged=0,
        is_sample=is_explicit_demo,
        completed_at=datetime.utcnow()
    )
    g.db.add(scan_rec)
    g.db.flush()

    # Per-source statistics
    per_source_stats: Dict[str, Dict[str, int]] = {}
    for c in selected_conns:
        per_source_stats[c.provider_id] = {
            "candidates": 0,
            "infringements": 0,
            "official_matches": 0,
            "inconclusive": 0
        }

    for cand in unique_candidates:
        src_key = cand.provider
        if src_key not in per_source_stats:
            per_source_stats[src_key] = {"candidates": 0, "infringements": 0, "official_matches": 0, "inconclusive": 0}
        per_source_stats[src_key]["candidates"] += 1

        # Process through full pipeline (Normalizers, Unicode, Leet, Added Words, Publisher, Payment, Assessments)
        pipe_res = process_candidate_pipeline(
            candidate=cand,
            brand_id=active_brand.id,
            brand_name=active_brand.name,
            brand_aliases=brand_aliases,
            official_assets=official_assets,
            organization_id=g.org_id,
            db_session=g.db,
            scan_id=scan_rec.id,
            is_sample=is_explicit_demo
        )

        assessment = pipe_res["assessment"]
        if assessment == ASSESSMENT_OFFICIAL_MATCH:
            official_assets_excluded += 1
            per_source_stats[src_key]["official_matches"] += 1
        elif assessment == ASSESSMENT_LIKELY_IMPERSONATION:
            impersonation_findings += 1
            per_source_stats[src_key]["infringements"] += 1
        elif assessment == ASSESSMENT_INCONCLUSIVE:
            inconclusive_results += 1
            per_source_stats[src_key]["inconclusive"] += 1
        else:
            unrelated_count += 1

        # Format detection representation for frontend results table & evidence card
        is_app = cand.asset_type == "mobile_app" or cand.provider in ["apple_app_store", "google_play"]
        icon_map = {
            "youtube": "youtube",
            "telegram": "telegram",
            "facebook": "facebook",
            "apple_app_store": "appstore",
            "google_play": "playstore"
        }

        generated_detections.append({
            "id": pipe_res["detection_id"],
            "target_name": cand.display_name,
            "category": "Apps" if is_app else "Social",
            "platform": cand.provider.replace("_", " ").title(),
            "platform_icon": icon_map.get(cand.provider, "globe"),
            "risk_level": pipe_res["risk_level"].title(),
            "risk_score": pipe_res["risk_score"],
            "detection_type": pipe_res["detection_type"],
            "match_score": pipe_res["evidence"].get("name_similarity", {}).get("score", 0.0),
            "match_score_display": f"{int(pipe_res['evidence'].get('name_similarity', {}).get('score', 0.0) * 100)}% Match",
            "detected_at": "Just now",
            "status": "Whitelisted" if pipe_res["is_official"] else ("Flagged" if assessment == ASSESSMENT_LIKELY_IMPERSONATION else "Under Review"),
            "identity_status": pipe_res["identity_status"],
            "assessment": assessment,
            "evidence": {
                "target_handle": cand.handle_or_package,
                "official_counterpart": f"{active_brand.name} Registered Asset",
                "source_url": cand.source_url,
                "violations": [
                    f"Assessment: {assessment.replace('_', ' ').title()}",
                    pipe_res["rationale"]
                ],
                "corroborating_signals": pipe_res["corroborating_signals"],
                "missing_evidence_indicators": cand.missing_evidence_indicators,
                "provenance": cand.provenance,
                "detailed_evidence": pipe_res["evidence"]
            }
        })

    scan_rec.detections_flagged = impersonation_findings
    g.db.commit()

    log_audit_event("scan.multi_complete", "scan", scan_rec.id, {
        "query": query,
        "sources_queried": len(selected_conns),
        "candidates_examined": len(unique_candidates),
        "official_excluded": official_assets_excluded,
        "impersonations_flagged": impersonation_findings,
        "inconclusive_count": inconclusive_results,
        "failed_sources_count": len(failed_sources),
        "is_demo": is_explicit_demo
    })

    return jsonify({
        "status": scan_status,
        "scan_id": scan_rec.id,
        "query": query,
        "sources_queried": [c.provider_id or c.platform for c in selected_conns],
        "failed_sources": failed_sources,
        "failed_source_details": failed_sources,
        "skipped_sources": skipped_sources,
        "total_candidates": len(unique_candidates),
        "official_excluded_count": official_assets_excluded,
        "impersonators_flagged": impersonation_findings,
        "inconclusive_count": inconclusive_results,
        "unrelated_count": unrelated_count,
        "per_source_breakdown": per_source_stats,
        "findings": generated_detections,
        "first_finding": generated_detections[0] if generated_detections else None,
        "detector_version": DETECTOR_VERSION,
        "is_sample": is_explicit_demo,
        "summary": {
            "sources_queried": len(selected_conns),
            "candidates_examined": len(unique_candidates),
            "official_assets_excluded": official_assets_excluded,
            "impersonation_findings": impersonation_findings,
            "inconclusive_results": inconclusive_results,
            "failed_sources_count": len(failed_sources),
            "skipped_sources_count": len(skipped_sources)
        }
    })


# ==============================================================================
# EXACT YOUTUBE CHANNEL VERIFICATION API
# ==============================================================================

@app.route("/api/verify/youtube", methods=["POST"])
@validate_csrf
@require_permission("scan:run")
def verify_youtube_channel():
    """
    Checks ONE YouTube channel using its channel URL, @handle, or UC... channel ID
    and compares it with the selected brand's registered official YouTube channel.

    Guarantees:
    - Resolves the exact channel through official YouTube Data API v3 channels endpoint.
    - Never executes discovery/fuzzy name-search in this verification workflow.
    - Reuses existing backend credentials without exposing keys in frontend code or logs.
    - Handles invalid input, unsupported video links, channel not found, missing credentials,
      quota exhaustion, and provider errors with distinct messages.
    - Never converts errors into safe, fake, or successful zero-result scans.
    - Preserves authentication, authorization, CSRF, tenant isolation, and credential encryption.
    - Never overwrites official assets or registers channels automatically.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    payload = request.get_json(silent=True) or {}
    identifier = (payload.get("identifier") or "").strip()
    brand_id_req = payload.get("brand_id")

    if not identifier:
        return jsonify({
            "error": "Please enter a YouTube channel identifier (channel URL, @handle, or UC... channel ID).",
            "code": "EMPTY_INPUT"
        }), 400

    # 1. Parse and validate channel input format
    parsed = YouTubeConnector.parse_channel_input(identifier)
    if not parsed.get("valid"):
        return jsonify({
            "error": parsed.get("message"),
            "code": parsed.get("error_type", "INVALID_INPUT")
        }), 400

    # 2. Resolve Brand and Tenant Scoping
    brand_query = g.db.query(Brand).filter(Brand.organization_id == g.org_id)
    if brand_id_req:
        active_brand = brand_query.filter(Brand.id == brand_id_req).first()
    else:
        active_brand = brand_query.first()

    if not active_brand:
        return jsonify({
            "error": "Brand not found or access denied for this organization.",
            "code": "BRAND_NOT_FOUND"
        }), 404

    # 3. Fetch Brand's Registered Official YouTube Assets
    official_assets = g.db.query(OfficialAsset).filter(
        OfficialAsset.brand_id == active_brand.id,
        OfficialAsset.organization_id == g.org_id
    ).all()

    # 4. Resolve YouTube API Key via Backend Credential System (strictly non-logging, non-exposing)
    api_key = None

    # Check organization's stored encrypted credentials in database
    conn = g.db.query(SourceConnection).filter(
        SourceConnection.organization_id == g.org_id,
        (SourceConnection.platform == "youtube") | (SourceConnection.provider_id == "youtube")
    ).first()

    if conn and conn.encrypted_credentials:
        try:
            creds = decrypt_credentials(conn.encrypted_credentials)
            api_key = creds.get("api_key")
        except Exception:
            api_key = None

    # Fall back to deployment connector configuration
    if not api_key:
        if "youtube" in app_config.connectors and app_config.connectors["youtube"].enabled:
            dep_c = app_config.connectors["youtube"]
            key_val = dep_c.credentials.get("api_key")
            if key_val:
                api_key = key_val.get_secret_value()

    # Fall back to environment variable
    if not api_key:
        env_key = os.getenv("YOUTUBE_API_KEY", "").strip()
        if env_key:
            api_key = env_key

    if not api_key:
        return jsonify({
            "error": "Missing API credentials. YouTube Data API v3 key is not configured for this organization or deployment. Please configure it in API Connections.",
            "code": "MISSING_CREDENTIALS"
        }), 400

    # 5. Resolve Exact Channel via YouTube Data API v3
    res = YouTubeConnector.resolve_exact_channel(api_key, parsed)
    if not res.get("success"):
        err_type = res.get("error_type", "PROVIDER_ERROR")
        status_map = {
            "CHANNEL_NOT_FOUND": 404,
            "QUOTA_EXCEEDED": 429,
            "INVALID_CREDENTIALS": 401,
            "FORBIDDEN": 403,
            "API_NOT_ENABLED": 403,
            "RESTRICTED_KEY": 403,
            "PROVIDER_OUTAGE": 503,
            "OUTAGE": 503,
            "TIMEOUT": 504,
            "NETWORK_ERROR": 502,
        }
        status_code = status_map.get(err_type, 400)
        return jsonify({
            "error": res.get("message", "Failed to resolve channel through YouTube API."),
            "code": err_type
        }), status_code

    # 6. Perform Evidence-Based Identity Comparison
    channel_data = res["channel"]
    verification = evaluate_youtube_channel_verification(
        channel_data=channel_data,
        brand=active_brand,
        official_assets=official_assets
    )

    # Attach raw channel metadata without exposing sensitive credentials
    verification["channel_metadata"] = {
        "channel_id": channel_data.get("channel_id") or channel_data.get("id"),
        "title": channel_data.get("title"),
        "description": channel_data.get("description"),
        "custom_url": channel_data.get("custom_url"),
        "canonical_url": channel_data.get("canonical_url"),
        "thumbnail_url": channel_data.get("thumbnail_url"),
        "published_at": channel_data.get("published_at"),
        "subscriber_count": channel_data.get("subscriber_count"),
        "video_count": channel_data.get("video_count"),
        "view_count": channel_data.get("view_count")
    }

    app.logger.info(
        "YouTube exact verification executed for brand '%s'. Verdict: %s (Channel ID: %s)",
        active_brand.name,
        verification.get("verdict"),
        channel_data.get("channel_id")
    )

    return jsonify({
        "success": True,
        "verification": verification
    }), 200


@app.route("/api/scan/import", methods=["POST"])
@require_permission("scan:run")
@validate_csrf
def import_scan_candidates():
    """
    Ingests validated JSON candidate records directly through the scanning pipeline:
    JSON import → normalized candidate → exact official-asset check
    → evidence analysis → assessment → stored result.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    payload = request.get_json(silent=True) or {}
    brand_id = payload.get("brand_id")
    
    if brand_id:
        brand = g.db.query(Brand).filter(
            Brand.id == brand_id,
            Brand.organization_id == g.org_id
        ).first()
    else:
        brand = g.db.query(Brand).filter(Brand.organization_id == g.org_id).first()

    if not brand:
        return jsonify({"error": "No brand configured for organization", "code": "BRAND_NOT_FOUND"}), 404

    # Validate JSON schema and parse into NormalizedCandidate objects
    is_valid, candidates, err_msg = validate_and_parse_import_json(payload)
    if not is_valid:
        return jsonify({
            "error": f"Invalid candidate import JSON: {err_msg}",
            "code": "SCHEMA_VALIDATION_ERROR"
        }), 400

    # Fetch official assets for exact matching
    official_assets = g.db.query(OfficialAsset).filter(
        OfficialAsset.brand_id == brand.id,
        OfficialAsset.organization_id == g.org_id
    ).all()

    brand_aliases = []
    try:
        brand_aliases = json.loads(brand.aliases_json) if brand.aliases_json else []
    except Exception:
        brand_aliases = []

    # Create persistent Scan record for this batch
    scan_rec = Scan(
        organization_id=g.org_id,
        brand_id=brand.id,
        target_query="[VALIDATED JSON IMPORT BATCH]",
        source_platform="json_import",
        status="completed",
        initiated_by_user_id=getattr(g, "user_id", None),
        candidates_found=len(candidates),
        detections_flagged=0,
        is_sample=False,
        completed_at=datetime.utcnow()
    )
    g.db.add(scan_rec)
    g.db.flush()

    official_count = 0
    impersonation_count = 0
    inconclusive_count = 0
    unrelated_count = 0
    processed_results = []

    for cand in candidates:
        res = process_candidate_pipeline(
            candidate=cand,
            brand_id=brand.id,
            brand_name=brand.name,
            brand_aliases=brand_aliases,
            official_assets=official_assets,
            organization_id=g.org_id,
            db_session=g.db,
            scan_id=scan_rec.id,
            is_sample=False
        )
        processed_results.append(res)
        if res["assessment"] == ASSESSMENT_OFFICIAL_MATCH:
            official_count += 1
        elif res["assessment"] == ASSESSMENT_LIKELY_IMPERSONATION:
            impersonation_count += 1
        elif res["assessment"] == ASSESSMENT_INCONCLUSIVE:
            inconclusive_count += 1
        else:
            unrelated_count += 1

    scan_rec.detections_flagged = impersonation_count
    g.db.commit()

    log_audit_event("scan.import_candidates", "scan", scan_rec.id, {
        "brand_id": brand.id,
        "total_imported": len(candidates),
        "official_matches": official_count,
        "likely_impersonations": impersonation_count,
        "inconclusive": inconclusive_count
    })

    return jsonify({
        "status": "completed",
        "scan_id": scan_rec.id,
        "brand_id": brand.id,
        "total_candidates": len(candidates),
        "official_matches": official_count,
        "likely_impersonations": impersonation_count,
        "inconclusive_count": inconclusive_count,
        "unrelated_count": unrelated_count,
        "detector_version": DETECTOR_VERSION,
        "results": processed_results
    }), 201

# ==========================================
# AUDIT EVENTS API (Scoped to Organization)
# ==========================================

@app.route("/api/audit", methods=["GET"])
@require_permission("audit:read")
def get_audit_trail():
    events = g.db.query(AuditEvent).filter(
        AuditEvent.organization_id == g.org_id
    ).order_by(AuditEvent.created_at.desc()).limit(50).all()

    out = []
    for e in events:
        details = {}
        try:
            details = json.loads(e.details_json) if e.details_json else {}
        except Exception:
            details = {}
        out.append({
            "id": e.id,
            "action": e.action,
            "entity_type": e.entity_type,
            "entity_id": e.entity_id,
            "details": details,
            "ip_address": e.ip_address,
            "created_at": e.created_at.isoformat() if e.created_at else None
        })
    return jsonify({"events": out, "count": len(out)})

# Full State Payload for Initial Web App Render
@app.route("/api/data", methods=["GET"])
def get_all_data():
    # Return consolidated payload matching frontend contract
    brands_resp = list_brands().get_json()
    sources_resp = manage_sources().get_json()
    findings_resp = get_findings().get_json()

    # Active brand - respect requested brand_id or default to MG Indian Super League if available, else first brand
    requested_brand_id = request.args.get("brand_id")
    active_b = None
    if requested_brand_id:
        active_b = g.db.query(Brand).filter(
            Brand.id == requested_brand_id,
            Brand.organization_id == g.org_id
        ).first()

    if not active_b:
        active_b = g.db.query(Brand).filter(
            Brand.organization_id == g.org_id,
            func.lower(Brand.name) == "mg indian super league"
        ).first()

    if not active_b:
        active_b = g.db.query(Brand).filter(
            Brand.organization_id == g.org_id
        ).first()

    current_brand_dict = {}
    if active_b:
        current_brand_dict = get_brand(active_b.id).get_json()

    return jsonify({
        "system_info": {
            "app_name": "BrandSentinel",
            "version": "v1.4.2-db-persist",
            "environment": "Demo Sandbox",
            "disclaimer": "FICTIONAL SAMPLE DATA ACTIVE. Scoped to Northstar Technologies demo organization. Zero credential persistence."
        },
        "current_brand": current_brand_dict,
        "available_brands": brands_resp,
        "sources": sources_resp,
        "findings": findings_resp.get("findings", []),
        "counts": findings_resp.get("counts", {}),
        "has_live_scans": findings_resp.get("has_live_scans", False),
        "is_sample_dataset": findings_resp.get("is_sample_dataset", True)
    })

# =============================================================================
# DATASET IMPORT & PHISHING ML ENDPOINTS
# =============================================================================

@app.route('/api/datasets/import', methods=['POST'])
@validate_csrf
@require_permission("brand:update")
def import_dataset():
    """
    Validates, cleans, deduplicates, and imports a phishing URL dataset.
    Supports multipart/form-data file upload (up to 120 MiB) or JSON body with server file_path.
    Enforces authentication, CSRF, and organization isolation.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    temp_path = None
    try:
        # Check if multipart upload
        if 'file' in request.files:
            uploaded_file = request.files['file']
            if not uploaded_file.filename:
                return jsonify({"error": "No file selected for upload.", "code": "NO_FILE"}), 400
            if not uploaded_file.filename.lower().endswith('.csv'):
                return jsonify({"error": "Only CSV files are supported for dataset import.", "code": "INVALID_FORMAT"}), 400

            upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "managed_datasets")
            os.makedirs(upload_dir, exist_ok=True)
            temp_path = os.path.join(upload_dir, f"upload_{secrets.token_hex(8)}_{uploaded_file.filename}")
            uploaded_file.save(temp_path)
            file_to_process = temp_path
            orig_filename = uploaded_file.filename
        else:
            payload = request.get_json(silent=True) or {}
            file_path_req = payload.get("file_path") or r"C:\hackathon\data\datasets\PhiUSIIL_Phishing_URL_Dataset.csv"
            if not os.path.exists(file_path_req):
                return jsonify({
                    "error": f"File not found at specified path: {file_path_req}",
                    "code": "FILE_NOT_FOUND"
                }), 404
            file_to_process = file_path_req
            orig_filename = os.path.basename(file_path_req)

        result = validate_and_import_csv(
            file_path=file_to_process,
            organization_id=g.org_id,
            original_filename=orig_filename
        )

        log_audit_event(
            "dataset.import",
            "dataset",
            result["dataset_id"],
            {"filename": result["filename"], "total_rows": result["total_rows"]}
        )

        return jsonify({
            "message": "Dataset processed and imported successfully",
            "dataset": result
        }), 200

    except ValueError as ve:
        return jsonify({"error": str(ve), "code": "INVALID_DATASET"}), 400
    except Exception as e:
        app.logger.error(f"Dataset import error: {e}", exc_info=True)
        return jsonify({"error": f"Dataset import failed: {str(e)}", "code": "IMPORT_ERROR"}), 500


@app.route('/api/datasets/<dataset_id>', methods=['GET'])
def get_dataset(dataset_id):
    """Retrieves dataset metadata and cleaning report."""
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    ds = g.db.query(Dataset).filter(
        Dataset.id == dataset_id,
        Dataset.organization_id == g.org_id
    ).first()

    if not ds:
        return jsonify({"error": "Dataset not found or access denied.", "code": "NOT_FOUND"}), 404

    cleaning_report = {}
    try:
        cleaning_report = json.loads(ds.cleaning_report_json) if ds.cleaning_report_json else {}
    except Exception:
        pass

    return jsonify({
        "id": ds.id,
        "name": ds.name,
        "filename": ds.filename,
        "file_hash": ds.file_hash,
        "total_rows": ds.total_rows,
        "accepted_rows": ds.accepted_rows,
        "rejected_rows": ds.rejected_rows,
        "duplicate_rows": ds.duplicate_rows,
        "conflicting_rows": ds.conflicting_rows,
        "legitimate_count": ds.legitimate_count,
        "phishing_count": ds.phishing_count,
        "cleaning_report": cleaning_report,
        "created_at": ds.created_at.isoformat() if ds.created_at else None
    })


@app.route('/api/datasets/<dataset_id>/preview', methods=['GET'])
def get_dataset_preview_route(dataset_id):
    """Returns paginated preview of clean dataset rows."""
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    page_size = min(max(page_size, 1), 100)

    try:
        preview = get_dataset_preview(
            dataset_id=dataset_id,
            organization_id=g.org_id,
            page=page,
            page_size=page_size
        )
        return jsonify(preview)
    except ValueError as ve:
        return jsonify({"error": str(ve), "code": "NOT_FOUND"}), 404
    except Exception as e:
        app.logger.error(f"Error fetching dataset preview: {e}")
        return jsonify({"error": "Failed to fetch dataset preview.", "code": "PREVIEW_ERROR"}), 500


@app.route('/api/models/phishing/train', methods=['POST'])
@validate_csrf
@require_permission("brand:update")
def train_phishing_model():
    """
    Triggers asynchronous background training on the imported dataset.
    Compares Logistic Regression baseline and HistGradientBoosting.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    payload = request.get_json(silent=True) or {}
    dataset_id = payload.get("dataset_id")

    try:
        job = start_training_job(
            organization_id=g.org_id,
            dataset_id=dataset_id
        )
        log_audit_event("model.train", "ml_training_job", job["job_id"], {"stage": job["stage"]})
        return jsonify(job), 202
    except ValueError as ve:
        return jsonify({"error": str(ve), "code": "TRAIN_PRECONDITION_FAILED"}), 400
    except Exception as e:
        app.logger.error(f"Failed to initiate training: {e}", exc_info=True)
        return jsonify({"error": f"Failed to start training: {str(e)}", "code": "TRAIN_ERROR"}), 500


@app.route('/api/models/phishing/jobs/<job_id>', methods=['GET'])
def get_training_job(job_id):
    """Returns training job progress, stages, and metrics."""
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    try:
        status = get_job_status(job_id=job_id, organization_id=g.org_id)
        return jsonify(status)
    except ValueError as ve:
        return jsonify({"error": str(ve), "code": "JOB_NOT_FOUND"}), 404
    except Exception as e:
        app.logger.error(f"Error querying job {job_id}: {e}")
        return jsonify({"error": "Failed to query job status.", "code": "JOB_ERROR"}), 500


@app.route('/api/models/phishing/status', methods=['GET'])
def get_phishing_model_status():
    """Returns the current active model status, active version, and test metrics."""
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    info = get_active_model_info(organization_id=g.org_id)
    return jsonify(info)


@app.route('/api/scan/url', methods=['POST'])
@validate_csrf
@require_permission("scan:run")
def scan_website_url():
    """
    Evaluates a website URL for brand identity and phishing risk.
    Features are extracted strictly from URL string.
    Official identity and phishing assessment remain independent.
    """
    auth_err = check_production_auth()
    if auth_err:
        return auth_err
    if getattr(g, "org_access_denied", False):
        return jsonify({"error": "Forbidden: Tenant access denied.", "code": "ORGANIZATION_ACCESS_DENIED"}), 403

    payload = request.get_json(silent=True) or {}
    raw_url = (payload.get("url") or "").strip()
    brand_id = payload.get("brand_id")

    if not raw_url:
        return jsonify({"error": "Please enter a valid website URL to analyze.", "code": "EMPTY_URL"}), 400

    # Validate URL structure and scheme
    try:
        norm_url = normalize_url(raw_url)
        parsed = urlparse(norm_url)
        if not parsed.scheme or not parsed.hostname:
            return jsonify({
                "error": "Invalid website URL format. Please enter a full URL (e.g. https://example.com/login).",
                "code": "INVALID_URL"
            }), 400

        if parsed.scheme.lower() not in ("http", "https"):
            return jsonify({
                "error": f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS URLs are supported.",
                "code": "UNSUPPORTED_PROTOCOL"
            }), 400

        submitted_host = parsed.hostname.lower()
    except Exception as e:
        return jsonify({"error": f"Malformed URL: {str(e)}", "code": "MALFORMED_URL"}), 400

    # 1. Independent Official Identity Verification
    official_assets = []
    if brand_id:
        assets_query = g.db.query(OfficialAsset).filter(
            OfficialAsset.organization_id == g.org_id,
            OfficialAsset.brand_id == brand_id
        ).all()
        official_assets = [
            {
                "id": a.id,
                "identifier": a.exact_identifier,
                "domain": a.exact_identifier,
                "label": a.display_name or a.exact_identifier,
                "asset_type": a.asset_type
            }
            for a in assets_query
        ]

    identity_res = verify_official_identity(
        url=norm_url,
        brand_id=brand_id,
        official_assets=official_assets
    )

    # 2. Independent Phishing Assessment via Active ML Model
    active_artifact = g.db.query(MLModelArtifact).filter(
        MLModelArtifact.organization_id == g.org_id,
        MLModelArtifact.is_active == True
    ).first()

    if not active_artifact:
        phishing_res = {
            "status": "Unable to assess",
            "probability": None,
            "threshold": 0.5,
            "description": "No trained phishing model is currently active. Please train a model in Data Sources."
        }
        model_version = None
    else:
        try:
            bundle = load_cached_model_bundle(active_artifact.artifact_path, active_artifact.model_version)
            phishing_res = predict_url_risk(norm_url, bundle)
            model_version = active_artifact.model_version
        except Exception as e:
            app.logger.error(f"Inference failure: {e}", exc_info=True)
            phishing_res = {
                "status": "Unable to assess",
                "probability": None,
                "threshold": 0.5,
                "description": f"Model inference error: {str(e)}"
            }
            model_version = active_artifact.model_version

    # 3. Check Platform Limitation (e.g. YouTube, Telegram, Instagram, App Store links)
    limitation_note = get_platform_limitation_note(norm_url)

    # 4. Save scan record in database
    try:
        url_scan = URLScan(
            organization_id=g.org_id,
            brand_id=brand_id,
            url=norm_url,
            parsed_domain=submitted_host,
            identity_verdict=identity_res["status"],
            identity_details_json=json.dumps(identity_res),
            phishing_verdict=phishing_res["status"],
            phishing_score=phishing_res.get("probability"),
            model_version=model_version,
            created_at=datetime.utcnow()
        )
        g.db.add(url_scan)
        g.db.commit()

        log_audit_event(
            "url.scan",
            "url_scan",
            url_scan.id,
            {"url": norm_url, "identity": identity_res["status"], "phishing": phishing_res["status"]}
        )
    except Exception as se:
        app.logger.warning(f"Failed to record URL scan in DB: {se}")

    return jsonify({
        "url": norm_url,
        "domain": submitted_host,
        "identity": identity_res,
        "phishing": phishing_res,
        "model_version": model_version,
        "disclaimer": "A phishing prediction does not establish official identity.",
        "limitation_note": limitation_note
    }), 200

if __name__ == "__main__":
    app.run(host=app_config.host, port=app_config.port, debug=False)

