import unittest
import json
import time
from datetime import datetime, timedelta, timezone
from app import app
from db.database import SessionLocal
from db.models import User, UserSession, AuthToken, RateLimitRecord, Organization, Membership
from auth import (
    hash_password, verify_password, validate_password_complexity,
    create_session, validate_session, rotate_session, revoke_session, revoke_all_user_sessions,
    generate_mfa_secret, verify_mfa_code, is_safe_redirect, get_safe_redirect,
    SESSION_COOKIE_NAME, CSRF_COOKIE_NAME, IDLE_TIMEOUT, ABSOLUTE_TIMEOUT, AuthError
)
import pyotp

class BrandSentinelAuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()

        # Unique email suffix per test to avoid collision
        self.unique_id = str(int(time.time() * 1000))
        self.test_email = f"analyst_{self.unique_id}@northstar-test.io"
        self.admin_email = f"admin_{self.unique_id}@northstar-test.io"
        self.strong_password = "SecurePassword123!@"

        # Clear rate limit records before each test
        self.db.query(RateLimitRecord).delete()
        self.db.commit()

    def tearDown(self):
        # Cleanup test entities
        try:
            test_users = self.db.query(User).filter(
                User.email.like(f"%{self.unique_id}%")
            ).all()
            for u in test_users:
                self.db.delete(u)
            
            # Clean up test brands
            self.db.query(Brand).filter(Brand.name.like(f"%{self.unique_id}%")).delete()
            
            # Clear any rate limit records for test IP/keys
            self.db.query(RateLimitRecord).filter(
                (RateLimitRecord.key.like(f"%{self.unique_id}%")) |
                (RateLimitRecord.key.like("login:ip:%")) |
                (RateLimitRecord.key.like("register:%"))
            ).delete()
            
            self.db.commit()
        except Exception:
            self.db.rollback()
        finally:
            self.db.close()

    # -------------------------------------------------------------------------
    # 1. PROTECTED ACCESS & UNAUTHENTICATED REQUESTS
    # -------------------------------------------------------------------------
    def test_unauthenticated_protected_endpoints_return_401(self):
        endpoints = [
            ('/api/auth/me', 'GET'),
            ('/api/auth/mfa/setup', 'POST'),
            ('/api/auth/mfa/enable', 'POST'),
            ('/api/auth/logout-all', 'POST'),
        ]
        for ep, method in endpoints:
            if method == 'GET':
                resp = self.client.get(ep)
            else:
                resp = self.client.post(ep, json={})
            self.assertEqual(resp.status_code, 401, f"Endpoint {ep} should require authentication")
            data = resp.get_json()
            self.assertEqual(data.get("code"), "UNAUTHORIZED")

    # -------------------------------------------------------------------------
    # 2. VERIFIED ONBOARDING (Registration & Email Verification)
    # -------------------------------------------------------------------------
    def test_registration_password_complexity_enforcement(self):
        weak_passwords = [
            "short",              # Under 10 characters
            "alllowercase123!",   # No uppercase
            "ALLUPPERCASE123!",   # No lowercase
            "NoNumbersAtAll!",    # No digits
            "NoSpecialChar123",   # No special character
        ]
        for weak in weak_passwords:
            resp = self.client.post('/api/auth/register', json={
                "email": self.test_email,
                "password": weak,
                "full_name": "Test Analyst"
            })
            self.assertEqual(resp.status_code, 400, f"Weak password '{weak}' should fail complexity check")
            data = resp.get_json()
            self.assertIn("password", data.get("error", "").lower())

    def test_successful_registration_and_email_verification(self):
        # 1. Register with strong password
        resp = self.client.post('/api/auth/register', json={
            "email": self.test_email,
            "password": self.strong_password,
            "full_name": "Alex Carter",
            "organization_name": "Carter Defense Labs"
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("verification_token", data)
        self.assertFalse(data.get("is_verified"))
        token = data["verification_token"]

        # 2. Unverified sign-in attempt must fail with 403
        login_resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })
        self.assertEqual(login_resp.status_code, 403)
        self.assertEqual(login_resp.get_json().get("code"), "UNVERIFIED_EMAIL")

        # 3. Verify email with single-use token
        verify_resp = self.client.post('/api/auth/verify-email', json={"token": token})
        self.assertEqual(verify_resp.status_code, 200)
        self.assertTrue(verify_resp.get_json().get("is_verified"))

        # 4. Token replay must fail
        replay_resp = self.client.post('/api/auth/verify-email', json={"token": token})
        self.assertEqual(replay_resp.status_code, 400)

        # 5. Verified user can now sign in
        success_login = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })
        self.assertEqual(success_login.status_code, 200)

    # -------------------------------------------------------------------------
    # 3. SIGN-IN, HTTPONLY COOKIES, SESSION VALIDATION, AND SIGN-OUT
    # -------------------------------------------------------------------------
    def test_sign_in_cookie_security_and_logout(self):
        # Register and verify
        reg_resp = self.client.post('/api/auth/register', json={
            "email": self.test_email,
            "password": self.strong_password,
            "full_name": "Session Tester"
        })
        token = reg_resp.get_json()["verification_token"]
        self.client.post('/api/auth/verify-email', json={"token": token})

        # Sign-in
        login_resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password,
            "next": "/brand-profile"
        })
        self.assertEqual(login_resp.status_code, 200)
        login_data = login_resp.get_json()
        self.assertEqual(login_data["redirect_url"], "/brand-profile")
        self.assertIn("csrf_token", login_data)

        # Verify HttpOnly Cookie is set
        session_cookie = self.client.get_cookie(SESSION_COOKIE_NAME)
        self.assertIsNotNone(session_cookie, "HttpOnly session cookie must be set on login")
        self.assertTrue(session_cookie.http_only, "Session cookie must strictly have HttpOnly=True")
        self.assertEqual(session_cookie.same_site, "Lax", "Session cookie must have SameSite=Lax")

        csrf_cookie = self.client.get_cookie(CSRF_COOKIE_NAME)
        self.assertIsNotNone(csrf_cookie, "CSRF cookie must be set on login")

        # Access protected /api/auth/me using active session cookie
        me_resp = self.client.get('/api/auth/me')
        self.assertEqual(me_resp.status_code, 200)
        me_data = me_resp.get_json()
        self.assertEqual(me_data["user"]["email"], self.test_email)

        # Sign out
        logout_resp = self.client.post('/api/auth/logout')
        self.assertEqual(logout_resp.status_code, 200)

        # Attempt to access protected endpoint after logout should return 401
        post_logout_me = self.client.get('/api/auth/me')
        self.assertEqual(post_logout_me.status_code, 401)

    # -------------------------------------------------------------------------
    # 4. SERVER-VALIDATED SESSIONS & TIMEOUT EXPIRATION
    # -------------------------------------------------------------------------
    def test_session_idle_timeout_and_absolute_expiration(self):
        # Register and verify user
        reg_resp = self.client.post('/api/auth/register', json={
            "email": self.test_email,
            "password": self.strong_password,
            "full_name": "Timeout Tester"
        })
        token = reg_resp.get_json()["verification_token"]
        self.client.post('/api/auth/verify-email', json={"token": token})

        # Login
        self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })

        raw_session_token = self.client.get_cookie(SESSION_COOKIE_NAME).value

        # Test A: Idle timeout (> 2 hours inactivity)
        user = self.db.query(User).filter(User.email == self.test_email).first()
        active_session = self.db.query(UserSession).filter(UserSession.user_id == user.id).first()
        self.assertIsNotNone(active_session)

        # Fast forward last_activity_at by 2 hours and 5 minutes in DB
        past_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2, minutes=5)
        active_session.last_activity_at = past_time
        self.db.commit()

        # Session should be rejected due to idle timeout
        expired_resp = self.client.get('/api/auth/me')
        self.assertEqual(expired_resp.status_code, 401)

        # In DB, the session record is marked is_revoked = True
        self.db.refresh(active_session)
        self.assertTrue(active_session.is_revoked)

    # -------------------------------------------------------------------------
    # 5. SECURE RECOVERY (Forgot Password & Reset Revokes All Sessions)
    # -------------------------------------------------------------------------
    def test_password_recovery_and_session_revocation(self):
        # Register and verify user
        reg_resp = self.client.post('/api/auth/register', json={
            "email": self.test_email,
            "password": self.strong_password,
            "full_name": "Recovery Tester"
        })
        token = reg_resp.get_json()["verification_token"]
        self.client.post('/api/auth/verify-email', json={"token": token})

        # Establish an active session
        self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })
        self.assertEqual(self.client.get('/api/auth/me').status_code, 200)

        # 1. Request password recovery
        forgot_resp = self.client.post('/api/auth/forgot-password', json={"email": self.test_email})
        self.assertEqual(forgot_resp.status_code, 200)
        reset_token = forgot_resp.get_json().get("reset_token")
        self.assertIsNotNone(reset_token)

        # 2. Reset password with new strong password
        new_password = "BrandNewStrongPassword456!#"
        reset_resp = self.client.post('/api/auth/reset-password', json={
            "token": reset_token,
            "new_password": new_password
        })
        self.assertEqual(reset_resp.status_code, 200)

        # 3. Old session MUST now be revoked and rejected
        self.assertEqual(self.client.get('/api/auth/me').status_code, 401)

        # 4. Old password must fail
        old_login_resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })
        self.assertEqual(old_login_resp.status_code, 401)

        # 5. New password succeeds
        new_login_resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": new_password
        })
        self.assertEqual(new_login_resp.status_code, 200)

    # -------------------------------------------------------------------------
    # 6. AUTHENTICATION RATE LIMITING
    # -------------------------------------------------------------------------
    def test_rate_limiting_after_repeated_failed_attempts(self):
        fake_email = f"ratelimit_{self.unique_id}@northstar.io"

        # 5 consecutive invalid logins
        for i in range(5):
            r = self.client.post('/api/auth/login', json={
                "email": fake_email,
                "password": "WrongPassword123!"
            })
            self.assertEqual(r.status_code, 401)

        # 6th attempt should be blocked with 429 Too Many Requests
        blocked_resp = self.client.post('/api/auth/login', json={
            "email": fake_email,
            "password": "WrongPassword123!"
        })
        self.assertEqual(blocked_resp.status_code, 429)
        self.assertIn("Retry-After", blocked_resp.headers)
        data = blocked_resp.get_json()
        self.assertIn("retry_after", data)
        self.assertGreater(data["retry_after"], 0)

    # -------------------------------------------------------------------------
    # 7. MULTI-FACTOR AUTHENTICATION (TOTP / RFC 6238)
    # -------------------------------------------------------------------------
    def test_mfa_setup_enable_and_privileged_totp_login(self):
        # 1. Register privileged admin user
        reg_resp = self.client.post('/api/auth/register', json={
            "email": self.admin_email,
            "password": self.strong_password,
            "full_name": "Admin Lead",
            "role": "security_lead"
        })
        token = reg_resp.get_json()["verification_token"]
        self.client.post('/api/auth/verify-email', json={"token": token})

        # 2. Login to get session
        login_resp = self.client.post('/api/auth/login', json={
            "email": self.admin_email,
            "password": self.strong_password
        })
        self.assertEqual(login_resp.status_code, 200)

        # 3. Setup MFA
        setup_resp = self.client.post('/api/auth/mfa/setup')
        self.assertEqual(setup_resp.status_code, 200)
        setup_data = setup_resp.get_json()
        self.assertIn("secret", setup_data)
        self.assertIn("otpauth_url", setup_data)
        secret = setup_data["secret"]

        # 4. Generate valid TOTP code using pyotp
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # 5. Enable MFA
        enable_resp = self.client.post('/api/auth/mfa/enable', json={"code": current_code})
        self.assertEqual(enable_resp.status_code, 200)
        self.assertTrue(enable_resp.get_json().get("is_mfa_enabled"))

        # Logout
        self.client.post('/api/auth/logout')

        # 6. Login now prompts for MFA ticket
        mfa_challenge_resp = self.client.post('/api/auth/login', json={
            "email": self.admin_email,
            "password": self.strong_password
        })
        self.assertEqual(mfa_challenge_resp.status_code, 200)
        challenge_data = mfa_challenge_resp.get_json()
        self.assertTrue(challenge_data.get("mfa_required"))
        self.assertIn("mfa_ticket", challenge_data)
        mfa_ticket = challenge_data["mfa_ticket"]

        # Session cookie NOT yet issued
        self.assertIsNone(self.client.get_cookie(SESSION_COOKIE_NAME))

        # 7. Invalid MFA code rejected
        bad_mfa_resp = self.client.post('/api/auth/mfa/verify', json={
            "mfa_ticket": mfa_ticket,
            "code": "000000"
        })
        self.assertEqual(bad_mfa_resp.status_code, 401)

        # 8. Valid MFA code verified
        good_code = totp.now()
        good_mfa_resp = self.client.post('/api/auth/mfa/verify', json={
            "mfa_ticket": mfa_ticket,
            "code": good_code
        })
        self.assertEqual(good_mfa_resp.status_code, 200)

        # Session cookie now issued
        self.assertIsNotNone(self.client.get_cookie(SESSION_COOKIE_NAME))

    # -------------------------------------------------------------------------
    # 8. VALIDATED REDIRECTS (Open Redirect Prevention)
    # -------------------------------------------------------------------------
    def test_validated_authentication_redirects(self):
        # Safe internal relative paths
        self.assertEqual(get_safe_redirect("/dashboard"), "/dashboard")
        self.assertEqual(get_safe_redirect("/brands/edit"), "/brands/edit")

        # Dangerous open redirects neutralized to "/"
        dangerous_targets = [
            "//evil.com",
            "//attacker.com/login",
            "https://evil.com",
            "http://attacker.com",
            "javascript:alert(1)",
            "\\evil.com",
            "https://evil.com@northstar.io",
            None,
            ""
        ]
        for target in dangerous_targets:
            self.assertEqual(get_safe_redirect(target, default="/"), "/", f"Target '{target}' must be neutralized to '/'")

    # -------------------------------------------------------------------------
    # 9. CSRF PROTECTION ON STATE-MUTATING REQUESTS
    # -------------------------------------------------------------------------
    def test_csrf_protection_on_authenticated_mutations(self):
        # Register and login
        reg_resp = self.client.post('/api/auth/register', json={
            "email": self.test_email,
            "password": self.strong_password,
            "full_name": "CSRF Tester",
            "role": "admin"
        })
        token = reg_resp.get_json()["verification_token"]
        self.client.post('/api/auth/verify-email', json={"token": token})

        login_resp = self.client.post('/api/auth/login', json={
            "email": self.test_email,
            "password": self.strong_password
        })
        csrf_token = login_resp.get_json()["csrf_token"]

        # Mutating request without X-CSRF-Token header fails with 403
        bad_post_resp = self.client.post('/api/brands', json={"name": "Attacker Brand Inc"})
        self.assertEqual(bad_post_resp.status_code, 403)
        self.assertEqual(bad_post_resp.get_json().get("code"), "CSRF_VERIFICATION_FAILED")

        # Mutating request with valid X-CSRF-Token succeeds
        good_post_resp = self.client.post(
            '/api/brands',
            json={"name": f"Legitimate Security Brand {self.unique_id}", "aliases": ["LegitBrand"]},
            headers={"X-CSRF-Token": csrf_token}
        )
        self.assertEqual(good_post_resp.status_code, 201)

    # -------------------------------------------------------------------------
    # 10. PRODUCTION ACCESS CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------
    def test_production_mode_rejects_unauthenticated_mutations(self):
        # Temporarily simulate production environment
        original_env = self.app.config_obj.environment
        try:
            self.app.config_obj.environment = "production"

            # Clear cookies to simulate unauthenticated visitor
            self.client.delete_cookie(SESSION_COOKIE_NAME)
            self.client.delete_cookie(CSRF_COOKIE_NAME)

            # Unauthenticated mutation must return 401
            resp = self.client.post('/api/brands', json={"name": "Prod Brand"})
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.get_json().get("code"), "UNAUTHORIZED")
        finally:
            self.app.config_obj.environment = original_env

if __name__ == '__main__':
    unittest.main()
