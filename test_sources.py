"""
BrandSentinel Source Connection, Credential Vault, and Provider Tests
=====================================================================
Tests:
1. Owner-authorized credential submission, replacement, and deletion.
2. Fernet vault encryption & database isolation.
3. Zero secret exposure in responses and audit trails.
4. Cross-organization credential tampering defense.
5. YouTube Data API v3 verification: success, invalid keys, quota limits, timeouts, outages.
6. Apple App Store iTunes catalog discovery.
7. Google Play developer package manifest import.
8. Unimplemented social platforms strictly marked unconfigured.
"""

import unittest
import json
import base64
from unittest.mock import patch, MagicMock
import requests

from app import app
from db.database import SessionLocal
from db.models import User, Organization, Membership, SourceConnection, AuditEvent
from auth import hash_password, create_session, set_auth_cookies
from vault import encrypt_credentials, decrypt_credentials, derive_vault_key
from connectors import (
    YouTubeConnector, AppleAppStoreConnector, GooglePlayConnector,
    ConnectionResult, CONNECTOR_CLIENTS
)

class SourceConnectionTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()

        # Seed two organizations for isolation tests
        self.org_alpha = self.db.query(Organization).filter(Organization.id == "org-source-alpha").first()
        if not self.org_alpha:
            self.org_alpha = Organization(id="org-source-alpha", name="Org Alpha Telemetry", slug="org-alpha-tel")
            self.db.add(self.org_alpha)
            self.db.commit()

        self.org_beta = self.db.query(Organization).filter(Organization.id == "org-source-beta").first()
        if not self.org_beta:
            self.org_beta = Organization(id="org-source-beta", name="Org Beta Telemetry", slug="org-beta-tel")
            self.db.add(self.org_beta)
            self.db.commit()

        # Create Users
        # 1. Alpha Owner
        self.user_alpha_owner = self._get_or_create_user("user-alpha-owner@test.io", "Alpha Owner", "owner", self.org_alpha.id)
        # 2. Alpha Analyst
        self.user_alpha_analyst = self._get_or_create_user("user-alpha-analyst@test.io", "Alpha Analyst", "analyst", self.org_alpha.id)
        # 3. Alpha Viewer
        self.user_alpha_viewer = self._get_or_create_user("user-alpha-viewer@test.io", "Alpha Viewer", "viewer", self.org_alpha.id)
        # 4. Beta Owner
        self.user_beta_owner = self._get_or_create_user("user-beta-owner@test.io", "Beta Owner", "owner", self.org_beta.id)

        # Ensure Source Connections exist for Org Alpha
        self.src_youtube = self._get_or_create_source(self.org_alpha.id, "youtube", "YouTube Data API v3")
        self.src_apple = self._get_or_create_source(self.org_alpha.id, "apple_app_store", "Apple App Store Connect")
        self.src_play = self._get_or_create_source(self.org_alpha.id, "google_play", "Google Play Developer API")
        self.src_ig = self._get_or_create_source(self.org_alpha.id, "instagram", "Instagram Graph API")

        # Ensure Source Connection exists for Org Beta
        self.src_beta_youtube = self._get_or_create_source(self.org_beta.id, "youtube", "YouTube Data API v3")

    def tearDown(self):
        self.db.close()

    def _get_or_create_user(self, email, name, role, org_id):
        user = self.db.query(User).filter(User.email == email).first()
        if not user:
            user = User(
                email=email,
                full_name=name,
                password_hash=hash_password("Complex@Pass123!"),
                is_verified=True,
                is_active=True
            )
            self.db.add(user)
            self.db.commit()

        mem = self.db.query(Membership).filter(Membership.user_id == user.id, Membership.organization_id == org_id).first()
        if not mem:
            mem = Membership(user_id=user.id, organization_id=org_id, role=role)
            self.db.add(mem)
            self.db.commit()
        else:
            mem.role = role
            self.db.commit()
        return user

    def _get_or_create_source(self, org_id, platform, name):
        s = self.db.query(SourceConnection).filter(
            SourceConnection.organization_id == org_id,
            SourceConnection.platform == platform
        ).first()
        if not s:
            s = SourceConnection(
                organization_id=org_id,
                platform=platform,
                name=name,
                connection_status="unconfigured",
                test_status="unconfigured",
                is_configured=False,
                status_message="Unconfigured"
            )
            self.db.add(s)
            self.db.commit()
        return s

    def _login(self, client, user):
        sess, raw_token, csrf_token = create_session(self.db, user)
        client.set_cookie("brandsentinel_session", raw_token)
        client.set_cookie("brandsentinel_csrf", csrf_token)
        return csrf_token

    # ==========================================================================
    # 1. OWNER AUTHORIZATION & CREDENTIAL ENCRYPTION TESTS
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_owner_can_save_and_encrypt_youtube_key(self, mock_get):
        # Mock successful YouTube API response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "youtube#videoListResponse", "items": [{"id": "123"}]}
        mock_get.return_value = mock_resp

        client = self.app.test_client()
        csrf = self._login(client, self.user_alpha_owner)

        raw_key = "AIzaSyD9876543210ABCDEF1234567890ABCDEF"
        payload = {"api_key": raw_key}

        res = client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json=payload
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Check response metadata
        self.assertTrue(data["source"]["is_configured"])
        self.assertTrue(data["source"]["connected"])
        self.assertEqual(data["source"]["status"], "Connected")
        self.assertEqual(data["source"]["key_source"], "org_supplied")

        # SECURITY RULE: Never return saved secret to the browser
        self.assertNotIn("api_key", data["source"])
        self.assertNotIn(raw_key, json.dumps(data))
        self.assertNotIn("encrypted_credentials", data["source"])

        # Check Database Record
        self.db.expire_all()
        src_db = self.db.query(SourceConnection).filter(SourceConnection.id == self.src_youtube.id).first()
        self.assertTrue(src_db.is_configured)
        self.assertIsNotNone(src_db.encrypted_credentials)
        # Cleartext key must NOT be stored in DB
        self.assertNotIn(raw_key, src_db.encrypted_credentials)

        # Decrypting via vault key should recover original key
        decrypted = decrypt_credentials(src_db.encrypted_credentials)
        self.assertEqual(decrypted.get("api_key"), raw_key)

    def test_non_owner_forbidden_from_managing_credentials(self):
        client = self.app.test_client()

        # Analyst Attempt
        csrf_analyst = self._login(client, self.user_alpha_analyst)
        res_analyst = client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf_analyst, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": "AIzaSyFakeKey123"}
        )
        self.assertEqual(res_analyst.status_code, 403)
        self.assertIn("FORBIDDEN", res_analyst.get_json().get("code", ""))

        # Viewer Attempt
        csrf_viewer = self._login(client, self.user_alpha_viewer)
        res_viewer = client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf_viewer, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": "AIzaSyFakeKey123"}
        )
        self.assertEqual(res_viewer.status_code, 403)

        # Unauthenticated Attempt
        anon_client = self.app.test_client()
        res_anon = anon_client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            json={"api_key": "AIzaSyFakeKey123"}
        )
        self.assertIn(res_anon.status_code, [401, 403])

    # ==========================================================================
    # 2. KEY ISOLATION & CROSS-TENANT DEFENSE
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_key_isolation_between_organizations(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "youtube#videoListResponse", "items": [{"id": "1"}]}
        mock_get.return_value = mock_resp

        # Org Alpha Owner configures credentials
        client_alpha = self.app.test_client()
        csrf_alpha = self._login(client_alpha, self.user_alpha_owner)
        client_alpha.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf_alpha, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": "AIzaSyAlphaSecretKey999"}
        )

        # Org Beta Owner attempts to access/modify Org Alpha's source connection
        client_beta = self.app.test_client()
        csrf_beta = self._login(client_beta, self.user_beta_owner)

        # Tampering attempt with Alpha's source ID from Beta session
        res_tamper = client_beta.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf_beta, "X-Organization-Id": self.org_beta.id},
            json={"api_key": "AIzaSyBetaAttackerKey"}
        )
        # Must return 404 NOT_FOUND due to strict organization scoping
        self.assertEqual(res_tamper.status_code, 404)

        # Org Beta's own source remains unconfigured
        self.db.expire_all()
        src_beta_db = self.db.query(SourceConnection).filter(SourceConnection.id == self.src_beta_youtube.id).first()
        self.assertFalse(src_beta_db.is_configured)
        self.assertIsNone(src_beta_db.encrypted_credentials)

    # ==========================================================================
    # 3. REPLACEMENT & DELETION WITHOUT REVEALING STORED KEYS
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_replacement_and_deletion_without_revealing_keys(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "youtube#videoListResponse", "items": [{"id": "1"}]}
        mock_get.return_value = mock_resp

        client = self.app.test_client()
        csrf = self._login(client, self.user_alpha_owner)

        # 1. Save initial key
        client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": "AIzaSyKeyInitial111"}
        )

        # 2. Replace with new key
        res_replace = client.put(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": "AIzaSyKeyReplacement222"}
        )
        self.assertEqual(res_replace.status_code, 200)
        replace_data = res_replace.get_json()
        self.assertNotIn("AIzaSyKeyInitial111", json.dumps(replace_data))
        self.assertNotIn("AIzaSyKeyReplacement222", json.dumps(replace_data))

        # Check DB reflects new key
        self.db.expire_all()
        src_db = self.db.query(SourceConnection).filter(SourceConnection.id == self.src_youtube.id).first()
        decrypted = decrypt_credentials(src_db.encrypted_credentials)
        self.assertEqual(decrypted.get("api_key"), "AIzaSyKeyReplacement222")

        # 3. Delete stored key
        res_del = client.delete(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id}
        )
        self.assertEqual(res_del.status_code, 200)
        del_data = res_del.get_json()
        self.assertFalse(del_data["source"]["is_configured"])
        self.assertEqual(del_data["source"]["status"], "Unconfigured")
        self.assertNotIn("AIzaSyKeyReplacement222", json.dumps(del_data))

        # DB check: credentials cleared
        self.db.expire_all()
        src_cleared = self.db.query(SourceConnection).filter(SourceConnection.id == self.src_youtube.id).first()
        self.assertFalse(src_cleared.is_configured)
        self.assertIsNone(src_cleared.encrypted_credentials)

    # ==========================================================================
    # 4. YOUTUBE API CONNECTION FAILURE HANDLING
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_youtube_invalid_credentials_returns_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.json.return_value = {
            "error": {
                "code": 400,
                "message": "API key not valid. Please pass a valid API key.",
                "errors": [{"reason": "keyInvalid"}]
            }
        }
        mock_get.return_value = mock_resp

        res = YouTubeConnector.test_connection("AIzaSyInvalidKey123456789")
        self.assertFalse(res.success)
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_type, "INVALID_CREDENTIALS")
        self.assertIn("Invalid YouTube API key", res.status_message)

    @patch("connectors.requests.get")
    def test_youtube_quota_exceeded_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {
                "code": 403,
                "message": "Quota exceeded.",
                "errors": [{"reason": "quotaExceeded"}]
            }
        }
        mock_get.return_value = mock_resp

        res = YouTubeConnector.test_connection("AIzaSyValidKeyExhaustedQuota123456")
        self.assertFalse(res.success)
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_type, "QUOTA_EXCEEDED")
        self.assertIn("quota limit exceeded", res.status_message.lower())

    @patch("connectors.requests.get")
    def test_youtube_api_not_enabled_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {
                "code": 403,
                "message": "Access Not Configured.",
                "errors": [{"reason": "accessNotConfigured"}]
            }
        }
        mock_get.return_value = mock_resp

        res = YouTubeConnector.test_connection("AIzaSyValidKeyUnenabledService123")
        self.assertFalse(res.success)
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_type, "API_NOT_ENABLED")
        self.assertIn("not enabled", res.status_message.lower())

    @patch("connectors.requests.get")
    def test_youtube_timeout_handling(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

        res = YouTubeConnector.test_connection("AIzaSyValidKeyTimingOut123456789")
        self.assertFalse(res.success)
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_type, "TIMEOUT")
        self.assertIn("timed out", res.status_message.lower())

    @patch("connectors.requests.get")
    def test_youtube_outage_handling(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        res = YouTubeConnector.test_connection("AIzaSyValidKeyProviderOutage12345")
        self.assertFalse(res.success)
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_type, "OUTAGE")
        self.assertIn("outage", res.status_message.lower())

    # ==========================================================================
    # 5. APPLE APP STORE CATALOG DISCOVERY
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_apple_app_store_discovery_via_itunes_api(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "resultCount": 1,
            "results": [{
                "trackId": 158932014,
                "bundleId": "com.northstar.security",
                "trackName": "Northstar Mobile Suite",
                "sellerName": "Northstar Technologies LLC",
                "version": "2.4.1",
                "artworkUrl512": "https://is1-ssl.mzstatic.com/image/thumb/icon.png",
                "averageUserRating": 4.8
            }]
        }
        mock_get.return_value = mock_resp

        # Test connection test
        conn_res = AppleAppStoreConnector.test_connection()
        self.assertTrue(conn_res.success)
        self.assertEqual(conn_res.status, "connected")

        # Test app discovery search
        apps = AppleAppStoreConnector.search_apps("northstar")
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["bundle_id"], "com.northstar.security")
        self.assertEqual(apps[0]["track_name"], "Northstar Mobile Suite")

    # ==========================================================================
    # 6. GOOGLE PLAY STRUCTURED IMPORT
    # ==========================================================================

    def test_google_play_developer_package_import(self):
        client = self.app.test_client()
        csrf = self._login(client, self.user_alpha_owner)

        payload = {
            "packages": [
                {
                    "package_name": "com.northstar.mobile",
                    "publisher_id": "pub-northstar-official-9021",
                    "version": "3.1.0"
                },
                {
                    "package_name": "com.northstar.authenticator",
                    "publisher_id": "pub-northstar-official-9021",
                    "version": "1.0.4"
                }
            ]
        }

        res = client.post(
            "/api/sources/google-play/import",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json=payload
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["imported_count"], 2)
        self.assertEqual(data["source"]["status"], "Connected")
        self.assertTrue(data["source"]["connected"])

        # Check DB
        self.db.expire_all()
        play_db = self.db.query(SourceConnection).filter(
            SourceConnection.platform == "google_play",
            SourceConnection.organization_id == self.org_alpha.id
        ).first()
        self.assertTrue(play_db.is_configured)
        self.assertEqual(play_db.test_status, "connected")
        manifest = json.loads(play_db.connection_metadata_json)
        self.assertEqual(len(manifest["imported_packages"]), 2)

    # ==========================================================================
    # 7. UNIMPLEMENTED SOCIAL PLATFORMS MARKED UNCONFIGURED
    # ==========================================================================

    def test_unimplemented_social_platforms_strictly_unconfigured(self):
        client = self.app.test_client()
        self._login(client, self.user_alpha_owner)

        res = client.get("/api/sources", headers={"X-Organization-Id": self.org_alpha.id})
        self.assertEqual(res.status_code, 200)
        sources = res.get_json()

        for s in sources:
            if s["platform"] in ["instagram", "twitter_x", "tiktok"]:
                # ZERO fabricated success: must be unconfigured
                self.assertFalse(s["connected"])
                self.assertNotEqual(s["status"], "Connected")
                self.assertIn("unconfigured", s["status"].lower())

    # ==========================================================================
    # 8. AUDIT LOG REDACTION
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_audit_logs_redact_credentials(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "youtube#videoListResponse", "items": [{"id": "1"}]}
        mock_get.return_value = mock_resp

        client = self.app.test_client()
        csrf = self._login(client, self.user_alpha_owner)

        secret_key = "AIzaSySuperSecretKeyToAudit987654"
        client.post(
            f"/api/sources/{self.src_youtube.id}/credentials",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json={"api_key": secret_key}
        )

        # Check AuditEvent table
        self.db.expire_all()
        event = self.db.query(AuditEvent).filter(
            AuditEvent.action == "source.credentials_save",
            AuditEvent.organization_id == self.org_alpha.id
        ).order_by(AuditEvent.created_at.desc()).first()

        self.assertIsNotNone(event)
        # Event details must NOT contain cleartext secret
        self.assertNotIn(secret_key, event.details_json)

if __name__ == "__main__":
    unittest.main()
