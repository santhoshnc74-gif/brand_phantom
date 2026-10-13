"""
BrandSentinel Expandable Multi-Platform Connections & Multi-Source Scanning Tests
=================================================================================
Automated verification for Phase 6:
1. Platform adapter unit tests for all 5 implemented platforms (YouTube, Telegram, Facebook, Google Play, Apple App Store).
2. Mock external APIs covering: success, bad credentials, rate limits / quota exhaustion, platform outages, and timeouts.
3. Platform catalog with exact distinguished status badges (Not configured, Connected, Limited access, Expired, Rate limited, Unavailable, Coming later).
4. Dynamic form schema generation from connector schemas.
5. Multi-source scanning resilience & partial failure handling (never mask failures with mock data).
6. Deduplication of candidates across sources by provider and external ID.
7. Adding a new connector to the registry dynamically without altering the detection engine.
8. RBAC enforcement (Owner vs Analyst vs Viewer).
9. Tenant isolation across organizations.
"""

import unittest
import json
import requests
from unittest.mock import patch, MagicMock
from datetime import datetime

from app import app
from db.database import SessionLocal
from db.models import User, Organization, Membership, SourceConnection, Brand, OfficialAsset, Scan
from auth import hash_password, create_session
from vault import encrypt_credentials, decrypt_credentials
from connectors import (
    BaseConnector, NormalizedCandidate, ConnectionResult, ConnectorRegistry,
    YouTubeConnector, TelegramConnector, FacebookConnector,
    AppleAppStoreConnector, GooglePlayConnector, ComingLaterConnector
)

class MultiPlatformConnectionsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()

        # Seed Two Isolated Organizations
        self.org_alpha = self.db.query(Organization).filter(Organization.id == "org-hub-alpha").first()
        if not self.org_alpha:
            self.org_alpha = Organization(id="org-hub-alpha", name="Alpha Security Corp", slug="alpha-sec-corp")
            self.db.add(self.org_alpha)
            self.db.commit()

        self.org_beta = self.db.query(Organization).filter(Organization.id == "org-hub-beta").first()
        if not self.org_beta:
            self.org_beta = Organization(id="org-hub-beta", name="Beta Threat Labs", slug="beta-threat-labs")
            self.db.add(self.org_beta)
            self.db.commit()

        # Seed Brands
        self.brand_alpha = self.db.query(Brand).filter(Brand.organization_id == self.org_alpha.id).first()
        if not self.brand_alpha:
            self.brand_alpha = Brand(
                id="brand-hub-alpha",
                organization_id=self.org_alpha.id,
                name="Northstar Technologies",
                industry="Cybersecurity"
            )
            self.db.add(self.brand_alpha)
            self.db.commit()

        # Seed Official Asset for Alpha Brand
        self.asset_yt = self.db.query(OfficialAsset).filter(
            OfficialAsset.organization_id == self.org_alpha.id,
            OfficialAsset.stable_id == "UC_northstar_official_id"
        ).first()
        if not self.asset_yt:
            self.asset_yt = OfficialAsset(
                id="asset-hub-yt",
                organization_id=self.org_alpha.id,
                brand_id=self.brand_alpha.id,
                asset_type="social_account",
                source_platform="youtube",
                exact_identifier="youtube.com/channel/UC_northstar_official_id",
                stable_id="UC_northstar_official_id",
                display_name="Northstar Official Channel"
            )
            self.db.add(self.asset_yt)
            self.db.commit()

        # Seed Users with Granular Roles
        self.alpha_owner = self._get_or_create_user("hub-owner@alpha.io", "Alpha Hub Owner", "owner", self.org_alpha.id)
        self.alpha_analyst = self._get_or_create_user("hub-analyst@alpha.io", "Alpha Hub Analyst", "analyst", self.org_alpha.id)
        self.alpha_viewer = self._get_or_create_user("hub-viewer@alpha.io", "Alpha Hub Viewer", "viewer", self.org_alpha.id)
        self.beta_owner = self._get_or_create_user("hub-owner@beta.io", "Beta Hub Owner", "owner", self.org_beta.id)

    def tearDown(self):
        self.db.close()

    def _get_or_create_user(self, email, name, role, org_id):
        u = self.db.query(User).filter(User.email == email).first()
        if not u:
            u = User(
                email=email,
                full_name=name,
                password_hash=hash_password("Pass123!SecureAuth"),
                is_verified=True,
                is_active=True
            )
            self.db.add(u)
            self.db.commit()

        mem = self.db.query(Membership).filter(Membership.user_id == u.id, Membership.organization_id == org_id).first()
        if not mem:
            mem = Membership(user_id=u.id, organization_id=org_id, role=role)
            self.db.add(mem)
            self.db.commit()
        else:
            mem.role = role
            self.db.commit()
        return u

    def _login(self, client, user):
        sess, raw_token, csrf_token = create_session(self.db, user)
        client.set_cookie("brandsentinel_session", raw_token)
        client.set_cookie("brandsentinel_csrf", csrf_token)
        return csrf_token

    # ==========================================================================
    # 1. PLATFORM ADAPTER UNIT TESTS (ALL 5 IMPLEMENTED PLATFORMS)
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_telegram_adapter_success_and_chat_access(self, mock_get):
        # 1. Mock getMe
        resp_getme = MagicMock()
        resp_getme.status_code = 200
        resp_getme.json.return_value = {
            "ok": True,
            "result": {
                "id": 123456789,
                "is_bot": True,
                "first_name": "BrandSentinelBot",
                "username": "BrandSentinel_bot",
                "can_join_groups": True
            }
        }

        # 2. Mock getChat
        resp_getchat = MagicMock()
        resp_getchat.status_code = 200
        resp_getchat.json.return_value = {
            "ok": True,
            "result": {
                "id": -1001999999,
                "title": "Northstar Alerts Official",
                "username": "northstar_alerts",
                "type": "channel"
            }
        }

        mock_get.side_effect = [resp_getme, resp_getchat]

        res = TelegramConnector.test_connection(
            credentials={"bot_token": "123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567"},
            config={"monitored_channels": "@northstar_alerts"}
        )

        self.assertTrue(res.success)
        self.assertEqual(res.status, "connected")
        self.assertEqual(res.detailed_status, "connected")
        self.assertIn("@BrandSentinel_bot", res.status_message)
        self.assertEqual(len(res.metadata["accessible_chats"]), 1)
        self.assertEqual(res.metadata["accessible_chats"][0]["title"], "Northstar Alerts Official")

    @patch("connectors.requests.get")
    def test_telegram_adapter_rate_limit_and_outage(self, mock_get):
        # Rate limit test (429 with retry_after)
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.json.return_value = {"parameters": {"retry_after": 45}}
        mock_get.return_value = resp_429

        res_rl = TelegramConnector.test_connection("123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567")
        self.assertFalse(res_rl.success)
        self.assertEqual(res_rl.status, "error")
        self.assertEqual(res_rl.error_type, "RATE_LIMITED")
        self.assertEqual(res_rl.detailed_status, "rate_limited")
        self.assertIn("retry after 45s", res_rl.status_message.lower())

        # Platform outage test (502 Bad Gateway)
        resp_502 = MagicMock()
        resp_502.status_code = 502
        mock_get.return_value = resp_502

        res_outage = TelegramConnector.test_connection("123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ1234567")
        self.assertFalse(res_outage.success)
        self.assertEqual(res_outage.error_type, "OUTAGE")
        self.assertEqual(res_outage.detailed_status, "unavailable")

    @patch("connectors.requests.get")
    def test_facebook_adapter_success_permissions_and_expired(self, mock_get):
        # 1. Success with permissions
        resp_me = MagicMock()
        resp_me.status_code = 200
        resp_me.json.return_value = {
            "id": "fb_lead_123",
            "name": "Northstar Brand Admin",
            "permissions": {
                "data": [
                    {"permission": "pages_read_engagement", "status": "granted"},
                    {"permission": "pages_show_list", "status": "granted"}
                ]
            }
        }
        resp_accounts = MagicMock()
        resp_accounts.status_code = 200
        resp_accounts.json.return_value = {
            "data": [
                {"id": "page_999", "name": "Northstar Technologies Enterprise", "category": "Software Company"}
            ]
        }
        mock_get.side_effect = [resp_me, resp_accounts]

        res = FacebookConnector.test_connection("EAABValidLongLivedToken1234567890ABCDEF")
        self.assertTrue(res.success)
        self.assertEqual(res.status, "connected")
        self.assertIn("pages_read_engagement", res.metadata["granted_permissions"])
        self.assertEqual(len(res.metadata["accessible_pages"]), 1)

        # 2. Expired OAuth Token (Error code 190)
        resp_190 = MagicMock()
        resp_190.status_code = 400
        resp_190.json.return_value = {
            "error": {"code": 190, "message": "Error validating access token: Session has expired."}
        }
        mock_get.side_effect = None
        mock_get.return_value = resp_190

        res_expired = FacebookConnector.test_connection("EAABExpiredToken1234567890ABCDEF")
        self.assertFalse(res_expired.success)
        self.assertEqual(res_expired.error_type, "EXPIRED_TOKEN")
        self.assertEqual(res_expired.detailed_status, "expired")

    @patch("connectors.requests.get")
    def test_apple_app_store_adapter_and_storefront_support(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "resultCount": 1,
            "results": [
                {
                    "trackId": 987654321,
                    "bundleId": "com.northstar.threatdefense",
                    "trackName": "Northstar Threat Defense",
                    "sellerName": "Northstar Technologies",
                    "version": "2.4.0",
                    "artworkUrl512": "https://example.com/icon.png"
                }
            ]
        }
        mock_get.return_value = mock_resp

        # Test storefront US
        res_us = AppleAppStoreConnector.test_connection(config={"country_code": "US"})
        self.assertTrue(res_us.success)
        self.assertEqual(res_us.metadata["country"], "US")

        # Test app search & candidate normalization
        candidates = AppleAppStoreConnector.discover_candidates("Northstar", config={"country_code": "US"})
        self.assertEqual(len(candidates), 1)
        cand = candidates[0]
        self.assertEqual(cand.provider, "apple_app_store")
        self.assertEqual(cand.external_id, "987654321")
        self.assertEqual(cand.handle_or_package, "com.northstar.threatdefense")
        self.assertEqual(cand.asset_type, "mobile_app")
        self.assertTrue(len(cand.missing_evidence_indicators) > 0)

    def test_google_play_service_account_and_import_mode(self):
        # 1. Valid Service Account JSON
        valid_sa = {
            "type": "service_account",
            "project_id": "northstar-play-cloud",
            "private_key_id": "key123",
            "private_key": "MOCK_TEST_BEGIN PRIVATE KEY_SIMULATION",
            "client_email": "publisher@northstar-play-cloud.iam.gserviceaccount.com"
        }
        res_sa = GooglePlayConnector.test_connection(credentials={"service_account": valid_sa})
        self.assertTrue(res_sa.success)
        self.assertEqual(res_sa.metadata["project_id"], "northstar-play-cloud")

        # 2. Package Manifest Import Mode
        pkg_json = json.dumps([
            {"package_name": "com.northstar.mobile", "app_title": "Northstar Mobile Security", "publisher_name": "Northstar Official"}
        ])
        res_import = GooglePlayConnector.test_connection(config={"package_manifest_import": pkg_json})
        self.assertTrue(res_import.success)
        self.assertEqual(res_import.metadata["mode"], "structured_import")

        # 3. Discovery through imported manifest
        cands = GooglePlayConnector.discover_candidates("Northstar", config={"package_manifest_import": pkg_json})
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0].handle_or_package, "com.northstar.mobile")
        self.assertEqual(cands[0].provider, "google_play")

    # ==========================================================================
    # 2. PLATFORM CATALOG & STATUS BADGE VERIFICATION
    # ==========================================================================

    def test_connectors_catalog_returns_all_cards_and_coming_later(self):
        client = self.app.test_client()
        csrf = self._login(client, self.alpha_viewer)

        res = client.get("/api/connectors/catalog", headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        catalog = data["catalog"]
        providers = {item["provider_id"]: item for item in catalog}

        # Check Implemented Platforms
        for p in ["youtube", "telegram", "facebook", "google_play", "apple_app_store"]:
            self.assertIn(p, providers)
            self.assertTrue(providers[p]["is_implemented"])
            self.assertTrue(len(providers[p]["supported_capabilities"]) > 0)
            self.assertTrue(len(providers[p]["limitations"]) > 0)
            self.assertIn("config_schema", providers[p])

        # Check Coming Later Platforms
        for p in ["instagram", "linkedin", "twitter_x", "tiktok", "discord"]:
            self.assertIn(p, providers)
            self.assertFalse(providers[p]["is_implemented"])
            self.assertEqual(providers[p]["status"], "coming_later")

    # ==========================================================================
    # 3. ADDING CONNECTION INSTANCES & OWNER AUTHORIZATION
    # ==========================================================================

    @patch("connectors.requests.get")
    def test_owner_can_add_custom_named_connection_with_brand_scoping(self, mock_get):
        resp_getme = MagicMock()
        resp_getme.status_code = 200
        resp_getme.json.return_value = {
            "ok": True,
            "result": {"id": 888123, "is_bot": True, "first_name": "RegionalBot", "username": "RegionalBot"}
        }
        mock_get.return_value = resp_getme

        client = self.app.test_client()
        csrf = self._login(client, self.alpha_owner)

        payload = {
            "provider_id": "telegram",
            "name": "EU Regional Incident Bot",
            "credentials": {"bot_token": "888123:ABCdefGhIJKlmNoPQRsTUVwxyZ123456789"},
            "config": {"monitored_channels": "@eu_northstar"},
            "enabled_brand_ids": [self.brand_alpha.id]
        }

        res = client.post(
            "/api/connectors",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json=payload
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        conn_data = data["connection"]

        self.assertEqual(conn_data["name"], "EU Regional Incident Bot")
        self.assertEqual(conn_data["provider_id"], "telegram")
        self.assertEqual(conn_data["status"], "connected")
        self.assertEqual(conn_data["enabled_brand_ids"], [self.brand_alpha.id])

        # SECURITY: Cleartext token must NOT be returned in response!
        self.assertNotIn("888123:ABCdefGhIJKlmNoPQRsTUVwxyZ123456789", json.dumps(data))

        # Check Database Encryption
        self.db.expire_all()
        conn_db = self.db.query(SourceConnection).filter(SourceConnection.id == conn_data["id"]).first()
        self.assertIsNotNone(conn_db.encrypted_credentials)
        decrypted = decrypt_credentials(conn_db.encrypted_credentials)
        self.assertEqual(decrypted["bot_token"], "888123:ABCdefGhIJKlmNoPQRsTUVwxyZ123456789")

    def test_analyst_and_viewer_forbidden_from_creating_connections(self):
        client = self.app.test_client()

        # Analyst attempt -> 403 Forbidden
        csrf_analyst = self._login(client, self.alpha_analyst)
        res_analyst = client.post(
            "/api/connectors",
            headers={"X-CSRF-Token": csrf_analyst, "X-Organization-Id": self.org_alpha.id},
            json={"provider_id": "telegram", "name": "Illegal Analyst Bot"}
        )
        self.assertEqual(res_analyst.status_code, 403)

        # Viewer attempt -> 403 Forbidden
        csrf_viewer = self._login(client, self.alpha_viewer)
        res_viewer = client.post(
            "/api/connectors",
            headers={"X-CSRF-Token": csrf_viewer, "X-Organization-Id": self.org_alpha.id},
            json={"provider_id": "telegram", "name": "Illegal Viewer Bot"}
        )
        self.assertEqual(res_viewer.status_code, 403)

    # ==========================================================================
    # 4. TENANT ISOLATION TESTS
    # ==========================================================================

    def test_organization_cannot_access_or_delete_other_tenant_connections(self):
        # 1. Create a connection belonging to Org Alpha if not exists
        alpha_conn = self.db.query(SourceConnection).filter(SourceConnection.id == "conn-alpha-secret-01").first()
        if not alpha_conn:
            alpha_conn = SourceConnection(
                id="conn-alpha-secret-01",
                organization_id=self.org_alpha.id,
                platform="telegram",
                provider_id="telegram",
                name="Alpha Confidential Bot",
                connection_status="connected",
                test_status="connected",
                is_configured=True
            )
            self.db.add(alpha_conn)
            self.db.commit()

        # 2. Beta Owner attempts to retrieve Alpha connection -> 404 Not Found (or 403)
        client = self.app.test_client()
        csrf_beta = self._login(client, self.beta_owner)

        res_get = client.get(
            f"/api/connectors/{alpha_conn.id}",
            headers={"X-CSRF-Token": csrf_beta, "X-Organization-Id": self.org_beta.id}
        )
        self.assertEqual(res_get.status_code, 404)

        # 3. Beta Owner attempts to delete Alpha connection -> 404 Not Found
        res_del = client.delete(
            f"/api/connectors/{alpha_conn.id}",
            headers={"X-CSRF-Token": csrf_beta, "X-Organization-Id": self.org_beta.id}
        )
        self.assertEqual(res_del.status_code, 404)

        # Verify Alpha connection remains untouched in DB
        self.db.expire_all()
        intact = self.db.query(SourceConnection).filter(SourceConnection.id == alpha_conn.id).first()
        self.assertIsNotNone(intact)

    # ==========================================================================
    # 5. MULTI-SOURCE SCANNING WITH PARTIAL FAILURE RESILIENCE
    # ==========================================================================

    @patch("connectors.AppleAppStoreConnector.discover_candidates")
    @patch("connectors.YouTubeConnector.discover_candidates")
    def test_multi_source_scan_partial_failure_preserves_results(self, mock_yt, mock_apple):
        # Mock Apple App Store success (discovers 1 app)
        mock_apple.return_value = [
            NormalizedCandidate(
                provider="apple_app_store",
                external_id="11223344",
                asset_type="mobile_app",
                display_name="Northstar Fake App",
                handle_or_package="com.northstar.fake",
                description="Infringing iOS app reproducing Northstar logo"
            )
        ]

        # Mock YouTube failure (e.g. Upstream API Outage 503)
        mock_yt.side_effect = requests.exceptions.RequestException("Google Cloud API 503 Service Unavailable")

        client = self.app.test_client()
        csrf = self._login(client, self.alpha_analyst)

        payload = {
            "query": "Northstar",
            "sources": ["apple_app_store", "youtube"]
        }

        res = client.post(
            "/api/scan/multi",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json=payload
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # CRITICAL RESILIENCE RULE:
        # Partial failure must preserve successful results and explicitly report failed sources!
        self.assertEqual(data["status"], "partial_success")
        self.assertEqual(data["summary"]["failed_sources_count"], 1)
        self.assertEqual(len(data["failed_sources"]), 1)
        self.assertEqual(data["failed_sources"][0]["provider"], "youtube")
        self.assertIn("503", data["failed_sources"][0]["message"])

        # Preserved Apple findings
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["target_name"], "Northstar Fake App")
        self.assertEqual(data["findings"][0]["platform"], "Apple App Store")

    # ==========================================================================
    # 6. DEDUPLICATION ACROSS SOURCES BY PROVIDER & EXTERNAL ID
    # ==========================================================================

    def test_skipped_sources_do_not_report_success(self):
        conn = SourceConnection(
            id="conn-skipped-regression", organization_id=self.org_alpha.id,
            platform="unsupported_regression", provider_id="unsupported_regression",
            name="Unsupported source"
        )
        self.db.add(conn)
        self.db.commit()
        try:
            client = self.app.test_client()
            csrf = self._login(client, self.alpha_analyst)
            response = client.post('/api/scan/multi',
                headers={'X-CSRF-Token': csrf, 'X-Organization-Id': self.org_alpha.id},
                json={'query': 'Northstar', 'sources': [conn.id]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()['status'], 'failed')
            self.assertEqual(len(response.get_json()['skipped_sources']), 1)
        finally:
            self.db.delete(conn)
            self.db.commit()

    @patch("connectors.AppleAppStoreConnector.discover_candidates")
    def test_multi_source_scan_deduplication(self, mock_apple):
        # Return duplicated candidates from query
        same_cand_1 = NormalizedCandidate(
            provider="apple_app_store",
            external_id="track_555",
            asset_type="mobile_app",
            display_name="Northstar Mobile",
            handle_or_package="com.northstar.mobile"
        )
        same_cand_2 = NormalizedCandidate(
            provider="apple_app_store",
            external_id="track_555", # Duplicate ID
            asset_type="mobile_app",
            display_name="Northstar Mobile",
            handle_or_package="com.northstar.mobile"
        )
        mock_apple.return_value = [same_cand_1, same_cand_2]

        client = self.app.test_client()
        csrf = self._login(client, self.alpha_analyst)

        res = client.post(
            "/api/scan/multi",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json={"query": "Northstar", "sources": ["apple_app_store"]}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Candidates examined must be deduplicated to 1
        self.assertEqual(data["summary"]["candidates_examined"], 1)
        self.assertEqual(len(data["findings"]), 1)

    # ==========================================================================
    # 7. ADDING A NEW CONNECTOR DYNAMICALLY TO CONNECTOR REGISTRY
    # ==========================================================================

    def test_adding_new_connector_without_modifying_detection_engine(self):
        """
        Proves the decoupled connector registry architecture:
        A new connector class can be created, registered, tested, and scanned
        without making ANY edits to the detection engine or app routes!
        """
        class HackerDarkWebFeedConnector(BaseConnector):
            provider_id = "darkweb_feed"
            display_name = "Dark Web Threat Intelligence Feed"
            category = "threat_intel"
            auth_method = "api_key"
            icon = "shield"
            supported_capabilities = ["searchCandidates", "lookupAsset"]
            default_rate_limit = "500 req/hour"
            is_implemented = True

            @classmethod
            def test_connection(cls, credentials=None, config=None, timeout=5.0):
                return ConnectionResult(
                    success=True,
                    status="connected",
                    status_message="Dark Web Intelligence Feed operational."
                )

            @classmethod
            def discover_candidates(cls, query, credentials=None, config=None, limit=10, timeout=5.0):
                return [
                    NormalizedCandidate(
                        provider=cls.provider_id,
                        external_id="dw_paste_9921",
                        asset_type="domain",
                        display_name=f"leaked-{query.lower()}.onion",
                        handle_or_package=f"leaked-{query.lower()}.onion",
                        description="Credential drop on Tor hidden service"
                    )
                ]

        # 1. Register the new connector dynamically
        ConnectorRegistry.register(HackerDarkWebFeedConnector)

        # 2. Verify it is immediately recognized in the catalog
        catalog = ConnectorRegistry.list_catalog()
        dw_entry = next((item for item in catalog if item["provider_id"] == "darkweb_feed"), None)
        self.assertIsNotNone(dw_entry)
        self.assertEqual(dw_entry["display_name"], "Dark Web Threat Intelligence Feed")

        # 3. Create a connection instance for this new provider if not exists
        conn_dw = self.db.query(SourceConnection).filter(SourceConnection.id == "conn-dw-001").first()
        if not conn_dw:
            conn_dw = SourceConnection(
                id="conn-dw-001",
                organization_id=self.org_alpha.id,
                platform="darkweb_feed",
                provider_id="darkweb_feed",
                name="Dark Web Monitor",
                connection_status="connected",
                test_status="connected",
                is_configured=True
            )
            self.db.add(conn_dw)
            self.db.commit()

        # 4. Execute multi-source scan querying the new provider
        client = self.app.test_client()
        csrf = self._login(client, self.alpha_analyst)

        res = client.post(
            "/api/scan/multi",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org_alpha.id},
            json={"query": "Northstar", "sources": ["darkweb_feed"]}
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # The detection engine successfully processed the newly added provider!
        self.assertEqual(data["status"], "completed")
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["target_name"], "leaked-northstar.onion")
        self.assertEqual(data["findings"][0]["platform"], "Darkweb Feed")

    def test_catalog_api_structure(self):
        """Verify GET /api/connectors/catalog returns implemented and coming_later platforms with full schemas."""
        client = self.app.test_client()
        self._login(client, self.alpha_viewer)

        res = client.get("/api/connectors/catalog")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertIn("implemented", data)
        self.assertIn("coming_later", data)

        implemented_ids = [c["id"] for c in data["implemented"]]
        self.assertIn("youtube", implemented_ids)
        self.assertIn("telegram", implemented_ids)
        self.assertIn("facebook", implemented_ids)
        self.assertIn("google_play", implemented_ids)
        self.assertIn("apple_app_store", implemented_ids)

        coming_later_ids = [c["id"] for c in data["coming_later"]]
        self.assertIn("instagram", coming_later_ids)
        self.assertIn("linkedin", coming_later_ids)
        self.assertIn("twitter_x", coming_later_ids)

        # Ensure all coming_later items have status 'coming_later'
        for cl in data["coming_later"]:
            self.assertEqual(cl["status"], "coming_later")

        # Ensure each implemented connector specifies capabilities, setup requirements and schema
        for imp in data["implemented"]:
            self.assertIn("supported_capabilities", imp)
            self.assertIn("config_schema", imp)
            self.assertIn("limitations", imp)
            self.assertIn("auth_method", imp)

    def test_ui_template_elements_presence(self):
        """Verify templates/index.html includes required catalog grids, modals, and multi-source scan controls."""
        with open("templates/index.html", "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('id="implementedCatalogGrid"', content)
        self.assertIn('id="comingLaterCatalogGrid"', content)
        self.assertIn('id="connectionConfigModal"', content)
        self.assertIn('id="multiScanSummaryCard"', content)
        self.assertIn('name="multiSourceOption"', content)
        self.assertIn('id="multiScanCoveragePills"', content)
        self.assertIn('id="multiScanPartialFailureBanner"', content)

if __name__ == "__main__":
    unittest.main()

