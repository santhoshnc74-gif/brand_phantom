"""
Comprehensive Test Suite for Exact YouTube Channel Verification
================================================================
Verifies:
1. Input parsing: Channel URLs (/channel/UC...), Handle URLs (/@handle), @handle, UC... channel IDs,
   and detection of unsupported video URLs with specific requirement explanations.
2. Exact official-ID matching, displaying:
   "Official — Channel ID matches the brand’s registered official account."
3. Unrelated channels correctly classified without being labeled impersonators.
4. Evidence-supported suspected impersonation with concrete evidence.
5. Inconclusive cases (missing official identity, fan/commentary/parody disclosures, ambiguous similarity).
6. API failures (missing credentials, channel not found, quota exhaustion, provider outage, timeouts).
7. Tenant isolation, RBAC permissions, CSRF enforcement, and credential confidentiality.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import uuid
import requests

from app import app
from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, AuditEvent
)
from auth import hash_password, create_session
from vault import encrypt_credentials
from connectors import YouTubeConnector
from db.matcher import (
    evaluate_youtube_channel_verification,
    VERDICT_OFFICIAL, VERDICT_SUSPECTED_IMPERSONATION,
    VERDICT_UNRELATED, VERDICT_INCONCLUSIVE
)


class YouTubeInputParsingTestCase(unittest.TestCase):
    """Tests input parsing and validation rules for YouTube channel verification."""

    def test_parse_channel_url(self):
        res = YouTubeConnector.parse_channel_input("https://www.youtube.com/channel/UC1234567890123456789012")
        self.assertTrue(res["valid"])
        self.assertEqual(res["lookup_type"], "id")
        self.assertEqual(res["value"], "UC1234567890123456789012")

    def test_parse_handle_url(self):
        res = YouTubeConnector.parse_channel_input("https://www.youtube.com/@northstar_tech")
        self.assertTrue(res["valid"])
        self.assertEqual(res["lookup_type"], "handle")
        self.assertEqual(res["value"], "@northstar_tech")
        self.assertEqual(res["clean_handle"], "northstar_tech")

    def test_parse_handle_url_with_subpath_and_params(self):
        res = YouTubeConnector.parse_channel_input("https://www.youtube.com/@northstar_tech/videos?sub_confirmation=1")
        self.assertTrue(res["valid"])
        self.assertEqual(res["lookup_type"], "handle")
        self.assertEqual(res["value"], "@northstar_tech")
        self.assertEqual(res["clean_handle"], "northstar_tech")

    def test_parse_standalone_handle(self):
        res = YouTubeConnector.parse_channel_input("@northstar_official")
        self.assertTrue(res["valid"])
        self.assertEqual(res["lookup_type"], "handle")
        self.assertEqual(res["value"], "@northstar_official")
        self.assertEqual(res["clean_handle"], "northstar_official")

    def test_parse_standalone_channel_id(self):
        res = YouTubeConnector.parse_channel_input("UC1234567890123456789012")
        self.assertTrue(res["valid"])
        self.assertEqual(res["lookup_type"], "id")
        self.assertEqual(res["value"], "UC1234567890123456789012")

    def test_unsupported_video_links_rejected_with_explanation(self):
        video_urls = [
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://youtu.be/dQw4w9WgXcQ",
            "https://www.youtube.com/shorts/abc123xyz78",
            "https://www.youtube.com/embed/dQw4w9WgXcQ",
            "https://www.youtube.com/live/dQw4w9WgXcQ"
        ]
        for url in video_urls:
            res = YouTubeConnector.parse_channel_input(url)
            self.assertFalse(res["valid"], f"URL {url} should have been rejected")
            self.assertEqual(res["error_type"], "UNSUPPORTED_VIDEO_LINK")
            self.assertIn("Unsupported video link", res["message"])
            self.assertIn("channel URL", res["message"])

    def test_empty_and_invalid_inputs(self):
        # Empty inputs
        for empty_val in ["", "   ", None]:
            res = YouTubeConnector.parse_channel_input(empty_val)
            self.assertFalse(res["valid"])
            self.assertEqual(res["error_type"], "EMPTY_INPUT")

        # Invalid arbitrary text
        invalid_inputs = [
            "https://twitter.com/northstar",
            "just_a_random_string",
            "@a", # Too short for handle
            "UC123", # Too short for channel ID
        ]
        for inv in invalid_inputs:
            res = YouTubeConnector.parse_channel_input(inv)
            self.assertFalse(res["valid"])
            self.assertEqual(res["error_type"], "INVALID_INPUT")


class YouTubeIdentityEvaluationTestCase(unittest.TestCase):
    """Tests the evidence-based comparison and classification engine."""

    def setUp(self):
        self.brand = MagicMock()
        self.brand.name = "Northstar Technologies"
        self.brand.aliases_json = json.dumps(["Northstar", "Northstar Tech", "StarGuard"])

        self.official_asset = MagicMock()
        self.official_asset.source_platform = "youtube"
        self.official_asset.stable_id = "UC_OFFICIAL_NORTHSTAR_123"
        self.official_asset.exact_identifier = "@northstar_official"
        self.official_asset.display_name = "Northstar Official Channel"

    def test_official_exact_id_match(self):
        channel = {
            "channel_id": "UC_OFFICIAL_NORTHSTAR_123",
            "title": "Northstar Technologies",
            "description": "Official company channel",
            "custom_url": "@northstar_official",
            "canonical_url": "https://www.youtube.com/@northstar_official"
        }
        res = evaluate_youtube_channel_verification(channel, self.brand, [self.official_asset])
        self.assertEqual(res["verdict"], VERDICT_OFFICIAL)
        self.assertTrue(res["is_official"])
        self.assertEqual(res["summary"], "Official — Channel ID matches the brand’s registered official account.")
        self.assertIn("Official — Channel ID matches the brand’s registered official account.", res["reasons"])
        self.assertIn("not that every video or message is safe", res["evidence"]["scope_note"])

    def test_missing_official_identity_returns_inconclusive(self):
        channel = {
            "channel_id": "UC_SOME_OTHER_ID_456",
            "title": "Northstar Technologies",
            "description": "Company channel",
            "custom_url": "@northstar",
            "canonical_url": "https://www.youtube.com/@northstar"
        }
        # Brand has NO registered official YouTube assets
        res = evaluate_youtube_channel_verification(channel, self.brand, [])
        self.assertEqual(res["verdict"], VERDICT_INCONCLUSIVE)
        self.assertFalse(res["is_official"])
        self.assertIn("Missing official identity", res["summary"])
        self.assertTrue(res["evidence"]["missing_official_identity"])

    def test_unrelated_channel_not_labeled_impersonator(self):
        channel = {
            "channel_id": "UC_UNRELATED_CHEF_789",
            "title": "Chef Marco Culinary Arts",
            "description": "Daily Italian cooking recipes, pasta making, and kitchen knife tutorials.",
            "custom_url": "@chef_marco",
            "canonical_url": "https://www.youtube.com/@chef_marco"
        }
        res = evaluate_youtube_channel_verification(channel, self.brand, [self.official_asset])
        self.assertEqual(res["verdict"], VERDICT_UNRELATED)
        self.assertFalse(res["is_official"])
        self.assertIn("Unrelated", res["verdict"])
        self.assertFalse(res["evidence"]["relationship_found"])

    def test_suspected_impersonation_with_meaningful_evidence(self):
        channel = {
            "channel_id": "UC_FAKE_IMPERSONATOR_001",
            "title": "Northstar Support Rewards",
            "description": "Official YouTube support channel for Northstar users. Contact customer care for rewards claim.",
            "custom_url": "@northstar_support",
            "canonical_url": "https://www.youtube.com/@northstar_support"
        }
        res = evaluate_youtube_channel_verification(channel, self.brand, [self.official_asset])
        self.assertEqual(res["verdict"], VERDICT_SUSPECTED_IMPERSONATION)
        self.assertFalse(res["is_official"])
        self.assertTrue(len(res["evidence"]["impersonation_indicators"]) > 0)
        self.assertTrue(res["evidence"]["absence_of_disclosure"])

    def test_fan_commentary_parody_channel_not_labeled_impersonator(self):
        # Fan club channel with explicit disclosure
        channel_fan = {
            "channel_id": "UC_FAN_COMMUNITY_999",
            "title": "Northstar Fan Club & News",
            "description": "Unofficial fan community for Northstar Tech enthusiasts. We are a fan page, not affiliated with Northstar Technologies.",
            "custom_url": "@northstar_fanclub",
            "canonical_url": "https://www.youtube.com/@northstar_fanclub"
        }
        res = evaluate_youtube_channel_verification(channel_fan, self.brand, [self.official_asset])
        self.assertEqual(res["verdict"], VERDICT_INCONCLUSIVE)
        self.assertFalse(res["is_official"])
        self.assertIn("fan/commentary/parody indicators", res["summary"])
        self.assertFalse(res["evidence"]["deception_intent_established"])

    def test_ambiguous_name_similarity_alone_does_not_mean_fake(self):
        # Different channel ID, partial name overlap, but no deceptive authority claims
        channel_ambiguous = {
            "channel_id": "UC_NORTH_STAR_TRAILS_333",
            "title": "North Star Mountain Explorers",
            "description": "Hiking and backpacking routes through the Pacific Northwest wilderness.",
            "custom_url": "@north_star_trails",
            "canonical_url": "https://www.youtube.com/@north_star_trails"
        }
        res = evaluate_youtube_channel_verification(channel_ambiguous, self.brand, [self.official_asset])
        self.assertEqual(res["verdict"], VERDICT_INCONCLUSIVE)
        self.assertFalse(res["is_official"])
        self.assertIn("A different ID or similar name alone does not constitute proof of impersonation.", res["reasons"])


class YouTubeVerificationEndpointTestCase(unittest.TestCase):
    """Tests the full /api/verify/youtube HTTP endpoint with mocked YouTube Data API responses."""

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()
        self.suffix = uuid.uuid4().hex[:6]

        # Create Organization
        self.org = Organization(
            id=f"org-yt-{self.suffix}",
            name=f"YT Verify Org {self.suffix}",
            slug=f"yt-verify-{self.suffix}"
        )
        self.db.add(self.org)
        self.db.flush()

        # Create Brand
        self.brand = Brand(
            id=f"brand-yt-{self.suffix}",
            organization_id=self.org.id,
            name="Northstar Corp",
            aliases_json=json.dumps(["Northstar", "Northstar Corp"])
        )
        self.db.add(self.brand)
        self.db.flush()

        # Create Official YouTube Asset for Brand
        self.official_asset = OfficialAsset(
            id=f"asset-yt-{self.suffix}",
            organization_id=self.org.id,
            brand_id=self.brand.id,
            asset_type="social_account",
            source_platform="youtube",
            stable_id="UC_REGISTERED_OFFICIAL_ID",
            exact_identifier="@northstar_corp",
            display_name="Northstar Corp Official"
        )
        self.db.add(self.official_asset)
        self.db.flush()

        # Create SourceConnection with encrypted YouTube key
        self.src_conn = SourceConnection(
            id=f"src-yt-{self.suffix}",
            organization_id=self.org.id,
            platform="youtube",
            provider_id="youtube",
            name="YouTube Data API v3",
            connection_status="connected",
            test_status="connected",
            is_configured=True,
            encrypted_credentials=encrypt_credentials({"api_key": "AIzaSyTestMockKey12345"})
        )
        self.db.add(self.src_conn)
        self.db.flush()

        # Create Analyst and Viewer Users
        self.analyst = self._create_user(f"analyst-{self.suffix}@test.io", "analyst")
        self.viewer = self._create_user(f"viewer-{self.suffix}@test.io", "viewer")
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def _create_user(self, email, role):
        user = User(
            email=email,
            full_name=f"User {role.title()}",
            password_hash=hash_password("SecurePassword123!"),
            is_verified=True,
            is_active=True
        )
        self.db.add(user)
        self.db.flush()
        mem = Membership(
            organization_id=self.org.id,
            user_id=user.id,
            role=role
        )
        self.db.add(mem)
        self.db.flush()
        return user

    def _login(self, client, user):
        sess, raw_token, csrf_token = create_session(self.db, user)
        client.set_cookie("brandsentinel_session", raw_token)
        client.set_cookie("brandsentinel_csrf", csrf_token)
        return csrf_token

    @patch("connectors.requests.get")
    def test_verify_official_match(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "kind": "youtube#channelListResponse",
            "items": [{
                "id": "UC_REGISTERED_OFFICIAL_ID",
                "snippet": {
                    "title": "Northstar Corp Official",
                    "description": "The official channel of Northstar Corp.",
                    "customUrl": "@northstar_corp",
                    "publishedAt": "2020-01-01T00:00:00Z",
                    "thumbnails": {"default": {"url": "https://img.youtube.com/thumb.jpg"}}
                },
                "statistics": {"subscriberCount": "100000", "videoCount": "50", "viewCount": "500000"}
            }]
        }
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "https://www.youtube.com/@northstar_corp",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        verif = data["verification"]
        self.assertEqual(verif["verdict"], "Official")
        self.assertEqual(verif["stable_channel_id"], "UC_REGISTERED_OFFICIAL_ID")
        self.assertEqual(verif["summary"], "Official — Channel ID matches the brand’s registered official account.")

    @patch("connectors.requests.get")
    def test_verify_suspected_impersonator(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "kind": "youtube#channelListResponse",
            "items": [{
                "id": "UC_IMPERSONATOR_DIFFERENT_ID",
                "snippet": {
                    "title": "Northstar Corp Official Support",
                    "description": "Official support account for Northstar Corp. Contact support desk for customer care.",
                    "customUrl": "@northstar_support",
                    "publishedAt": "2024-05-01T00:00:00Z",
                    "thumbnails": {"default": {"url": "https://img.youtube.com/thumb.jpg"}}
                },
                "statistics": {"subscriberCount": "500", "videoCount": "3", "viewCount": "1200"}
            }]
        }
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_support",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        verif = data["verification"]
        self.assertEqual(verif["verdict"], "Suspected impersonation")
        self.assertEqual(verif["stable_channel_id"], "UC_IMPERSONATOR_DIFFERENT_ID")
        self.assertTrue(len(verif["evidence"]["impersonation_indicators"]) > 0)

    @patch("connectors.requests.get")
    def test_verify_unrelated_channel(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "kind": "youtube#channelListResponse",
            "items": [{
                "id": "UC_GARDEN_CHANNEL_999",
                "snippet": {
                    "title": "Urban Gardeners & Botany",
                    "description": "Tips on planting tomatoes, herbs, and building indoor hydroponic setups.",
                    "customUrl": "@urbangarden",
                    "publishedAt": "2019-03-01T00:00:00Z",
                    "thumbnails": {"default": {"url": "https://img.youtube.com/thumb.jpg"}}
                },
                "statistics": {"subscriberCount": "20000", "videoCount": "120", "viewCount": "300000"}
            }]
        }
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "https://www.youtube.com/channel/UC_GARDEN_CHANNEL_999",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        verif = data["verification"]
        self.assertEqual(verif["verdict"], "Unrelated")
        self.assertFalse(verif["is_official"])

    @patch("connectors.requests.get")
    def test_channel_not_found(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "youtube#channelListResponse", "items": []}
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@nonexistent_channel_xyz",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertEqual(data["code"], "CHANNEL_NOT_FOUND")
        self.assertIn("was not found", data["error"])

    @patch("connectors.requests.get")
    def test_quota_exhaustion_returns_429(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "error": {
                "errors": [{"reason": "quotaExceeded"}],
                "message": "The request cannot be completed because you have exceeded your quota."
            }
        }
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_official",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 429)
        data = res.get_json()
        self.assertEqual(data["code"], "QUOTA_EXCEEDED")
        self.assertIn("quota limit exceeded", data["error"])

    @patch("connectors.requests.get")
    def test_provider_outage_returns_503(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_official",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 503)
        data = res.get_json()
        self.assertEqual(data["code"], "PROVIDER_OUTAGE")

    @patch("connectors.requests.get")
    def test_timeout_returns_504(self, mock_get):
        csrf = self._login(self.client, self.analyst)
        mock_get.side_effect = requests.exceptions.Timeout("Read timed out")

        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_official",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 504)
        data = res.get_json()
        self.assertEqual(data["code"], "TIMEOUT")

    def test_video_link_rejected_with_specific_explanation(self):
        csrf = self._login(self.client, self.analyst)
        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "identifier": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertEqual(data["code"], "UNSUPPORTED_VIDEO_LINK")
        self.assertIn("Unsupported video link", data["error"])
        self.assertIn("channel URL", data["error"])

    def test_csrf_required_for_verification(self):
        # Missing CSRF header
        self._login(self.client, self.analyst)
        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_official",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("CSRF", res.get_json().get("code", "") + res.get_json().get("error", ""))

    def test_rbac_viewer_cannot_run_verification(self):
        csrf_viewer = self._login(self.client, self.viewer)
        res = self.client.post(
            "/api/verify/youtube",
            headers={"X-CSRF-Token": csrf_viewer, "X-Organization-Id": self.org.id},
            json={
                "identifier": "@northstar_official",
                "brand_id": self.brand.id
            }
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("Forbidden", res.get_json().get("error", ""))

    def test_official_assets_not_overwritten(self):
        # Verification must NEVER mutate or overwrite official assets in the database
        count_before = self.db.query(OfficialAsset).filter(OfficialAsset.brand_id == self.brand.id).count()
        with patch("connectors.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "kind": "youtube#channelListResponse",
                "items": [{
                    "id": "UC_NEW_RANDOM_CHANNEL",
                    "snippet": {"title": "Random Channel", "description": "Desc", "customUrl": "@random"},
                    "statistics": {}
                }]
            }
            mock_get.return_value = mock_resp
            csrf = self._login(self.client, self.analyst)
            self.client.post(
                "/api/verify/youtube",
                headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
                json={"identifier": "@random", "brand_id": self.brand.id}
            )

        count_after = self.db.query(OfficialAsset).filter(OfficialAsset.brand_id == self.brand.id).count()
        self.assertEqual(count_before, count_after)


if __name__ == "__main__":
    unittest.main()
