import json
import unittest
from unittest.mock import patch

from app import app
from db.database import SessionLocal
from db.models import User, Organization, Membership, Brand, OfficialAsset, SourceConnection, Detection


class BrandCreationAndISLWorkflowTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = app.test_client()
        self.db = SessionLocal()

        # Retrieve or verify fictional Northstar org and security lead user
        self.org = self.db.query(Organization).filter(Organization.slug == "northstar-tech").first()
        self.user = self.db.query(User).filter(User.email == "security@northstar-tech.io").first()

        # Ensure active session with cookies
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user.id
            sess["org_id"] = self.org.id

        # Set cookies for auth and CSRF
        self.client.set_cookie("brandsentinel_session", "session-token-valid")
        self.client.set_cookie("brandsentinel_csrf", "csrf-token-valid")
        self.csrf_headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": "csrf-token-valid"
        }

    def tearDown(self):
        self.db.close()

    def test_existing_brands_and_records_remain_intact(self):
        """1. Verify Northstar Technologies, Northstar Athletics, Northstar FinTech and records remain intact."""
        northstar_tech = self.db.query(Brand).filter(Brand.id == "brand-northstar-tech").first()
        self.assertIsNotNone(northstar_tech)
        self.assertEqual(northstar_tech.name, "Northstar Technologies")

        tech_assets = self.db.query(OfficialAsset).filter(OfficialAsset.brand_id == northstar_tech.id).count()
        self.assertGreaterEqual(tech_assets, 6)

        northstar_athletics = self.db.query(Brand).filter(Brand.id == "brand-northstar-athletics").first()
        self.assertIsNotNone(northstar_athletics)
        self.assertEqual(northstar_athletics.name, "Northstar Athletics")

        northstar_fintech = self.db.query(Brand).filter(Brand.id == "brand-northstar-fintech").first()
        self.assertIsNotNone(northstar_fintech)
        self.assertEqual(northstar_fintech.name, "Northstar FinTech")

    def test_mg_isl_brand_duplicate_handling(self):
        """2. Verify duplicate creation returns existing record without creating duplicate rows."""
        # Query brand count before
        count_before = self.db.query(Brand).filter(
            Brand.organization_id == self.org.id,
            Brand.name == "MG Indian Super League"
        ).count()
        self.assertGreaterEqual(count_before, 1)

        # Attempt to create duplicate with identical name
        res = self.client.post("/api/brands", json={
            "name": "MG Indian Super League",
            "aliases": ["ISL", "Indian Super League"]
        }, headers=self.csrf_headers)

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("already_exists"))
        self.assertEqual(data["brand"]["name"], "MG Indian Super League")

        # Attempt with different case
        res_case = self.client.post("/api/brands", json={
            "name": "mg indian super league"
        }, headers=self.csrf_headers)
        self.assertEqual(res_case.status_code, 200)
        self.assertTrue(res_case.get_json().get("already_exists"))

        # Verify no duplicate was added
        count_after = self.db.query(Brand).filter(
            Brand.organization_id == self.org.id,
            Brand.name == "MG Indian Super League"
        ).count()
        self.assertEqual(count_before, count_after)

    def test_dropdown_and_api_data_selection(self):
        """3. Verify brand appears in available_brands list and can be selected via /api/data."""
        res = self.client.get("/api/data")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        available = data.get("available_brands", [])
        brand_names = [b["name"] for b in available]
        self.assertIn("MG Indian Super League", brand_names)
        self.assertIn("Northstar Technologies", brand_names)

        # Check explicitly requesting brand_id
        isl_brand = self.db.query(Brand).filter(
            Brand.organization_id == self.org.id,
            Brand.name == "MG Indian Super League"
        ).first()
        self.assertIsNotNone(isl_brand)

        res_sel = self.client.get(f"/api/data?brand_id={isl_brand.id}")
        self.assertEqual(res_sel.status_code, 200)
        sel_data = res_sel.get_json()
        self.assertEqual(sel_data["current_brand"]["id"], isl_brand.id)
        self.assertEqual(sel_data["current_brand"]["name"], "MG Indian Super League")

    def test_official_youtube_channel_registration_and_verification(self):
        """4. Verify registering official YouTube account via Official Social Accounts workflow and exact verification."""
        isl_brand = self.db.query(Brand).filter(
            Brand.organization_id == self.org.id,
            Brand.name == "MG Indian Super League"
        ).first()
        self.assertIsNotNone(isl_brand)

        # Clean any prior test asset for idempotency
        prior_assets = self.db.query(OfficialAsset).filter(
            OfficialAsset.brand_id == isl_brand.id,
            OfficialAsset.source_platform == "youtube"
        ).all()
        for a in prior_assets:
            self.db.delete(a)
        self.db.commit()

        # Step A: Before registration, verification returns Inconclusive
        with patch("connectors.YouTubeConnector.resolve_exact_channel") as mock_resolve:
            mock_resolve.return_value = {
                "success": True,
                "channel": {
                    "channel_id": "UC_ISL_OFFICIAL_STABLE_999",
                    "title": "Indian Super League Official",
                    "custom_url": "@indiansuperleague",
                    "description": "Official YouTube channel of the Indian Super League."
                }
            }

            res_unreg = self.client.post("/api/verify/youtube", json={
                "identifier": "@indiansuperleague",
                "brand_id": isl_brand.id
            }, headers=self.csrf_headers)
            self.assertEqual(res_unreg.status_code, 200)
            self.assertEqual(res_unreg.get_json()["verification"]["verdict"], "Inconclusive")

        # Step B: Register official YouTube channel using the existing workflow
        res_add = self.client.post(f"/api/brands/{isl_brand.id}/assets", json={
            "asset_type": "social_account",
            "source_platform": "youtube",
            "handle": "@indiansuperleague",
            "stable_account_id": "UC_ISL_OFFICIAL_STABLE_999"
        }, headers=self.csrf_headers)
        self.assertEqual(res_add.status_code, 201)
        added_asset = res_add.get_json()["asset"]
        self.assertEqual(added_asset["source_platform"], "youtube")
        self.assertEqual(added_asset["exact_identifier"], "@indiansuperleague")
        self.assertEqual(added_asset["stable_id"], "UC_ISL_OFFICIAL_STABLE_999")

        # Step C: Exact verification with matching ID returns Official
        with patch("connectors.YouTubeConnector.resolve_exact_channel") as mock_resolve:
            mock_resolve.return_value = {
                "success": True,
                "channel": {
                    "channel_id": "UC_ISL_OFFICIAL_STABLE_999",
                    "title": "Indian Super League",
                    "custom_url": "@indiansuperleague",
                    "description": "Official YouTube channel of Indian Super League."
                }
            }

            res_ver = self.client.post("/api/verify/youtube", json={
                "identifier": "https://www.youtube.com/channel/UC_ISL_OFFICIAL_STABLE_999",
                "brand_id": isl_brand.id
            }, headers=self.csrf_headers)
            self.assertEqual(res_ver.status_code, 200)
            ver = res_ver.get_json()["verification"]
            self.assertEqual(ver["verdict"], "Official")
            self.assertEqual(ver["summary"], "Official — Channel ID matches the brand’s registered official account.")

        # Step D: Unrelated channel returns Unrelated
        with patch("connectors.YouTubeConnector.resolve_exact_channel") as mock_resolve:
            mock_resolve.return_value = {
                "success": True,
                "channel": {
                    "channel_id": "UC_UNRELATED_COOKING_888",
                    "title": "Grandma's Traditional Kitchen",
                    "custom_url": "@grandma_cooking",
                    "description": "Delicious recipes from around the world."
                }
            }

            res_unrel = self.client.post("/api/verify/youtube", json={
                "identifier": "@grandma_cooking",
                "brand_id": isl_brand.id
            }, headers=self.csrf_headers)
            self.assertEqual(res_unrel.status_code, 200)
            self.assertEqual(res_unrel.get_json()["verification"]["verdict"], "Unrelated")

        # Clean up test official asset to prevent test leakage
        clean_assets = self.db.query(OfficialAsset).filter(
            OfficialAsset.brand_id == isl_brand.id,
            OfficialAsset.source_platform == "youtube"
        ).all()
        for a in clean_assets:
            self.db.delete(a)
        self.db.commit()

    def test_youtube_api_connection_scope_reused_safely(self):
        """5. Check saved YouTube connection brand scope and ensure zero API key leakage."""
        yt_conn = self.db.query(SourceConnection).filter(
            SourceConnection.organization_id == self.org.id,
            SourceConnection.platform == "youtube"
        ).first()

        self.assertIsNotNone(yt_conn)
        self.assertTrue(yt_conn.is_configured)
        self.assertEqual(yt_conn.connection_status, "connected")

        # Brand scope check: empty list [] indicates universal access across all org brands
        brand_scopes = json.loads(yt_conn.enabled_brand_ids_json) if yt_conn.enabled_brand_ids_json else []
        self.assertEqual(brand_scopes, [])

        # Ensure API response from GET /api/data never exposes encrypted_credentials or secrets
        res = self.client.get("/api/data")
        data_str = res.get_data(as_text=True)
        self.assertNotIn("encrypted_credentials", data_str)
        self.assertNotIn("AIza", data_str)


if __name__ == "__main__":
    unittest.main()
