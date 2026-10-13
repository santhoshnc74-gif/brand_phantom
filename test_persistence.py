import unittest
import json
from sqlalchemy import text
from app import app
from db.database import SessionLocal, engine
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, Scan, Candidate, Detection, Review, AuditEvent
)
from db.validators import (
    validate_brand_name, validate_aliases, validate_domain,
    validate_social_asset, validate_app_asset, validate_review_verdict,
    validate_org_scope, ValidationError
)
from db.matcher import (
    evaluate_candidate_identity,
    IDENTITY_VERIFIED_OFFICIAL,
    IDENTITY_UNAUTHORIZED_IMPERSONATOR,
    IDENTITY_SUSPICIOUS_CANDIDATE
)
from db.migrations.migrator import get_applied_migrations

class PersistenceAndValidationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # ==========================================
    # 1. DATABASE MIGRATIONS TESTS
    # ==========================================
    def test_database_migrations_applied(self):
        applied = get_applied_migrations()
        self.assertIn("v001_initial_schema", applied)
        self.assertIn("v002_add_publisher_indices", applied)
        self.assertIn("v003_add_auth_tables", applied)
        self.assertIn("v004_add_source_credentials", applied)

    def test_all_11_tables_exist(self):
        expected_tables = {
            "users", "organizations", "memberships", "brands", "official_assets",
            "source_connections", "scans", "candidates", "detections", "reviews",
            "audit_events", "schema_migrations"
        }
        with engine.connect() as conn:
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
            tables = {row[0] for row in result.fetchall()}
            for t in expected_tables:
                self.assertIn(t, tables, f"Expected table '{t}' was not found in database.")

    # ==========================================
    # 2. SERVER-SIDE VALIDATION TESTS
    # ==========================================
    def test_domain_validator(self):
        # Valid domains
        self.assertEqual(validate_domain("northstar-tech.io"), "northstar-tech.io")
        self.assertEqual(validate_domain("sub.northstar.com"), "sub.northstar.com")

        # Invalid domains with protocols or slashes
        with self.assertRaises(ValidationError) as cm:
            validate_domain("https://northstar.com")
        self.assertIn("http", cm.exception.message)

        with self.assertRaises(ValidationError):
            validate_domain("northstar.com/login")

        with self.assertRaises(ValidationError):
            validate_domain("invalid_domain")

    def test_social_asset_validator(self):
        # Valid social asset with stable ID
        p, h, s = validate_social_asset("instagram", "@northstar_tech", "ig_user_12345")
        self.assertEqual(p, "instagram")
        self.assertEqual(h, "@northstar_tech")
        self.assertEqual(s, "ig_user_12345")

        # Missing stable ID must fail
        with self.assertRaises(ValidationError) as cm:
            validate_social_asset("instagram", "@northstar_tech", "")
        self.assertIn("stable", cm.exception.message.lower())

        # Unsupported platform must fail
        with self.assertRaises(ValidationError):
            validate_social_asset("myspace", "@northstar", "stable_1")

    def test_app_asset_validator(self):
        # Valid Google Play package
        store, exact, stable, pub = validate_app_asset(
            "google_play", "com.northstar.mobile", "com.northstar.mobile", "pub-123"
        )
        self.assertEqual(store, "google_play")
        self.assertEqual(exact, "com.northstar.mobile")
        self.assertEqual(stable, "com.northstar.mobile")
        self.assertEqual(pub, "pub-123")

        # Invalid package syntax
        with self.assertRaises(ValidationError):
            validate_app_asset("google_play", "invalidpackage", "stable_1")

        # Valid Apple App Store ID
        store, exact, stable, _ = validate_app_asset("apple_app_store", "158932014", "158932014")
        self.assertEqual(exact, "158932014")

        # Invalid Apple ID (letters)
        with self.assertRaises(ValidationError):
            validate_app_asset("apple_app_store", "abc_invalid", "stable_1")

    def test_brand_validators(self):
        # Valid name and aliases
        name = validate_brand_name("Northstar Technologies")
        self.assertEqual(name, "Northstar Technologies")
        
        aliases = validate_aliases(["Northstar", "StarGuard"])
        self.assertEqual(len(aliases), 2)

        # Empty name must fail
        with self.assertRaises(ValidationError):
            validate_brand_name("")

        with self.assertRaises(ValidationError):
            validate_brand_name("   ")

    def test_org_scope_validator(self):
        # Matching org IDs pass
        validate_org_scope("org-1", "org-1")

        # Mismatched org IDs must fail
        with self.assertRaises(ValidationError) as cm:
            validate_org_scope("org-1", "org-2")
        self.assertIn("Cross-organization", cm.exception.message)

    # ==========================================
    # 3. EXACT IDENTITY MATCHING ENGINE TESTS
    # Rule: Never establish official identity from a similar name or logo alone.
    # ==========================================
    def test_identity_matching_rule_exact_stable_id(self):
        brand = self.db.query(Brand).filter(Brand.name == "Northstar Technologies").first()
        officials = self.db.query(OfficialAsset).filter(OfficialAsset.brand_id == brand.id).all()

        # Case A: Exact stable ID matches official Instagram asset
        result_official = evaluate_candidate_identity(
            source_platform="instagram",
            candidate_identifier="@northstar_tech",
            stable_source_id="ig_act_982348123", # Exact official stable ID
            display_name="Northstar Technologies",
            name_similarity_score=1.0,
            logo_similarity_score=1.0,
            official_assets=officials
        )
        self.assertEqual(result_official["identity_status"], IDENTITY_VERIFIED_OFFICIAL)
        self.assertTrue(result_official["is_official"])

        # Case B: High visual and name similarity (99%), but DIFFERENT stable ID
        # RULE: Never establish official identity from similar name or logo alone!
        result_impersonator = evaluate_candidate_identity(
            source_platform="instagram",
            candidate_identifier="@northstar_official_sale",
            stable_source_id="ig_fake_impersonator_9981", # Different stable ID
            display_name="Northstar Technologies Official",
            name_similarity_score=0.99,
            logo_similarity_score=0.99,
            official_assets=officials
        )
        self.assertEqual(result_impersonator["identity_status"], IDENTITY_UNAUTHORIZED_IMPERSONATOR)
        self.assertFalse(result_impersonator["is_official"])
        self.assertEqual(result_impersonator["recommended_verdict"], "flagged")

    def test_identity_matching_rule_app_store_trojan(self):
        brand = self.db.query(Brand).filter(Brand.name == "Northstar Technologies").first()
        officials = self.db.query(OfficialAsset).filter(OfficialAsset.brand_id == brand.id).all()

        # Trojan app: exact same title and icon, but different package name / publisher
        result_trojan = evaluate_candidate_identity(
            source_platform="google_play",
            candidate_identifier="com.fake.northstar.auth",
            stable_source_id="com.fake.northstar.auth",
            display_name="Northstar Mobile Security",
            publisher_identifier="pub-trojan-dev-11",
            name_similarity_score=1.0,
            logo_similarity_score=0.98,
            official_assets=officials
        )
        self.assertEqual(result_trojan["identity_status"], IDENTITY_UNAUTHORIZED_IMPERSONATOR)
        self.assertFalse(result_trojan["is_official"])
        self.assertEqual(result_trojan["risk_level"], "critical")

    # ==========================================
    # 4. SAMPLE DATA SEGREGATION TESTS
    # ==========================================
    def test_sample_data_segregation(self):
        # Querying with include_samples=false excludes sample brands
        resp_all = self.client.get("/api/brands?include_samples=true")
        self.assertEqual(resp_all.status_code, 200)
        data_all = resp_all.get_json()
        self.assertTrue(any(b["is_sample"] for b in data_all))

        resp_prod = self.client.get("/api/brands?include_samples=false")
        self.assertEqual(resp_prod.status_code, 200)
        data_prod = resp_prod.get_json()
        self.assertFalse(any(b["is_sample"] for b in data_prod))

    # ==========================================
    # 5. BRAND SETUP AND EDITING API TESTS
    # ==========================================
    def test_brand_crud_and_assets(self):
        # 1. Create a brand via API
        payload = {
            "name": "Northstar Enterprise Cloud",
            "aliases": ["Northstar Cloud", "NEC Security"],
            "industry": "Cloud Infrastructure",
            "is_sample": False
        }
        res_create = self.client.post("/api/brands", json=payload)
        self.assertEqual(res_create.status_code, 201)
        created_brand = res_create.get_json()["brand"]
        brand_id = created_brand["id"]

        # 2. Update brand aliases and name
        res_update = self.client.put(f"/api/brands/{brand_id}", json={
            "name": "Northstar Cloud Global",
            "aliases": ["Northstar Global", "NEC Cloud"]
        })
        self.assertEqual(res_update.status_code, 200)
        updated_brand = res_update.get_json()["brand"]
        self.assertEqual(updated_brand["name"], "Northstar Cloud Global")
        self.assertIn("NEC Cloud", updated_brand["aliases"])

        # 3. Add Official Domain
        res_dom = self.client.post(f"/api/brands/{brand_id}/assets", json={
            "asset_type": "domain",
            "domain": "cloud-northstar.io",
            "display_name": "Cloud Production Domain"
        })
        self.assertEqual(res_dom.status_code, 201)
        dom_asset = res_dom.get_json()["asset"]
        self.assertEqual(dom_asset["exact_identifier"], "cloud-northstar.io")

        # 4. Add Official Social Account with Stable ID
        res_soc = self.client.post(f"/api/brands/{brand_id}/assets", json={
            "asset_type": "social_account",
            "source_platform": "instagram",
            "handle": "@northstar_cloud",
            "stable_account_id": "ig_cloud_official_991823"
        })
        self.assertEqual(res_soc.status_code, 201)

        # 5. Add Official Mobile App with Package & Publisher
        res_app = self.client.post(f"/api/brands/{brand_id}/assets", json={
            "asset_type": "mobile_app",
            "source_platform": "google_play",
            "package_or_app_id": "io.northstar.cloud.app",
            "stable_app_id": "io.northstar.cloud.app",
            "authorized_publisher_id": "pub-northstar-cloud-primary"
        })
        self.assertEqual(res_app.status_code, 201)

        # 6. Verify brand details contain all 3 official assets
        res_get = self.client.get(f"/api/brands/{brand_id}")
        self.assertEqual(res_get.status_code, 200)
        brand_detail = res_get.get_json()
        self.assertEqual(len(brand_detail["official_assets"]), 3)

        # 7. Check Audit Events recorded
        res_audit = self.client.get("/api/audit")
        self.assertEqual(res_audit.status_code, 200)
        events = res_audit.get_json()["events"]
        actions = [e["action"] for e in events]
        self.assertIn("brand.create", actions)
        self.assertIn("brand.update", actions)
        self.assertIn("asset.create", actions)

    # ==========================================
    # 6. CROSS-ORGANIZATION SCOPING TESTS
    # ==========================================
    def test_organization_scoping_isolation(self):
        # Create or fetch a second organization
        import uuid
        unique_slug = f"external-tenant-{uuid.uuid4().hex[:8]}"
        org2 = Organization(id=str(uuid.uuid4()), name="External Tenant Corp", slug=unique_slug)
        self.db.add(org2)
        self.db.commit()

        # Try accessing a brand from org-northstar-fictional while sending org2 header
        brand_northstar = self.db.query(Brand).filter(Brand.organization_id == "org-northstar-fictional").first()
        
        # Access with tenant 2 header must return 404 (not in organization)
        res_isolated = self.client.get(
            f"/api/brands/{brand_northstar.id}",
            headers={"X-Organization-Id": org2.id}
        )
        self.assertEqual(res_isolated.status_code, 404)

if __name__ == "__main__":
    unittest.main()
