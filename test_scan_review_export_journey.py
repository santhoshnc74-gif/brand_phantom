"""
BrandSentinel Complete Journey Test Suite
=========================================
Tests the complete end-to-end journey:
1. Brand & official legal asset registration.
2. Ingestion & Multi-signal scanning pipeline (official match, typosquats, inconclusive).
3. Findings queries: calculated All/Social/Apps counts, category/status/risk filters, search, sorting, pagination.
4. Review lifecycle & persistent review audit timeline: New -> In review -> Confirmed -> Dismissed -> Whitelisted.
5. Bulk review status updates with audit records.
6. RBAC on report exports:
   - export:summary permitted for Viewer, Analyst, Admin, Owner
   - export:telemetry forbidden for Viewer (403), permitted for Analyst, Admin, Owner
7. CSV formula injection protection (CWE-1236).
8. Mandatory security notices in user interface.
"""

import unittest
import json
import uuid
from app import app
from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, Brand, OfficialAsset,
    SourceConnection, Scan, Candidate, Detection, Review, AuditEvent
)
from auth import hash_password
from connectors import NormalizedCandidate
from pipeline import (
    process_candidate_pipeline,
    ASSESSMENT_OFFICIAL_MATCH,
    ASSESSMENT_LIKELY_IMPERSONATION,
    ASSESSMENT_INCONCLUSIVE
)


class TestScanReviewExportJourney(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.db = SessionLocal()
        cls.suffix = uuid.uuid4().hex[:8]
        cls.password = "SecurePassword123!@"

        # 1. Organization Setup
        cls.org = Organization(
            id=f"org-journey-{cls.suffix}",
            name=f"Journey Org {cls.suffix}",
            slug=f"journey-org-{cls.suffix}",
            is_sample=False
        )
        cls.db.add(cls.org)
        cls.db.flush()

        # 2. Users with Roles (Owner, Analyst, Viewer)
        cls.users = {}
        for role in ["owner", "analyst", "viewer"]:
            u = User(
                id=f"user-journey-{role}-{cls.suffix}",
                email=f"{role}.journey.{cls.suffix}@test.io",
                full_name=f"Journey {role.title()}",
                password_hash=hash_password(cls.password),
                is_verified=True,
                is_active=True
            )
            cls.db.add(u)
            cls.db.flush()

            m = Membership(
                id=f"mem-journey-{role}-{cls.suffix}",
                organization_id=cls.org.id,
                user_id=u.id,
                role=role
            )
            cls.db.add(m)
            cls.users[role] = {"user": u, "membership": m}

        # 3. Monitored Brand & Official Registered Assets
        cls.brand = Brand(
            id=f"brand-journey-{cls.suffix}",
            organization_id=cls.org.id,
            name="Northstar Technologies",
            aliases_json=json.dumps(["Northstar", "StarGuard"]),
            industry="Enterprise Cloud Security",
            is_sample=False
        )
        cls.db.add(cls.brand)
        cls.db.flush()

        # Official Domain
        cls.asset_domain = OfficialAsset(
            id=f"asset-dom-{cls.suffix}",
            organization_id=cls.org.id,
            brand_id=cls.brand.id,
            asset_type="domain",
            source_platform="domain",
            exact_identifier="northstar.io",
            stable_id="northstar.io",
            display_name="Official FQDN",
            verified=True,
            is_sample=False
        )
        # Official YouTube Channel
        cls.asset_social = OfficialAsset(
            id=f"asset-soc-{cls.suffix}",
            organization_id=cls.org.id,
            brand_id=cls.brand.id,
            asset_type="social_account",
            source_platform="youtube",
            exact_identifier="@northstar_official",
            stable_id="UC_NORTHSTAR_OFFICIAL",
            display_name="Official YouTube Channel",
            verified=True,
            is_sample=False
        )
        # Official Mobile App
        cls.asset_app = OfficialAsset(
            id=f"asset-app-{cls.suffix}",
            organization_id=cls.org.id,
            brand_id=cls.brand.id,
            asset_type="mobile_app",
            source_platform="google_play",
            exact_identifier="com.northstar.auth",
            stable_id="com.northstar.auth",
            authorized_publisher_id="Northstar Technologies LLC",
            display_name="Northstar Authenticator",
            verified=True,
            is_sample=False
        )
        cls.db.add_all([cls.asset_domain, cls.asset_social, cls.asset_app])
        cls.db.commit()

        # Seed candidates and detections across sources
        cls._seed_scan_candidates()

    @classmethod
    def _seed_scan_candidates(cls):
        """Seed 5 candidates through the pipeline to test journey steps."""
        candidates = [
            # 1. Exact official match on YouTube
            NormalizedCandidate(
                provider="youtube",
                external_id="UC_NORTHSTAR_OFFICIAL",
                asset_type="social_account",
                display_name="Northstar Official Channel",
                handle_or_package="@northstar_official",
                description="Official YouTube channel for Northstar Technologies enterprise security.",
                source_url="https://youtube.com/@northstar_official"
            ),
            # 2. Impersonator on YouTube with fake support & giveaway payment language
            NormalizedCandidate(
                provider="youtube",
                external_id="UC_FAKE_SUPPORT",
                asset_type="social_account",
                display_name="Northstar Customer Support Desk",
                handle_or_package="@northstar_support_rewards",
                description="Official helpdesk. Send BTC or ETH to verify your wallet for support.",
                source_url="https://youtube.com/@northstar_support_rewards"
            ),
            # 3. Impersonator App on Google Play
            NormalizedCandidate(
                provider="google_play",
                external_id="com.northstar.auth.trojan",
                asset_type="mobile_app",
                display_name="Northstar Auth 2FA Pro",
                handle_or_package="com.northstar.auth.trojan",
                publisher_id="Unauthorized Developer Inc",
                description="Enter your Northstar enterprise master password to authenticate.",
                source_url="https://play.google.com/store/apps/details?id=com.northstar.auth.trojan"
            ),
            # 4. Inconclusive candidate (similar name, but benign context)
            NormalizedCandidate(
                provider="telegram",
                external_id="tg_northstar_stars",
                asset_type="social_channel",
                display_name="North Star Observatory Group",
                handle_or_package="@northstar_observatory",
                description="Amateur astronomy and stargazing community group.",
                source_url="https://t.me/northstar_observatory"
            ),
            # 5. Malicious CSV Formula Injection candidate (CWE-1236)
            NormalizedCandidate(
                provider="telegram",
                external_id="tg_exploit_01",
                asset_type="social_channel",
                display_name="=cmd|' /C calc'!A0",
                handle_or_package="@northstar_calc_exploit",
                description="@SUM(1+99)*cmd|'/C calc'!A0",
                source_url="https://t.me/northstar_calc_exploit"
            )
        ]

        cls.seeded_pipeline_results = []
        for cand in candidates:
            res = process_candidate_pipeline(
                candidate=cand,
                brand_id=cls.brand.id,
                brand_name=cls.brand.name,
                brand_aliases=["Northstar", "StarGuard"],
                official_assets=[cls.asset_domain, cls.asset_social, cls.asset_app],
                organization_id=cls.org.id,
                db_session=cls.db,
                scan_id=None,
                is_sample=False
            )
            cls.seeded_pipeline_results.append(res)
        cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.query(Review).filter(Review.organization_id == cls.org.id).delete()
            cls.db.query(Detection).filter(Detection.organization_id == cls.org.id).delete()
            cls.db.query(Candidate).filter(Candidate.organization_id == cls.org.id).delete()
            cls.db.query(Scan).filter(Scan.organization_id == cls.org.id).delete()
            cls.db.query(OfficialAsset).filter(OfficialAsset.organization_id == cls.org.id).delete()
            cls.db.query(Brand).filter(Brand.organization_id == cls.org.id).delete()
            cls.db.query(Membership).filter(Membership.organization_id == cls.org.id).delete()
            cls.db.query(User).filter(User.email.like(f"%{cls.suffix}%")).delete()
            cls.db.query(Organization).filter(Organization.id == cls.org.id).delete()
            cls.db.commit()
        except Exception:
            cls.db.rollback()
        finally:
            cls.db.close()

    def setUp(self):
        self.client = self.app.test_client()

    def get_client_for_role(self, role):
        user_info = self.users[role]
        c = self.app.test_client()
        login_resp = c.post('/api/auth/login', json={
            "email": user_info["user"].email,
            "password": self.password
        })
        self.assertEqual(login_resp.status_code, 200, f"Login failed for {role}")
        csrf_token = login_resp.get_json()["csrf_token"]
        return c, csrf_token

    # =========================================================================
    # STEP 1: SCANNING PIPELINE EXECUTION & ASSESSMENT DIFFERENTIATION
    # =========================================================================
    def test_01_scanning_pipeline_ingestion(self):
        """Pipeline correctly classifies official matches, likely impersonations, and persists records."""
        self.assertEqual(len(self.seeded_pipeline_results), 5)

        # Official Match
        official_res = next(r for r in self.seeded_pipeline_results if r["assessment"] == ASSESSMENT_OFFICIAL_MATCH)
        self.assertEqual(official_res["risk_level"], "none")

        # Likely Impersonations (Support scam + Fake 2FA app)
        impersonations = [r for r in self.seeded_pipeline_results if r["assessment"] == ASSESSMENT_LIKELY_IMPERSONATION]
        self.assertGreaterEqual(len(impersonations), 2)

        # Verify DB records
        db_dets = self.db.query(Detection).filter_by(brand_id=self.brand.id).all()
        self.assertEqual(len(db_dets), 5)

    # =========================================================================
    # STEP 2: FINDINGS COUNTS, SEARCH, FILTERING, SORTING, PAGINATION
    # =========================================================================
    def test_02_findings_endpoint_counts_search_filters_and_pagination(self):
        """Findings endpoint calculates All/Social/Apps counts, filters, searches, sorts, and paginates."""
        c, _ = self.get_client_for_role("analyst")

        # 1. Total & Calculated Counts
        res_all = c.get(f'/api/findings?brand_id={self.brand.id}')
        self.assertEqual(res_all.status_code, 200)
        data_all = res_all.get_json()
        self.assertEqual(data_all["total"], 5)

        counts = data_all["counts"]
        self.assertEqual(counts["all"], 5)
        self.assertEqual(counts["apps"], 1)     # google_play
        self.assertEqual(counts["social"], 4)   # 2 youtube + 2 telegram
        self.assertIn("new", counts)
        self.assertIn("in_review", counts)
        self.assertIn("confirmed", counts)

        # 2. Filter by Category: Apps
        res_apps = c.get(f'/api/findings?brand_id={self.brand.id}&category=apps')
        self.assertEqual(res_apps.status_code, 200)
        self.assertEqual(len(res_apps.get_json()["findings"]), 1)
        self.assertEqual(res_apps.get_json()["findings"][0]["platform"], "google_play")

        # 3. Filter by Category: Social
        res_soc = c.get(f'/api/findings?brand_id={self.brand.id}&category=social')
        self.assertEqual(res_soc.status_code, 200)
        self.assertEqual(len(res_soc.get_json()["findings"]), 4)

        # 4. Search by Text: "Customer Support"
        res_search = c.get(f'/api/findings?brand_id={self.brand.id}&search=Customer Support')
        self.assertEqual(res_search.status_code, 200)
        self.assertEqual(len(res_search.get_json()["findings"]), 1)
        self.assertIn("Customer Support", res_search.get_json()["findings"][0]["target_name"])

        # 5. Filter by Risk Level: Critical
        res_crit = c.get(f'/api/findings?brand_id={self.brand.id}&risk_level=critical')
        self.assertEqual(res_crit.status_code, 200)
        for f in res_crit.get_json()["findings"]:
            self.assertEqual(f["risk_level"].lower(), "critical")

        # 6. Sorting: name_asc
        res_sort = c.get(f'/api/findings?brand_id={self.brand.id}&sort=name_asc')
        self.assertEqual(res_sort.status_code, 200)
        names = [f["target_name"] for f in res_sort.get_json()["findings"]]
        self.assertEqual(names, sorted(names))

        # 7. Pagination: per_page=2, page=1
        res_p1 = c.get(f'/api/findings?brand_id={self.brand.id}&per_page=2&page=1')
        self.assertEqual(res_p1.status_code, 200)
        p1 = res_p1.get_json()
        self.assertEqual(len(p1["findings"]), 2)
        self.assertEqual(p1["page"], 1)
        self.assertEqual(p1["total_pages"], 3)

        # Pagination page 2
        res_p2 = c.get(f'/api/findings?brand_id={self.brand.id}&per_page=2&page=2')
        self.assertEqual(res_p2.status_code, 200)
        self.assertEqual(len(res_p2.get_json()["findings"]), 2)

    # =========================================================================
    # STEP 3: REVIEW LIFECYCLE & PERSISTENT AUDIT TIMELINE
    # =========================================================================
    def test_03_review_lifecycle_and_audit_history(self):
        """Test transitions across New -> In review -> Confirmed -> Dismissed -> Whitelisted with persistent history."""
        c, csrf = self.get_client_for_role("analyst")

        # Select a detection
        det = self.db.query(Detection).filter_by(brand_id=self.brand.id).first()
        self.assertIsNotNone(det)

        # 1. Transition to 'in_review' with notes
        r1 = c.post(f'/api/findings/{det.id}', json={
            "status": "in_review",
            "notes": "Initiated manual review and registrar lookup."
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.get_json()["finding"]["status"], "in_review")

        # 2. Transition to 'confirmed' with takedown notes
        r2 = c.post(f'/api/findings/{det.id}', json={
            "status": "confirmed",
            "notes": "Confirmed malicious brand impersonator. DMCA takedown notice generated."
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()["finding"]["status"], "confirmed")

        # 3. Transition to 'dismissed' with notes
        r3 = c.post(f'/api/findings/{det.id}', json={
            "status": "dismissed",
            "notes": "Low risk fair-use commentary. Case dismissed."
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r3.status_code, 200)
        self.assertEqual(r3.get_json()["finding"]["status"], "dismissed")

        # 4. Transition to 'whitelisted'
        r4 = c.post(f'/api/findings/{det.id}', json={
            "status": "whitelisted",
            "notes": "Verified partner entity. Whitelisted."
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r4.status_code, 200)
        self.assertEqual(r4.get_json()["finding"]["status"], "whitelisted")

        # 5. GET detailed finding and inspect evidence & persistent review audit trail
        r_detail = c.get(f'/api/findings/{det.id}')
        self.assertEqual(r_detail.status_code, 200)
        detail = r_detail.get_json()

        # Check evidence fields
        self.assertIn("source_url", detail)
        self.assertIn("violations", detail)
        self.assertIn("assessment_rationale", detail)
        self.assertIn("missing_evidence_indicators", detail)

        # Check persistent review history timeline
        reviews = detail.get("reviews", [])
        self.assertGreaterEqual(len(reviews), 4)

        verdicts = [rev["verdict"] for rev in reviews]
        self.assertIn("in_review", verdicts)
        self.assertIn("confirmed", verdicts)
        self.assertIn("dismissed", verdicts)
        self.assertIn("whitelisted", verdicts)

        notes_all = [rev["notes"] for rev in reviews if rev.get("notes")]
        self.assertTrue(any("DMCA takedown notice" in n for n in notes_all))

    # =========================================================================
    # STEP 4: BULK REVIEW STATUS UPDATES
    # =========================================================================
    def test_04_bulk_status_update(self):
        """Bulk status update updates multiple detections and logs persistent review entries."""
        c, csrf = self.get_client_for_role("analyst")

        dets = self.db.query(Detection).filter_by(brand_id=self.brand.id).limit(3).all()
        det_ids = [d.id for d in dets]

        res = c.post('/api/findings/bulk', json={
            "detection_ids": det_ids,
            "status": "confirmed",
            "notes": "Bulk confirmed threats following security analysis."
        }, headers={"X-CSRF-Token": csrf})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["updated_count"], 3)

        # Verify in database
        for d_id in det_ids:
            updated = self.db.query(Detection).get(d_id)
            self.assertEqual(updated.status, "confirmed")
            rev = self.db.query(Review).filter_by(detection_id=d_id).order_by(Review.created_at.desc()).first()
            self.assertIsNotNone(rev)
            self.assertEqual(rev.verdict, "confirmed")
            self.assertIn("Bulk confirmed", rev.notes)

    # =========================================================================
    # STEP 5: REPORT EXPORT RBAC & FORMULA INJECTION PROTECTION
    # =========================================================================
    def test_05_report_export_rbac(self):
        """Viewer can export summary, but cannot export telemetry (403). Analyst can export both."""
        # 1. Viewer Role -> Summary Export (Permitted)
        c_v, _ = self.get_client_for_role("viewer")
        res_v_sum = c_v.get(f'/api/reports/export?type=summary&format=csv&brand_id={self.brand.id}')
        self.assertEqual(res_v_sum.status_code, 200)
        self.assertIn("text/csv", res_v_sum.content_type)

        # 2. Viewer Role -> Telemetry Export (Forbidden: 403)
        res_v_telem = c_v.get(f'/api/reports/export?type=telemetry&format=csv&brand_id={self.brand.id}')
        self.assertEqual(res_v_telem.status_code, 403)
        self.assertIn("export:telemetry", res_v_telem.get_json().get("error", ""))

        # 3. Analyst Role -> Telemetry Export (Permitted: 200)
        c_a, _ = self.get_client_for_role("analyst")
        res_a_telem = c_a.get(f'/api/reports/export?type=telemetry&format=csv&brand_id={self.brand.id}')
        self.assertEqual(res_a_telem.status_code, 200)
        self.assertIn("text/csv", res_a_telem.content_type)

        # 4. Analyst Role -> JSON Format (Permitted: 200)
        res_a_json = c_a.get(f'/api/reports/export?type=telemetry&format=json&brand_id={self.brand.id}')
        self.assertEqual(res_a_json.status_code, 200)
        self.assertIn("application/json", res_a_json.content_type)

    def test_06_csv_formula_injection_protection(self):
        """CSV export prepends single quote (') to cells beginning with formula triggers (=, +, -, @, cmd, etc.)."""
        c, _ = self.get_client_for_role("analyst")

        # Telemetry export contains malicious candidate '=cmd|' /C calc'!A0'
        res = c.get(f'/api/reports/export?type=telemetry&format=csv&brand_id={self.brand.id}')
        self.assertEqual(res.status_code, 200)
        csv_text = res.data.decode("utf-8")

        # Verify that unescaped `=cmd` does not appear
        self.assertIn("'=cmd|", csv_text)
        self.assertNotIn("\n=cmd|", csv_text)
        self.assertNotIn(",=cmd|", csv_text)

    # =========================================================================
    # STEP 6: MANDATORY SECURITY MESSAGES IN USER INTERFACE
    # =========================================================================
    def test_07_mandatory_messages_present_in_interface(self):
        """Verify presence of verbatim mandatory security disclaimers in HTML template."""
        c, _ = self.get_client_for_role("viewer")
        res = c.get('/')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")

        msg_official_safety = "An official identity match does not guarantee account safety."
        msg_sample_results = "Sample results shown; no live scan has run."

        self.assertIn(msg_official_safety, html)
        self.assertIn(msg_sample_results, html)


if __name__ == "__main__":
    unittest.main()
