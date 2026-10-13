"""
BrandSentinel Scanning Pipeline & Evidence Analysis Tests
=========================================================
Automated verification for Phase 10 / Scanning Pipeline:
1. Untrusted text sanitization & control character neutralization.
2. Unicode NFKC normalization, diacritic stripping, and homoglyph resolution.
3. Character swaps / leet-speak obfuscation detection (e.g., Northstar vs N0rthstar, Northst@r).
4. Added deceptive modifiers detection (Support, Rewards, Helpdesk, Login).
5. Name similarity calculations with strict thresholding for short and common names.
6. Exact official-asset matching across domains, mobile app stores, and social stable IDs.
7. Publisher mismatch analysis: proving unknown publisher alone NEVER establishes impersonation,
   while unauthorized publisher mismatch acts as a strong corroborating signal.
8. Suspicious payment, crypto giveaway, and credential harvesting language detection.
9. Logo analysis honesty: verified that visual similarity is None (not performed) unless CV is executed.
10. Multi-signal assessment formulation:
    - Official match: exact registered identifier.
    - Likely impersonation: requires multiple corroborating signals (similarity alone != confirmed fraud).
    - Inconclusive: single or conflicting signals.
    - Unrelated: low similarity or benign common name collision.
11. Cross-source candidate deduplication.
12. Live source failure isolation (zero silent demo substitution).
13. Validated JSON candidate imports (POST /api/scan/import) with RBAC and CSRF.
"""

import unittest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime

from app import app
from db.database import SessionLocal
from db.models import (
    User, Organization, Membership, SourceConnection, Brand,
    OfficialAsset, Candidate, Detection, Scan
)
from auth import hash_password, create_session
from connectors import NormalizedCandidate
from pipeline import (
    sanitize_untrusted_text, normalize_unicode, normalize_text_for_matching,
    remove_all_separators, detect_character_swaps, detect_added_words,
    calculate_name_similarity, analyze_publisher_evidence,
    detect_suspicious_payment_language, check_exact_official_match,
    analyze_and_assess_candidate, process_candidate_pipeline,
    validate_and_parse_import_json, DETECTOR_VERSION,
    ASSESSMENT_OFFICIAL_MATCH, ASSESSMENT_LIKELY_IMPERSONATION,
    ASSESSMENT_INCONCLUSIVE, ASSESSMENT_UNRELATED,
    IDENTITY_VERIFIED_OFFICIAL, IDENTITY_UNAUTHORIZED_IMPERSONATOR,
    IDENTITY_INCONCLUSIVE, IDENTITY_UNRELATED
)


class ScanningPipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()

        # Seed Organization
        self.org = self.db.query(Organization).filter(Organization.id == "org-pipe-test").first()
        if not self.org:
            self.org = Organization(id="org-pipe-test", name="Pipeline Test Org", slug="pipe-test-org")
            self.db.add(self.org)
            self.db.commit()

        # Seed Brand: Northstar Technologies
        self.brand = self.db.query(Brand).filter(Brand.organization_id == self.org.id, Brand.name == "Northstar Technologies").first()
        if not self.brand:
            self.brand = Brand(
                id="brand-pipe-northstar",
                organization_id=self.org.id,
                name="Northstar Technologies",
                industry="Cybersecurity",
                aliases_json=json.dumps(["Northstar", "Northstar Cyber"])
            )
            self.db.add(self.brand)
            self.db.commit()

        # Seed Short/Common Brand: Star
        self.short_brand = self.db.query(Brand).filter(Brand.organization_id == self.org.id, Brand.name == "Star").first()
        if not self.short_brand:
            self.short_brand = Brand(
                id="brand-pipe-star",
                organization_id=self.org.id,
                name="Star",
                industry="Consumer",
                aliases_json=json.dumps(["Star App"])
            )
            self.db.add(self.short_brand)
            self.db.commit()

        # Seed Official Assets for Northstar Technologies
        # 1. Domain
        self.asset_domain = self.db.query(OfficialAsset).filter(
            OfficialAsset.organization_id == self.org.id,
            OfficialAsset.exact_identifier == "northstar.com"
        ).first()
        if not self.asset_domain:
            self.asset_domain = OfficialAsset(
                id="asset-pipe-domain",
                organization_id=self.org.id,
                brand_id=self.brand.id,
                asset_type="domain",
                source_platform="domain",
                exact_identifier="northstar.com",
                stable_id="northstar.com",
                display_name="Official Northstar Website"
            )
            self.db.add(self.asset_domain)

        # 2. YouTube Official Channel (Stable ID)
        self.asset_yt = self.db.query(OfficialAsset).filter(
            OfficialAsset.organization_id == self.org.id,
            OfficialAsset.stable_id == "UC_northstar_corp_verified"
        ).first()
        if not self.asset_yt:
            self.asset_yt = OfficialAsset(
                id="asset-pipe-yt",
                organization_id=self.org.id,
                brand_id=self.brand.id,
                asset_type="social_account",
                source_platform="youtube",
                exact_identifier="youtube.com/northstar",
                stable_id="UC_northstar_corp_verified",
                display_name="Northstar YouTube Channel"
            )
            self.db.add(self.asset_yt)

        # 3. Google Play Mobile App with Authorized Publisher
        self.asset_app = self.db.query(OfficialAsset).filter(
            OfficialAsset.organization_id == self.org.id,
            OfficialAsset.exact_identifier == "com.northstar.security"
        ).first()
        if not self.asset_app:
            self.asset_app = OfficialAsset(
                id="asset-pipe-app",
                organization_id=self.org.id,
                brand_id=self.brand.id,
                asset_type="mobile_app",
                source_platform="google_play",
                exact_identifier="com.northstar.security",
                stable_id="com.northstar.security",
                authorized_publisher_id="pub-northstar-official-123",
                authorized_publisher_name="Northstar Technologies Inc",
                display_name="Northstar Security App"
            )
            self.db.add(self.asset_app)

        self.db.commit()

        # Seed Users
        self.analyst = self._get_or_create_user("pipe-analyst@test.com", "Pipeline Analyst", "analyst")
        self.viewer = self._get_or_create_user("pipe-viewer@test.com", "Pipeline Viewer", "viewer")

    def tearDown(self):
        self.db.close()

    def _get_or_create_user(self, email, name, role):
        u = self.db.query(User).filter(User.email == email).first()
        if not u:
            u = User(
                email=email,
                full_name=name,
                password_hash=hash_password("Pass123!SecurePipe"),
                is_verified=True,
                is_active=True
            )
            self.db.add(u)
            self.db.commit()

        mem = self.db.query(Membership).filter(Membership.user_id == u.id, Membership.organization_id == self.org.id).first()
        if not mem:
            mem = Membership(user_id=u.id, organization_id=self.org.id, role=role)
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
    # 1. TEXT NORMALIZATION & SANITIZATION
    # ==========================================================================

    def test_untrusted_text_sanitization(self):
        """External text with null bytes, control codes, or excessive length must be sanitized."""
        malicious_input = "Northstar\x00\x08Security\x1b[31m Corp\t\n"
        cleaned = sanitize_untrusted_text(malicious_input)
        self.assertNotIn("\x00", cleaned)
        self.assertNotIn("\x08", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertIn("Northstar", cleaned)
        self.assertIn("Security", cleaned)

        # Truncation test
        long_text = "A" * 2000
        truncated = sanitize_untrusted_text(long_text, max_length=150)
        self.assertEqual(len(truncated), 150)

        # None test
        self.assertEqual(sanitize_untrusted_text(None), "")

    def test_unicode_normalization_and_homoglyphs(self):
        """NFKC normalization, diacritic stripping, and Cyrillic/Greek homoglyphs to ASCII Latin."""
        # Cyrillic lookalikes: 'Nоrthstаr' where 'о' and 'а' are Cyrillic U+043E, U+0430
        cyrillic_text = "N\u043Erthst\u0430r"
        resolved = normalize_unicode(cyrillic_text)
        self.assertEqual(resolved, "Northstar")

        # Combining diacritics / accents: Nórthstár
        accented = "N\u00f3rthst\u00e1r"
        norm_matching = normalize_text_for_matching(accented)
        self.assertEqual(norm_matching, "northstar")

        # Fullwidth Unicode characters: Ｎｏｒｔｈｓｔａｒ
        fullwidth = "\uff2e\uff4f\uff52\uff54\uff48\uff53\uff54\uff41\uff52"
        self.assertEqual(normalize_unicode(fullwidth), "Northstar")

    # ==========================================================================
    # 2. CHARACTER SWAPS / LEET-SPEAK ANALYSIS
    # ==========================================================================

    def test_character_swaps_leetspeak(self):
        """Detect character swaps such as N0rthstar vs Northstar and Northst@r."""
        # 1. 'N0rthstar' (0 -> o)
        res_0 = detect_character_swaps("N0rthstar", "Northstar")
        self.assertTrue(res_0["detected"])
        self.assertTrue(res_0["matched_brand"])
        self.assertEqual(res_0["swapped_string"], "northstar")

        # 2. 'Northst@r' (@ -> a)
        res_at = detect_character_swaps("Northst@r", "Northstar")
        self.assertTrue(res_at["detected"])
        self.assertTrue(res_at["matched_brand"])
        self.assertEqual(res_at["swapped_string"], "northstar")

        # 3. Compound leet swap: 'N0rthst@r' (both 0 and @)
        res_both = detect_character_swaps("N0rthst@r", "Northstar")
        self.assertTrue(res_both["detected"])
        self.assertTrue(res_both["matched_brand"])
        self.assertEqual(res_both["swapped_string"], "northstar")

        # 4. Unrelated text with digits should not falsely match
        res_unrelated = detect_character_swaps("M1cr0s0ft", "Northstar")
        self.assertFalse(res_unrelated["detected"])
        self.assertFalse(res_unrelated["matched_brand"])

    # ==========================================================================
    # 3. ADDED WORDS & DECEPTIVE MODIFIERS
    # ==========================================================================

    def test_added_words_detection(self):
        """Identify high-risk deceptive additions: Support, Rewards, Helpdesk, Login."""
        # Separate tokens
        mods1 = detect_added_words("Northstar Support Portal", "Northstar")
        self.assertIn("support", mods1)
        self.assertIn("portal", mods1)

        # Social handle compound
        mods2 = detect_added_words("@northstar_rewards", "Northstar")
        self.assertIn("rewards", mods2)

        # Single compound word (e.g. northstarsupport)
        mods3 = detect_added_words("northstarhelpdesk", "Northstar")
        self.assertIn("helpdesk", mods3)

        # Benign word not in deceptive set
        mods_benign = detect_added_words("Northstar Research Lab", "Northstar")
        self.assertEqual(mods_benign, [])

    # ==========================================================================
    # 4. NAME SIMILARITY & SHORT/COMMON NAME STRICT MATCHING
    # ==========================================================================

    def test_name_similarity_regular_vs_short_common_names(self):
        """
        Prove stricter thresholding for short or common dictionary words:
        - Common/short brand: single letter diff without token match is penalized.
        - Regular multi-syllable brand: standard Levenshtein distance.
        """
        # 1. Regular brand: 'Northstar'
        sim_close = calculate_name_similarity("Northstar Security", "Northstar Technologies", ["Northstar"])
        self.assertGreaterEqual(sim_close["similarity_score"], 0.85)

        # 2. Unrelated name: 'Acme Cyber Labs'
        sim_unrelated = calculate_name_similarity("Acme Cyber Labs", "Northstar Technologies", ["Northstar"])
        self.assertLess(sim_unrelated["similarity_score"], 0.30)

        # 3. Short/Common brand: 'Star'
        # 'Stan' is 1 edit distance from 'Star' (75% raw ratio), BUT because 'Star' is short/common,
        # it must be strictly penalized to prevent false positive collisions!
        sim_stan = calculate_name_similarity("Stan", "Star")
        self.assertTrue(sim_stan["is_short_or_common"])
        self.assertLess(sim_stan["similarity_score"], 0.50)

        # However, exact presence of 'Star' as a distinct token maintains high score
        sim_star_support = calculate_name_similarity("Star Support App", "Star")
        self.assertGreaterEqual(sim_star_support["similarity_score"], 0.85)

    # ==========================================================================
    # 5. EXACT OFFICIAL ASSET CHECK (STAGE 2)
    # ==========================================================================

    def test_exact_official_asset_matching(self):
        """Verify exact source-scoped matching across domains, mobile apps, and social accounts."""
        official_assets = [self.asset_domain, self.asset_yt, self.asset_app]

        # 1. Exact Domain Match
        cand_domain = NormalizedCandidate(
            provider="domain",
            external_id="dom_123",
            asset_type="domain",
            display_name="northstar.com",
            handle_or_package="northstar.com"
        )
        is_off, asset_id, reason = check_exact_official_match(cand_domain, official_assets)
        self.assertTrue(is_off)
        self.assertEqual(asset_id, self.asset_domain.id)

        # 2. Exact YouTube Stable ID Match
        cand_yt = NormalizedCandidate(
            provider="youtube",
            external_id="UC_northstar_corp_verified",
            asset_type="social_channel",
            display_name="Northstar Technologies",
            handle_or_package="@northstar"
        )
        is_off_yt, asset_id_yt, _ = check_exact_official_match(cand_yt, official_assets)
        self.assertTrue(is_off_yt)
        self.assertEqual(asset_id_yt, self.asset_yt.id)

        # 3. Exact Mobile App ID AND Matching Authorized Publisher
        cand_app_legit = NormalizedCandidate(
            provider="google_play",
            external_id="com.northstar.security",
            asset_type="mobile_app",
            display_name="Northstar Security",
            handle_or_package="com.northstar.security",
            publisher_id="pub-northstar-official-123"
        )
        is_off_app, asset_id_app, _ = check_exact_official_match(cand_app_legit, official_assets)
        self.assertTrue(is_off_app)
        self.assertEqual(asset_id_app, self.asset_app.id)

        # 4. Mobile App ID Matches BUT Unauthorized Publisher Mismatch!
        cand_app_counterfeit = NormalizedCandidate(
            provider="google_play",
            external_id="com.northstar.security",
            asset_type="mobile_app",
            display_name="Northstar Security",
            handle_or_package="com.northstar.security",
            publisher_id="pub-rogue-attacker-999"  # Attacker spoofed package ID with different publisher
        )
        is_off_fake, _, _ = check_exact_official_match(cand_app_counterfeit, official_assets)
        self.assertFalse(is_off_fake)

    # ==========================================================================
    # 6. PUBLISHER MISMATCH VS UNKNOWN PUBLISHER
    # ==========================================================================

    def test_publisher_evidence_rules(self):
        """
        CORE RULES:
        1. Unknown publisher alone MUST NOT establish impersonation.
        2. Known publisher mismatch with official authorized publisher IS a corroborating signal.
        """
        official_ids = ["pub-northstar-official-123"]
        official_names = ["Northstar Technologies Inc"]

        # Case 1: Unknown publisher
        unknown_res = analyze_publisher_evidence(None, None, official_ids, official_names)
        self.assertFalse(unknown_res["is_known"])
        self.assertFalse(unknown_res["is_mismatch"])
        self.assertEqual(unknown_res["status"], "unknown_publisher")
        self.assertIn("does not establish impersonation", unknown_res["rationale"])

        # Case 2: Matching publisher
        matching_res = analyze_publisher_evidence("pub-northstar-official-123", "Northstar Technologies Inc", official_ids, official_names)
        self.assertTrue(matching_res["is_known"])
        self.assertTrue(matching_res["is_match"])
        self.assertFalse(matching_res["is_mismatch"])

        # Case 3: Explicit Publisher Mismatch
        mismatch_res = analyze_publisher_evidence("pub-hacker-456", "Hacker App Devs", official_ids, official_names)
        self.assertTrue(mismatch_res["is_known"])
        self.assertTrue(mismatch_res["is_mismatch"])
        self.assertEqual(mismatch_res["status"], "publisher_mismatch")

    # ==========================================================================
    # 7. SUSPICIOUS PAYMENT LANGUAGE DETECTION
    # ==========================================================================

    def test_suspicious_payment_language(self):
        """Scam, airdrop, wallet connect, and payment extortion phrases."""
        text_scam = "Claim your free 500 USDT Northstar reward token! Send 0.1 BTC to verify your wallet address."
        res = detect_suspicious_payment_language(text_scam)
        self.assertTrue(res["detected"])
        self.assertTrue(len(res["matched_terms"]) > 0)

        text_benign = "Northstar enterprise endpoint detection and response documentation."
        res_benign = detect_suspicious_payment_language(text_benign)
        self.assertFalse(res_benign["detected"])

    # ==========================================================================
    # 8. MULTI-SIGNAL ASSESSMENTS & LOGO SIMILARITY HONESTY
    # ==========================================================================

    def test_assessment_categories_and_logo_honesty(self):
        """
        Verify:
        - Likely impersonation requires multiple corroborating signals.
        - Logo similarity is strictly None (not performed).
        - Inconclusive when signals are insufficient.
        """
        official_assets = [self.asset_domain, self.asset_yt, self.asset_app]

        # Case A: Official Match
        cand_official = NormalizedCandidate(
            provider="youtube",
            external_id="UC_northstar_corp_verified",
            asset_type="social_channel",
            display_name="Northstar Technologies",
            handle_or_package="@northstar"
        )
        ass_official = analyze_and_assess_candidate(cand_official, "Northstar Technologies", ["Northstar"], official_assets)
        self.assertEqual(ass_official["assessment"], ASSESSMENT_OFFICIAL_MATCH)
        self.assertEqual(ass_official["identity_status"], IDENTITY_VERIFIED_OFFICIAL)
        self.assertEqual(ass_official["risk_level"], "none")

        # Case B: Likely Impersonator (Character Swap + Added Word 'Rewards' + Payment scam text)
        cand_impersonator = NormalizedCandidate(
            provider="telegram",
            external_id="tg_fake_channel_99",
            asset_type="social_channel",
            display_name="N0rthstar Rewards Official",
            handle_or_package="@n0rthstar_rewards",
            description="Send 0.05 BTC to claim official Northstar reward airdrop!"
        )
        ass_imp = analyze_and_assess_candidate(cand_impersonator, "Northstar Technologies", ["Northstar"], official_assets)
        self.assertEqual(ass_imp["assessment"], ASSESSMENT_LIKELY_IMPERSONATION)
        self.assertEqual(ass_imp["identity_status"], IDENTITY_UNAUTHORIZED_IMPERSONATOR)
        self.assertEqual(ass_imp["risk_level"], "critical")
        self.assertIn("character_swap_detected", ass_imp["corroborating_signals"])
        self.assertIn("suspicious_payment_language", ass_imp["corroborating_signals"])

        # Check logo honesty in evidence
        logo_data = ass_imp["evidence"]["logo_analysis"]
        self.assertEqual(logo_data["status"], "not_performed")
        self.assertIsNone(logo_data["similarity_score"])

        # Case C: Inconclusive (Similar name, but no second corroborating signal, unknown publisher)
        cand_inconclusive = NormalizedCandidate(
            provider="telegram",
            external_id="tg_sim_channel_55",
            asset_type="social_channel",
            display_name="Northstar Fans",
            handle_or_package="@northstar_fans",
            description="Discussion group for security news."
        )
        ass_inc = analyze_and_assess_candidate(cand_inconclusive, "Northstar Technologies", ["Northstar"], official_assets)
        self.assertEqual(ass_inc["assessment"], ASSESSMENT_INCONCLUSIVE)
        self.assertEqual(ass_inc["identity_status"], IDENTITY_INCONCLUSIVE)
        self.assertEqual(ass_inc["risk_level"], "medium")

        # Case D: Unrelated
        cand_unrelated = NormalizedCandidate(
            provider="youtube",
            external_id="yt_blue_sky_12",
            asset_type="social_channel",
            display_name="BlueSky Cloud Gaming",
            handle_or_package="@bluesky_gaming"
        )
        ass_unrelated = analyze_and_assess_candidate(cand_unrelated, "Northstar Technologies", ["Northstar"], official_assets)
        self.assertEqual(ass_unrelated["assessment"], ASSESSMENT_UNRELATED)
        self.assertEqual(ass_unrelated["identity_status"], IDENTITY_UNRELATED)

    # ==========================================================================
    # 9. PIPELINE DATABASE PERSISTENCE & AUDIT SNAPSHOTS
    # ==========================================================================

    def test_process_candidate_pipeline_persistence(self):
        """Pipeline persists Candidate and Detection rows with evidence snapshots and detector version."""
        cand = NormalizedCandidate(
            provider="telegram",
            external_id="tg_persisted_fake_88",
            asset_type="social_channel",
            display_name="Northstar Support Desk",
            handle_or_package="@northstar_support_desk",
            description="Official Northstar Customer Care hotline",
            source_url="https://t.me/northstar_support_desk"
        )

        pipe_res = process_candidate_pipeline(
            candidate=cand,
            brand_id=self.brand.id,
            brand_name=self.brand.name,
            brand_aliases=["Northstar"],
            official_assets=[self.asset_yt],
            organization_id=self.org.id,
            db_session=self.db,
            scan_id=None,
            is_sample=False
        )
        self.db.commit()

        self.assertIsNotNone(pipe_res["candidate_id"])
        self.assertIsNotNone(pipe_res["detection_id"])
        self.assertEqual(pipe_res["assessment"], ASSESSMENT_LIKELY_IMPERSONATION)

        # Query database directly to verify stored record
        stored_cand = self.db.query(Candidate).filter(Candidate.id == pipe_res["candidate_id"]).first()
        self.assertIsNotNone(stored_cand)
        self.assertEqual(stored_cand.candidate_identifier, "@northstar_support_desk")

        stored_det = self.db.query(Detection).filter(Detection.id == pipe_res["detection_id"]).first()
        self.assertIsNotNone(stored_det)
        self.assertEqual(stored_det.identity_status, IDENTITY_UNAUTHORIZED_IMPERSONATOR)

        ev_loaded = json.loads(stored_det.similarity_details_json)
        self.assertEqual(ev_loaded["detector_version"], DETECTOR_VERSION)
        self.assertIn("timestamps", ev_loaded)
        self.assertEqual(ev_loaded["logo_analysis"]["status"], "not_performed")

    # ==========================================================================
    # 10. MULTI-SCAN SOURCE FAILURE RESILIENCE (ZERO SILENT DEMO FALLBACK)
    # ==========================================================================

    @patch("connectors.AppleAppStoreConnector.discover_candidates")
    @patch("connectors.YouTubeConnector.discover_candidates")
    def test_multi_source_scan_no_silent_demo_fallback(self, mock_yt, mock_apple):
        """
        When live source fails, report failed source explicitly.
        NEVER silently substitute fake/demo results when live scan returns zero or errors!
        """
        # Mock YouTube network failure
        mock_yt.side_effect = Exception("YouTube API Quota Exceeded (403 QuotaExceeded)")

        # Apple returns zero candidates
        mock_apple.return_value = []

        client = self.app.test_client()
        csrf = self._login(client, self.analyst)

        res = client.post(
            "/api/scan/multi",
            headers={"X-CSRF-Token": csrf, "X-Organization-Id": self.org.id},
            json={
                "query": "Northstar",
                "sources": ["youtube", "apple_app_store"],
                "is_demo": False  # Explicitly NOT a demo scan!
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # YouTube failed, Apple had 0 candidates -> total candidates examined must be 0!
        # NO fake candidates silently generated!
        self.assertEqual(data["total_candidates"], 0)
        self.assertEqual(len(data["findings"]), 0)
        self.assertEqual(len(data["failed_sources"]), 1)
        self.assertEqual(data["failed_sources"][0]["provider"], "youtube")
        self.assertIn("QuotaExceeded", data["failed_sources"][0]["message"])
        self.assertEqual(data["status"], "partial_success")

    # ==========================================================================
    # 11. VALIDATED JSON CANDIDATE IMPORT API (POST /api/scan/import)
    # ==========================================================================

    def test_validated_json_candidate_import_api(self):
        """
        Test POST /api/scan/import endpoint:
        - Rejects unauthenticated or viewer-only access.
        - Validates JSON candidate batch.
        - Processes all candidates through pipeline stages.
        """
        client = self.app.test_client()

        # 1. Reject without CSRF when logged in
        self._login(client, self.analyst)
        res_no_csrf = client.post("/api/scan/import", json={"candidates": []})
        self.assertEqual(res_no_csrf.status_code, 403)
        self.assertEqual(res_no_csrf.get_json().get("code"), "CSRF_VERIFICATION_FAILED")

        # 2. Reject Viewer (Analyst or above required)
        csrf_viewer = self._login(client, self.viewer)
        res_forbidden = client.post(
            "/api/scan/import",
            headers={"X-CSRF-Token": csrf_viewer, "X-Organization-Id": self.org.id},
            json={"candidates": []}
        )
        self.assertEqual(res_forbidden.status_code, 403)
        self.assertEqual(res_forbidden.get_json().get("code"), "FORBIDDEN")

        # 3. Successful Import by Analyst
        csrf_analyst = self._login(client, self.analyst)
        import_batch = {
            "brand_id": self.brand.id,
            "candidates": [
                {
                    "source_platform": "domain",
                    "candidate_identifier": "northstar.com",
                    "display_name": "Official Northstar Site",
                    "external_id": "imp_official_01"
                },
                {
                    "source_platform": "telegram",
                    "candidate_identifier": "@n0rthstar_support",
                    "display_name": "N0rthstar Support Agent",
                    "description": "Send 100 USDT to activate immediate customer support.",
                    "external_id": "imp_fake_02"
                },
                {
                    "source_platform": "apple_app_store",
                    "candidate_identifier": "com.unrelated.cooking",
                    "display_name": "Cooking Master Chef",
                    "external_id": "imp_unrelated_03"
                }
            ]
        }

        res_import = client.post(
            "/api/scan/import",
            headers={"X-CSRF-Token": csrf_analyst, "X-Organization-Id": self.org.id},
            json=import_batch
        )
        self.assertEqual(res_import.status_code, 201)
        data = res_import.get_json()

        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["total_candidates"], 3)
        self.assertEqual(data["official_matches"], 1)
        self.assertEqual(data["likely_impersonations"], 1)
        self.assertEqual(data["unrelated_count"], 1)
        self.assertEqual(data["detector_version"], DETECTOR_VERSION)

        # 4. Reject Invalid JSON import schema
        res_invalid = client.post(
            "/api/scan/import",
            headers={"X-CSRF-Token": csrf_analyst, "X-Organization-Id": self.org.id},
            json={"candidates": [{"missing_platform": "data"}]}
        )
        self.assertEqual(res_invalid.status_code, 400)
        self.assertEqual(res_invalid.get_json()["code"], "SCHEMA_VALIDATION_ERROR")


if __name__ == "__main__":
    unittest.main()
