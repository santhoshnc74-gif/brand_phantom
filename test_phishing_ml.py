"""
test_phishing_ml.py
Comprehensive test suite for BrandSentinel Phishing URL Dataset Import,
Domain-Grouped ML Training Pipeline, and Safe URL Prediction.
"""

import os
import unittest
import json
import tempfile
import numpy as np
import pandas as pd

from app import app
from db.database import SessionLocal
from db.models import (
    Organization, Brand, OfficialAsset, Dataset, DatasetRecord,
    MLTrainingJob, MLModelArtifact, URLScan
)
from ml.url_features import (
    normalize_url,
    extract_domain_and_registrable,
    extract_features_dict,
    extract_features_vector,
    FEATURE_NAMES,
)
from ml.train_phishing import (
    create_domain_grouped_split,
    evaluate_metrics,
    train_phishing_pipeline,
    PhishingModelBundle,
)
from ml.predict_phishing import (
    verify_official_identity,
    predict_url_risk,
    get_platform_limitation_note,
)
from services.dataset_service import (
    validate_and_import_csv,
    get_dataset_preview,
    recover_interrupted_jobs,
)

class PhishingMLTestSuite(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()
        self.org_id = "org-northstar-fictional"

    def tearDown(self):
        self.db.close()

    # 1. Feature Extraction Parity & Determinism
    def test_feature_extraction_identical_parity(self):
        url = "https://secure-login.portal.example.com:8443/auth/verify?session=xyz#frag"
        v1 = extract_features_vector(url)
        v2 = extract_features_vector(url)
        self.assertEqual(len(v1), len(FEATURE_NAMES))
        self.assertEqual(v1, v2, "Feature extraction must be 100% deterministic")

        # Verify fragment is stripped but path and query are preserved
        norm = normalize_url(url)
        self.assertNotIn("#frag", norm)
        self.assertIn("/auth/verify", norm)
        self.assertIn("?session=xyz", norm)
        self.assertTrue(norm.startswith("https://secure-login.portal.example.com:8443"))

    # 2. Label Mapping and Phishing Metrics (0 = Phishing, 1 = Legitimate)
    def test_label_mapping_and_phishing_metrics(self):
        # In our binary target: 1 = Phishing, 0 = Legitimate
        y_true = np.array([1, 1, 0, 0]) # 2 phish, 2 legit
        y_pred_prob = np.array([0.9, 0.4, 0.1, 0.8]) # pred: 1, 0, 0, 1 -> TP=1, FN=1, TN=1, FP=1

        metrics = evaluate_metrics(y_true, y_pred_prob, threshold=0.5)
        self.assertEqual(metrics["confusion_matrix"]["tp"], 1)
        self.assertEqual(metrics["confusion_matrix"]["fn"], 1)
        self.assertEqual(metrics["confusion_matrix"]["tn"], 1)
        self.assertEqual(metrics["confusion_matrix"]["fp"], 1)
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.5)

    # 3. Domain Grouping with Zero Overlap
    def test_domain_grouping_zero_overlap(self):
        data = []
        domains = ["alpha.com", "beta.org", "gamma.co.uk", "delta.io", "epsilon.net", "zeta.com", "eta.org"]
        for d in domains:
            for i in range(15):
                lbl = 0 if (i % 2 == 0) else 1
                data.append({
                    "url": f"https://sub{i}.{d}/page_{i}",
                    "registrable_domain": d,
                    "is_phishing": lbl
                })
        df = pd.DataFrame(data)

        train_m, val_m, test_m, train_d, val_d, test_d = create_domain_grouped_split(df, random_state=42)

        # Assert zero domain overlap
        self.assertEqual(len(train_d.intersection(val_d)), 0)
        self.assertEqual(len(train_d.intersection(test_d)), 0)
        self.assertEqual(len(val_d.intersection(test_d)), 0)

        # Assert no row is in multiple splits
        self.assertFalse((train_m & val_m).any())
        self.assertFalse((train_m & test_m).any())
        self.assertFalse((val_m & test_m).any())

    # 4. CSV Validation, Cleaning, Deduplication, and Conflicting Quarantine
    def test_dataset_cleaning_and_quarantine(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("FILENAME,URL,label\n")
            tf.write("f1.txt,https://clean1.example.com,1\n")
            tf.write("f2.txt,https://clean1.example.com,1\n") # duplicate
            tf.write("f3.txt,https://phish1.example.com/bad,0\n")
            tf.write("f4.txt,https://conflict.example.com,1\n") # conflict
            tf.write("f5.txt,https://conflict.example.com,0\n") # conflict
            tf.write("f6.txt,,1\n") # empty URL -> reject
            tf.write("f7.txt,https://badlabel.example.com,invalid\n") # invalid label -> reject
            tmp_path = tf.name

        try:
            res = validate_and_import_csv(tmp_path, organization_id="org-temp-test")
            self.assertEqual(res["total_rows"], 7)
            self.assertEqual(res["duplicate_rows"], 1)
            self.assertEqual(res["rejected_rows"], 2)
            self.assertEqual(res["conflicting_rows"], 2)
            self.assertEqual(res["accepted_rows"], 2) # clean1 (1) and phish1 (0)
            self.assertEqual(res["legitimate_count"], 1)
            self.assertEqual(res["phishing_count"], 1)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            # Cleanup test records
            self.db.query(Dataset).filter(Dataset.organization_id == "org-temp-test").delete()
            self.db.commit()

    # 5. Idempotent Import via SHA-256 Hash
    def test_idempotent_import_does_not_duplicate(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("URL,label\n")
            tf.write("https://idempotent.example.com/login,0\n")
            tf.write("https://idempotent.example.com/about,1\n")
            tmp_path = tf.name

        try:
            res1 = validate_and_import_csv(tmp_path, organization_id="org-idemp-test")
            self.assertFalse(res1["already_imported"])

            res2 = validate_and_import_csv(tmp_path, organization_id="org-idemp-test")
            self.assertTrue(res2["already_imported"])
            self.assertEqual(res1["dataset_id"], res2["dataset_id"])
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            self.db.query(Dataset).filter(Dataset.organization_id == "org-idemp-test").delete()
            self.db.commit()

    # 6. Organization Isolation
    def test_organization_isolation(self):
        # Create dataset under org A
        ds_a = Dataset(
            organization_id="org-tenant-a",
            name="dataset-a.csv",
            filename="dataset-a.csv",
            file_hash="dummyhash_org_a",
            file_size_bytes=1000,
            total_rows=10,
            accepted_rows=10
        )
        self.db.add(ds_a)
        self.db.commit()

        # Query preview under org B
        with self.assertRaises(ValueError):
            get_dataset_preview(ds_a.id, organization_id="org-tenant-b")

        # Cleanup
        self.db.delete(ds_a)
        self.db.commit()

    # 7. Safe Domain Matching and Suffix Attack Rejection
    def test_safe_domain_matching_rejects_lookalikes(self):
        official_assets = [
            {"id": "asset-1", "identifier": "northstar.io", "domain": "northstar.io"}
        ]

        # Exact match -> Official
        r1 = verify_official_identity("https://northstar.io/login", "brand-1", official_assets)
        self.assertEqual(r1["status"], "Official")

        # Subdomain match -> Official
        r2 = verify_official_identity("https://portal.northstar.io/dashboard", "brand-1", official_assets)
        self.assertEqual(r2["status"], "Official")

        # Lookalike Suffix Attack: official.example.attacker.example -> REJECT
        r3 = verify_official_identity("https://northstar.io.attacker.example/login", "brand-1", official_assets)
        self.assertEqual(r3["status"], "Not verified as official")

        # Lookalike Prefix: mynorthstar.io -> REJECT
        r4 = verify_official_identity("https://mynorthstar.io/login", "brand-1", official_assets)
        self.assertEqual(r4["status"], "Not verified as official")

        # No brand or empty assets -> Unable to verify
        r5 = verify_official_identity("https://northstar.io", None, [])
        self.assertEqual(r5["status"], "Unable to verify")

    # 8. Conflicting Identity and Phishing Independence
    def test_conflicting_identity_and_phishing_independence(self):
        # Scenario: Legitimate official domain hosting a phishing/compromised page
        official_assets = [{"id": "asset-1", "identifier": "northstar.io"}]
        id_res = verify_official_identity("https://northstar.io/compromised", "brand-1", official_assets)
        self.assertEqual(id_res["status"], "Official")

        # Mock model predicting phishing
        class DummyPhishModel:
            def predict_proba(self, X):
                return np.array([[0.05, 0.95]])
        bundle = PhishingModelBundle(DummyPhishModel(), None, 0.5, FEATURE_NAMES, {})
        phish_res = predict_url_risk("https://northstar.io/compromised", bundle)
        self.assertEqual(phish_res["status"], "Likely phishing")

        # Both results must coexist without suppressing either
        self.assertEqual(id_res["status"], "Official")
        self.assertEqual(phish_res["status"], "Likely phishing")

    # 9. Platform Limitation Notices
    def test_platform_limitation_notices(self):
        yt_note = get_platform_limitation_note("https://www.youtube.com/watch?v=123")
        self.assertIsNotNone(yt_note)
        self.assertIn("YouTube", yt_note)

        ig_note = get_platform_limitation_note("https://instagram.com/p/abc")
        self.assertIsNotNone(ig_note)
        self.assertIn("Instagram", ig_note)

        tg_note = get_platform_limitation_note("https://t.me/fake_group")
        self.assertIsNotNone(tg_note)
        self.assertIn("Telegram", tg_note)

        norm_note = get_platform_limitation_note("https://normal-site.org/page")
        self.assertIsNone(norm_note)

    # 10. Model Training and Unseen URL Inference
    def test_lightweight_pipeline_training_and_inference(self):
        # Mini dataset of clean records
        records = [
            {"url": "https://bank-login.xyz/verify", "label": 0},
            {"url": "https://secure-update-account.com/signin", "label": 0},
            {"url": "https://paypal-security-alert.net/confirm", "label": 0},
            {"url": "https://wikipedia.org/wiki/Phishing", "label": 1},
            {"url": "https://python.org/doc", "label": 1},
            {"url": "https://google.com/search?q=security", "label": 1},
        ]
        result = train_phishing_pipeline(
            cleaned_records=records,
            dataset_hash="dummy_hash_test",
            random_state=42
        )
        self.assertIn("model_version", result)
        self.assertIn("test_metrics", result)
        self.assertTrue(os.path.exists(result["artifact_path"]))

        # Load bundle and test unseen URL
        bundle = PhishingModelBundle(
            result["bundle_metadata"]["baseline_comparison"]["hist_gradient_boosting"] if False else None,
            None, 0.5, FEATURE_NAMES, {}
        )
        import joblib
        loaded = joblib.load(result["artifact_path"])
        pred = predict_url_risk("https://unseen-phishing-login.com/account", loaded)
        self.assertIn(pred["status"], ("Likely phishing", "Likely legitimate"))
        self.assertIsNotNone(pred["probability"])

    # 11. Restart Persistence & Interrupted Job Recovery
    def test_recover_interrupted_jobs(self):
        job = MLTrainingJob(
            organization_id="org-restart-test",
            dataset_id="ds-test",
            status="running",
            current_stage="extracting_features"
        )
        self.db.add(job)
        self.db.commit()

        # Run recovery
        recover_interrupted_jobs()

        recovered_job = self.db.query(MLTrainingJob).filter(MLTrainingJob.id == job.id).first()
        self.assertEqual(recovered_job.status, "failed")
        self.assertIn("interrupted", recovered_job.error_message.lower())

        # Cleanup
        self.db.delete(recovered_job)
        self.db.commit()

if __name__ == "__main__":
    unittest.main()
