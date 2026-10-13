"""
test_phishing_api.py
API endpoint tests for dataset import, training management, and URL scanning in BrandSentinel.
"""

import unittest
import json
import os
import tempfile
from app import app
from db.database import SessionLocal
from db.models import Dataset, MLTrainingJob, MLModelArtifact, Brand, OfficialAsset

class PhishingAPITestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.db = SessionLocal()
        self.org_id = "org-northstar-fictional"

    def tearDown(self):
        self.db.close()

    def test_dataset_import_api_with_local_path(self):
        # Test importing a mini sample file
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as tf:
            tf.write("URL,label\n")
            tf.write("https://api-test1.com/login,0\n")
            tf.write("https://api-test2.com/home,1\n")
            tmp_path = tf.name

        try:
            resp = self.client.post("/api/datasets/import", json={
                "file_path": tmp_path
            })
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn("dataset", data)
            self.assertEqual(data["dataset"]["total_rows"], 2)
            self.assertEqual(data["dataset"]["accepted_rows"], 2)
            dataset_id = data["dataset"]["dataset_id"]

            # Test GET /api/datasets/<id>
            get_resp = self.client.get(f"/api/datasets/{dataset_id}")
            self.assertEqual(get_resp.status_code, 200)
            get_data = get_resp.get_json()
            self.assertEqual(get_data["id"], dataset_id)

            # Test GET /api/datasets/<id>/preview
            prev_resp = self.client.get(f"/api/datasets/{dataset_id}/preview?page=1&page_size=10")
            self.assertEqual(prev_resp.status_code, 200)
            prev_data = prev_resp.get_json()
            self.assertEqual(len(prev_data["rows"]), 2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_phishing_model_status_api(self):
        resp = self.client.get("/api/models/phishing/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("status", data)
        self.assertIn(data["status"], ["Ready", "Training", "Training required", "Not trained"])

    def test_scan_url_api_validation_and_official_matching(self):
        # 1. Empty URL returns 400
        r_empty = self.client.post("/api/scan/url", json={"url": ""})
        self.assertEqual(r_empty.status_code, 400)
        self.assertEqual(r_empty.get_json()["code"], "EMPTY_URL")

        # 2. Unsupported protocol returns 400
        r_ftp = self.client.post("/api/scan/url", json={"url": "ftp://files.example.com"})
        self.assertEqual(r_ftp.status_code, 400)
        self.assertEqual(r_ftp.get_json()["code"], "UNSUPPORTED_PROTOCOL")

        # 3. Valid URL scan for Northstar brand
        brand = self.db.query(Brand).filter(Brand.organization_id == self.org_id).first()
        brand_id = brand.id if brand else None

        r_valid = self.client.post("/api/scan/url", json={
            "url": "https://portal.example.com/account",
            "brand_id": brand_id
        })
        self.assertEqual(r_valid.status_code, 200)
        data = r_valid.get_json()
        self.assertEqual(data["url"], "https://portal.example.com/account")
        self.assertEqual(data["domain"], "portal.example.com")
        self.assertIn("identity", data)
        self.assertIn("phishing", data)
        self.assertIn(data["identity"]["status"], ["Official", "Not verified as official", "Unable to verify"])
        self.assertIn(data["phishing"]["status"], ["Likely phishing", "Likely legitimate", "Unable to assess"])
        self.assertIn("disclaimer", data)

    def test_scan_url_youtube_limitation_advisory(self):
        r_yt = self.client.post("/api/scan/url", json={
            "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        })
        self.assertEqual(r_yt.status_code, 200)
        data = r_yt.get_json()
        self.assertIsNotNone(data["limitation_note"])
        self.assertIn("YouTube", data["limitation_note"])

if __name__ == "__main__":
    unittest.main()
