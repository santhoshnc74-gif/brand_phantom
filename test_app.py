import unittest
import json
from app import app

class BrandSentinelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()

    def test_index_page(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        html = response.data.decode('utf-8')
        self.assertIn("BrandSentinel", html)
        self.assertIn("Connect. Scan. Verify.", html)
        self.assertIn("Northstar Technologies", html)
        self.assertIn("Fictional Sample Data", html)

    def test_api_data(self):
        response = self.client.get('/api/data')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("system_info", data)
        self.assertIn("current_brand", data)
        self.assertIn("sources", data)
        self.assertIn("findings", data)
        self.assertGreater(len(data["findings"]), 0)

    def test_api_findings_filtering(self):
        # Test category all
        r_all = self.client.get('/api/findings?category=all')
        self.assertEqual(r_all.status_code, 200)
        data_all = r_all.get_json()
        
        # Test category social
        r_soc = self.client.get('/api/findings?category=social')
        self.assertEqual(r_soc.status_code, 200)
        data_soc = r_soc.get_json()
        for f in data_soc["findings"]:
            self.assertEqual(f["category"].lower(), "social")

        # Test category apps
        r_apps = self.client.get('/api/findings?category=apps')
        self.assertEqual(r_apps.status_code, 200)
        data_apps = r_apps.get_json()
        for f in data_apps["findings"]:
            self.assertEqual(f["category"].lower(), "apps")

    def test_api_scan_simulation(self):
        payload = {
            "query": "@northstar_fake_promo",
            "source": "Instagram"
        }
        response = self.client.post('/api/scan', json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("simulated"))
        self.assertIn("new_finding", data)
        self.assertEqual(data["new_finding"]["target_name"], "@northstar_fake_promo")

    def test_findings_are_filtered_by_brand(self):
        from db.database import SessionLocal
        from db.models import Detection
        response = self.client.get('/api/findings?brand_id=brand-northstar-tech')
        self.assertEqual(response.status_code, 200)
        with SessionLocal() as db:
            expected = {d.id for d in db.query(Detection).filter_by(
                organization_id='org-northstar-fictional', brand_id='brand-northstar-tech').all()}
        self.assertEqual({f['id'] for f in response.get_json()['findings']}, expected)
        response = self.client.get('/api/findings?brand_id=nonexistent-brand')
        self.assertEqual(response.get_json()['findings'], [])

    def test_api_source_toggle(self):
        payload = {
            "id": "source-ig",
            "action": "toggle"
        }
        response = self.client.post('/api/sources', json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("source", data)

    def test_api_finding_status_update(self):
        r_list = self.client.get('/api/findings')
        self.assertEqual(r_list.status_code, 200)
        findings = r_list.get_json()["findings"]
        self.assertGreater(len(findings), 0)
        first_id = findings[0]["id"]
        
        payload = {"status": "Takedown Sent"}
        response = self.client.post(f'/api/findings/{first_id}', json=payload)
        self.assertEqual(response.status_code, 200)
        res_data = response.get_json()
        self.assertIn("takedown", res_data["status"].lower())

    def test_static_assets(self):
        r_css = self.client.get('/static/css/styles.css')
        self.assertEqual(r_css.status_code, 200)
        r_js = self.client.get('/static/js/app.js')
        self.assertEqual(r_js.status_code, 200)

if __name__ == '__main__':
    unittest.main()
