import os
import sys
import unittest
from fastapi.testclient import TestClient

# Add backend to sys.path
sys.path.insert(0, "backend")

from app.main import app
from app.services.target_validator import validate_target


class TestRegressions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Login Yash
        login_res = cls.client.post("/api/v1/auth/login", json={"email_or_username": "Yash", "password": "Password123!"})
        if login_res.status_code != 200:
            login_res = cls.client.post("/api/v1/auth/login", json={"email_or_username": "Yash", "password": "Yash@4050"})
        assert login_res.status_code == 200, f"Failed to login: {login_res.text}"
        cls.token = login_res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_phase_7b_safety_validation(self):
        """Phase 7B: Verify blocking of localhost, RFC1918, cloud metadata, etc."""
        blocked = [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://192.168.1.50",
            "http://10.0.0.1",
            "http://172.16.0.5",
            "http://169.254.169.254",
            "http://100.100.100.200",
            "http://metadata.google.internal",
            "http://internal.corp"
        ]
        for url in blocked:
            res = validate_target(url)
            self.assertFalse(res.is_valid, f"Expected {url} to be blocked")

    def test_phase_2_scans_api(self):
        """Phase 2: Scans list and details API."""
        res = self.client.get("/api/v1/scans/", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        scans = res.json()
        self.assertIsInstance(scans, list)
        self.assertGreater(len(scans), 0)

    def test_phase_4_findings_api(self):
        """Phase 4: Findings list and details API."""
        res = self.client.get("/api/v1/findings/", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        findings = res.json()
        self.assertIsInstance(findings, list)

    def test_phase_5_settings_api(self):
        """Phase 5: Settings API."""
        res = self.client.get("/api/v1/settings/", headers=self.headers)
        self.assertEqual(res.status_code, 200)

    def test_phase_6_reports_api(self):
        """Phase 6: Reports generation and preview."""
        scans = self.client.get("/api/v1/scans/", headers=self.headers).json()
        if scans:
            first_id = scans[0]["id"]
            res = self.client.get(f"/api/v1/reports/preview/{first_id}", headers=self.headers)
            self.assertIn(res.status_code, [200, 404])


if __name__ == "__main__":
    unittest.main()
