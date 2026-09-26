"""
Regression test: security_score float type -- prevents re-introduction of
  pydantic_core.ValidationError: security_score
    Input should be a valid integer, got a number with a fractional part
    input_value=82.5

Run from project root:
  python -m pytest scratch/test_security_score_float.py -v
"""
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from fastapi.testclient import TestClient
from app.main import app
from app.schemas import ScanResponse, ReconResultResponse, SecurityScoreResponse


class TestSecurityScoreFloatType(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        res = cls.client.post(
            "/api/v1/auth/login",
            json={"email_or_username": "Yash", "password": "Yash@4050"}
        )
        assert res.status_code == 200, f"Login failed: {res.text}"
        cls.token = res.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def test_01_scan_response_accepts_float_security_score(self):
        """ScanResponse must accept security_score=82.5 without ValidationError."""
        r = ScanResponse(
            id=22, user_id=1, target_url="https://example.com",
            scan_type="Standard", status="Completed",
            security_score=82.5, created_at=datetime.now(timezone.utc),
        )
        self.assertEqual(r.security_score, 82.5)
        self.assertIsInstance(r.security_score, float)

    def test_02_recon_result_response_accepts_float_security_score(self):
        """ReconResultResponse must accept security_score=82.5 without ValidationError.

        Primary crash point: schema had security_score: int which Pydantic v2
        refuses to coerce from 82.5 with int_from_float error.
        """
        r = ReconResultResponse(
            id=1, user_id=1, scan_id=22,
            target_url="https://example.com",
            ip_address="93.184.216.34", web_server="nginx",
            ssl_issuer="LetsEncrypt", ssl_expires_days=90,
            security_score=82.5, details={},
            created_at=datetime.now(timezone.utc),
        )
        self.assertEqual(r.security_score, 82.5)
        self.assertIsInstance(r.security_score, float)

    def test_03_recon_result_response_rejects_non_numeric_score(self):
        """ReconResultResponse should reject a non-numeric security_score."""
        import pydantic
        with self.assertRaises(pydantic.ValidationError):
            ReconResultResponse(
                id=1, user_id=1, scan_id=22,
                target_url="https://example.com",
                ip_address="1.2.3.4", web_server="nginx",
                ssl_issuer="LetsEncrypt", ssl_expires_days=90,
                security_score="not-a-number", details={},
                created_at=datetime.now(timezone.utc),
            )

    def test_04_security_score_response_accepts_82_5(self):
        """SecurityScoreResponse.score must accept 82.5."""
        from app.schemas import ScoreFactors, ScoreDeductions
        r = SecurityScoreResponse(
            score=82.5, grade="A", risk_level="Low",
            factors=ScoreFactors(), deductions=ScoreDeductions(),
            scan_id=22, target_url="https://example.com",
        )
        self.assertEqual(r.score, 82.5)
        self.assertIsInstance(r.score, float)

    def test_05_scan_response_field_type_is_float(self):
        """ScanResponse.security_score annotation must include float, not int."""
        import typing
        annotation = ScanResponse.__annotations__.get("security_score")
        args = typing.get_args(annotation)
        self.assertIn(float, args,
            f"Expected float in security_score annotation, got: {annotation}")

    def test_06_recon_result_response_field_type_is_float(self):
        """ReconResultResponse.security_score annotation must be float (not int).

        This is the exact regression guard: if someone reverts to int, this fails.
        """
        annotation = ReconResultResponse.__annotations__.get("security_score")
        self.assertIs(annotation, float,
            f"Expected float for security_score, got: {annotation}. "
            "Reverting to int causes ValidationError on scores like 82.5.")

    def test_07_get_scan_22_returns_security_score_82_5(self):
        """GET /api/v1/scans/22 must return security_score=82.5 (not rounded, not int)."""
        res = self.client.get("/api/v1/scans/22", headers=self.headers)
        self.assertEqual(res.status_code, 200, f"Expected 200, got {res.status_code}: {res.text}")
        data = res.json()
        self.assertIn("security_score", data)
        score = data["security_score"]
        self.assertIsNotNone(score, "security_score must not be None for a completed scan")
        self.assertEqual(score, 82.5,
            f"Expected security_score=82.5, got {score}. Score must not be rounded or truncated.")
        self.assertIsInstance(score, (int, float))

    def test_08_scan_list_security_score_preserves_decimal(self):
        """GET /api/v1/scans/ list must preserve security_score=82.5 for scan 22."""
        res = self.client.get("/api/v1/scans/", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        scans = res.json()
        scan_22 = next((s for s in scans if s["id"] == 22), None)
        self.assertIsNotNone(scan_22, "Scan 22 not found in list response")
        self.assertEqual(scan_22["security_score"], 82.5,
            f"Scan list: expected 82.5, got {scan_22['security_score']}")

    def test_09_security_score_api_returns_82_5(self):
        """GET /api/v1/security-score/22 must return score=82.5."""
        res = self.client.get("/api/v1/security-score/22", headers=self.headers)
        self.assertEqual(res.status_code, 200, f"security-score API failed: {res.text}")
        data = res.json()
        self.assertIn("score", data)
        self.assertEqual(data["score"], 82.5, f"Expected score=82.5, got {data['score']}")

    def test_10_float_score_not_rounded_to_int(self):
        """82.5 must never be rounded to 82 or 83 anywhere in the scan response."""
        res = self.client.get("/api/v1/scans/22", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        score = data.get("security_score")
        self.assertNotEqual(score, 82, "score was rounded down to 82 -- regression!")
        self.assertNotEqual(score, 83, "score was rounded up to 83 -- regression!")
        self.assertEqual(score, 82.5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
