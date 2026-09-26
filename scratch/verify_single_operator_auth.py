import os
import sys
import unittest
from pathlib import Path

# Setup paths
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.auth import get_password_hash, verify_password


class TestSingleOperatorAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.op_user = settings.OPERATOR_USERNAME
        cls.op_email = settings.OPERATOR_EMAIL
        cls.op_pass = settings.OPERATOR_PASSWORD or "Yash@4050"

    def test_01_correct_operator_credentials_login_via_username(self):
        """1. Correct operator username + password can log in and returns 200."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_user,
            "password": self.op_pass
        })
        self.assertEqual(res.status_code, 200, f"Login failed: {res.text}")
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["username"], self.op_user)
        self.assertNotIn("password", data["user"])
        self.assertNotIn("hashed_password", data["user"])

    def test_02_correct_operator_credentials_login_via_email(self):
        """1b. Correct operator email + password can log in and returns 200."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_email,
            "password": self.op_pass
        })
        self.assertEqual(res.status_code, 200, f"Login via email failed: {res.text}")
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.op_email)

    def test_03_incorrect_password_rejected(self):
        """2. Incorrect password is rejected with HTTP 401."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_user,
            "password": "WrongPassword!999"
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn("Incorrect username/email or password", res.json()["detail"])

    def test_04_unknown_user_rejected(self):
        """3. Unknown username/email is rejected with HTTP 401."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": "non_existent_operator_999@cyvera.io",
            "password": self.op_pass
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn("Incorrect username/email or password", res.json()["detail"])

    def test_05_public_registration_rejected(self):
        """4. Public registration is rejected with HTTP 403 Forbidden."""
        res = self.client.post("/api/v1/auth/register", json={
            "username": "unauthorized_user",
            "email": "unauth@example.com",
            "password": "StrongPassword!123"
        })
        self.assertEqual(res.status_code, 403)
        self.assertIn("Public registration is disabled", res.json()["detail"])

    def test_06_forgot_password_endpoint_no_longer_exists(self):
        """5. Forgot-password endpoint no longer exists (404/405)."""
        res = self.client.post("/api/v1/auth/forgot-password", json={
            "email": self.op_email
        })
        self.assertIn(res.status_code, [404, 405], f"Unexpected status: {res.status_code}")

    def test_07_reset_password_endpoint_no_longer_exists(self):
        """6. Reset-password endpoint no longer exists (404/405)."""
        res = self.client.post("/api/v1/auth/reset-password", json={
            "token": "dummy_test_token_12345",
            "new_password": "NewStrongPassword!123"
        })
        self.assertIn(res.status_code, [404, 405], f"Unexpected status: {res.status_code}")

    def test_08_login_returns_valid_jwt(self):
        """7. Login returns a valid JWT access token with expected claims."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_user,
            "password": self.op_pass
        })
        self.assertEqual(res.status_code, 200)
        token = res.json()["access_token"]
        import jwt
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        self.assertEqual(payload["sub"], self.op_user)
        self.assertEqual(payload["email"], self.op_email)
        self.assertIn("pwd_ver", payload)
        self.assertIn("exp", payload)

    def test_09_authenticated_api_me(self):
        """8a. Existing authenticated API /auth/me returns current user."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_user,
            "password": self.op_pass
        })
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        me_res = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["username"], self.op_user)

    def test_10_authenticated_scans_and_authorization(self):
        """8b & 9. Authenticated APIs and scan authorization remain intact."""
        res = self.client.post("/api/v1/auth/login", json={
            "email_or_username": self.op_user,
            "password": self.op_pass
        })
        token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        scans_res = self.client.get("/api/v1/scans", headers=headers)
        self.assertEqual(scans_res.status_code, 200)
        self.assertIsInstance(scans_res.json(), list)

        findings_res = self.client.get("/api/v1/findings", headers=headers)
        self.assertEqual(findings_res.status_code, 200)
        self.assertIsInstance(findings_res.json(), list)

    def test_11_dead_modules_removed(self):
        """Verify obsolete email_service and auth_limiter files are deleted."""
        email_service_file = backend_dir / "app" / "services" / "email_service.py"
        auth_limiter_file = backend_dir / "app" / "services" / "auth_limiter.py"
        self.assertFalse(email_service_file.exists(), "email_service.py still exists!")
        self.assertFalse(auth_limiter_file.exists(), "auth_limiter.py still exists!")

    def test_12_no_forgot_or_reset_routes_in_fastapi(self):
        """Verify no forgot-password or reset-password routes registered in app."""
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        self.assertNotIn("/api/v1/auth/forgot-password", routes)
        self.assertNotIn("/api/v1/auth/reset-password", routes)


if __name__ == "__main__":
    unittest.main()
