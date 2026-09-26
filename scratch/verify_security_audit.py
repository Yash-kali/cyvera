import asyncio
import ipaddress
import socket
import ssl
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add backend to path
sys.path.insert(0, "backend")

from app.services.target_validator import validate_target, is_ip_blocked
from app.services.safe_client import (
    SafeHttpClient,
    PinnedNetworkBackend,
    PinnedAsyncHTTPTransport,
    SecurityPolicyViolation,
    UnsafeRedirectError
)


class TestSecurityDeepAudit(unittest.TestCase):

    def test_01_actual_socket_destination_pinning(self):
        """
        Verify that PinnedNetworkBackend.connect_tcp intercepts the call
        and passes the validated IP address (not the hostname) to the underlying backend.
        """
        backend = PinnedNetworkBackend()
        mock_underlying = AsyncMock()
        backend._backend = mock_underlying

        with patch("app.services.safe_client.validate_target") as mock_val:
            mock_res = MagicMock()
            mock_res.is_valid = True
            mock_res.resolved_ips = ["93.184.216.34"]
            mock_val.return_value = mock_res

            asyncio.run(backend.connect_tcp("authorized-target.org", 443))

            # Verify mock_underlying.connect_tcp was called with the IP, NOT the hostname
            mock_underlying.connect_tcp.assert_called_once()
            called_args = mock_underlying.connect_tcp.call_args
            destination_arg = called_args[0][0]
            port_arg = called_args[0][1]

            self.assertEqual(destination_arg, "93.184.216.34", "TCP destination must be pinned to the validated IP!")
            self.assertEqual(port_arg, 443)
            self.assertNotEqual(destination_arg, "authorized-target.org", "Underlying socket must NEVER receive unpinned hostname!")

    def test_02_dns_rebinding_attack_simulation(self):
        """
        Scenario:
        1. Target resolves initially to 93.184.216.34 (public, approved).
        2. Attacker modifies DNS so that next lookup resolves to 127.0.0.1 (rebound to loopback).
        Requirement: The request must NEVER connect to 127.0.0.1.
        """
        backend = PinnedNetworkBackend()
        mock_underlying = AsyncMock()
        backend._backend = mock_underlying

        # Simulate DNS rebind: validate_target will encounter 127.0.0.1
        with patch("app.services.target_validator.resolve_all_ips", return_value=["127.0.0.1"]):
            with self.assertRaises(SecurityPolicyViolation) as ctx:
                asyncio.run(backend.connect_tcp("attacker-controlled-rebinding.org", 80))

            # Assert underlying socket was NEVER called
            mock_underlying.connect_tcp.assert_not_called()
            self.assertIn("blocked by target safety policy", str(ctx.exception).lower())

    def test_03_private_ip_revalidation(self):
        """
        Test simulated DNS responses for all forbidden addresses:
        127.0.0.1, 10.0.0.1, 172.16.0.1, 192.168.1.1, 169.254.169.254, 100.100.100.200, ::1, fc00::1, fe80::1
        Every single one must be rejected before connection.
        """
        forbidden_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "::1",
            "fc00::1",
            "fe80::1"
        ]

        backend = PinnedNetworkBackend()
        mock_underlying = AsyncMock()
        backend._backend = mock_underlying

        for ip in forbidden_ips:
            with patch("app.services.target_validator.resolve_all_ips", return_value=[ip]):
                with self.assertRaises(SecurityPolicyViolation, msg=f"IP {ip} should have been blocked!"):
                    asyncio.run(backend.connect_tcp("target-audit-domain.org", 443))

            mock_underlying.connect_tcp.assert_not_called()

    def test_04_redirect_rebinding_simulation(self):
        """
        Simulate authorized-target.org -> HTTP 302 -> http://redirect-target.org
        Initial redirect-target resolution: 93.184.216.34.
        Then DNS rebinding changes redirect-target to 127.0.0.1.
        The redirect request MUST NOT connect to localhost and must reject the redirect.
        """
        client = SafeHttpClient(allow_cross_domain_redirects=True)

        resp_302 = MagicMock()
        resp_302.is_redirect = True
        resp_302.status_code = 302
        resp_302.headers = {"Location": "http://redirect-target.org/admin"}

        def mock_resolve(hostname, port=443):
            if "authorized-target" in hostname:
                return ["93.184.216.34"]
            # Rebound destination
            return ["127.0.0.1"]

        with patch("app.services.target_validator.resolve_all_ips", side_effect=mock_resolve):
            with patch("httpx.AsyncClient.request", return_value=resp_302) as mock_req:
                with self.assertRaises(UnsafeRedirectError) as ctx:
                    asyncio.run(client.get("http://authorized-target.org"))

                self.assertIn("unsafe destination", str(ctx.exception).lower())

    def test_05_redirect_scope_enforcement(self):
        """
        Verify:
        authorized-target.org -> https://authorized-target.org/path is allowed (same host).
        authorized-target.org -> http://127.0.0.1/ is blocked.
        authorized-target.org -> http://192.168.1.1/ is blocked.
        authorized-target.org -> http://unrelated-third-party.org is blocked by default scope check.
        """
        client = SafeHttpClient(allow_cross_domain_redirects=False)

        # 1. Blocked: 127.0.0.1
        resp_302_loopback = MagicMock(is_redirect=True, status_code=302, headers={"Location": "http://127.0.0.1/admin"})
        with patch("httpx.AsyncClient.request", return_value=resp_302_loopback):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                with self.assertRaises(UnsafeRedirectError) as ctx:
                    asyncio.run(client.get("http://authorized-target.org"))
                self.assertIn("loopback", str(ctx.exception).lower())

        # 2. Blocked: 192.168.1.1
        resp_302_private = MagicMock(is_redirect=True, status_code=302, headers={"Location": "http://192.168.1.1/admin"})
        with patch("httpx.AsyncClient.request", return_value=resp_302_private):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                with self.assertRaises(UnsafeRedirectError) as ctx:
                    asyncio.run(client.get("http://authorized-target.org"))
                self.assertIn("private", str(ctx.exception).lower())

        # 3. Blocked: External third-party domain
        resp_302_external = MagicMock(is_redirect=True, status_code=302, headers={"Location": "http://external-unrelated.org/login"})
        with patch("httpx.AsyncClient.request", return_value=resp_302_external):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                with self.assertRaises(UnsafeRedirectError) as ctx:
                    asyncio.run(client.get("http://authorized-target.org"))
                self.assertIn("outside authorized scope", str(ctx.exception).lower())

    def test_06_response_size_truncation(self):
        """
        Verify response size truncation at 2MB.
        """
        client = SafeHttpClient()
        large_body = b"A" * (3 * 1024 * 1024)  # 3MB

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = large_body
        mock_resp.url = "http://authorized-target.org"

        with patch("httpx.AsyncClient.request", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                safe_resp = asyncio.run(client.get("http://authorized-target.org"))
                self.assertEqual(len(safe_resp.content_bytes), 2 * 1024 * 1024)
                self.assertEqual(len(safe_resp.text), 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
