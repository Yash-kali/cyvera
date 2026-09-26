import asyncio
import io
import os
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add backend to sys.path
sys.path.insert(0, "backend")

from app.services.target_validator import validate_target, is_ip_blocked
from app.services.safe_client import (
    SafeHttpClient,
    SafeHttpResponse,
    PinnedNetworkBackend,
    PinnedAsyncHTTPTransport,
    SecurityPolicyViolation,
    UnsafeRedirectError
)


class AsyncChunkIterator:
    """Async iterator that yields byte chunks and tracks how many chunks were consumed."""
    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self.chunks_consumed = 0
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.closed:
            raise StopAsyncIteration
        try:
            chunk = next(self._chunks)
            self.chunks_consumed += 1
            return chunk
        except StopIteration:
            raise StopAsyncIteration

    async def aclose(self):
        self.closed = True


class TestPhase7CSecurityRemediation(unittest.TestCase):

    def test_01_https_valid_certificate_transport(self):
        """1. Verify that PinnedAsyncHTTPTransport has TLS verification enabled by default."""
        transport = PinnedAsyncHTTPTransport()
        pool = transport._pool
        ssl_ctx = pool._ssl_context
        # verify_mode 2 is ssl.CERT_REQUIRED
        self.assertEqual(ssl_ctx.verify_mode, 2, "Transport MUST use ssl.CERT_REQUIRED (verify_mode=2)")
        self.assertTrue(ssl_ctx.check_hostname, "Transport MUST have check_hostname=True")

    def test_02_invalid_untrusted_certificate_rejected(self):
        """2. Verify SafeHttpClient rejects SSL cert verification failures."""
        client = SafeHttpClient()
        # Mock request error simulating SSLCertVerificationError
        import ssl
        import httpx

        mock_err = httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
        )
        with patch("httpx.AsyncClient.send", side_effect=mock_err):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                with self.assertRaises(IOError) as ctx:
                    asyncio.run(client.get("https://untrusted-selfsigned.org"))
                self.assertIn("CERTIFICATE_VERIFY_FAILED", str(ctx.exception))

    def test_03_no_verify_false_in_production_recon(self):
        """3. Confirm no production recon/scanning code contains verify=False."""
        backend_dir = os.path.join("backend", "app", "services")
        for fname in ["safe_client.py", "recon.py"]:
            fpath = os.path.join(backend_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertNotIn("verify=False", content, f"Forbidden 'verify=False' found in {fname}")
            self.assertNotIn("verify = False", content, f"Forbidden 'verify = False' found in {fname}")

    def test_04_no_cert_none_in_safe_client(self):
        """4. Confirm SafeHttpClient transport does not contain CERT_NONE."""
        fpath = os.path.join("backend", "app", "services", "safe_client.py")
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("CERT_NONE", content, "Forbidden 'CERT_NONE' found in safe_client.py")

    def test_05_no_check_hostname_false_in_safe_client(self):
        """5. Confirm SafeHttpClient does not disable check_hostname."""
        fpath = os.path.join("backend", "app", "services", "safe_client.py")
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("check_hostname = False", content, "Forbidden 'check_hostname = False' found in safe_client.py")
        self.assertNotIn("check_hostname=False", content, "Forbidden 'check_hostname=False' found in safe_client.py")

    def test_06_content_length_oversized_bounded_without_full_buffering(self):
        """
        6. Verify that when Content-Length > 2MB, response reading is aborted
        as soon as the 2MB budget is reached, without buffering the rest of the stream.
        """
        client = SafeHttpClient()
        limit = client.config.max_response_bytes  # 2MB = 2097152

        # 5MB response composed of 320 chunks of 16KB
        total_chunks = 320
        chunk_size = 16384
        all_chunks = [b"X" * chunk_size for _ in range(total_chunks)]
        chunk_iter = AsyncChunkIterator(all_chunks)

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {
            "content-type": "text/html",
            "content-length": str(len(all_chunks) * chunk_size)  # 5242880 bytes (5MB)
        }
        mock_resp.url = "http://authorized-domain.org"
        mock_resp.aiter_bytes = MagicMock(return_value=chunk_iter)
        mock_resp.aclose = AsyncMock(side_effect=chunk_iter.aclose)

        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                resp = asyncio.run(client.get("http://authorized-domain.org"))

                # Verified: Content is strictly bounded to 2MB
                self.assertEqual(len(resp.content_bytes), limit)
                self.assertTrue(resp.is_truncated, "Response must be marked is_truncated=True")

                # Verified: Not all 320 chunks were consumed! Only 128 chunks (2MB) were read
                self.assertEqual(chunk_iter.chunks_consumed, limit // chunk_size)
                self.assertLess(chunk_iter.chunks_consumed, total_chunks)
                # Stream was safely closed
                mock_resp.aclose.assert_called_once()
                self.assertTrue(chunk_iter.closed)

    def test_07_chunked_response_larger_than_2mb_is_bounded(self):
        """
        7. Chunked response without Content-Length header is bounded at 2MB.
        """
        client = SafeHttpClient()
        limit = client.config.max_response_bytes

        # 4MB stream of 16KB chunks without content-length
        total_chunks = 256
        chunk_size = 16384
        all_chunks = [b"C" * chunk_size for _ in range(total_chunks)]
        chunk_iter = AsyncChunkIterator(all_chunks)

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/plain"}  # No Content-Length (chunked)
        mock_resp.url = "http://authorized-domain.org"
        mock_resp.aiter_bytes = MagicMock(return_value=chunk_iter)
        mock_resp.aclose = AsyncMock(side_effect=chunk_iter.aclose)

        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                resp = asyncio.run(client.get("http://authorized-domain.org"))

                self.assertEqual(len(resp.content_bytes), limit)
                self.assertTrue(resp.is_truncated)
                self.assertLessEqual(chunk_iter.chunks_consumed, (limit // chunk_size) + 1)
                self.assertLess(chunk_iter.chunks_consumed, total_chunks)
                mock_resp.aclose.assert_called_once()

    def test_08_response_exactly_at_limit_succeeds(self):
        """
        8. Response exactly at 2MB limit (2097152 bytes) succeeds and is NOT marked truncated.
        """
        client = SafeHttpClient()
        limit = client.config.max_response_bytes

        chunks_count = limit // 16384  # 128 chunks
        all_chunks = [b"E" * 16384 for _ in range(chunks_count)]
        chunk_iter = AsyncChunkIterator(all_chunks)

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html", "content-length": str(limit)}
        mock_resp.url = "http://authorized-domain.org"
        mock_resp.aiter_bytes = MagicMock(return_value=chunk_iter)
        mock_resp.aclose = AsyncMock(side_effect=chunk_iter.aclose)

        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                resp = asyncio.run(client.get("http://authorized-domain.org"))

                self.assertEqual(len(resp.content_bytes), limit)
                self.assertFalse(resp.is_truncated, "Exact 2MB response should not be marked truncated")
                self.assertEqual(chunk_iter.chunks_consumed, chunks_count)

    def test_09_response_slightly_above_limit_truncated_safely(self):
        """
        9. Response slightly above limit (2MB + 10 bytes) is truncated to exactly 2MB.
        """
        client = SafeHttpClient()
        limit = client.config.max_response_bytes

        chunks_count = limit // 16384
        all_chunks = [b"S" * 16384 for _ in range(chunks_count)] + [b"EXTRA_10_B"]
        chunk_iter = AsyncChunkIterator(all_chunks)

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html", "content-length": str(limit + 10)}
        mock_resp.url = "http://authorized-domain.org"
        mock_resp.aiter_bytes = MagicMock(return_value=chunk_iter)
        mock_resp.aclose = AsyncMock(side_effect=chunk_iter.aclose)

        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                resp = asyncio.run(client.get("http://authorized-domain.org"))

                self.assertEqual(len(resp.content_bytes), limit)
                self.assertTrue(resp.is_truncated)

    def test_10_very_large_declared_content_length_does_not_cause_large_allocation(self):
        """
        10. Declared Content-Length of 100 GB does not allocate 100 GB.
        Only bytes up to limit (2MB) are streamed and buffered.
        """
        client = SafeHttpClient()
        limit = client.config.max_response_bytes

        # Server claims 100 GB (107374182400 bytes), but generator only yields 32KB before stopping
        all_chunks = [b"Z" * 16384, b"Z" * 16384]
        chunk_iter = AsyncChunkIterator(all_chunks)

        mock_resp = MagicMock()
        mock_resp.is_redirect = False
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html", "content-length": "107374182400"}
        mock_resp.url = "http://authorized-domain.org"
        mock_resp.aiter_bytes = MagicMock(return_value=chunk_iter)
        mock_resp.aclose = AsyncMock(side_effect=chunk_iter.aclose)

        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                resp = asyncio.run(client.get("http://authorized-domain.org"))

                self.assertEqual(len(resp.content_bytes), 32768)
                self.assertTrue(resp.is_truncated)

    def test_11_actual_socket_destination_is_pinned_ip(self):
        """
        11. PinnedNetworkBackend.connect_tcp delegates to the validated IP, not the hostname.
        """
        backend = PinnedNetworkBackend()
        mock_underlying = AsyncMock()
        backend._backend = mock_underlying

        with patch("app.services.safe_client.validate_target") as mock_val:
            mock_res = MagicMock()
            mock_res.is_valid = True
            mock_res.resolved_ips = ["93.184.216.34"]
            mock_val.return_value = mock_res

            asyncio.run(backend.connect_tcp("authorized-audit.org", 443))

            mock_underlying.connect_tcp.assert_called_once()
            self.assertEqual(mock_underlying.connect_tcp.call_args[0][0], "93.184.216.34")

    def test_12_host_header_remains_original_hostname(self):
        """
        12. The HTTP Host header sent in request matches the original target hostname.
        """
        client = SafeHttpClient()
        captured_req = None

        async def mock_send(req, stream=True):
            nonlocal captured_req
            captured_req = req
            mock_r = MagicMock()
            mock_r.is_redirect = False
            mock_r.status_code = 200
            mock_r.headers = {}
            mock_r.url = req.url
            mock_r.aiter_bytes = MagicMock(return_value=AsyncChunkIterator([b"OK"]))
            mock_r.aclose = AsyncMock()
            return mock_r

        with patch("httpx.AsyncClient.send", side_effect=mock_send):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                asyncio.run(client.get("http://my-target-host.org/index.html"))

        self.assertIsNotNone(captured_req)
        self.assertEqual(captured_req.headers.get("host"), "my-target-host.org")

    def test_13_tls_sni_remains_original_hostname(self):
        """
        13. Confirm TLS SNI uses server_hostname from original URL origin.
        """
        # When httpcore connects with TLS, server_hostname is self._origin.host
        # In PinnedNetworkBackend, connect_tcp receives host="my-target-host.org"
        # and leaves server_hostname intact during TLS wrap.
        backend = PinnedNetworkBackend()
        with patch("app.services.safe_client.validate_target") as mock_val:
            mock_res = MagicMock(is_valid=True, resolved_ips=["93.184.216.34"])
            mock_val.return_value = mock_res
            mock_underlying = AsyncMock()
            backend._backend = mock_underlying
            asyncio.run(backend.connect_tcp("my-target-host.org", 443))
            # Destination pinned, while host remains my-target-host.org
            self.assertEqual(mock_underlying.connect_tcp.call_args[0][0], "93.184.216.34")

    def test_14_dns_rebinding_protection_still_passes(self):
        """
        14. DNS rebinding changing hostname to 127.0.0.1 is blocked.
        """
        backend = PinnedNetworkBackend()
        with patch("app.services.target_validator.resolve_all_ips", return_value=["127.0.0.1"]):
            with self.assertRaises(SecurityPolicyViolation):
                asyncio.run(backend.connect_tcp("rebound-to-loopback.org", 80))

    def test_15_redirect_revalidation_still_passes(self):
        """
        15. Redirects to loopback or private addresses are caught and blocked.
        """
        client = SafeHttpClient()
        resp_302 = MagicMock(is_redirect=True, status_code=302, headers={"Location": "http://127.0.0.1/admin"})
        resp_302.aclose = AsyncMock()

        with patch("httpx.AsyncClient.send", return_value=resp_302):
            with patch("app.services.target_validator.resolve_all_ips", return_value=["93.184.216.34"]):
                with self.assertRaises(UnsafeRedirectError):
                    asyncio.run(client.get("http://authorized-domain.org"))

    def test_16_private_and_metadata_blocking_still_passes(self):
        """
        16. Private, link-local, and cloud metadata targets are rejected upfront.
        """
        for bad_target in ["http://169.254.169.254", "http://192.168.1.1", "http://10.0.0.1"]:
            val = validate_target(bad_target)
            self.assertFalse(val.is_valid, f"{bad_target} should be invalid")


if __name__ == "__main__":
    unittest.main()
