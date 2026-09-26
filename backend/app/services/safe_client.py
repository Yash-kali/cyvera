import asyncio
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
import httpx
import httpcore

from app.services.target_validator import validate_target
from app.services.scan_config import DEFAULT_SAFETY_CONFIG, ScanSafetyConfig


class SecurityPolicyViolation(Exception):
    """Raised when an outbound HTTP request violates target safety or SSRF policies."""
    pass


class UnsafeRedirectError(SecurityPolicyViolation):
    """Raised when an HTTP redirect targets a private, loopback, or unauthorized destination."""
    pass


class RequestBudgetExceededError(SecurityPolicyViolation):
    """Raised when a scan exceeds its configured request quota or duration limit."""
    pass


@dataclass
class SafeHttpResponse:
    status_code: int
    headers: Dict[str, str]
    text: str
    content_bytes: bytes
    final_url: str
    redirect_history: List[Dict[str, Any]] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    http_version: str = "HTTP/1.1"
    is_truncated: bool = False


SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "cookie"}


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact sensitive authorization tokens, API keys, and cookie secret values."""
    sanitized = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in SENSITIVE_HEADERS:
            sanitized[k] = "[REDACTED]"
        elif kl == "set-cookie":
            parts = v.split(";")
            if parts:
                name_val = parts[0].split("=", 1)
                c_name = name_val[0].strip()
                flags = "; ".join(p.strip() for p in parts[1:])
                sanitized[k] = f"{c_name}=[REDACTED]; {flags}" if flags else f"{c_name}=[REDACTED]"
            else:
                sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    Custom httpcore network backend enforcing socket-level IP pinning and DNS rebinding defense.
    Intercepts connect_tcp(host, port) and strictly establishes the underlying socket connection
    to the pre-validated destination IP while preserving SNI and HTTP Host headers.
    """
    def __init__(self, backend: Optional[httpcore.AsyncNetworkBackend] = None):
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None
    ) -> httpcore.AsyncNetworkStream:
        # Validate target destination before establishing socket
        val_res = validate_target(f"http://{host}:{port}")
        if not val_res.is_valid:
            raise SecurityPolicyViolation(
                f"Socket connection to destination '{host}:{port}' blocked by target safety policy: {val_res.error_message}"
            )

        if not val_res.resolved_ips:
            raise SecurityPolicyViolation(f"No IP addresses resolved for target '{host}'.")

        # Pinned destination IP
        pinned_ip = val_res.resolved_ips[0]

        # Connect directly to the validated IP to defend against DNS rebinding
        return await self._backend.connect_tcp(
            pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options
        )


class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """Async transport utilizing PinnedNetworkBackend for IP-pinned, SSRF-safe HTTP connections."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._pool._ssl_context,
            max_connections=10,
            network_backend=PinnedNetworkBackend()
        )


class TokenBucketRateLimiter:
    """Per-domain token-bucket rate limiter enforcing max requests per second."""
    def __init__(self, rps: float = 5.0):
        self.rps = max(0.5, rps)
        self.capacity = max(1.0, rps)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)

            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rps
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
                self.last_update = time.monotonic()
            else:
                self.tokens -= 1.0


# Cache of rate limiters per domain
_domain_rate_limiters: Dict[str, TokenBucketRateLimiter] = {}


def get_rate_limiter_for_domain(domain: str, rps: float = 5.0) -> TokenBucketRateLimiter:
    clean_domain = domain.lower().strip()
    if clean_domain not in _domain_rate_limiters:
        _domain_rate_limiters[clean_domain] = TokenBucketRateLimiter(rps=rps)
    return _domain_rate_limiters[clean_domain]


class SafeHttpClient:
    """
    Hardened, canonical HTTP Client designed for authorized web security assessment.
    Perimeter Protections:
    1. Pre-request validation of URL, scheme, hostname, and resolved IP addresses.
    2. Socket-level IP Pinning & DNS Rebinding defense via PinnedAsyncHTTPTransport.
    3. Manual redirect traversal: intercepts every 3xx redirect and re-validates destination.
    4. Rejects redirects to localhost, private RFC 1918, RFC 4193, link-local, or cloud metadata.
    5. Enforces same-host scope by default to prevent pivot attacks.
    6. Rate limiting via token-bucket.
    7. Response payload truncation at max_response_bytes (2MB).
    8. Strict redaction of credentials, cookies, and secret tokens in logs/evidence.
    """

    def __init__(
        self,
        config: Optional[ScanSafetyConfig] = None,
        allow_cross_domain_redirects: bool = False
    ):
        self.config = config or DEFAULT_SAFETY_CONFIG
        self.allow_cross_domain_redirects = allow_cross_domain_redirects

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> SafeHttpResponse:
        effective_timeout = timeout or self.config.request_timeout_seconds
        current_url = url
        redirect_history: List[Dict[str, Any]] = []
        start_time = time.monotonic()

        req_headers = {
            "User-Agent": "Cyvera-Security-Scanner/2.0 (+https://autopentest.ai/safety-policy)",
            "Accept": "*/*",
            **(headers or {})
        }

        parsed_origin = urllib.parse.urlparse(url)
        origin_hostname = (parsed_origin.hostname or "").lower()

        transport = PinnedAsyncHTTPTransport()
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=httpx.Timeout(effective_timeout, connect=self.config.connect_timeout_seconds)
        ) as client:
            for hop in range(self.config.max_redirects + 1):
                # 1. SSRF & Target Validation on every hop
                val_res = validate_target(current_url)
                if not val_res.is_valid:
                    if hop > 0:
                        redirect_history.append({
                            "status": "BLOCKED",
                            "from_url": redirect_history[-1]["to_url"] if redirect_history else current_url,
                            "to_url": current_url,
                            "valid": False,
                            "reason": val_res.error_message
                        })
                        raise UnsafeRedirectError(
                            f"Redirect to unsafe destination '{current_url}' rejected: {val_res.error_message}"
                        )
                    raise SecurityPolicyViolation(
                        f"Target request to '{current_url}' rejected: {val_res.error_message}"
                    )

                # Scope check: same-host enforcement
                current_hostname = val_res.hostname.lower()
                if not self.allow_cross_domain_redirects and hop > 0:
                    if current_hostname != origin_hostname:
                        redirect_history.append({
                            "status": "OUT_OF_SCOPE",
                            "from_url": redirect_history[-1]["to_url"] if redirect_history else current_url,
                            "to_url": current_url,
                            "valid": False,
                            "reason": f"External domain redirect to '{current_hostname}' outside authorized scope."
                        })
                        raise UnsafeRedirectError(
                            f"Redirect from '{origin_hostname}' to external domain '{current_hostname}' is outside authorized scope."
                        )

                # 2. Rate Limiting
                limiter = get_rate_limiter_for_domain(current_hostname, self.config.rate_limit_rps)
                await limiter.acquire()

                # 3. Issue HTTP Request with streaming
                try:
                    req = client.build_request(
                        method=method,
                        url=current_url,
                        headers=req_headers,
                        data=data,
                        params=params
                    )
                    resp = await client.send(req, stream=True)
                except httpx.TimeoutException:
                    raise asyncio.TimeoutError(f"HTTP request to '{current_url}' timed out after {effective_timeout}s.")
                except httpx.RequestError as e:
                    raise IOError(f"Network transport error connecting to '{current_url}': {str(e)}")

                # Check for HTTP Redirect (301, 302, 303, 307, 308)
                if resp.is_redirect:
                    location = resp.headers.get("Location")
                    await resp.aclose()
                    if not location:
                        break  # Malformed redirect, treat as terminal response

                    next_url = urllib.parse.urljoin(current_url, location)
                    redirect_history.append({
                        "status_code": resp.status_code,
                        "from_url": current_url,
                        "to_url": next_url,
                        "valid": True,
                        "reason": None
                    })
                    current_url = next_url
                    continue

                # Terminal response reached: bounded streaming enforcement
                limit = self.config.max_response_bytes
                content_length_hdr = resp.headers.get("content-length")
                declared_size = None
                if content_length_hdr:
                    try:
                        declared_size = int(content_length_hdr.strip())
                    except ValueError:
                        declared_size = None

                chunks: List[bytes] = []
                total_bytes = 0
                is_truncated = False

                if declared_size is not None and declared_size > limit:
                    is_truncated = True

                try:
                    async for chunk in resp.aiter_bytes(chunk_size=16384):
                        chunk_len = len(chunk)
                        if total_bytes + chunk_len > limit:
                            allowed = limit - total_bytes
                            if allowed > 0:
                                chunks.append(chunk[:allowed])
                                total_bytes += allowed
                            is_truncated = True
                            break
                        else:
                            chunks.append(chunk)
                            total_bytes += chunk_len
                            if total_bytes >= limit:
                                if declared_size is not None and declared_size > limit:
                                    is_truncated = True
                                    break
                finally:
                    await resp.aclose()

                content = b"".join(chunks)
                elapsed = time.monotonic() - start_time
                http_version = getattr(resp, "http_version", "HTTP/1.1")

                return SafeHttpResponse(
                    status_code=resp.status_code,
                    headers=sanitize_headers(dict(resp.headers)),
                    text=content.decode("utf-8", errors="replace"),
                    content_bytes=content,
                    final_url=str(resp.url),
                    redirect_history=redirect_history,
                    elapsed_seconds=elapsed,
                    http_version=http_version,
                    is_truncated=is_truncated
                )

            raise UnsafeRedirectError(f"Exceeded maximum redirect limit of {self.config.max_redirects} hops.")

    async def get(self, url: str, **kwargs) -> SafeHttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> SafeHttpResponse:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs) -> SafeHttpResponse:
        return await self.request("OPTIONS", url, **kwargs)

    async def head(self, url: str, **kwargs) -> SafeHttpResponse:
        return await self.request("HEAD", url, **kwargs)
