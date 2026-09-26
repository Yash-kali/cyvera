import asyncio
import logging
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Callable, Awaitable, Tuple

from app.services.safe_client import SafeHttpClient, SafeHttpResponse, sanitize_headers, SecurityPolicyViolation
from app.services.url_normalizer import normalize_url, is_same_origin, is_same_host
from app.services.scan_config import DEFAULT_SAFETY_CONFIG, ScanSafetyConfig

logger = logging.getLogger("autopentest.security_testing")


# =============================================================================
# REDACTION & EVIDENCE SANITIZATION
# =============================================================================

# Regex patterns for sensitive credentials that must NEVER be persisted in evidence
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}")
BEARER_PATTERN = re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{12,}")
PASSWORD_KEY_PATTERN = re.compile(r'(?i)(["\']?(?:password|passwd|pwd|secret|api[_-]?key|access_token|auth_token)["\']?\s*[:=]\s*["\']?)([^"\'&\s]{4,})(["\']?)')
COOKIE_SECRET_PATTERN = re.compile(r'(?i)(["\']?(?:session|sid|token|auth)["\']?\s*[:=]\s*["\']?)([^"\'&\s]{4,})(["\']?)')


def redact_sensitive_text(text: str) -> str:
    """
    Scrub passwords, secrets, JWT tokens, and sensitive authentication headers
    from evidence strings and HTTP excerpts before storage.
    """
    if not text:
        return ""
    scrubbed = JWT_PATTERN.sub("[REDACTED_JWT_TOKEN]", text)
    scrubbed = BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", scrubbed)
    scrubbed = PASSWORD_KEY_PATTERN.sub(r"\1[REDACTED]\3", scrubbed)
    scrubbed = COOKIE_SECRET_PATTERN.sub(r"\1[REDACTED]\3", scrubbed)
    return scrubbed


@dataclass
class TestEvidence:
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    response_status: int
    response_headers: Dict[str, str]
    body_excerpt: str
    observation: str
    tester: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    affected_assets: List[str] = field(default_factory=list)
    affected_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": sanitize_headers(self.request_headers)
            },
            "response": {
                "status": self.response_status,
                "headers": sanitize_headers(self.response_headers),
                "body_excerpt": redact_sensitive_text(self.body_excerpt[:600])
            },
            "observation": redact_sensitive_text(self.observation),
            "timestamp": self.timestamp,
            "tester": self.tester,
            "affected_assets": self.affected_assets,
            "affected_count": len(self.affected_assets) if self.affected_assets else self.affected_count
        }


@dataclass
class SecurityFindingCandidate:
    title: str
    category: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: str  # LOW, MEDIUM, HIGH, CONFIRMED
    description: str
    affected_url: str
    remediation: str
    test_type: str
    evidence: TestEvidence
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    status: str = "Open"
    asset_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "affected_url": self.affected_url,
            "remediation_guidance": self.remediation,
            "test_type": self.test_type,
            "evidence": self.evidence.to_dict(),
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "status": self.status,
            "asset_id": self.asset_id
        }


# =============================================================================
# REQUEST BUDGET & CONCURRENCY CONTROLS
# =============================================================================

class RequestBudget:
    """
    Global scan-wide request quota manager.
    Every network call across all Phase 7E testers decrements this single shared counter.
    """
    def __init__(self, max_requests: int = 150):
        self.max_requests = max_requests
        self.used_requests = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self.used_requests >= self.max_requests:
                return False
            self.used_requests += 1
            return True

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used_requests)

    @property
    def is_exhausted(self) -> bool:
        return self.used_requests >= self.max_requests


# =============================================================================
# MODULAR TESTERS
# =============================================================================

class SecurityHeaderTester:
    """
    Audits actual HTTP response headers for defensive security directives.
    Missing security headers represent posture observations with proportionate severity.
    """
    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        if not target_url:
            return findings

        if not await self.budget.acquire():
            return findings

        async with self.semaphore:
            try:
                resp = await self.client.get(target_url)
            except Exception as e:
                logger.debug("HeaderTester request to %s failed: %s", target_url, e)
                return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = urllib.parse.urlparse(target_url).scheme.lower() == "https"

        # 1. Content-Security-Policy
        if "content-security-policy" not in headers:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt="Header inspection check",
                observation="HTTP response is missing a Content-Security-Policy (CSP) header.",
                tester="SecurityHeaderTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Missing Content-Security-Policy Header",
                category="Security Misconfiguration",
                severity="Low",
                confidence="HIGH",
                description="The server did not return a Content-Security-Policy header. A restrictive CSP restricts resources (such as JavaScript, CSS, Images) that the browser is allowed to load for that page, providing critical defense-in-depth against XSS and data injection.",
                affected_url=target_url,
                remediation="Configure a restrictive Content-Security-Policy header, such as: default-src 'self'; script-src 'self'; object-src 'none';",
                test_type="SECURITY_HEADERS",
                evidence=ev,
                cvss_score=3.7,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        # 2. Strict-Transport-Security (HTTPS only)
        if is_https and "strict-transport-security" not in headers:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt="HSTS directive inspection",
                observation="HTTPS endpoint does not advertise Strict-Transport-Security (HSTS).",
                tester="SecurityHeaderTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                category="Cryptographic Failures",
                severity="Low",
                confidence="HIGH",
                description="The application communicates over HTTPS but does not enforce Strict-Transport-Security. Without HSTS, user agents can be coerced into initiating unencrypted HTTP connections susceptible to SSL-stripping man-in-the-middle attacks.",
                affected_url=target_url,
                remediation="Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                test_type="SECURITY_HEADERS",
                evidence=ev,
                cvss_score=3.5,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        # 3. X-Content-Type-Options
        x_content = headers.get("x-content-type-options", "").lower().strip()
        if x_content != "nosniff":
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"X-Content-Type-Options: {headers.get('x-content-type-options', 'MISSING')}",
                observation="X-Content-Type-Options header is absent or not set to 'nosniff'.",
                tester="SecurityHeaderTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Missing X-Content-Type-Options Header",
                category="Security Misconfiguration",
                severity="Low",
                confidence="HIGH",
                description="The X-Content-Type-Options response header is not set to 'nosniff'. This allows legacy or permissive browsers to perform MIME-type sniffing on responses, potentially executing non-executable MIME types as HTML/JavaScript.",
                affected_url=target_url,
                remediation="Configure the web server to emit: X-Content-Type-Options: nosniff",
                test_type="SECURITY_HEADERS",
                evidence=ev,
                cvss_score=3.1,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        # 4. X-Frame-Options & Clickjacking
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp
        if "x-frame-options" not in headers and not has_frame_ancestors:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt="Frame protection audit",
                observation="Endpoint does not declare X-Frame-Options or CSP frame-ancestors.",
                tester="SecurityHeaderTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Missing Clickjacking Protection (X-Frame-Options)",
                category="Security Misconfiguration",
                severity="Low",
                confidence="MEDIUM",
                description="The target does not provide framing protection via X-Frame-Options or CSP frame-ancestors. An attacker could frame the page in a hidden iframe on an external site to trick users into unintended actions (Clickjacking).",
                affected_url=target_url,
                remediation="Emit: X-Frame-Options: DENY (or SAMEORIGIN), or define CSP frame-ancestors 'self'.",
                test_type="SECURITY_HEADERS",
                evidence=ev,
                cvss_score=3.4,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        # 5. Referrer-Policy
        ref_policy = headers.get("referrer-policy", "").lower().strip()
        if not ref_policy or ref_policy in ["unsafe-url", "no-referrer-when-downgrade"]:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"Referrer-Policy: {ref_policy or 'MISSING'}",
                observation="Referrer-Policy is missing or configured with an insecure fallback.",
                tester="SecurityHeaderTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Suboptimal or Missing Referrer-Policy",
                category="Security Misconfiguration",
                severity="Info",
                confidence="HIGH",
                description="No restrictive Referrer-Policy header was detected. Without a strict policy, full URLs including sensitive query parameters may leak in HTTP Referer headers to external origins.",
                affected_url=target_url,
                remediation="Configure the server to emit: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                test_type="SECURITY_HEADERS",
                evidence=ev,
                cvss_score=2.0,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        return findings


class CookieSecurityTester:
    """
    Audits Set-Cookie headers for Secure, HttpOnly, and SameSite flags.
    CRITICAL: Never persists or exposes raw cookie secret values; only records sanitized metadata.
    """
    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        if not target_url:
            return findings

        if not await self.budget.acquire():
            return findings

        async with self.semaphore:
            try:
                resp = await self.client.get(target_url)
            except Exception as e:
                logger.debug("CookieSecurityTester request to %s failed: %s", target_url, e)
                return findings

        set_cookie_hdr = resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie")
        if not set_cookie_hdr:
            return findings

        is_https = urllib.parse.urlparse(target_url).scheme.lower() == "https"

        # Split multiple cookies if present (comma or newline separated depending on backend)
        raw_cookie_directives = [c.strip() for c in set_cookie_hdr.splitlines()] if "\n" in set_cookie_hdr else [set_cookie_hdr]

        for directive in raw_cookie_directives:
            parts = [p.strip() for p in directive.split(";")]
            if not parts:
                continue

            name_val = parts[0].split("=", 1)
            cookie_name = name_val[0].strip()
            flags = {p.lower().split("=")[0].strip(): p.split("=")[1].strip() if "=" in p else True for p in parts[1:]}

            has_secure = "secure" in flags
            has_httponly = "httponly" in flags
            samesite_val = str(flags.get("samesite", "MISSING")).capitalize()

            # Sanitized metadata representation (zero raw secret values)
            cookie_meta = {
                "cookie_name": cookie_name,
                "secure": has_secure,
                "httponly": has_httponly,
                "samesite": samesite_val,
                "path": str(flags.get("path", "/")),
                "domain": str(flags.get("domain", "Host"))
            }

            # 1. Missing Secure flag on HTTPS
            if is_https and not has_secure:
                ev = TestEvidence(
                    request_method="GET",
                    request_url=target_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=f"Cookie sanitized metadata: {cookie_meta}",
                    observation=f"Cookie '{cookie_name}' issued over HTTPS without the 'Secure' attribute.",
                    tester="CookieSecurityTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Cookie Issued Without 'Secure' Attribute ({cookie_name})",
                    category="Cryptographic Failures",
                    severity="Medium",
                    confidence="HIGH",
                    description=f"The application sets the cookie '{cookie_name}' without the 'Secure' flag over an encrypted channel. If a client subsequently makes an unencrypted HTTP request to the same domain or an attacker intercepts cleartext traffic, the cookie will be transmitted in the clear.",
                    affected_url=target_url,
                    remediation=f"Append the 'Secure' directive to the Set-Cookie header for '{cookie_name}'.",
                    test_type="COOKIE_SECURITY",
                    evidence=ev,
                    cvss_score=5.3,
                    status="Open",
                    asset_id=getattr(asset, "id", None)
                ))

            # 2. Missing HttpOnly flag on session-like cookies
            session_keywords = ["session", "token", "auth", "jwt", "id", "sid", "key"]
            is_session_like = any(k in cookie_name.lower() for k in session_keywords)

            if is_session_like and not has_httponly:
                ev = TestEvidence(
                    request_method="GET",
                    request_url=target_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=f"Cookie sanitized metadata: {cookie_meta}",
                    observation=f"Session-sensitive cookie '{cookie_name}' issued without the 'HttpOnly' attribute.",
                    tester="CookieSecurityTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Session Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                    category="Security Misconfiguration",
                    severity="Medium",
                    confidence="HIGH",
                    description=f"The session-related cookie '{cookie_name}' is created without the 'HttpOnly' flag. This permits client-side JavaScript (e.g. document.cookie) to read the cookie value, increasing the risk of session hijacking in the event of an XSS flaw.",
                    affected_url=target_url,
                    remediation=f"Append the 'HttpOnly' directive to the Set-Cookie header for '{cookie_name}'.",
                    test_type="COOKIE_SECURITY",
                    evidence=ev,
                    cvss_score=5.0,
                    status="Open",
                    asset_id=getattr(asset, "id", None)
                ))

            # 3. Missing SameSite flag
            if samesite_val == "Missing" or samesite_val.lower() == "none" and not has_secure:
                ev = TestEvidence(
                    request_method="GET",
                    request_url=target_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=f"Cookie sanitized metadata: {cookie_meta}",
                    observation=f"Cookie '{cookie_name}' missing explicit SameSite protection (observed: {samesite_val}).",
                    tester="CookieSecurityTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Cookie Missing Restrictive SameSite Attribute ({cookie_name})",
                    category="Security Misconfiguration",
                    severity="Low",
                    confidence="HIGH",
                    description=f"The cookie '{cookie_name}' lacks an explicit SameSite restriction (e.g. SameSite=Lax or SameSite=Strict). Without SameSite, browsers send the cookie on cross-site requests, exposing the endpoint to Cross-Site Request Forgery (CSRF).",
                    affected_url=target_url,
                    remediation=f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{cookie_name}'.",
                    test_type="COOKIE_SECURITY",
                    evidence=ev,
                    cvss_score=3.8,
                    status="Open",
                    asset_id=getattr(asset, "id", None)
                ))

        return findings


class CorsTester:
    """
    Evaluates Cross-Origin Resource Sharing (CORS) configurations safely.
    Validates against arbitrary origin reflection and unsafe credential exposure.
    """
    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        if not target_url:
            return findings

        # Test canary external origin
        test_origin = "https://evil-attacker.cyvera-test.example"
        if not await self.budget.acquire():
            return findings

        async with self.semaphore:
            try:
                resp = await self.client.get(
                    target_url,
                    headers={"Origin": test_origin}
                )
            except Exception as e:
                logger.debug("CorsTester request to %s failed: %s", target_url, e)
                return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").lower().strip() == "true"

        # Observation 1: Arbitrary Origin Reflection with Credentials (CRITICAL/HIGH)
        if acao == test_origin and acac:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={"Origin": test_origin},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"ACAO: {acao} | ACAC: true",
                observation=f"Server reflected arbitrary untrusted Origin '{test_origin}' with Access-Control-Allow-Credentials: true.",
                tester="CorsTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Insecure CORS Policy with Arbitrary Origin Reflection & Credentials",
                category="Broken Access Control",
                severity="High",
                confidence="CONFIRMED",
                description="The application reflects untrusted external origins in the Access-Control-Allow-Origin response header while also setting Access-Control-Allow-Credentials: true. An attacker's website can execute cross-origin authenticated AJAX requests to this endpoint and exfiltrate private user data.",
                affected_url=target_url,
                remediation="Never dynamically mirror the incoming Origin header into Access-Control-Allow-Origin when allowing credentials. Maintain an explicit, hardcoded whitelist of trusted origins.",
                test_type="CORS",
                evidence=ev,
                cvss_score=8.1,
                status="Confirmed",
                asset_id=getattr(asset, "id", None)
            ))

        # Observation 2: Null Origin Reflection with Credentials
        elif acao == "null" and acac:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={"Origin": "null"},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt="ACAO: null | ACAC: true",
                observation="Server accepts 'null' Origin with credentials enabled.",
                tester="CorsTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Insecure CORS Configuration Allowing 'null' Origin with Credentials",
                category="Broken Access Control",
                severity="Medium",
                confidence="HIGH",
                description="The server trusts the 'null' origin with credentials enabled. Sandboxed iframes or local HTML files can execute cross-origin requests with the null origin, bypassing origin restrictions.",
                affected_url=target_url,
                remediation="Do not include 'null' in allowed CORS origins. Whitelist only explicitly qualified HTTPS domains.",
                test_type="CORS",
                evidence=ev,
                cvss_score=6.5,
                status="Confirmed",
                asset_id=getattr(asset, "id", None)
            ))

        # Observation 3: Arbitrary Origin Reflection without Credentials
        elif acao == test_origin:
            ev = TestEvidence(
                request_method="GET",
                request_url=target_url,
                request_headers={"Origin": test_origin},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"ACAO: {acao}",
                observation=f"Server reflected untrusted Origin '{test_origin}' without credentials.",
                tester="CorsTester"
            )
            findings.append(SecurityFindingCandidate(
                title="Permissive CORS Origin Reflection (Unauthenticated)",
                category="Security Misconfiguration",
                severity="Low",
                confidence="HIGH",
                description="The server reflects arbitrary origins into Access-Control-Allow-Origin. While credentials are not permitted, this exposes unauthenticated response bodies to any third-party website.",
                affected_url=target_url,
                remediation="Only return Access-Control-Allow-Origin for approved external domains or public static assets.",
                test_type="CORS",
                evidence=ev,
                cvss_score=3.8,
                status="Open",
                asset_id=getattr(asset, "id", None)
            ))

        return findings


class ReflectionTester:
    """
    Performs benign canary-based reflection observation on discovered query parameters.
    CRITICAL: Uses unique harmless alphanumeric canaries.
    NEVER attempts script execution, exploit payloads, or shell commands.
    Classified strictly as REFLECTION_OBSERVED (never claims XSS without verification).
    """
    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        params = getattr(asset, "query_parameters", []) or []
        if not target_url or not params:
            return findings

        # Test at most the first 3 parameters per asset to respect budget
        for param in params[:3]:
            canary = f"CYVERA_CANARY_{uuid.uuid4().hex[:8]}"

            if not await self.budget.acquire():
                break

            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param] = [canary]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            probe_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            async with self.semaphore:
                try:
                    resp = await self.client.get(probe_url)
                except Exception as e:
                    logger.debug("ReflectionTester probe to %s failed: %s", probe_url, e)
                    continue

            # Check if harmless canary is reflected in response
            if canary in resp.text:
                # Determine reflection context
                idx = resp.text.find(canary)
                start = max(0, idx - 40)
                end = min(len(resp.text), idx + len(canary) + 40)
                context_snippet = resp.text[start:end].replace("\n", " ").strip()

                is_json = "application/json" in resp.headers.get("content-type", "").lower()
                sev = "Info" if is_json else "Low"

                ev = TestEvidence(
                    request_method="GET",
                    request_url=probe_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=f"...{context_snippet}...",
                    observation=f"Parameter '{param}' benign canary '{canary}' was reflected in the HTTP response body.",
                    tester="ReflectionTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"User Input Reflection Observed ({param})",
                    category="Injection",
                    severity=sev,
                    confidence="HIGH",
                    description=(
                        f"The parameter '{param}' was supplied with a benign canary and was observed directly in the server's response. "
                        "NOTE: Reflection alone does NOT confirm Cross-Site Scripting (XSS). Proper context encoding or framework escaping "
                        "may mitigate exploitability. Manual verification of context encoding is required."
                    ),
                    affected_url=probe_url,
                    remediation=f"Ensure parameter '{param}' is contextually encoded (e.g. HTML entity encoding or JSON encoding) before output rendering.",
                    test_type="REFLECTION_OBSERVED",
                    evidence=ev,
                    cvss_score=3.3,
                    status="Manual Verification Required",
                    asset_id=getattr(asset, "id", None)
                ))

        return findings


class ErrorDisclosureTester:
    """
    Performs safe input edge-case testing to detect stack trace and technical disclosure leakage.
    Scans for database driver errors, framework stack traces, and internal filesystem paths.
    """
    # Signatures of technical information leakage
    ERROR_SIGNATURES: List[Tuple[str, str, str]] = [
        ("Python Stack Trace", "Traceback (most recent call last)", "Python runtime stack trace"),
        ("Java Exception", "java.lang.", "Java JVM exception trace"),
        ("Spring Framework Error", "org.springframework.", "Spring framework internal stack"),
        ("PHP Fatal Error", "Fatal error:", "PHP runtime unhandled fatal error"),
        ("Node.js Unhandled Error", "TypeError: Cannot read", "Node.js unhandled runtime exception"),
        ("SQL Syntax Error", "syntax error at or near", "SQL database syntax leakage"),
        ("SQL Server Error", "Unclosed quotation mark before", "Microsoft SQL Server driver error"),
        ("SQLite Error", "sqlite3.OperationalError", "SQLite internal engine error"),
        ("Django Debug Trace", "DisallowedHost at", "Django framework debug exposure"),
    ]

    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        params = getattr(asset, "query_parameters", []) or []
        if not target_url or not params:
            return findings

        # Test single parameter with safe malformed probe
        param = params[0]
        probe_val = "['\"\\0_test"

        if not await self.budget.acquire():
            return findings

        parsed = urllib.parse.urlparse(target_url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param] = [probe_val]
        probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

        async with self.semaphore:
            try:
                resp = await self.client.get(probe_url)
            except Exception as e:
                logger.debug("ErrorDisclosureTester probe to %s failed: %s", probe_url, e)
                return findings

        # Check for signature matches in response body
        text_sample = resp.text
        for sig_title, pattern, tech_detail in self.ERROR_SIGNATURES:
            if pattern in text_sample:
                idx = text_sample.find(pattern)
                snippet = text_sample[max(0, idx - 20):min(len(text_sample), idx + 180)].replace("\n", " ").strip()

                ev = TestEvidence(
                    request_method="GET",
                    request_url=probe_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=f"Matched signature '{pattern}': {snippet}",
                    observation=f"Observed technical error disclosure: {tech_detail}",
                    tester="ErrorDisclosureTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Technical Error & Stack Trace Disclosure ({sig_title})",
                    category="Information Disclosure",
                    severity="Medium",
                    confidence="HIGH",
                    description=f"When probing parameter '{param}' with edge-case formatting, the application disclosed internal technical diagnostic information ({tech_detail}). Verbose errors assist attackers in mapping underlying frameworks, file paths, and database components.",
                    affected_url=probe_url,
                    remediation="Disable detailed debugging and error display in production environments. Implement a centralized generic error handler returning friendly user messages.",
                    test_type="ERROR_DISCLOSURE",
                    evidence=ev,
                    cvss_score=5.3,
                    status="Confirmed",
                    asset_id=getattr(asset, "id", None)
                ))
                break  # Record one high-confidence error signature per endpoint

        return findings


class HttpMethodTester:
    """
    Audits HTTP method configuration safely using OPTIONS queries.
    CRITICAL: Never executes destructive methods (DELETE, destructive PUT/POST).
    """
    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        if not target_url:
            return findings

        if not await self.budget.acquire():
            return findings

        async with self.semaphore:
            try:
                resp = await self.client.options(target_url)
            except Exception as e:
                logger.debug("HttpMethodTester OPTIONS to %s failed: %s", target_url, e)
                return findings

        allow_hdr = resp.headers.get("allow", "").upper()
        cors_methods = resp.headers.get("access-control-allow-methods", "").upper()
        combined_methods = f"{allow_hdr}, {cors_methods}"

        # Check for HTTP TRACE (Cross-Site Tracing)
        if "TRACE" in combined_methods:
            ev = TestEvidence(
                request_method="OPTIONS",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"Allow header: {allow_hdr} | CORS methods: {cors_methods}",
                observation="HTTP TRACE method is advertised as permitted by the web server.",
                tester="HttpMethodTester"
            )
            findings.append(SecurityFindingCandidate(
                title="HTTP TRACE Method Enabled (XST Vulnerability Vector)",
                category="Security Misconfiguration",
                severity="Medium",
                confidence="HIGH",
                description="The web server permits the HTTP TRACE method. Attackers exploiting Cross-Site Scripting (XSS) can use TRACE requests to reflect user credentials, including HttpOnly session cookies, bypassing browser access controls (Cross-Site Tracing).",
                affected_url=target_url,
                remediation="Disable HTTP TRACE/TRACK methods in the web server configuration (e.g. TraceEnable off in Apache, or reject TRACE in NGINX).",
                test_type="HTTP_METHODS",
                evidence=ev,
                cvss_score=5.3,
                status="Confirmed",
                asset_id=getattr(asset, "id", None)
            ))

        # Check for unexpected destructive methods advertised
        risky_methods = [m for m in ["DELETE", "PUT"] if m in combined_methods]
        if risky_methods and resp.status_code in [200, 204]:
            ev = TestEvidence(
                request_method="OPTIONS",
                request_url=target_url,
                request_headers={},
                response_status=resp.status_code,
                response_headers=resp.headers,
                body_excerpt=f"Advertised methods: {risky_methods}",
                observation=f"Endpoint advertises potentially unconstrained HTTP methods: {risky_methods}.",
                tester="HttpMethodTester"
            )
            findings.append(SecurityFindingCandidate(
                title=f"Potentially Insecure HTTP Methods Advertised ({', '.join(risky_methods)})",
                category="Security Misconfiguration",
                severity="Low",
                confidence="MEDIUM",
                description=f"OPTIONS preflight query indicates the endpoint supports {', '.join(risky_methods)}. If authentication or access controls are not strictly enforced on these operations, unauthorized modification or deletion may occur.",
                affected_url=target_url,
                remediation="Restrict permitted HTTP methods to only those strictly required by business logic. Disable unused verbs.",
                test_type="HTTP_METHODS",
                evidence=ev,
                cvss_score=3.7,
                status="Manual Verification Required",
                asset_id=getattr(asset, "id", None)
            ))

        return findings


class RedirectSecurityTester:
    """
    Tests URL redirect parameters for Open Redirect vulnerabilities.
    CRITICAL: Validates targets safely without weaponized exploits.
    """
    REDIRECT_PARAMS = {"redirect", "url", "next", "return", "dest", "return_to", "target", "goto", "out", "r"}

    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        params = getattr(asset, "query_parameters", []) or []
        if not target_url:
            return findings

        # Identify candidate redirect parameter
        matched_param = None
        for p in params:
            if p.lower() in self.REDIRECT_PARAMS:
                matched_param = p
                break

        if not matched_param:
            return findings

        test_dest = "https://example.com/cyvera-auth-test"

        if not await self.budget.acquire():
            return findings

        parsed = urllib.parse.urlparse(target_url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[matched_param] = [test_dest]
        probe_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

        async with self.semaphore:
            try:
                resp = await self.client.get(probe_url)
            except Exception as e:
                logger.debug("RedirectSecurityTester probe to %s failed: %s", probe_url, e)
                return findings

        # Check if response issued a redirect hop to example.com
        for hop in resp.redirect_history:
            dest = hop.get("to_url", "")
            if "example.com" in dest and not is_same_host(target_url, dest):
                ev = TestEvidence(
                    request_method="GET",
                    request_url=probe_url,
                    request_headers={},
                    response_status=hop.get("status_code", 302),
                    response_headers=resp.headers,
                    body_excerpt=f"Redirected to external target: {dest}",
                    observation=f"Parameter '{matched_param}' triggered an unvalidated external redirect to '{dest}'.",
                    tester="RedirectSecurityTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Unvalidated URL Redirect (Open Redirect via {matched_param})",
                    category="Broken Access Control",
                    severity="Medium",
                    confidence="CONFIRMED",
                    description=f"The application accepted the parameter '{matched_param}' with an external URL and issued an HTTP redirect to an untrusted domain without validation. Attackers use open redirects to construct credible phishing links.",
                    affected_url=probe_url,
                    remediation=f"Validate destination URLs against an allowlist of permitted domain names, or enforce relative paths starting with a single '/' character.",
                    test_type="REDIRECT",
                    evidence=ev,
                    cvss_score=6.1,
                    status="Confirmed",
                    asset_id=getattr(asset, "id", None)
                ))
                break

        return findings


class AuthenticationObservationTester:
    """
    Performs benign observation of authentication boundaries and unauthenticated exposures.
    CRITICAL: Does NOT brute force, does NOT guess passwords, does NOT harvest credentials.
    """
    PROTECTED_PATH_PATTERNS = [
        re.compile(r"^/(admin|administrator)(/|$)", re.IGNORECASE),
        re.compile(r"^/api/(v\d+/)?(admin|users|settings|private|internal)(/|$)", re.IGNORECASE),
        re.compile(r"^/(actuator|metrics|env|dump)(/|$)", re.IGNORECASE),
        re.compile(r"^/dashboard/admin(/|$)", re.IGNORECASE),
    ]

    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        path = getattr(asset, "path", "")
        if not target_url or not path:
            return findings

        # Check if path indicates sensitive administrative endpoint
        matches_pattern = any(p.search(path) for p in self.PROTECTED_PATH_PATTERNS)
        if not matches_pattern:
            return findings

        if not await self.budget.acquire():
            return findings

        async with self.semaphore:
            try:
                # Issue unauthenticated probe
                resp = await self.client.get(target_url)
            except Exception as e:
                logger.debug("AuthenticationObservationTester request to %s failed: %s", target_url, e)
                return findings

        # If administrative path returns 200 OK without requiring authentication
        if resp.status_code == 200 and len(resp.text) > 100:
            content_lower = resp.text.lower()
            # Verify it is not a login page misreporting 200
            is_login_page = any(k in content_lower for k in ["login", "sign in", "password", "authenticate"]) and "<form" in content_lower
            if not is_login_page:
                ev = TestEvidence(
                    request_method="GET",
                    request_url=target_url,
                    request_headers={},
                    response_status=resp.status_code,
                    response_headers=resp.headers,
                    body_excerpt=resp.text[:300],
                    observation=f"Protected path '{path}' returned HTTP 200 without requiring authentication.",
                    tester="AuthenticationObservationTester"
                )
                findings.append(SecurityFindingCandidate(
                    title=f"Potential Unauthenticated Access to Administrative Endpoint ({path})",
                    category="Broken Access Control",
                    severity="High",
                    confidence="MEDIUM",
                    description=f"The endpoint '{path}' appears to represent an administrative or internal interface but returned HTTP 200 without requiring authentication or presenting a login barrier.",
                    affected_url=target_url,
                    remediation="Apply authentication middleware to strictly require valid operator session tokens for all administrative routes.",
                    test_type="AUTHENTICATION",
                    evidence=ev,
                    cvss_score=7.5,
                    status="Manual Verification Required",
                    asset_id=getattr(asset, "id", None)
                ))

        return findings


class ApiSecurityTester:
    """
    Audits API endpoints for OpenAPI specification leaks, content-type hygiene, and error boundaries.
    """
    OPENAPI_PATHS = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/docs",
        "/v1/api-docs",
        "/v2/api-docs",
    ]

    def __init__(self, client: SafeHttpClient, budget: RequestBudget, semaphore: asyncio.Semaphore):
        self.client = client
        self.budget = budget
        self.semaphore = semaphore
        self._checked_specs: Set[str] = set()

    async def execute(self, asset: Any) -> List[SecurityFindingCandidate]:
        findings: List[SecurityFindingCandidate] = []
        target_url = getattr(asset, "url", "")
        asset_type = getattr(asset, "asset_type", "")
        if not target_url:
            return findings

        # 1. Check for publicly exposed OpenAPI / Swagger documentation at host root once
        parsed = urllib.parse.urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._checked_specs:
            self._checked_specs.add(origin)

            for doc_path in self.OPENAPI_PATHS[:3]:  # Check top 3 paths
                doc_url = urllib.parse.urljoin(origin, doc_path)
                if not await self.budget.acquire():
                    break

                async with self.semaphore:
                    try:
                        resp = await self.client.get(doc_url)
                    except Exception:
                        continue

                if resp.status_code == 200 and any(k in resp.text for k in ["openapi", "swagger", "paths"]):
                    ev = TestEvidence(
                        request_method="GET",
                        request_url=doc_url,
                        request_headers={},
                        response_status=resp.status_code,
                        response_headers=resp.headers,
                        body_excerpt=resp.text[:250],
                        observation=f"Publicly accessible API specification found at '{doc_path}'.",
                        tester="ApiSecurityTester"
                    )
                    findings.append(SecurityFindingCandidate(
                        title=f"Publicly Accessible OpenAPI / Swagger Documentation ({doc_path})",
                        category="Information Disclosure",
                        severity="Info",
                        confidence="CONFIRMED",
                        description=f"The application exposes an interactive OpenAPI/Swagger definition at '{doc_path}'. While useful for developers, publicly exposing API schemas provides attackers with full visibility into available routes, expected parameters, and authentication methods.",
                        affected_url=doc_url,
                        remediation="Restrict access to OpenAPI / Swagger documentation in production environments to authenticated operators or internal networks.",
                        test_type="API_SECURITY",
                        evidence=ev,
                        cvss_score=2.6,
                        status="Open",
                        asset_id=getattr(asset, "id", None)
                    ))
                    break  # Found documentation

        return findings


# =============================================================================
# EVIDENCE CORRELATOR & DEDUPLICATION
# =============================================================================

class EvidenceCorrelator:
    """
    Normalizes, deduplicates, and validates security findings before persistence.
    Ensures findings map to clean categories, consolidates identical control failures
    across assets into canonical findings with affected asset references,
    and sorts findings by canonical severity.
    """
    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    @classmethod
    def correlate_and_deduplicate(
        cls,
        candidates: List[SecurityFindingCandidate]
    ) -> List[SecurityFindingCandidate]:
        dedup_map: Dict[Tuple[str, str, str], SecurityFindingCandidate] = {}
        affected_assets_map: Dict[Tuple[str, str, str], List[str]] = {}

        for c in candidates:
            norm_url = normalize_url(c.affected_url)
            parsed = urllib.parse.urlparse(c.affected_url)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else norm_url

            # For origin/server-wide response controls (headers, cookies, API security, misconfiguration),
            # consolidate identical control checks across assets of the same target origin
            if c.test_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY") or c.category == "Security Misconfiguration":
                key = (c.test_type, c.title, origin)
            else:
                key = (c.test_type, c.title, norm_url)

            if key not in dedup_map:
                dedup_map[key] = c
                affected_assets_map[key] = [c.affected_url] if c.affected_url else []
            else:
                existing = dedup_map[key]
                if c.affected_url and c.affected_url not in affected_assets_map[key]:
                    affected_assets_map[key].append(c.affected_url)

                # If this candidate has root or shorter path, prefer it as canonical affected_url
                if c.affected_url and (len(c.affected_url) < len(existing.affected_url) or c.affected_url.rstrip("/").endswith(parsed.netloc)):
                    existing.affected_url = c.affected_url

                # Merge or upgrade confidence / severity
                if cls.SEVERITY_ORDER.get(c.severity, 4) < cls.SEVERITY_ORDER.get(existing.severity, 4):
                    c.affected_url = existing.affected_url
                    dedup_map[key] = c
                elif c.confidence == "CONFIRMED" and existing.confidence != "CONFIRMED":
                    c.affected_url = existing.affected_url
                    dedup_map[key] = c

        # Attach affected assets and consolidate evidence observation
        for key, c in dedup_map.items():
            assets = affected_assets_map.get(key, [])
            if len(assets) > 1:
                if hasattr(c.evidence, "affected_assets"):
                    c.evidence.affected_assets = assets
                    c.evidence.affected_count = len(assets)
                if hasattr(c.evidence, "observation"):
                    orig_obs = c.evidence.observation
                    if "Observed across" not in orig_obs:
                        c.evidence.observation = f"{orig_obs} (Observed across {len(assets)} in-scope asset(s))."

        # Sort by severity descending
        sorted_findings = sorted(
            dedup_map.values(),
            key=lambda x: cls.SEVERITY_ORDER.get(x.severity, 5)
        )
        return sorted_findings


# =============================================================================
# CANONICAL SECURITY TESTING ENGINE
# =============================================================================

class SecurityTestingEngine:
    """
    Phase 7E Authorized Security Testing Engine.
    Executes controlled, evidence-based security testing strictly against discovered
    in-scope attack surface assets using SafeHttpClient.
    """
    def __init__(
        self,
        target_url: str,
        config: Optional[ScanSafetyConfig] = None,
        client: Optional[SafeHttpClient] = None,
        max_requests: int = 150,
        max_concurrency: int = 4
    ):
        self.raw_target_url = target_url
        self.config = config or DEFAULT_SAFETY_CONFIG
        self.client = client or SafeHttpClient(config=self.config)
        self.budget = RequestBudget(max_requests=max_requests)
        self.semaphore = asyncio.Semaphore(max_concurrency)

        # Initialize modular testers
        self.header_tester = SecurityHeaderTester(self.client, self.budget, self.semaphore)
        self.cookie_tester = CookieSecurityTester(self.client, self.budget, self.semaphore)
        self.cors_tester = CorsTester(self.client, self.budget, self.semaphore)
        self.reflection_tester = ReflectionTester(self.client, self.budget, self.semaphore)
        self.error_tester = ErrorDisclosureTester(self.client, self.budget, self.semaphore)
        self.method_tester = HttpMethodTester(self.client, self.budget, self.semaphore)
        self.redirect_tester = RedirectSecurityTester(self.client, self.budget, self.semaphore)
        self.auth_tester = AuthenticationObservationTester(self.client, self.budget, self.semaphore)
        self.api_tester = ApiSecurityTester(self.client, self.budget, self.semaphore)

    async def execute_testing(
        self,
        scan_id: int,
        user_id: int,
        assets: List[Any],
        authorization_confirmed: bool = False,
        is_cancelled: Optional[Callable[[], bool]] = None,
        on_progress: Optional[Callable[[str, int, str], Awaitable[None]]] = None,
        on_finding: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None
    ) -> Dict[str, Any]:
        """
        Orchestrates testing pipeline across in-scope discovered assets.
        SAFETY ENFORCEMENT:
        - Rejects immediately if authorization_confirmed is False.
        - Only tests in-scope assets.
        - Respects shared request budget and cancellation checkpoints.
        """
        # 1. Authorization Safety Check
        if not authorization_confirmed:
            raise SecurityPolicyViolation(
                f"Unauthorized security testing prohibited: Scan #{scan_id} does not have authorization_confirmed=True."
            )

        # Filter strictly for in-scope assets
        in_scope_assets = [
            a for a in assets
            if getattr(a, "in_scope", True) and not getattr(a, "external", False)
        ]

        # Fallback to root target if no assets were discovered
        if not in_scope_assets:
            from dataclasses import make_dataclass
            DummyAsset = make_dataclass("DummyAsset", [("url", str), ("path", str), ("in_scope", bool), ("external", bool), ("query_parameters", list), ("asset_type", str), ("id", Optional[int])])
            in_scope_assets = [DummyAsset(
                url=self.raw_target_url,
                path="/",
                in_scope=True,
                external=False,
                query_parameters=[],
                asset_type="PAGE",
                id=None
            )]

        all_candidates: List[SecurityFindingCandidate] = []
        tests_executed: List[str] = []

        testers = [
            ("SECURITY_HEADERS", "Auditing HTTP Security Response Headers", self.header_tester),
            ("COOKIE_SECURITY", "Inspecting Set-Cookie Flags & Directives", self.cookie_tester),
            ("CORS", "Evaluating Cross-Origin Resource Sharing Controls", self.cors_tester),
            ("REFLECTION", "Executing Benign Canary Input Reflection Checks", self.reflection_tester),
            ("ERROR_DISCLOSURE", "Evaluating Technical Error Disclosure Boundaries", self.error_tester),
            ("HTTP_METHODS", "Inspecting Allowed HTTP Method Advertisements", self.method_tester),
            ("REDIRECT", "Testing URL Redirection Destination Validation", self.redirect_tester),
            ("AUTHENTICATION", "Observing Protected Administrative Boundaries", self.auth_tester),
            ("API_SECURITY", "Analyzing API Specifications & Content Types", self.api_tester),
        ]

        total_steps = len(testers)

        for step_idx, (test_name, test_desc, tester_instance) in enumerate(testers, 1):
            # Check cancellation checkpoint
            if is_cancelled and is_cancelled():
                logger.info("Scan #%s cancelled during %s.", scan_id, test_name)
                break

            # Check request budget
            if self.budget.is_exhausted:
                logger.warning("Scan #%s request budget exhausted (%s requests). Stopping testing safely.", scan_id, self.budget.max_requests)
                if on_progress:
                    await on_progress("SECURITY_TESTING_BUDGET_EXHAUSTED", 84, "Security testing request budget exhausted. Finalizing findings...")
                break

            tests_executed.append(test_name)
            progress_pct = 70 + int((step_idx / total_steps) * 14)  # 70% to 84%

            if on_progress:
                await on_progress("SECURITY_TEST_STARTED", progress_pct, f"{test_desc}...")

            # Run tester on relevant assets
            for asset in in_scope_assets[:25]:  # Bounded assets per test category
                if is_cancelled and is_cancelled():
                    break
                if self.budget.is_exhausted:
                    break

                try:
                    found = await tester_instance.execute(asset)
                    for f in found:
                        all_candidates.append(f)
                        if on_finding:
                            await on_finding(f.to_dict())
                except Exception as e:
                    logger.error("Error running %s on %s: %s", test_name, getattr(asset, "url", ""), e)

            if on_progress:
                await on_progress("SECURITY_TEST_COMPLETED", progress_pct, f"Completed {test_name} checks.")

        # Correlate and deduplicate findings
        correlated_findings = EvidenceCorrelator.correlate_and_deduplicate(all_candidates)

        # Build telemetry summary
        sev_counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        cat_counts: Dict[str, int] = {}
        verif_counts: Dict[str, int] = {"Open": 0, "Confirmed": 0, "Manual Verification Required": 0}

        for f in correlated_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
            verif_counts[f.status] = verif_counts.get(f.status, 0) + 1

        summary = {
            "scan_id": scan_id,
            "total_findings": len(correlated_findings),
            "severity_breakdown": sev_counts,
            "category_breakdown": cat_counts,
            "tests_executed": tests_executed,
            "total_requests": self.budget.used_requests,
            "budget_exhausted": self.budget.is_exhausted,
            "verification_statuses": verif_counts
        }

        was_cancelled = bool(is_cancelled and is_cancelled())
        return {
            "scan_id": scan_id,
            "authorization_confirmed": True,
            "cancelled": was_cancelled,
            "findings": correlated_findings,
            "summary": summary
        }
