"""
Phase 8 — Production Hardening Verification Test Suite
=====================================================
62 deterministic tests covering:
  - Configuration safety (config validator, production guards)
  - Security headers (X-Content-Type-Options, X-Frame-Options, CSP, etc.)
  - X-Request-ID correlation middleware
  - Login rate limiting
  - Security event audit logging
  - Database health check endpoint
  - SQLite WAL mode
  - ScanWorker memory cleanup & graceful shutdown
  - Phase 1-7F regression (score=82.5, canonical_findings=4, asset_instances=64)

Run from project root:
  python scratch/verify_phase8_production.py
"""

import sys
import asyncio
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock
import httpx

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

BASE_URL = "http://127.0.0.1:8000"

PASS_COUNT = 0
FAIL_COUNT = 0
FAILURES = []


def run_test(name: str, fn):
    global PASS_COUNT, FAIL_COUNT
    try:
        fn()
        PASS_COUNT += 1
        print(f"  [PASS] {name}")
    except AssertionError as e:
        FAIL_COUNT += 1
        FAILURES.append((name, str(e)))
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        FAIL_COUNT += 1
        FAILURES.append((name, f"{type(e).__name__}: {e}"))
        print(f"  [FAIL] {name}: {type(e).__name__}: {e}")


def get_token() -> str:
    r = httpx.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email_or_username": "Yash",
        "password": "Yash@4050"
    }, timeout=10)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


def health_response():
    return httpx.get(f"{BASE_URL}/api/v1/health", timeout=10)


# ===========================================================================
# SECTION 1 — CONFIGURATION SAFETY
# ===========================================================================
print("\n[SECTION 1] Configuration Safety")


def cfg_01():
    from app.config import settings
    assert settings.PROJECT_NAME == "Cyvera"
    assert settings.ENVIRONMENT in ("development", "production", "staging")


def cfg_02():
    from app.config import settings
    assert settings.SECRET_KEY and len(settings.SECRET_KEY) >= 32


def cfg_03():
    from app.config import Settings
    raised = False
    try:
        Settings(JWT_SECRET_KEY="changeme", ENVIRONMENT="development")
    except (ValueError, Exception):
        raised = True
    assert raised, "Should have raised an error for 'changeme' secret"


def cfg_04():
    from app.config import Settings
    raised = False
    try:
        Settings(JWT_SECRET_KEY="REPLACE_WITH_A_STRONG_RANDOM_SECRET_KEY", ENVIRONMENT="development")
    except (ValueError, Exception):
        raised = True
    assert raised, "Should have raised an error for placeholder secret"


def cfg_05():
    from app.config import settings
    assert settings.ALLOW_PUBLIC_REGISTRATION is False


def cfg_06():
    from app.config import Settings
    raised = False
    try:
        Settings(
            JWT_SECRET_KEY="a" * 64,
            ENVIRONMENT="production",
            OPERATOR_PASSWORD="Yash@4050"
        )
    except (ValueError, Exception):
        raised = True
    assert raised, "Should block weak OPERATOR_PASSWORD in production"


def cfg_07():
    from app.config import Settings
    s = Settings(
        JWT_SECRET_KEY="a" * 64,
        ENVIRONMENT="production",
        OPERATOR_PASSWORD="MyStr0ng!SecureProductionPass2026"
    )
    assert s.DISABLE_API_DOCS is True


def cfg_08():
    from app.config import settings
    assert settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS >= 5
    assert settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS >= 60


def cfg_09():
    from app.config import settings
    assert settings.STALE_SCAN_THRESHOLD_SECONDS > 0


def cfg_10():
    from app.config import settings
    assert settings.SQLITE_WAL_MODE is True


run_test("CFG-01: Settings loads without error", cfg_01)
run_test("CFG-02: JWT_SECRET_KEY is present and non-empty (>=32 chars)", cfg_02)
run_test("CFG-03: 'changeme' JWT_SECRET_KEY rejected at startup", cfg_03)
run_test("CFG-04: Placeholder JWT_SECRET_KEY rejected at startup", cfg_04)
run_test("CFG-05: ALLOW_PUBLIC_REGISTRATION defaults False", cfg_05)
run_test("CFG-06: Production weak OPERATOR_PASSWORD rejected", cfg_06)
run_test("CFG-07: DISABLE_API_DOCS auto-enabled in production", cfg_07)
run_test("CFG-08: LOGIN_RATE_LIMIT settings have sane defaults", cfg_08)
run_test("CFG-09: STALE_SCAN_THRESHOLD_SECONDS is configurable", cfg_09)
run_test("CFG-10: SQLITE_WAL_MODE defaults True", cfg_10)


# ===========================================================================
# SECTION 2 — SECURITY HEADERS & X-REQUEST-ID
# ===========================================================================
print("\n[SECTION 2] Security Headers & X-Request-ID")


def hdr_01():
    r = health_response()
    assert r.headers.get("x-content-type-options") == "nosniff"


def hdr_02():
    r = health_response()
    assert r.headers.get("x-frame-options") == "DENY"


def hdr_03():
    r = health_response()
    assert "no-store" in r.headers.get("cache-control", "")


def hdr_04():
    r = health_response()
    assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


def hdr_05():
    r = health_response()
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors" in csp


def hdr_06():
    r = health_response()
    assert "camera" in r.headers.get("permissions-policy", "")


def hdr_07():
    r = health_response()
    assert "x-request-id" in r.headers
    assert len(r.headers["x-request-id"]) >= 8


def hdr_08():
    custom_id = "test-phase8-correlation-id-99999"
    r = httpx.get(f"{BASE_URL}/api/v1/health", headers={"X-Request-ID": custom_id}, timeout=10)
    assert r.headers.get("x-request-id") == custom_id


def hdr_09():
    r1 = health_response()
    r2 = health_response()
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]


run_test("HDR-01: X-Content-Type-Options: nosniff", hdr_01)
run_test("HDR-02: X-Frame-Options: DENY", hdr_02)
run_test("HDR-03: Cache-Control: no-store", hdr_03)
run_test("HDR-04: Referrer-Policy: strict-origin-when-cross-origin", hdr_04)
run_test("HDR-05: Content-Security-Policy with frame-ancestors", hdr_05)
run_test("HDR-06: Permissions-Policy present", hdr_06)
run_test("HDR-07: X-Request-ID returned in response", hdr_07)
run_test("HDR-08: X-Request-ID echoed when client supplies it", hdr_08)
run_test("HDR-09: X-Request-ID unique across requests", hdr_09)


# ===========================================================================
# SECTION 3 — HEALTH CHECK
# ===========================================================================
print("\n[SECTION 3] Health Check Endpoint")


def hlt_01():
    r = health_response()
    assert r.status_code == 200


def hlt_02():
    r = health_response()
    assert r.json()["status"] == "healthy"


def hlt_03():
    r = health_response()
    data = r.json()
    assert "database" in data
    assert data["database"] in ("healthy", "degraded", "unknown")


def hlt_04():
    r = health_response()
    assert "environment" in r.json()


def hlt_05():
    r = health_response()
    assert r.json().get("version") == "1.0.0"


run_test("HLT-01: /api/v1/health returns 200", hlt_01)
run_test("HLT-02: health.status == 'healthy'", hlt_02)
run_test("HLT-03: health.database field present", hlt_03)
run_test("HLT-04: health.environment field present", hlt_04)
run_test("HLT-05: health.version == '1.0.0'", hlt_05)


# ===========================================================================
# SECTION 4 — LOGIN RATE LIMITER
# ===========================================================================
print("\n[SECTION 4] Login Rate Limiter")


def rl_01():
    from app.main import LoginRateLimiter
    limiter = LoginRateLimiter()
    for _ in range(5):
        assert limiter.check_and_record("1.2.3.4") is True


def rl_02():
    from app.main import LoginRateLimiter
    limiter = LoginRateLimiter()
    for _ in range(10):
        limiter.check_and_record("10.0.0.1")
    assert limiter.check_and_record("10.0.0.1") is False


def rl_03():
    from app.main import LoginRateLimiter
    limiter = LoginRateLimiter()
    for _ in range(10):
        limiter.check_and_record("10.0.0.2")
    assert limiter.check_and_record("10.0.0.2") is False
    limiter.clear("10.0.0.2")
    assert limiter.check_and_record("10.0.0.2") is True


def rl_04():
    from app.main import LoginRateLimiter
    limiter = LoginRateLimiter()
    for _ in range(10):
        limiter.check_and_record("192.168.1.1")
    assert limiter.check_and_record("192.168.1.2") is True


def rl_05():
    from app.main import LoginRateLimiter
    limiter = LoginRateLimiter()
    for _ in range(10):
        limiter.check_and_record("99.99.99.99")
    assert limiter.check_and_record("99.99.99.99") is False


run_test("RL-01: Rate limiter allows within limit", rl_01)
run_test("RL-02: Rate limiter blocks after max attempts", rl_02)
run_test("RL-03: Rate limiter clear() resets counter", rl_03)
run_test("RL-04: Rate limiter isolates different IPs", rl_04)
run_test("RL-05: Rate limiter blocks at limit+1", rl_05)


# ===========================================================================
# SECTION 5 — AUTH & SECURITY
# ===========================================================================
print("\n[SECTION 5] Auth Security & Event Logging")


def auth_01():
    token = get_token()
    assert token and len(token) > 50


def auth_02():
    r = httpx.post(f"{BASE_URL}/api/v1/auth/login", json={
        "email_or_username": "Yash",
        "password": "WrongPassword123!"
    }, timeout=10)
    assert r.status_code == 401


def auth_03():
    r = httpx.post(f"{BASE_URL}/api/v1/auth/ws-ticket", timeout=10)
    assert r.status_code == 401


def auth_04():
    """WS ticket must not be usable as REST API bearer token."""
    from app.auth import create_websocket_ticket
    mock_user = MagicMock()
    mock_user.id = 1
    mock_user.username = "Yash"
    mock_user.password_version = 1
    ws_ticket = create_websocket_ticket(mock_user)
    r = httpx.get(
        f"{BASE_URL}/api/v1/scans",
        headers={"Authorization": f"Bearer {ws_ticket}"},
        timeout=10
    )
    assert r.status_code == 401, "WS ticket must not authenticate REST endpoints"


def auth_05():
    r = httpx.get(
        f"{BASE_URL}/api/v1/scans",
        headers={"Authorization": "Bearer invalid.token.here"},
        timeout=10
    )
    assert r.status_code == 401


run_test("AUTH-01: Valid login returns 200 + token", auth_01)
run_test("AUTH-02: Invalid password returns 401", auth_02)
run_test("AUTH-03: WS ticket endpoint requires auth", auth_03)
run_test("AUTH-04: WS ticket scope rejected by REST endpoints", auth_04)
run_test("AUTH-05: Invalid JWT returns 401", auth_05)


# ===========================================================================
# SECTION 6 — SCAN WORKER RESILIENCE
# ===========================================================================
print("\n[SECTION 6] ScanWorker Resilience")


def wrk_01():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "self.requests_used.pop(scan_id, None)" in src


def wrk_02():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "self.cancellation_requested.pop(scan_id, None)" in src


def wrk_03():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "traceback.print_exc()" not in src


def wrk_04():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "logger.exception(" in src


def wrk_05():
    main_src = (BACKEND / "app" / "main.py").read_text()
    assert "STALE_SCAN_THRESHOLD_SECONDS" in main_src


def wrk_06():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "self.heartbeat_tasks.pop(scan_id, None)" in src


run_test("WRK-01: requests_used dict cleaned in finally block", wrk_01)
run_test("WRK-02: cancellation_requested dict cleaned in finally block", wrk_02)
run_test("WRK-03: traceback.print_exc() removed from scan_worker", wrk_03)
run_test("WRK-04: logger.exception() used for structured error logging", wrk_04)
run_test("WRK-05: recover_stale_scans uses configurable threshold", wrk_05)
run_test("WRK-06: heartbeat_tasks cleaned in finally block", wrk_06)


# ===========================================================================
# SECTION 7 — DATABASE HARDENING
# ===========================================================================
print("\n[SECTION 7] Database Hardening")


def db_01():
    src = (BACKEND / "app" / "database.py").read_text()
    assert "journal_mode=WAL" in src


def db_02():
    src = (BACKEND / "app" / "database.py").read_text()
    # Silent exception swallowing removed
    assert "except Exception:\n            pass" not in src


def db_03():
    src = (BACKEND / "app" / "main.py").read_text()
    assert "SELECT 1" in src


def db_04():
    src = (BACKEND / "app" / "database.py").read_text()
    assert "SQLITE_WAL_MODE" in src


run_test("DB-01: SQLite WAL mode code present in database.py", db_01)
run_test("DB-02: Silent exception swallowing removed from schema migration", db_02)
run_test("DB-03: Database SELECT 1 health probe in health check", db_03)
run_test("DB-04: SQLITE_WAL_MODE setting wired in database init", db_04)


# ===========================================================================
# SECTION 8 — GRACEFUL SHUTDOWN
# ===========================================================================
print("\n[SECTION 8] Graceful Shutdown")


def sht_01():
    src = (BACKEND / "app" / "main.py").read_text()
    assert "_register_shutdown_handlers" in src


def sht_02():
    src = (BACKEND / "app" / "main.py").read_text()
    assert "signal.SIGTERM" in src


def sht_03():
    src = (BACKEND / "app" / "main.py").read_text()
    assert "signal.SIGINT" in src


def sht_04():
    src = (BACKEND / "app" / "main.py").read_text()
    assert '127.0.0.1' in src
    assert '"0.0.0.0"' not in src and "'0.0.0.0'" not in src


run_test("SHT-01: _register_shutdown_handlers function exists", sht_01)
run_test("SHT-02: SIGTERM handler registered", sht_02)
run_test("SHT-03: SIGINT handler registered", sht_03)
run_test("SHT-04: __main__ block binds to 127.0.0.1 not 0.0.0.0", sht_04)


# ===========================================================================
# SECTION 9 — PHASE 1-7F REGRESSION
# ===========================================================================
print("\n[SECTION 9] Phase 1-7F Regression (Non-Regression)")


def reg_01():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/scans/22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    score = r.json().get("security_score")
    assert score is not None
    assert abs(float(score) - 82.5) < 0.1, f"Expected 82.5, got {score}"


def reg_02():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/findings?scan_id=22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    findings = r.json()
    seen = set()
    for f in findings:
        title = f.get("title", "")
        test_type = f.get("test_type", "")
        url = f.get("affected_url", "")
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url
        if test_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY", "Security Misconfiguration"):
            key = (test_type, title, origin)
        else:
            key = (test_type, title, url)
        seen.add(key)
    assert len(seen) == 4, f"Expected 4 canonical findings, got {len(seen)}"


def reg_03():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/findings?scan_id=22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    findings = r.json()
    assert len(findings) == 64, f"Expected 64 asset instances, got {len(findings)}"


def reg_04():
    """Canonical findings = 4, total instances = 64 — deduplication intact."""
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/findings?scan_id=22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    findings = r.json()
    seen = set()
    for f in findings:
        title = f.get("title", "")
        test_type = f.get("test_type", "")
        url = f.get("affected_url", "")
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url
        if test_type in ("SECURITY_HEADERS", "COOKIE_SECURITY", "API_SECURITY", "Security Misconfiguration"):
            key = (test_type, title, origin)
        else:
            key = (test_type, title, url)
        seen.add(key)
    assert len(seen) == 4 and len(findings) == 64


def reg_05():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/scans/22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    data = r.json()
    score_details = data.get("score_details") or {}
    if isinstance(score_details, str):
        import json
        score_details = json.loads(score_details)
    req_used = score_details.get("requests_used", 0)
    assert req_used <= 150, f"Request budget exceeded: {req_used} > 150"


def reg_06():
    src = (BACKEND / "app" / "main.py").read_text()
    assert "scan.user_id != user.id" in src or "Tenant isolation" in src


def reg_07():
    src = (BACKEND / "app" / "services" / "scan_worker.py").read_text()
    assert "import httpx" not in src
    assert "import requests" not in src


def reg_08():
    src = (BACKEND / "app" / "routers" / "scans.py").read_text()
    assert "authorization_confirmed" in src


def reg_09():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/scans",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200


def reg_10():
    token = get_token()
    r = httpx.get(f"{BASE_URL}/api/v1/attack-surface/22",
                  headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assets = data if isinstance(data, list) else data.get("assets", [])
    assert len(assets) > 0


run_test("REG-01: Scan 22 score = 82.5 via REST API", reg_01)
run_test("REG-02: Scan 22 canonical findings = 4 (deduplication)", reg_02)
run_test("REG-03: Scan 22 total affected asset instances = 64", reg_03)
run_test("REG-04: canonical=4, instances=64, zero inflation", reg_04)
run_test("REG-05: HTTP request budget <= 150", reg_05)
run_test("REG-06: Tenant isolation check present in WS endpoint", reg_06)
run_test("REG-07: No raw httpx/requests import in scan_worker", reg_07)
run_test("REG-08: Target authorization check present in scans router", reg_08)
run_test("REG-09: Scan list API returns 200 for authenticated user", reg_09)
run_test("REG-10: Attack surface for scan 22 has assets", reg_10)


# ===========================================================================
# SECTION 10 — API HARDENING & DOCS
# ===========================================================================
print("\n[SECTION 10] API Hardening & Documentation")


def docs_01():
    src = (BACKEND / "app" / "config.py").read_text()
    assert "DISABLE_API_DOCS" in src


def docs_02():
    r = httpx.get(f"{BASE_URL}/api/v1/nonexistent-endpoint-p8-test", timeout=10)
    assert r.status_code == 404


def docs_03():
    r = httpx.post(f"{BASE_URL}/api/v1/auth/login",
                   json={"bad_field": "value"}, timeout=10)
    assert r.status_code == 422
    assert "detail" in r.json()


def docs_04():
    """Rate limiting code present in auth router."""
    src = (BACKEND / "app" / "routers" / "auth.py").read_text()
    assert "login_rate_limiter" in src
    assert "429" in src or "TOO_MANY_REQUESTS" in src


run_test("DOCS-01: DISABLE_API_DOCS flag present in config", docs_01)
run_test("DOCS-02: 404 for unknown endpoint", docs_02)
run_test("DOCS-03: 422 for invalid request payload", docs_03)
run_test("DOCS-04: Rate limiting wired in auth router", docs_04)


# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
print("\n" + "=" * 70)
print("PHASE 8 PRODUCTION HARDENING — FINAL RESULTS")
print("=" * 70)
print(f"  PASSED: {PASS_COUNT}")
print(f"  FAILED: {FAIL_COUNT}")
print(f"  TOTAL:  {PASS_COUNT + FAIL_COUNT}")
print("=" * 70)

if FAIL_COUNT > 0:
    print("\nFAILED TESTS:")
    for name, reason in FAILURES:
        print(f"  [FAIL] {name}: {reason}")

status = "ALL PASS" if FAIL_COUNT == 0 else f"{FAIL_COUNT} FAILURE(S)"
print(f"\nSTATUS: Phase 8 — {status}")

sys.exit(0 if FAIL_COUNT == 0 else 1)
