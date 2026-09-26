import signal
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import init_db
from app.logging_config import logger
from app.routers import (
    auth, scans, recon, findings, analytics, ai, reports,
    security_score, owasp, chat,
    settings as settings_router,
    attack_surface, security_testing
)


# ---------------------------------------------------------------------------
# Phase 8: Login Rate Limiter (in-memory, per-IP)
# ---------------------------------------------------------------------------
class LoginRateLimiter:
    """
    Simple in-memory per-IP login attempt rate limiter.
    Tracks attempt timestamps within a sliding window and blocks IPs that
    exceed LOGIN_RATE_LIMIT_MAX_ATTEMPTS within LOGIN_RATE_LIMIT_WINDOW_SECONDS.
    """
    def __init__(self):
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check_and_record(self, client_ip: str) -> bool:
        """
        Record a login attempt for the given IP.
        Returns True if the attempt is allowed, False if rate limited.
        """
        now = time.monotonic()
        window = settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS
        max_attempts = settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS

        # Prune stale timestamps outside the current window
        self._attempts[client_ip] = [
            ts for ts in self._attempts[client_ip] if (now - ts) < window
        ]

        if len(self._attempts[client_ip]) >= max_attempts:
            return False

        self._attempts[client_ip].append(now)
        return True

    def clear(self, client_ip: str) -> None:
        """Clear rate limit state for an IP after a successful login."""
        self._attempts.pop(client_ip, None)


# Global rate limiter instance — imported by the auth router
login_rate_limiter = LoginRateLimiter()


# ---------------------------------------------------------------------------
# Phase 8: Graceful Shutdown Signal Handlers
# ---------------------------------------------------------------------------
def _register_shutdown_handlers():
    """Register SIGTERM / SIGINT handlers for graceful shutdown notification."""
    def _handle_signal(sig, frame):
        logger.warning(
            f"[SHUTDOWN] Received signal {sig}. Initiating graceful shutdown. "
            "Active scans will be recovered as Failed on next startup."
        )

    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
    except (OSError, ValueError):
        # Signal registration fails in non-main threads (e.g., pytest workers)
        pass


# ---------------------------------------------------------------------------
# Lifespan: startup + shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler: database init, stale scan recovery, shutdown."""
    logger.info(
        f"[STARTUP] Starting {settings.PROJECT_NAME} (Env: {settings.ENVIRONMENT}) ..."
    )
    try:
        await init_db()
        logger.info("[STARTUP] Database tables initialized & verified.")

        # Crash recovery for stale worker scans
        from app.services.scan_worker import scan_worker
        threshold = settings.STALE_SCAN_THRESHOLD_SECONDS
        recovered = await scan_worker.recover_stale_scans(
            stale_threshold_seconds=threshold
        )
        if recovered > 0:
            logger.warning(
                f"[STARTUP] Crash recovery: Recovered {recovered} orphaned scan(s) -> marked Failed."
            )
    except Exception as e:
        logger.warning(f"[STARTUP] Database initialization note: {e}")

    _register_shutdown_handlers()
    logger.info(f"[STARTUP] {settings.PROJECT_NAME} ready.")

    yield

    logger.info(f"[SHUTDOWN] {settings.PROJECT_NAME} shutting down gracefully.")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
_docs_url = None if settings.DISABLE_API_DOCS else "/docs"
_redoc_url = None if settings.DISABLE_API_DOCS else "/redoc"
_openapi_url = None if settings.DISABLE_API_DOCS else "/openapi.json"

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AutoPentest AI — Production Automated Cybersecurity Operations Platform",
    version="1.0.0",
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Phase 8 Middlewares
# ---------------------------------------------------------------------------

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Phase 8: Assign a unique X-Request-ID to every request for end-to-end tracing.
    Uses client-supplied ID if provided, otherwise generates a new UUID4.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Phase 8: Inject OWASP-recommended security response headers on every response.
    Protects against MIME sniffing, clickjacking, and information leakage.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    # HSTS only in production (requires HTTPS)
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    return response


@app.middleware("http")
async def audit_logging_middleware(request: Request, call_next):
    """
    Phase 8: Structured audit log for every HTTP request.
    Includes X-Request-ID correlation, method, path, status, latency, and client IP.
    """
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    request_id = getattr(request.state, "request_id", "-")

    logger.info(
        f"AUDIT | req_id={request_id} | {request.method} {request.url.path} "
        f"| status={response.status_code} | {duration_ms}ms "
        f"| ip={request.client.host if request.client else 'unknown'}"
    )
    return response


# ---------------------------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------------------------

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    request_id = getattr(request.state, "request_id", "-")
    logger.warning(
        f"HTTP {exc.status_code} on {request.url.path} [req_id={request_id}]: {exc.detail}"
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
            "request_id": request_id
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", "-")
    logger.warning(
        f"Validation Error on {request.url.path} [req_id={request_id}]: {exc.errors()}"
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request payload validation failed.",
            "errors": jsonable_encoder(exc.errors()),
            "request_id": request_id
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", "-")
    logger.error(
        f"Unhandled Internal Server Error on {request.url.path} "
        f"[req_id={request_id}]: {exc}",
        exc_info=True
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred. Our security engineering team has been notified.",
            "request_id": request_id
        }
    )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(recon.router)
app.include_router(findings.router)
app.include_router(analytics.router)
app.include_router(ai.router)
app.include_router(reports.router)
app.include_router(security_score.router)
app.include_router(owasp.router)
app.include_router(chat.router)
app.include_router(settings_router.router)
app.include_router(attack_surface.router)
app.include_router(security_testing.router)


# ---------------------------------------------------------------------------
# WebSocket: /ws/scans/{scan_id}
# ---------------------------------------------------------------------------
from fastapi import WebSocket, WebSocketDisconnect, Query
from app.services.scan_progress import progress_manager


@app.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress(
    websocket: WebSocket,
    scan_id: int,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint: /ws/scans/{scan_id}
    Streams real-time scan progress payloads with strict JWT authentication and tenant isolation.
    """
    # 1. Token retrieval: Cookie -> Authorization header -> Query param
    if not token:
        cookie_token = (
            websocket.cookies.get("ws_ticket")
            or websocket.cookies.get("autopentest_session")
            or websocket.cookies.get("access_token")
        )
        if cookie_token:
            token = cookie_token

    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        await websocket.close(code=4401, reason="Authentication token required")
        return

    from app.auth import verify_websocket_token
    token_data = verify_websocket_token(token)
    if not token_data or not token_data.username:
        await websocket.close(code=4401, reason="Invalid or expired access token")
        return

    # 2. Strict tenant isolation check against database
    from app.database import AsyncSessionLocal
    from app.models import User, Scan
    from sqlalchemy.future import select

    async with AsyncSessionLocal() as session:
        stmt_user = select(User).where(User.username == token_data.username)
        res_user = await session.execute(stmt_user)
        user = res_user.scalars().first()

        if not user:
            await websocket.close(code=4401, reason="User account not found")
            return

        stmt_scan = select(Scan).where(Scan.id == scan_id)
        res_scan = await session.execute(stmt_scan)
        scan = res_scan.scalars().first()

        if not scan:
            await websocket.close(code=4404, reason="Scan record not found")
            return

        if scan.user_id != user.id and not getattr(user, "is_superuser", False):
            logger.warning(
                f"Tenant isolation violation attempt: User #{user.id} ({user.username}) "
                f"tried accessing Scan #{scan_id} owned by User #{scan.user_id}"
            )
            await websocket.close(code=4403, reason="Forbidden: Multi-tenant scan access denied")
            return

        # 3. Connection accepted & registered (authoritatively reconciled against DB record)
        await progress_manager.connect(websocket, scan_id, scan=scan)

    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        progress_manager.disconnect(websocket, scan_id)
    except Exception:
        progress_manager.disconnect(websocket, scan_id)


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """
    Production health check endpoint.
    Phase 8: Includes a basic DB connectivity probe and environment metadata.
    """
    db_status = "unknown"
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        logger.warning(f"Health check DB probe failed: {e}")
        db_status = "degraded"

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "app": settings.PROJECT_NAME,
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "database": db_status,
        "timestamp": time.time()
    }


if __name__ == "__main__":
    import uvicorn
    # Development only: bind to loopback to prevent accidental exposure
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
