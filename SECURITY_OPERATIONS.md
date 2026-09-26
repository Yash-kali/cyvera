# SECURITY OPERATIONS GUIDE
# Cyvera / AutoPentest AI

## Security Architecture Overview

Cyvera is a **single-operator** web-based security assessment platform. It is
designed to perform non-destructive, authorized security reconnaissance and
surface analysis against explicitly authorized targets.

---

## Authentication & Session Security

### JWT Authentication
- Algorithm: HS256 with a 96-byte (384-bit) random secret key
- Token lifetime: 60 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)
- Claims: `sub` (username), `user_id`, `email`, `pwd_ver`, `exp`, `iat`
- Session revocation: `password_version` claim — changing the operator password
  instantly invalidates all active sessions

### WebSocket Authentication
- Short-lived 60-second WS ticket tokens (scope: `websocket_scan`)
- WS tickets are rejected by all REST API endpoints (scope isolation)
- WS ticket prevents long-lived tokens from being exposed in WebSocket URLs

### Login Rate Limiting
- Configured via `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` (default: 10)
- Window: `LOGIN_RATE_LIMIT_WINDOW_SECONDS` (default: 300 seconds)
- Per-IP in-memory counter; counter cleared on successful login
- Returns HTTP 429 with `Retry-After` header when exceeded

### Password Policy
- Minimum 8 characters
- At least 1 uppercase, 1 lowercase, 1 number, 1 special character
- Known weak operator passwords blocked in production at startup

---

## Security Headers

Every API response includes:

| Header | Value |
|--------|-------|
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| Cache-Control | no-store |
| Pragma | no-cache |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | camera=(), microphone=(), geolocation=(), payment=() |
| Content-Security-Policy | default-src 'none'; frame-ancestors 'none' |
| Strict-Transport-Security | max-age=31536000; includeSubDomains; preload (production only) |

---

## Audit Logging

### Format
```
[timestamp] [LEVEL] [logger] [file:line] - AUDIT | req_id=<uuid> | METHOD /path | status=NNN | Nms | ip=x.x.x.x
```

### Security Events
```
SECURITY | LOGIN_SUCCESS | ip=1.2.3.4 | user='Yash' | user_id=1
SECURITY | LOGIN_FAILED | ip=1.2.3.4 | identifier='Yash'
SECURITY | LOGIN_RATE_LIMITED | ip=1.2.3.4 | identifier='Yash'
```

### Log Scrubbing
- All JWT tokens redacted in logs (`token=[REDACTED]`)
- WS ticket query params scrubbed before logging
- `SensitiveUrlFilter` applied to all uvicorn access logs

### Log Rotation
- `autopentest.log` with rotating handler
- Max 10MB per file, 5 backup files retained
- Total max: 50MB log storage

---

## Target Safety & SSRF Prevention

### SafeHttpClient Controls
1. **Pre-request IP validation**: Target hostname resolved; private/reserved IPs rejected
2. **DNS rebinding protection**: PinnedNetworkBackend pins resolved IP at connection time
3. **SSRF blocklist**: localhost, 169.254.x.x (cloud metadata), RFC 1918 ranges blocked
4. **Redirect safety**: All redirects re-validated against the blocklist
5. **Request budget**: 150 HTTP requests max per scan (hard limit)
6. **Authorization gate**: `authorization_confirmed=true` required for every scan

### Non-Destructive Scanning Policy
- No exploitation, no credential stuffing, no brute force
- Security tests are passive observation-based:
  - HTTP header inspection (no injection)
  - Cookie flag analysis (no session hijacking)
  - SSL/TLS certificate inspection (no downgrade attacks)
  - API endpoint discovery (no fuzzing with malicious payloads)
- All test probes are read-only HTTP GET/HEAD requests

---

## Multi-Tenant Isolation

- All database queries are scoped by `user_id`
- WebSocket connections verify scan ownership before streaming
- Tenant isolation violations are logged at WARNING level
- Attempted cross-tenant scan access returns 4403 (WS) or 403 (REST)

---

## Secrets Management

| Secret | Rotation Frequency | Method |
|--------|-------------------|--------|
| JWT_SECRET_KEY | Annually or after compromise | Update .env → restart |
| OPERATOR_PASSWORD | Per policy (90 days recommended) | Update .env → restart |
| DATABASE_URL | Per policy | Update .env → restart |
| GEMINI_API_KEY | Per Google policy | Update .env → restart |

**Rotation impact:**
- `JWT_SECRET_KEY` rotation: All active sessions invalidated (users must re-login)
- `OPERATOR_PASSWORD` rotation: Session revocation via `password_version` bump

---

## Incident Response

### Suspected Unauthorized Access
1. Immediately rotate `JWT_SECRET_KEY` → forces re-authentication of all sessions
2. Review `autopentest.log` for `SECURITY | LOGIN_*` events
3. Review `AUDIT` log lines for suspicious patterns
4. Check `SECURITY | Tenant isolation violation` warnings

### Scan Worker Failure
1. Failed scans are marked `Failed` status automatically
2. On restart, `recover_stale_scans()` marks any orphaned `Running` scans as `Failed`
3. Stale threshold: `STALE_SCAN_THRESHOLD_SECONDS` (default 60s)

### Database Corruption (SQLite)
1. Stop service
2. Restore from most recent `autopentest.db.YYYYMMDD` backup
3. Restart service

---

## Dependency Security

| Tool | Purpose |
|------|---------|
| `pip-audit` | Scan Python dependencies for known CVEs |
| `npm audit` | Scan Node.js dependencies |

Run periodically:
```bash
# Python
pip install pip-audit
pip-audit -r backend/requirements.txt

# Node.js
cd frontend && npm audit
```

**Key dependency note:** `passlib` is no longer actively maintained. Consider
migrating to `argon2-cffi` for password hashing in a future release.

---

## Penetration Testing Guidelines

This application is designed for operator use only. If you intend to perform
a security assessment of Cyvera itself:

1. Obtain explicit written authorization
2. Use a dedicated testing environment (never production)
3. Do not perform destructive testing (no DoS, no data deletion)
4. Report findings via the standard disclosure process

---

## Compliance Notes

- No PII stored beyond operator email and username
- No scan data transmitted to third parties (Gemini API is optional, opt-in)
- PDF reports stored encrypted-at-rest if database-level encryption is configured
- Audit logs retained per configured rotation policy
