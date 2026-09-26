# RELEASE READINESS CHECKLIST
# Cyvera / AutoPentest AI — Phase 8

## Release: v1.0.0 Production Hardening

---

## SECTION A — CODE QUALITY & TESTS

| # | Item | Status | Evidence |
|---|------|--------|---------|
| A-01 | Phase 7B tests (Safety & Worker) | PASS | 36 tests |
| A-02 | Phase 7C tests (Real Recon) | PASS | verify_phase7c |
| A-03 | Phase 7D tests (Attack Surface) | PASS | verify_phase7d |
| A-04 | Phase 7E tests (Security Testing) | PASS | 35 tests |
| A-05 | Phase 7E.1 tests (PDF Report) | PASS | verify_phase7e1 |
| A-06 | Phase 7F tests (Real-Time WS) | PASS | 36 tests |
| A-07 | Phase 8 tests (Production Hardening) | PASS | 62 tests |
| A-08 | Frontend production build | PASS | npm run build |
| A-09 | No traceback.print_exc() in production code | PASS | WRK-03 |
| A-10 | No hardcoded secrets in source code | PASS | manual audit |

---

## SECTION B — SECURITY HARDENING

| # | Item | Status | Details |
|---|------|--------|---------|
| B-01 | JWT_SECRET_KEY validated at startup | PASS | config.py validator |
| B-02 | Weak operator password blocked in production | PASS | CFG-06 |
| B-03 | DISABLE_API_DOCS auto-enabled in production | PASS | CFG-07 |
| B-04 | Login rate limiting implemented | PASS | 10 attempts / 5 min |
| B-05 | X-Request-ID correlation middleware | PASS | HDR-07 |
| B-06 | X-Content-Type-Options: nosniff | PASS | HDR-01 |
| B-07 | X-Frame-Options: DENY | PASS | HDR-02 |
| B-08 | Cache-Control: no-store | PASS | HDR-03 |
| B-09 | Content-Security-Policy | PASS | HDR-05 |
| B-10 | Referrer-Policy | PASS | HDR-04 |
| B-11 | Permissions-Policy | PASS | HDR-06 |
| B-12 | HSTS (production only) | PASS | security_headers_middleware |
| B-13 | WS ticket scope isolation | PASS | AUTH-04 |
| B-14 | Session revocation via password_version | PASS | auth.py |
| B-15 | SSRF prevention (SafeHttpClient) | PASS | Phase 7B |
| B-16 | DNS rebinding defense (PinnedNetworkBackend) | PASS | Phase 7B |
| B-17 | Target authorization attestation | PASS | REG-08 |
| B-18 | Multi-tenant isolation (REST + WS) | PASS | REG-06 |
| B-19 | Token scrubbing in logs | PASS | SensitiveUrlFilter |
| B-20 | WS payload secret redaction | PASS | scan_progress.py |

---

## SECTION C — RELIABILITY & RESILIENCE

| # | Item | Status | Details |
|---|------|--------|---------|
| C-01 | ScanWorker heartbeat (3s interval) | PASS | scan_worker.py |
| C-02 | Stale scan crash recovery on startup | PASS | recover_stale_scans() |
| C-03 | Configurable stale threshold | PASS | CFG-09 |
| C-04 | Cooperative cancellation at phase boundaries | PASS | check_cancellation() |
| C-05 | Semaphore-limited concurrency (default 4) | PASS | scan_worker.py |
| C-06 | requests_used dict cleaned after scan | PASS | WRK-01 |
| C-07 | cancellation_requested dict cleaned after scan | PASS | WRK-02 |
| C-08 | heartbeat_tasks dict cleaned after scan | PASS | WRK-06 |
| C-09 | SIGTERM/SIGINT handlers registered | PASS | SHT-02, SHT-03 |
| C-10 | logger.exception() for structured error output | PASS | WRK-04 |
| C-11 | SQLite WAL mode enabled | PASS | DB-01 |
| C-12 | Schema migration errors logged as warnings | PASS | DB-02 |
| C-13 | Database health probe in /api/v1/health | PASS | DB-03 |
| C-14 | __main__ binds to 127.0.0.1 not 0.0.0.0 | PASS | SHT-04 |

---

## SECTION D — DATA INTEGRITY

| # | Item | Status | Details |
|---|------|--------|---------|
| D-01 | Scan 22 score = 82.5 (all layers consistent) | PASS | REG-01 |
| D-02 | Canonical findings = 4 (deduplication) | PASS | REG-02 |
| D-03 | Affected asset instances = 64 | PASS | REG-03 |
| D-04 | Zero canonical finding duplication | PASS | REG-04 |
| D-05 | Request budget <= 150 per scan | PASS | REG-05 |
| D-06 | Score consistent across API / WS / PDF | PASS | Phase 7F verification |
| D-07 | cascade="all, delete-orphan" on all relationships | PASS | models.py audit |
| D-08 | Non-destructive schema migrations | PASS | database.py |

---

## SECTION E — OBSERVABILITY

| # | Item | Status | Details |
|---|------|--------|---------|
| E-01 | X-Request-ID in every response | PASS | HDR-07 |
| E-02 | Audit log for every HTTP request | PASS | audit_logging_middleware |
| E-03 | Request ID in audit logs | PASS | req_id= in format |
| E-04 | LOGIN_SUCCESS security events logged | PASS | auth router |
| E-05 | LOGIN_FAILED security events logged | PASS | auth router |
| E-06 | LOGIN_RATE_LIMITED events logged | PASS | auth router |
| E-07 | Tenant isolation violations logged | PASS | main.py WS endpoint |
| E-08 | Rotating log file (10MB x 5) | PASS | logging_config.py |
| E-09 | Token redaction from all logs | PASS | SensitiveUrlFilter |
| E-10 | health endpoint includes database status | PASS | HLT-03 |

---

## SECTION F — DOCUMENTATION

| # | Item | Status |
|---|------|--------|
| F-01 | PRODUCTION_DEPLOYMENT.md | DONE |
| F-02 | SECURITY_OPERATIONS.md | DONE |
| F-03 | RELEASE_READINESS_CHECKLIST.md (this file) | DONE |
| F-04 | PROJECT_PHASE8_PRODUCTION_AUDIT.md | DONE |
| F-05 | ARCHITECTURE.md | EXISTS |
| F-06 | README.md | EXISTS |
| F-07 | backend/.env.example | EXISTS |

---

## SECTION G — PRE-RELEASE FINAL VERIFICATION

Before tagging a production release, verify the following manually:

- [ ] `ENVIRONMENT=production` in production .env
- [ ] `JWT_SECRET_KEY` is at least 64 hex characters and unique
- [ ] `OPERATOR_PASSWORD` is strong and unique (not a default value)
- [ ] `/docs` returns 404 in production (DISABLE_API_DOCS=true)
- [ ] Health check returns `{"status":"healthy","database":"healthy"}`
- [ ] Login with valid credentials succeeds
- [ ] Login with invalid credentials returns 401
- [ ] 10+ rapid invalid login attempts trigger 429
- [ ] All Phase 8 tests pass: `python scratch/verify_phase8_production.py`
- [ ] All Phase 7F tests pass: `python scratch/verify_phase7f_realtime.py`
- [ ] All Phase 7E tests pass: `python scratch/verify_phase7e_security_testing.py`
- [ ] Frontend production build clean: `npm run build`
- [ ] No hardcoded secrets visible in `git diff` or `git log`
- [ ] `.env` file is in `.gitignore` and not committed

---

## HARD STOP CONDITIONS (Release Blocked If Any Triggered)

| Condition | Check |
|-----------|-------|
| Hardcoded production secret in source | git grep for known secret values |
| Phase 1-7F test regression | Run all verify_phase*.py suites |
| Phase 8 test failure | verify_phase8_production.py ALL PASS |
| Tenant isolation failure | AUTH-04 + REG-06 |
| SafeHttpClient bypass | REG-07 |
| Unauthorized scanning capability | Manual code review |
| Brute force / exploitation code | Manual code review |
| Frontend production build failure | npm run build exit code |

---

## Test Suite Quick Reference

```bash
# Phase 8 (62 tests — production hardening)
python scratch/verify_phase8_production.py

# Phase 7F (36 tests — real-time WebSocket)
python scratch/verify_phase7f_realtime.py

# Phase 7E (35 tests — security testing engine)
python scratch/verify_phase7e_security_testing.py

# Phase 7E.1 (PDF report)
python scratch/verify_phase7e1_pdf_report.py

# Phase 7D (attack surface)
python scratch/verify_phase7d_attack_surface.py

# Phase 7C (real recon)
python scratch/verify_phase7c_real_recon.py

# Frontend production build
cd frontend && npm run build
```

---

## Release Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Lead | | | |
| Engineering Lead | | | |
| QA Lead | | | |
