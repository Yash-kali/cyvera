# AutoPentest AI / Cyvera — Phase 7F Real-Time Orchestration & WebSocket Audit

## Executive Summary

Phase 7F delivers an end-to-end real-time scanning orchestration experience connecting the frontend web application with the persistent backend scan worker via authenticated WebSockets, canonical stage-weighted progress telemetry, live asset/finding emission, cooperative cancellation, heartbeat vitality tracking, and database-backed state reconciliation.

All progress telemetry is truthful and rooted in actual backend work performed during target validation, reconnaissance, attack surface discovery, authorized security testing, and ReportLab PDF compilation.

> **CRITICAL COMPLIANCE STATEMENT:**
> Phase 7F does **NOT** introduce exploitation, credential attacks, brute force, destructive testing, or unauthorized scanning. All activities remain strictly non-destructive, rate-limited, and operator-controlled.

---

## 1. System Architecture

```
+----------------------------------------------------------------------------------------------------+
|                                      FRONTEND (React + Vite)                                       |
|                                                                                                    |
|   +-----------------------+     +-------------------------------+     +------------------------+   |
|   | Dashboard & Queue     |     | Real-Time Command Center      |     | Execution Timeline     |   |
|   | (Live telemetry feeds)|     | (Progress, budget, heartbeat) |     | (7 canonical stages)   |   |
|   +-----------+-----------+     +---------------+---------------+     +-----------+------------+   |
|               |                                 |                                 |                |
|               |                                 v                                 |                |
|               |                    useScanProgress React Hook                     |                |
|               |                    - Authenticated WS client                      |                |
|               |                    - Reconnect & state reconciler                 |                |
|               |                    - Polling fallback                             |                |
+---------------+---------------------------------+---------------------------------+----------------+
                |                                 |
   HTTP REST    |                                 | WebSocket (/ws/scans/{id}?token=JWT)
   Endpoints    |                                 | Authenticated & Tenant-Isolated
                v                                 v
+---------------+---------------------------------+--------------------------------------------------+
|                                    BACKEND (FastAPI Engine)                                        |
|                                                                                                    |
|   +------------------------+    +-----------------------------+    +---------------------------+   |
|   | Authenticated Router   |    | WebSocket Gatekeeper        |    | ScanProgressManager       |   |
|   | POST /api/v1/scans     |    | - JWT query validation      |    | - Canonical schema        |   |
|   | POST /scans/{id}/cancel|    | - Ownership check (4403)    |    | - Secret redaction        |   |
|   | GET  /scans/status/{id}|    | - Ping/pong keepalive       |    | - Deduplicated broadcasts |   |
|   +-----------+------------+    +--------------+--------------+    +-------------+-------------+   |
|               |                                |                                 ^                 |
|               v                                v                                 | Events          |
|   +------------------------------------------------------------------------------+-------------+   |
|   |                               Persistent ScanWorker                                        |   |
|   |   - Lifecycle Orchestration (Validation -> Recon -> Discovery -> Testing -> Scoring -> PDF) |   |
|   |   - 150 HTTP Request Global Budget                                                         |   |
|   |   - Cooperative Cancellation Checkpoints (is_cancelled)                                    |   |
|   |   - 3-second Vitality Heartbeat Loop                                                       |   |
|   |   - Strict SafeHttpClient Transport (SSRF & DNS-rebinding defense)                         |   |
|   +--------------------------------------------+-----------------------------------------------+   |
+------------------------------------------------|---------------------------------------------------+
                                                 v
                                   +---------------------------+
                                   | SQLite / PostgreSQL DB    |
                                   | (Authoritative Ground     |
                                   |  Truth State)             |
                                   +---------------------------+
```

---

## 2. Canonical Scan State Machine

The scan engine follows strict, forward-progressing lifecycle stages. Every transition is persisted to the database and emitted over WebSocket:

```
[ PENDING ] (0%)
    │
    ▼
[ VALIDATING_TARGET ] (0% - 10%)
    ├── SSRF & private IP check (RFC 1918, RFC 4193, loopback, cloud metadata)
    ├── DNS resolution & hostname validation
    └── Target reachable validation
    │
    ▼
[ RECON ] (10% - 25%)
    ├── DNS record enumeration (A, AAAA, MX, NS, TXT)
    ├── TLS handshake & certificate posture audit
    └── Initial HTTP security headers inspection
    │
    ▼
[ DISCOVERY ] (25% - 50%)
    ├── Attack surface route & endpoint crawling
    ├── Emits live scan.asset_discovered events
    └── Strict same-origin scoping
    │
    ▼
[ SECURITY_TESTING ] (50% - 80%)
    ├── Passive / non-destructive vulnerability audits:
    │   ├── Security Headers inspection
    │   ├── Cookie security flags (Secure, HttpOnly, SameSite)
    │   ├── Sensitive file & path leakage
    │   ├── Information disclosure (server banners, stack traces)
    │   └── CORS misconfigurations
    └── Emits live scan.finding_discovered events (deduplicated)
    │
    ▼
[ SCORING ] (80% - 88%)
    ├── Evidence correlation & severity tallying
    ├── Deterministic mathematical score engine (0 - 100)
    └── Emits scan.score_updated event
    │
    ▼
[ REPORTING ] (88% - 100%)
    ├── Emits scan.report_started event
    ├── Generates executive ReportLab PDF artifact
    ├── Persists Report record with binary bytes & actual page count
    └── Emits scan.completed event with final verified telemetry
    │
    ▼
[ COMPLETED ] (100% Terminal)

[ CANCELLING ] ──► [ CANCELLED ] (Terminal)
[ FAILED ] (Terminal)
```

---

## 3. Canonical WebSocket Event Contract

All events broadcast to client WebSockets conform to the canonical event contract:

```json
{
  "type": "scan.progress",
  "scan_id": 22,
  "state": "SECURITY_TESTING",
  "stage": "Security Testing",
  "progress_percent": 65,
  "progress": 65,
  "message": "Auditing security headers and cookie flags across attack surface",
  "status": "Running",
  "timestamp": "2026-09-25T16:10:00.000000+00:00",
  "data": {
    "requests_used": 42,
    "requests_remaining": 108,
    "requests_total": 150
  }
}
```

### Supported Event Types:
1. `scan.connected`: Initial connection event carrying current cached state, asset previews, and finding previews.
2. `scan.state_changed`: Broadcast upon transitioning between canonical phases.
3. `scan.progress`: Stage-weighted progress advance with request budget telemetry.
4. `scan.asset_discovered`: Live emission when crawler discovers an in-scope asset.
5. `scan.finding_discovered`: Live emission when a canonical finding is verified.
6. `scan.score_updated`: Real-time score calculation update matching PDF report score.
7. `scan.report_started`: Signals executive PDF compilation start.
8. `scan.completed`: Final completion with score, grade, risk, total assets, and report ID.
9. `scan.cancel_requested`: Operator cancellation initiated (`CANCELLING`).
10. `scan.cancelled`: Worker safely terminated (`CANCELLED`).
11. `scan.failed`: Scan aborted due to network failure or target error.
12. `scan.heartbeat`: 3-second worker vitality heartbeat.

---

## 4. Multi-Tenant Security & Secret Redaction

### Multi-Tenant Isolation
- **Endpoint**: `/ws/scans/{scan_id}?token={JWT}`
- **Authentication**: JWT token decoded via `verify_access_token()`. Unauthenticated requests rejected with code `4401`.
- **Authorization**: Scan owner verification against database `scan.user_id == current_user.id`. Cross-tenant attempts rejected immediately with code `4403` (`Forbidden: Multi-tenant scan access denied`).
- **REST Isolation**: `POST /api/v1/scans/{scan_id}/cancel` and `GET /api/v1/scans/status/{scan_id}` enforce identical ownership checks.

### Secret Redaction Pipeline
Every payload passing through `broadcast_event()` is sanitized by `redact_event_data()`:
- `JWT_PATTERN`: Replaces any detected JWT token strings with `[REDACTED_JWT]`.
- `BEARER_PATTERN`: Strips `Bearer <token>` into `Bearer [REDACTED_TOKEN]`.
- `SECRET_KEY_PATTERN`: Replaces fields named `password`, `secret`, `token`, `cookie`, `authorization`, `api_key` with `[REDACTED]`.
- No request bodies, authentication headers, cookies, or credentials leak over WebSocket.

---

## 5. Reconnection & Database Reconciliation

- When the frontend reconnects after a page refresh, network fluctuation, or tab switch:
  1. Authenticated WebSocket reconnects with `?token=...`.
  2. Receives `scan.connected` payload with cached state.
  3. `reconcileFromDatabase()` fetches authoritative persisted database state via `GET /api/v1/scans/{id}`.
  4. The UI **never** resets running scans to 0%.
  5. If WebSocket is unavailable, `useScanProgress` activates transparent polling fallback every 2.5s.

---

## 6. Cooperative Cancellation & Request Budget

- **Cancellation Endpoint**: `POST /api/v1/scans/{scan_id}/cancel`
- **Behavior**:
  - Idempotent: Can be called multiple times safely.
  - Transitions DB to `Cancelling` (`CANCELLING`), broadcasts `scan.cancel_requested`.
  - Worker inspects `self.is_cancelled(scan_id)` at every phase checkpoint.
  - SafeHttpClient aborts active sockets.
  - Scan state finalized as `Cancelled` (`CANCELLED`). No subsequent HTTP requests executed.
- **Request Budget**:
  - Enforced strictly at 150 HTTP requests per scan across all modules.
  - Telemetry (`requests_used`, `requests_remaining`) broadcast transparently to frontend.

---

## 7. Verification Test Suite Results

The deterministic test suite `scratch/verify_phase7f_realtime.py` verifies all 32 required architectural guarantees:

```
Ran 32 tests in 0.102s
OK
```

### Verified Dimensions:
1. `test_01_websocket_authentication`: JWT token verification (valid, invalid, empty).
2. `test_02_websocket_tenant_isolation`: User A cannot receive User B's scan events.
3. `test_03_connection_event`: `scan.connected` sent on initial connection.
4. `test_04_state_transition_event`: `scan.state_changed` emitted on stage boundary.
5. `test_05_progress_event`: Canonical progress schema with request budget telemetry.
6. `test_06_asset_event`: `scan.asset_discovered` emitted for discovered assets.
7. `test_07_finding_event`: `scan.finding_discovered` emitted for verified findings.
8. `test_08_score_event`: `scan.score_updated` matches mathematical scoring engine.
9. `test_09_report_started_event`: `scan.report_started` emitted before PDF generation.
10. `test_10_completion_event`: `scan.completed` emitted with verified results.
11. `test_11_failure_event`: `scan.failed` with sanitized error message.
12. `test_12_heartbeat_event`: 3s periodic worker vitality pulse.
13. `test_13_reconnection_cached_state`: Reconnecting clients receive cached state.
14. `test_14_persisted_state_reconciliation`: DB authoritative on terminal or stale cache.
15. `test_15_cancellation_flow`: `CANCELLING` -> `CANCELLED` transition.
16. `test_16_cancellation_idempotency`: Multiple cancellation calls handled safely.
17. `test_17_no_requests_after_cancellation`: Worker halts without additional requests.
18. `test_18_request_budget_enforcement`: 150 max request quota enforced.
19. `test_19_request_budget_telemetry`: Requests used/remaining exposed safely.
20. `test_20_safe_http_client_enforcement`: SSRF and private-IP blocking verified.
21. `test_21_no_raw_http_bypass`: Zero raw `requests`, `urllib`, `aiohttp`, `curl` calls.
22. `test_22_event_redaction`: Sensitive keys scrubbed from events.
23. `test_23_secret_redaction_regex`: JWT and Bearer patterns scrubbed.
24. `test_24_duplicate_finding_prevention`: Canonical findings deduplicated in broadcast.
25. `test_25_score_report_consistency`: Scan score identical to PDF report score.
26. `test_26_scan_ownership_verification`: Multi-tenant ownership check verified.
27. `test_27_dashboard_real_data`: Real database telemetry returned without dummy data.
28. `test_28_stale_worker_handling`: Worker crash / stale heartbeat detection logic.
29. `test_29_startup_recovery`: Server reboot safely marks orphaned scans `Failed`.
30. `test_30_frontend_build_exists`: Vite production build verified (`dist/index.html`).
31. `test_31_ping_pong_keepalive`: WebSocket keepalive ping/pong verified.
32. `test_32_stage_weighted_progress_boundaries`: Progress conforms to canonical stage ranges.

---

## 8. Visual & Browser Verification

Executed via browser subagent on `http://localhost:5173`:
- **Login Flow**: Operator account `Yash` authenticated successfully.
- **Dashboard**: Posture score 82 (Grade B), 5-stage pipeline sequence at 100%, scan activity feed with direct PDF download button.
- **Scan Details Command Center**: Target URL, Quick Profile, Status Completed, 100% progress bar, Requests: 0/150, Worker status badge.
- **Execution Timeline**: 7-stage chronological timeline all verified with `Finished` status badges.
- **Console Log Audit**: No uncaught exceptions, no React rendering loops, graceful WebSocket state reconciliation.
- **Artifacts Captured**:
  - `dashboard_overview_1790352995855.png`
  - `scan_details_top_1790353175185.png`
  - `scan_details_bottom_1790353249207.png`
  - Recording: `phase7f_visual_verification_1790352839397.webp`

---

## 9. Known Limitations

1. **Browser WebSocket Header Support**: Standard browser `WebSocket` APIs cannot attach custom HTTP headers (such as `Authorization: Bearer <token>`). Authentication is passed via the query parameter `?token=<JWT>` over encrypted transport (WSS in production), which is securely verified on connection accept.
2. **Completed Scan Heartbeats**: For completed, failed, or cancelled scans, background heartbeat tasks are stopped to conserve resources; the frontend displays the worker as `OFFLINE` or `STANDBY`, accurately reflecting that no active background job is running.
