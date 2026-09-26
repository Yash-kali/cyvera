# PROJECT PHASE 7A — REAL WEB SECURITY SCANNING ENGINE ARCHITECTURE AUDIT

**Target Platform:** AutoPentest AI / Cyvera  
**Document Classification:** Architectural Assessment & System Design Audit  
**Status:** Audit Complete — No Source Code Changes Applied  
**Execution Date:** 2026-09-20  

---

## 1. Current Architecture

The current Cyvera scanning subsystem is designed as an API-orchestrated asynchronous simulation wrapped around a lightweight synchronous reconnaissance script.

### End-to-End Execution Trace
```
Operator submits Target URL & Scan Profile in UI
                      │
                      ▼
POST /api/v1/scans (`app/routers/scans.py`)
  ├── Validates target_url syntax via Pydantic validator (`app/schemas.py:48-58`)
  ├── Persists Scan entity with status="Running" in SQLite/PostgreSQL
  └── Invokes `progress_manager.start_scan_simulation(scan.id, scan.target_url)`
                      │
                      ▼
Background Task (`app/services/scan_progress.py`)
  ├── Spawns `asyncio.create_task(run_scan_execution(scan_id))` on FastAPI server event loop
  ├── Stage 1 (5%): Environment Initialization (`asyncio.sleep(1.0)`)
  ├── Stage 2 (25%): Reconnaissance via `perform_asset_recon_audit(target)` (`recon.py`)
  │     ├── `inspect_dns()`: synchronous `socket.gethostbyname`
  │     ├── `inspect_tls()`: synchronous `ssl.create_connection`
  │     └── `inspect_security_headers()`: synchronous `urllib.request.urlopen`
  ├── Stage 3 (55%): Vulnerability Assessment via `generate_target_findings()` (`scan_progress.py:275`)
  │     └── Injects hardcoded synthetic vulnerability records based on scan profile string!
  ├── Stage 4 (80%): Posture & Risk Computation (`security_score.py`, `owasp_mapper.py`)
  ├── Stage 5 (95%): PDF Generation (`pdf_generator.py`)
  └── Stage 6 (100%): Status marked "Completed", broadcast to WebSocket `/api/v1/scans/ws/{scan_id}`
```

### Architectural Realities Discovered
1. **In-Memory Asynchronous Tasks:** The scanner does not use an external worker queue (Celery, Redis Queue, or BullMQ). Tasks run inside the web application worker process. A server restart or crash orphans active scans in the `"Running"` state indefinitely.
2. **Blocking Synchronous I/O in Async Loop:** Network operations in `recon.py` (`socket.gethostbyname`, `socket.create_connection`, `urllib.request.urlopen`) run synchronously without threadpool offloading (`asyncio.to_thread`), blocking the central FastAPI asyncio event loop during network timeouts.
3. **No Active or Passive Security Scanners:** Beyond reading 5 HTTP headers, no crawlers, parsers, or security probes exist. The vulnerability assessment phase is a deterministic synthesis of static findings.

---

## 2. Current Scanner Capabilities (What Actually Works)

| Area | Component | Implementation Truth |
|---|---|---|
| **DNS Resolution** | `recon.py:inspect_dns` | Resolves a single IPv4 address via system resolver (`socket.gethostbyname`). Returns `"RESOLVED"` or `"UNRESOLVED"`. |
| **TLS Certificate Extraction** | `recon.py:inspect_tls` | Establishes a TLS connection to port 443 with `ssl.CERT_NONE`, extracting issuer organization, notAfter expiration timestamp, SAN list, and active cipher suite. |
| **Security Header Audit** | `recon.py:inspect_security_headers` | Sends a single GET request using `urllib.request`. Audits presence/absence of: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. |
| **Server Header Extraction** | `recon.py:inspect_security_headers` | Extracts the `Server` response header string (e.g., `nginx/1.24.0`) for asset identification. |
| **Security Score Engine** | `security_score.py` | Canonical mathematical deduction engine calculating score (0–100), letter grade (A–F), and risk category from finding severities and header/TLS deductions. |
| **OWASP Statistics Engine** | `owasp_mapper.py` | Groups stored findings into OWASP Top 10 2021 categories via regex on title and rule metadata. |
| **SARIF 2.1.0 Parser** | `sarif_parser.py` | High-fidelity ingestion engine for external static and dynamic scanner reports, featuring deduplication and severity normalization. |
| **PDF Report Engine** | `pdf_generator.py` | Enterprise ReportLab PDF compiler producing Quick, Standard, and Full reports with dynamic page counts (`pypdf`) and canonical findings binding. |

---

## 3. Missing Capabilities (Audit of the 50 Specific Areas)

| # | Audited Area | Current State | Missing Capability Required |
|---|---|---|---|
| 1 | **Target validation** | Primitive regex in `schemas.py:48` | Rejects empty strings only; permits `localhost`, internal IPs, and non-FQDNs. Needs comprehensive RFC domain and IP parsing. |
| 2 | **Scan creation** | Implemented | Lacks target authorization attestation, scope bounds, rate limit configuration, and crawl depth parameters. |
| 3 | **Scan worker architecture** | In-process `asyncio.Task` | Needs isolated worker processes, background task queues, heartbeat monitoring, and crash recovery. |
| 4 | **Recon engine** | Basic socket script | Needs structured multi-stage recon pipeline with async HTTP/DNS clients (`httpx`, `dnspython`). |
| 5 | **DNS enumeration** | Single IPv4 only | Missing AAAA, MX, NS, TXT (SPF/DKIM/DMARC), CNAME, CAA records, and DNSSEC verification. |
| 6 | **TLS analysis** | Partial (issuer, cipher) | Missing cert chain verification against root CAs, protocol negotiation (SSLv3, TLS 1.0, 1.1, 1.2, 1.3), and weak cipher detection (RC4, 3DES, EXPORT, NULL). |
| 7 | **HTTP analysis** | Single GET request | Missing redirect chain inspection, HTTP method testing (OPTIONS, TRACE, PUT, DELETE), and HTTP/2 protocol support. |
| 8 | **Security headers** | 5 headers checked | Missing Permissions-Policy, COOP, COEP, CORP, Cache-Control; lacks CSP policy syntax and directive strength validation. |
| 9 | **Cookie security** | **Completely Absent** | Does not inspect `Set-Cookie` headers for `Secure`, `HttpOnly`, `SameSite` flags, or cookie prefixes (`__Host-`, `__Secure-`). |
| 10 | **Technology detection** | `Server` header only | Missing Wappalyzer-grade fingerprinting (HTML meta tags, script paths, DOM elements, JS globals, cookie signatures). |
| 11 | **robots.txt** | **Completely Absent** | Does not fetch, parse, or extract disallowed paths, admin directories, or referenced sitemaps. |
| 12 | **sitemap.xml** | **Completely Absent** | Does not fetch or parse `/sitemap.xml` for target attack surface URL discovery. |
| 13 | **security.txt** | **Completely Absent** | Does not inspect `/.well-known/security.txt` or `/security.txt` (RFC 9116 compliance). |
| 14 | **Crawling** | **Completely Absent** | No web crawler or spider exists. Only the single root URL is evaluated. |
| 15 | **Endpoint discovery** | **Completely Absent** | No link extraction, sub-path crawling, directory discovery, or route enumeration. |
| 16 | **Form discovery** | **Completely Absent** | No HTML parsing for `<form>` elements, input types, actions, methods, or CSRF token presence. |
| 17 | **Parameter discovery** | **Completely Absent** | No parameter harvesting from URLs, forms, or JSON request bodies. |
| 18 | **JavaScript analysis** | **Completely Absent** | No static inspection of script tags or bundles for leaked API tokens, hardcoded secrets, or unmapped API routes. |
| 19 | **API discovery** | **Completely Absent** | No automated probing for `/openapi.json`, `/swagger.json`, `/api-docs`, or `/graphql`. |
| 20 | **OWASP testing** | Simulated in code | No active or passive scanners for the OWASP Top 10; findings are synthesized via template strings. |
| 21 | **Auth/Session testing** | **Completely Absent** | No checks for unauthenticated access on sensitive endpoints, session fixation, or token entropy. |
| 22 | **Authorization/BOLA** | Fabricated text | Claims BOLA on `/api/v1/user/keys` via hardcoded string without ever issuing a request. |
| 23 | **Input validation** | **Completely Absent** | No probes with canary boundary characters (`'`, `"`, `<`, `>`, `\`, `;`, `${{...}}`). |
| 24 | **Injection detection** | Fabricated text | Injects SQLi finding on `/api/v1/search?q=test` without sending test probes or inspecting error/time responses. |
| 25 | **XSS detection** | **Completely Absent** | No benign canary reflection analysis (e.g. `cyv7<canary>`) in HTML contexts or DOM sinks. |
| 26 | **SSRF detection** | Fabricated text | Injects SSRF finding on `/api/v1/webhook/fetch` without executing safe out-of-band or loopback probes. |
| 27 | **File upload checks** | **Completely Absent** | No inspection of multipart forms or validation of file extension/MIME restrictions. |
| 28 | **CORS testing** | Fabricated text | Claims wildcard CORS via string template without sending `Origin:` header or checking response headers. |
| 29 | **Info disclosure** | Server banner only | Does not check for exposed `.git/`, `.env`, stack traces, directory listings, or source maps. |
| 30 | **API security** | **Completely Absent** | No checks for missing rate limiting, excessive data exposure, or unauthenticated CRUD routes. |
| 31 | **Finding verification** | **Completely Absent** | All findings marked "Open" upon creation; no re-testing or confidence scoring ("Definite", "Firm", "Tentative"). |
| 32 | **Evidence collection** | **Completely Absent** | No storage of raw HTTP request, raw HTTP response, matched payload, or canary reflection. |
| 33 | **Finding deduplication**| Partial in SARIF | Absent in scan engine; multiple runs could insert duplicate findings for the same scan. |
| 34 | **Severity calculation** | Hardcoded strings | Severities assigned statically in template strings rather than derived from verified impact. |
| 35 | **CVSS engine** | Hardcoded floats | Floats (`9.1`, `8.4`, `7.5`) hardcoded directly in templates; no CVSS 3.1 vector string calculation. |
| 36 | **CWE engine** | Stored in `cve_id` | Missing dedicated `cwe_id` database column; CWE tags currently mixed with CVEs and OWASP IDs. |
| 37 | **OWASP mapping** | Regex on title | Rule-based regex mapper works, but depends on finding titles containing specific keywords. |
| 38 | **Security score** | Implemented | Works canonically, but relies on fake finding severities to compute score. |
| 39 | **AI analysis** | Implemented | Gemini AI integration works for post-scan explanation, but must remain strictly separated from detection. |
| 40 | **WebSocket streaming** | Basic stage/progress | Only streams 5 high-level stages. Does not stream live findings, discovered endpoints, or scanner activity logs. |
| 41 | **Scan cancellation** | **Completely Absent** | No endpoint, UI button, or task cancellation logic. Deleting a scan leaves the task running in the background. |
| 42 | **Error handling** | Catch-all try/except | Broad exception handling catches errors and marks scan "Failed", but does not isolate individual scanner failures. |
| 43 | **Rate limiting** | **Completely Absent** | No token-bucket or request throttling; scans can send burst requests without restriction. |
| 44 | **Concurrency control**| **Completely Absent** | `UserSettings.max_concurrency` exists in the database but is ignored by the execution engine. |
| 45 | **Database persistence**| Implemented | Persists Scan, ReconResult, Finding, and Report models cleanly. |
| 46 | **Tenant isolation** | Implemented | Enforced via `current_user.id` on scan CRUD, findings, reports, and downloads. |
| 47 | **Report generation** | Implemented | High-quality PDF report generation using ReportLab, but bound to simulated findings. |
| 48 | **Report evidence** | Limited | Reports cannot display real HTTP request/response evidence because the scanner does not capture it. |
| 49 | **Frontend experience**| Progress bar & logs | Clean UI with progress bar and terminal feed, but lacks cancellation, live findings feed, and scope settings. |
| 50 | **Production readiness**| Not production ready | System is currently an educational simulation and cannot be deployed as an authorized security scanner without significant architectural overhaul. |

---

## 4. Fake / Mock Data Discovered

A comprehensive codebase search identified the following hardcoded synthetic data:

### 1. `backend/app/services/scan_progress.py` (`generate_target_findings`)
- **Lines 304–315:** Hardcodes `Insecure Plaintext HTTP Transport` with static `cvss_score=7.5`, `cve_id="OWASP-A02-2021"`.
- **Lines 324–336:** Injects `Missing Content-Security-Policy (CSP) Header` even if `not missing_headers` (meaning NO missing headers!).
- **Lines 338–350:** Hardcodes `Missing HTTP Strict-Transport-Security (HSTS) Header` with `cvss_score=7.2`.
- **Lines 371–382:** Synthesizes `Broken Object Level Authorization (BOLA) on API Resource Keys` targeting `{clean_url}/api/v1/user/keys` with `cvss_score=8.4`.
- **Lines 384–395:** Synthesizes `Unsanitized Query Parameter SQL Injection Risk` targeting `{clean_url}/api/v1/search?q=test` with `cvss_score=9.1`.
- **Lines 398–408:** Synthesizes `Vulnerable Outdated Dependency Library Component` targeting `{clean_url}/api/v1/media/process` with hardcoded `cve_id="CVE-2023-4863"`, `cvss_score=7.8`.
- **Lines 411–421:** Synthesizes `Container Privilege Escalation & Host Breakout (runc)` targeting `{clean_url}/api/v1/container/exec` with hardcoded `cve_id="CVE-2024-21626"`, `cvss_score=9.8`.
- **Lines 424–435:** Synthesizes `Permissive Cross-Origin Resource Sharing (CORS) Policy` targeting `{clean_url}/api/v1/telemetry` with `cvss_score=7.6`.
- **Lines 437–448:** Synthesizes `Server-Side Request Forgery (SSRF) in External Webhook Fetcher` targeting `{clean_url}/api/v1/webhook/fetch` with `cvss_score=8.6`.

### 2. `backend/app/services/recon.py`
- **Lines 67–69:** Hardcoded TLS fallback values if peer cert lacks attributes:
  ```python
  days_remaining = 240
  expires_on = "2027-04-15T00:00:00Z"
  sans = ["*.autopentest.ai", "autopentest.ai"]
  ```
- **Line 171:** Hardcoded baseline posture score of `85`:
  ```python
  security_score = 85
  ```

### 3. `backend/app/services/security_score.py`
- **Line 64:** Hardcoded open ports default:
  ```python
  open_ports_cnt = 1 # Deducts 2 points from EVERY target unconditionally
  ```

---

## 5. Security Weaknesses in Current Implementation

### Critical Security Vulnerabilities
1. **Unrestricted Server-Side Request Forgery (SSRF):**
   - In `schemas.py:56`, the target URL validator explicitly allows `"localhost"` (`and "localhost" not in v_str`).
   - The scanner does not check for private IP ranges (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local/cloud metadata (`169.254.169.254`), or carrier-grade NAT (`100.64.0.0/10`).
   - An attacker can register an account and point Cyvera at `http://169.254.169.254/latest/meta-data/` or internal database ports (`http://127.0.0.1:5432`), using the server as a blind SSRF pivot.
2. **DNS Rebinding Vulnerability:**
   - The system resolves the domain once during recon, but subsequent HTTP requests use the hostname directly.
   - An attacker-controlled DNS server can return a public IP on initial lookup and `127.0.0.1` on subsequent requests, bypassing any perimeter checks.
3. **Open Redirect Pivot Vulnerability:**
   - `urllib.request.urlopen` follows HTTP 301/302 redirects automatically without validating the destination.
   - A public website redirecting to `http://169.254.169.254/` would cause the server to fetch cloud metadata.
4. **Denial of Service via Unbounded Scans:**
   - There are no rate limits, request timeouts are inconsistent, and there is no global concurrency throttle.
   - A user can launch dozens of scans simultaneously, exhausting network sockets and worker threads.
5. **Lack of Target Authorization / Scope Verification:**
   - Any authenticated user can scan any internet domain without proving ownership or administrative consent.
   - This exposes the platform host to legal liability and abuse reports from target networks.

---

## 6. API Gaps

The current scan API (`backend/app/routers/scans.py`) lacks essential operational endpoints:

1. **`POST /api/v1/scans/{id}/cancel`:** Missing. Cannot cancel or abort an in-flight scan.
2. **`POST /api/v1/scans/{id}/pause` & `POST /api/v1/scans/{id}/resume`:** Missing.
3. **`POST /api/v1/targets/authorize`:** Missing. No mechanism for target domain verification (e.g. via DNS TXT record or `.well-known/cyvera-challenge.txt`).
4. **`GET /api/v1/scans/{id}/endpoints`:** Missing. Cannot query endpoints discovered during the crawl.
5. **`GET /api/v1/scans/{id}/logs`:** Missing. Activity logs are stored in memory and lost if the WebSocket disconnects.
6. **Scope Configuration in `ScanCreate`:**
   - Missing fields: `allowed_subdomains`, `excluded_paths`, `max_depth`, `rate_limit_rps`, `custom_headers`, `auth_token`.

---

## 7. Database / Schema Gaps

### Deficiencies in `Finding` Model (`backend/app/models.py:123`)
```sql
-- Current Schema Limitations:
-- 1. No evidence storage for raw HTTP request/response payloads
-- 2. No dedicated CWE column (CWE mixed into cve_id)
-- 3. No confidence level (Definite, Firm, Tentative)
-- 4. No verification status flag
-- 5. No scanner identification (which module discovered it)
-- 6. No parameter or HTTP method tracking
```

### Deficiencies in `Scan` Model (`backend/app/models.py:76`)
- Missing `started_at`, `completed_at`, `cancelled_at` timestamps.
- Missing `requests_sent`, `endpoints_discovered`, `duration_seconds`.
- Missing `scope_config` (JSON) storing scan parameters and limits.
- Missing `cancellation_reason` string.

### Missing Tables
1. **`discovered_endpoints` Table:** Required to store crawl graph (`scan_id`, `url`, `method`, `status_code`, `content_type`, `discovered_params`, `created_at`).
2. **`target_authorizations` Table:** Required to store verified domains (`user_id`, `domain`, `verification_token`, `verification_status`, `verified_at`, `expires_at`).
3. **`scan_logs` Table:** Required to persist operational log events for post-scan debugging and audit compliance.

---

## 8. WebSocket Gaps

Current WebSocket implementation (`backend/app/routers/scans.py:216`, `scan_progress.py:17`):

### Problems Identified
1. **Coarse-Grained Event Model:** Only broadcasts 5 static stage transitions:
   ```json
   {"scan_id": 1, "stage": "Recon Progress", "progress": 25, "message": "...", "status": "Running"}
   ```
2. **Missing Granular Events:**
   - No `finding_discovered` event (findings cannot appear in real-time on UI).
   - No `endpoint_crawled` event (cannot show live crawl progress).
   - No `scanner_started` / `scanner_completed` module events.
   - No `scan_cancelled` event.
3. **One-Way Communication:** Does not accept client commands (e.g., client cannot send `{"action": "CANCEL"}` over the socket).
4. **Memory Leak Risk:** `ScanProgressManager.scan_progress_cache` stores payloads in memory indefinitely; never evicts completed scans.
5. **No Authentication on WebSocket Route:** `/api/v1/scans/ws/{scan_id}` does not validate user JWT token! Any unauthenticated client knowing a `scan_id` can connect and listen to progress events.

---

## 9. Frontend Gaps

Inspecting `RealTimeScanProgress.tsx`, `LiveProgressBar.tsx`, and `ScanHistory.tsx`:

1. **No Authorization Attestation:** The scan creation modal only asks for a URL and profile; it lacks an explicit checkbox: *"I confirm I am authorized to test this target."*
2. **No Scope Controls:** No settings for max crawl depth, request rate limit, or excluded paths.
3. **No Cancellation Button:** Operators cannot stop a running scan from the UI.
4. **No Live Finding Stream:** The UI only displays findings after the scan reaches 100% completion; findings do not appear progressively.
5. **No Attack Surface Visualizer:** No tree view or table of discovered endpoints, forms, or technologies.
6. **Hardcoded PDF Download Fallback:** `RealTimeScanProgress.tsx:32` contains a fallback downloading report `#1` if instant download fails.

---

## 10. Recommended Real Scanner Architecture

To make Cyvera a genuine, safe, and professional security scanner, the scanning pipeline must be divided into five strictly separated phases:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PHASE 1: TARGET VALIDATION                        │
│  - FQDN & Protocol Validation (http/https only)                            │
│  - Target Authorization Verification (Attestation & Scope Confirmation)     │
│  - SSRF Filter: Reject loopback, RFC 1918, link-local, cloud metadata        │
│  - DNS Resolution Pinning (pin IP to prevent DNS rebinding)                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PHASE 2: RECONNAISSANCE                           │
│  - DNS Audit (A, AAAA, MX, NS, TXT/SPF/DMARC, CAA, DNSSEC)                 │
│  - TLS Security Audit (Cert chain, protocols, cipher suites, expiration)    │
│  - HTTP Transport Audit (Redirect chain, HTTP/1.1 vs HTTP/2, Server tokens) │
│  - Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer)  │
│  - Cookie Security (Secure, HttpOnly, SameSite, __Host- prefixes)           │
│  - Metadata Endpoints (robots.txt, sitemap.xml, /.well-known/security.txt)  │
│  - Passive Tech Fingerprinting (Wappalyzer signatures from HTML/headers)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 3: ATTACK SURFACE DISCOVERY                     │
│  - Bounded Asynchronous Crawler (Strict Scope: Target domain only)          │
│  - Endpoint Discovery (links, CSS, scripts, anchor tags)                    │
│  - Form & Input Field Extraction (actions, methods, inputs, CSRF tokens)    │
│  - API Route Discovery (/openapi.json, /swagger.json, /api-docs)            │
│  - Parameter Inventory (query string, form body, path parameters)           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PHASE 4: AUTHORIZED SECURITY TESTING                    │
│  - Passive Audits: Information disclosure (.git, .env, debug routes, CORS)  │
│  - Active Safe Probing (Non-destructive, rate-limited, canary-based):       │
│      • Input Reflection Checks (Benign canary injection for XSS detection)  │
│      • Error-based Injection Checks (Benign boundary markers)               │
│      • Open Redirect Checks (Safe redirect destination testing)             │
│      • Sensitive Data Exposure (API keys, tokens in client-side JS bundles) │
│  - Real Evidence Capture: Request + Response + Canary Highlight             │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PHASE 5: VERIFICATION, SCORING & REPORTING               │
│  - Canonical Finding Deduplication & Storage with Evidence                  │
│  - Canonical Security Score Calculation (identical to Dashboard & Analytics)│
│  - Stored AI Explanation Generation (Gemini as analyst, NOT detector)       │
│  - Evidence-Based PDF Report Generation                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Recommended API Architecture

```
# Target Authorization & Scope
POST   /api/v1/targets/validate                # Validate target URL, resolve IP, check SSRF
POST   /api/v1/targets/attest                  # Record operator authorization attestation

# Scan Lifecycle
POST   /api/v1/scans                           # Create & start scan (with scope & rate limit)
GET    /api/v1/scans                           # List scans (tenant-scoped)
GET    /api/v1/scans/{id}                      # Get scan details & canonical metrics
DELETE /api/v1/scans/{id}                      # Delete scan & abort background worker
POST   /api/v1/scans/{id}/cancel               # Gracefully stop running scan

# Real-Time Telemetry & Progress
GET    /api/v1/scans/{id}/status               # Polling fallback with fine-grained state
GET    /api/v1/scans/{id}/endpoints            # List crawled endpoints for this scan
GET    /api/v1/scans/{id}/findings             # List findings discovered during scan
WS     /api/v1/scans/ws/{id}?token=<jwt>       # Authenticated bi-directional WebSocket
```

---

## 12. Recommended Worker Architecture

```
FastAPI Web App (FastAPI / Uvicorn)
  │
  ├── Writes Scan row with status="Pending"
  ├── Enqueues ScanJob into Redis / Background Queue
  └── Returns 201 Created immediately to client
           │
           ▼
Scan Worker Pool (Dedicated Process / AsyncIO Worker)
  ├── Rate-Limited HTTP Client (`httpx.AsyncClient` with custom Transport)
  │     ├── Enforces max_rps (e.g. 5 requests/sec for Quick, 10 req/sec for Full)
  │     ├── Enforces timeout (default 5.0s per request)
  │     └── IP Pinning: Enforces resolved IP on every connection (prevents DNS rebinding)
  ├── Cancellation Sentinel: Checks `scan.is_cancelled` before every network request
  ├── Concurrency Gate: Respects `UserSettings.max_concurrency` via `asyncio.Semaphore`
  └── Real-time Event Broadcaster: Publishes events to Redis Pub/Sub -> WebSocket
```

---

## 13. Target Authorization & Safety Model

Before executing any network probes against a target, the system must enforce strict authorization:

### 1. Pre-Flight Attestation
The user must explicitly submit a signed authorization payload:
```json
{
  "target_url": "https://myapp.example.com",
  "scan_type": "Standard",
  "authorized_by_operator": true,
  "attestation_statement": "I confirm that I own this target or have explicit written authorization from the owner to perform security assessments.",
  "scope_constraints": {
    "stay_within_subdomain": true,
    "max_depth": 3,
    "max_requests_per_second": 5
  }
}
```

### 2. Domain Verification Options (Optional Enterprise Mode)
- **DNS TXT Record:** Host `cyvera-site-verification=<token>` on domain.
- **HTTP Challenge:** Place verification token at `https://<target>/.well-known/cyvera-challenge.txt`.

---

## 14. Safety Controls & Perimeter Defenses

| Safety Layer | Control Implementation | Failure Action |
|---|---|---|
| **Private IP Protection** | `ipaddress.ip_address(ip).is_private` check on all resolved IPs | Reject with HTTP 400: Target resolves to private RFC 1918 address. |
| **Loopback Protection** | Reject `127.0.0.0/8`, `::1`, `localhost` | Reject with HTTP 400: Loopback targets are strictly prohibited. |
| **Cloud Metadata Protection** | Reject `169.254.169.254`, `metadata.google.internal`, `100.100.100.200` | Reject with HTTP 400: Cloud metadata endpoints are blocked. |
| **DNS Rebinding Protection** | Pin the resolved IP address in custom `httpx.AsyncHTTPTransport`; connect directly to IP with `Host: <hostname>` header | Discard connections that resolve to internal addresses mid-scan. |
| **Redirect Safety** | Custom redirect handler: Inspect destination IP before following any 301/302/307 redirect | Abort redirect if target resolves to private/internal IP. |
| **Rate Limiting** | Token-bucket rate limiter (Leaky Bucket): default 5 req/sec | Throttles outbound HTTP requests to prevent target DoS. |
| **Crawl Limits** | Bounded crawl: Max 50 URLs (Quick), 200 URLs (Standard), 500 URLs (Full); Max depth: 2 (Quick), 4 (Standard), 6 (Full) | Halts crawler once budget is exhausted. |
| **Payload Safety** | Non-destructive canaries only (`cyv7<rand_id>`); NEVER inject DROP TABLE, DELETE, or destructive shell exploits | Guaranteed safe evaluation without risk of data loss. |
| **Scan Cancellation** | Immediate cancellation checkpoint between every URL and payload execution | Terminates task within 250ms of user cancel request. |

---

## 15. Quick Profile Design (`QUICK`)

- **Objective:** Fast, non-intrusive perimeter hygiene and configuration audit.
- **Target Duration:** 15–45 seconds.
- **Target Page Range:** 5–10 pages.
- **Active Scanners Executed:**
  1. DNS Infrastructure Audit (A, AAAA, MX, NS, TXT/SPF/DMARC)
  2. TLS Certificate & Protocol Audit (Expiration, Trust Chain, Protocols)
  3. HTTP Security Headers Audit (HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy)
  4. Cookie Flags Audit on root response (`Secure`, `HttpOnly`, `SameSite`)
  5. Passive Server Banner & Technology Fingerprinting (HTML meta tags, Server tokens)
  6. Well-Known Files Check (`robots.txt`, `security.txt`)
- **Testing Depth:** 0 active crawl depth; only root URL (`/`) is audited. Zero active injection payloads.

---

## 16. Standard Profile Design (`STANDARD`)

- **Objective:** Comprehensive automated vulnerability assessment and attack surface discovery.
- **Target Duration:** 2–5 minutes.
- **Target Page Range:** 15–30 pages.
- **Active Scanners Executed:**
  1. All **QUICK** profile checks.
  2. Bounded Web Spider: Max 100 endpoints, Max Depth 3 (strictly scoped to target host).
  3. HTML Form Discovery: Identifies `<form>` actions, methods, and inputs.
  4. API Endpoint Discovery: Probes for `/openapi.json`, `/swagger.json`, `/api-docs`.
  5. Information Disclosure Audit: Checks for exposed `.git/HEAD`, `.env`, `composer.json`, `package.json`, source maps (`.js.map`).
  6. CORS Misconfiguration Audit: Sends `Origin: https://evil.com` to API endpoints and analyzes `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`.
  7. Passive Secret & Token Scanner: Scans discovered JS bundles for high-entropy strings, leaked AWS keys (`AKIA...`), and generic bearer tokens.
  8. Benign Canary Input Reflection Check: Tests query and form parameters with harmless canary strings (`cyv7a<id>`) to detect unencoded reflection contexts.
  9. OWASP Top 10 Mapping & Calculation.

---

## 17. Full Profile Design (`FULL`)

- **Objective:** In-depth autonomous penetration testing simulation for enterprise security reviews.
- **Target Duration:** 8–15 minutes.
- **Target Page Range:** 40–80 pages.
- **Active Scanners Executed:**
  1. All **STANDARD** profile checks.
  2. Deep Web Spider: Max 300 endpoints, Max Depth 5.
  3. Comprehensive Parameter Miner: Extracts parameters from URL queries, form bodies, JSON endpoints, and JS files.
  4. Safe Injection Boundary Probing:
     - SQL Injection Probing: Benign single-quote syntax marker testing (observing syntax error deltas vs clean inputs).
     - Cross-Site Scripting (XSS): Context-aware benign canary reflections in HTML, attribute, and script tags.
     - Open Redirect Probing: Tests redirect parameters against safe external canary domain.
  5. Cookie Prefix and Session Architecture Audit: Inspects session token entropy and lifecycle across multiple requests.
  6. Regulatory Compliance Mapping: Evaluates findings against PCI-DSS 4.0, SOC 2 Type II, NIST CSF, and ISO 27001 requirements.
  7. Gemini AI Remediation Synthesis: Generates contextual remediation guidance and secure coding examples for all verified findings.
  8. Exploitation Validation Statement: Explicitly documents that non-destructive canary payloads were utilized and production data was untouched.

---

## 18. Canonical Finding Design

The `Finding` model must be upgraded to support complete technical forensics and standard security tooling compatibility:

```python
class CanonicalFinding:
    id: int                                # Primary Key
    scan_id: int                           # Associated Scan ID
    user_id: int                           # Multi-tenant Operator ID
    title: str                             # Concise finding title (e.g. "Missing Content-Security-Policy Header")
    category: str                          # OWASP category (e.g. "A05:2021-Security Misconfiguration")
    severity: str                          # "Critical", "High", "Medium", "Low", "Info"
    confidence: str                        # "Definite", "Firm", "Tentative"
    verified: bool                         # True if automated verification confirmed
    cvss_score: Optional[float]            # CVSS 3.1 Base Score (e.g. 7.5)
    cvss_vector: Optional[str]             # CVSS Vector String (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N")
    cwe_id: Optional[str]                  # Dedicated CWE ID (e.g. "CWE-693")
    cve_id: Optional[str]                  # Relevant CVE ID if applicable
    owasp_category: str                    # Standard OWASP Top 10 identifier
    affected_url: str                      # Vulnerable endpoint URL
    http_method: str                       # "GET", "POST", "PUT", "DELETE"
    parameter: Optional[str]               # Vulnerable parameter name (e.g. "redirect_to", "q")
    description: str                       # Detailed technical explanation
    evidence: Optional[Dict[str, Any]]     # Structured forensic evidence (Request, Response, Canary, Match)
    remediation_guidance: str              # Step-by-step remediation instructions
    scanner_name: str                      # Tool module (e.g. "header-auditor", "cors-analyzer", "crawler")
    status: str                            # "Open", "In Review", "Resolved", "False Positive"
    created_at: datetime                   # Timestamp of discovery
```

---

## 19. Evidence Model

To ensure absolute content honesty in PDF reports and the UI, every finding must capture structured evidence at the moment of discovery:

```json
{
  "finding_evidence": {
    "request": {
      "method": "GET",
      "url": "https://target.com/search?q=cyv7test",
      "headers": {
        "User-Agent": "Cyvera-Security-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml"
      }
    },
    "response": {
      "status_code": 200,
      "headers": {
        "Content-Type": "text/html; charset=UTF-8",
        "Server": "nginx/1.24.0"
      },
      "body_snippet": "...<div class=\"results\">Search for: cyv7test</div>...",
      "response_time_ms": 142
    },
    "matched_indicator": {
      "type": "unencoded_reflection",
      "payload_sent": "cyv7test",
      "extracted_match": "Search for: cyv7test",
      "context": "html_body"
    }
  }
}
```

---

## 20. Real-Time Event Model

The WebSocket stream must emit typed, structured JSON events to drive dynamic frontend widgets:

```typescript
// Event 1: Phase Transition
{
  "type": "PHASE_CHANGED",
  "scan_id": 42,
  "phase": "RECONNAISSANCE", // "INITIALIZING" | "RECONNAISSANCE" | "CRAWLING" | "AUDITING" | "COMPILING"
  "progress": 25,
  "message": "Executing TLS and DNS infrastructure analysis..."
}

// Event 2: Endpoint Discovered
{
  "type": "ENDPOINT_DISCOVERED",
  "scan_id": 42,
  "endpoint": {
    "url": "https://target.com/api/v1/auth/login",
    "method": "POST",
    "has_forms": true,
    "depth": 2
  }
}

// Event 3: Finding Discovered
{
  "type": "FINDING_DISCOVERED",
  "scan_id": 42,
  "finding": {
    "id": 105,
    "title": "Missing Content-Security-Policy (CSP) Header",
    "severity": "Medium",
    "cvss_score": 5.4,
    "affected_url": "https://target.com/"
  },
  "current_score": 82
}

// Event 4: Scan Cancelled
{
  "type": "SCAN_CANCELLED",
  "scan_id": 42,
  "reason": "Cancelled by operator",
  "timestamp": "2026-09-20T18:45:00Z"
}
```

---

## 21. Implementation Phases (Roadmap for Phase 7B+)

| Phase | Milestone Name | Key Deliverables |
|---|---|---|
| **Phase 7B** | **Target Validation, Safety & Worker Engine** | SSRF filter, IP pinning, private IP rejection, target authorization attestation, dedicated background worker, scan cancellation API (`POST /cancel`), rate limiting. |
| **Phase 7C** | **Real Reconnaissance Engine** | Asynchronous DNS enumeration (dnspython), deep TLS audit (protocols, ciphers, chain), comprehensive HTTP security header & cookie audit, `robots.txt`/`security.txt` parsers, tech fingerprinting. |
| **Phase 7D** | **Attack Surface Discovery (Crawler & Spider)** | Bounded async web crawler, endpoint discovery, HTML `<form>` parser, API route finder (`/openapi.json`), parameter harvester. |
| **Phase 7E** | **Authorized Security Testing Engine** | Passive information disclosure auditor (.git, .env, secrets), CORS misconfiguration tester, benign canary reflection analyzer, real evidence capture into database. |
| **Phase 7F** | **WebSocket Streaming & Frontend Polish** | Granular WS events (`ENDPOINT_DISCOVERED`, `FINDING_DISCOVERED`), UI cancellation button, real-time finding cards, attack surface tree view. |

---

## 22. Production-Readiness Gaps Summary

| Domain | Current Implementation | Production-Ready Requirement | Severity |
|---|---|---|---|
| **Vulnerability Detection** | Template string synthesis | Real passive & active safe checks with canary payloads | **CRITICAL** |
| **SSRF Defense** | None (allows localhost/private IPs) | Strict IP blocklist, IP pinning, redirect validation | **CRITICAL** |
| **Evidence Forensics** | None | Captures raw HTTP request/response snippets | **CRITICAL** |
| **Task Management** | In-process asyncio tasks | Worker process with task cancellation & crash recovery | **HIGH** |
| **Target Authorization** | Unchecked URL entry | Mandatory legal attestation & scope limits | **HIGH** |
| **Database Schema** | Overloaded columns, no evidence | Dedicated `evidence`, `cwe_id`, `confidence` columns | **HIGH** |
| **WebSocket Security** | Unauthenticated route | Mandatory JWT token parameter authentication | **HIGH** |
| **Rate Limiting** | None | Token-bucket rate limiting per domain | **MEDIUM** |

---

## Final Executive Summary Table

| Category | CURRENT CAPABILITY | MISSING CAPABILITY | SECURITY RISK | RECOMMENDED FIX | IMPLEMENTATION PRIORITY |
|---|---|---|---|---|---|
| **Target Validation** | Regex syntax checking | SSRF filter, private IP blocking, localhost blocking, DNS rebinding protection | Critical SSRF: Server can be leveraged to scan internal networks or cloud metadata | Implement strict IP address inspection, block RFC 1918/loopback/cloud metadata, pin resolved IPs | **P0 (Immediate)** |
| **Worker Architecture** | In-process `asyncio.Task` on FastAPI web server | Dedicated worker, task cancellation, queue persistence, crash recovery | Server DoS, event loop blocking, orphaned scans on server restart | Move execution to background worker queue with cancellation tokens and threadpool offloading | **P0 (Immediate)** |
| **Target Authorization** | None; any URL accepted | Legal authorization attestation, domain verification, scope constraints | Legal liability for unauthorized scanning of third-party systems | Add mandatory operator authorization confirmation checkbox and scope bounds | **P0 (Immediate)** |
| **Security Testing** | Hardcoded synthetic templates (`generate_target_findings`) | Real passive checks (headers, cookies, CORS, info disclosure) and safe canary checks (reflection, syntax) | False confidence; platform reports imaginary vulnerabilities instead of actual security posture | Build modular Python security testing engine producing genuine, evidence-based findings | **P1 (Core)** |
| **Evidence Forensics** | None; descriptions only | Forensic capture of raw HTTP request, response status/headers/body, and matched canaries | Non-verifiable findings; inability to prove vulnerability exists in audit reports | Add structured `evidence` JSON column to `Finding` model and capture forensics during checks | **P1 (Core)** |
| **Reconnaissance** | Basic socket DNS, TLS, and 5 HTTP headers | DNSSEC, TXT/SPF/DMARC, cookie flags (`Secure`, `HttpOnly`), `robots.txt`, `security.txt`, tech stack detection | Incomplete attack surface visibility and missed configuration flaws | Expand recon engine with `dnspython`, `httpx`, and signature-based technology detection | **P1 (Core)** |
| **Attack Surface Discovery**| None; single root URL only | Web crawler/spider, endpoint discovery, HTML form extraction, parameter mining | Total blindness to application routes beyond the landing page | Implement bounded, asynchronous link crawler with depth and count limits | **P2 (Feature)** |
| **Real-Time Streaming** | Coarse 5-stage progress (0–100%) | Fine-grained events: `ENDPOINT_DISCOVERED`, `FINDING_DISCOVERED`, `SCAN_CANCELLED` | Suboptimal operator experience; no live visibility into discovering findings | Upgrade WebSocket manager to emit typed events and require JWT authentication | **P2 (Feature)** |
| **Database Schema** | Overloaded `cve_id`, no `evidence`, no `confidence` | Dedicated `cwe_id`, `evidence`, `confidence`, `scanner_name`, `verified` | Loss of structured security metadata and inability to export standard SARIF/evidence | Apply non-destructive database migration adding canonical finding fields | **P2 (Feature)** |
