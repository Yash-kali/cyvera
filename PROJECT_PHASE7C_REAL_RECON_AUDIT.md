# Phase 7C Audit: Real Reconnaissance & Verified Target Intelligence

**Project:** AutoPentest AI / Cyvera  
**Phase:** 7C — Real Reconnaissance & Verified Target Intelligence  
**Date:** September 23, 2026  
**Status:** COMPLETE (PASS)  

---

## 1. Executive Summary

Phase 7C establishes the **Real Reconnaissance & Verified Target Intelligence Subsystem** for AutoPentest AI / Cyvera. Operating strictly within authorized security boundaries, the system eliminates heuristic guessing, synthetic findings, and unverified mock vulnerabilities in favor of genuine, evidence-based telemetry gathered directly from the target.

### Key Milestones Completed:
1. **Database Path Hardening:** Deterministically resolves SQLite to `backend/autopentest.db` via canonical absolute pathing in `config.py` and `database.py`. Starting Uvicorn from the repository root, `backend/`, or an IDE workspace binds to the exact same database.
2. **DNS Rebinding Defense with Socket-Level IP Pinning:** Created `PinnedNetworkBackend` on `httpcore` / `httpx`, which intercepts `connect_tcp()` and binds the underlying socket connection directly to the pre-validated public IP address while preserving destination SNI and HTTP `Host` headers.
3. **Safe HTTP Transport & Intercepted Redirects:** `SafeHttpClient` enforces connect/read timeouts, max response truncation (2MB), rate limiting via token bucket, and intercepts all 3xx redirects to validate each intermediate destination through `validate_target()`.
4. **Evidence-Based Reconnaissance Modules:** Real DNS queries (A, AAAA, CNAME) with latency timing, TLS/SSL certificates and ciphers, HTTP response intelligence, 9-header security posture inspection, cookie attributes with value redaction (`[REDACTED]`), non-destructive `/robots.txt`, `/security.txt`, `/sitemap.xml`, and HTTP `OPTIONS`.
5. **Passive Attack Surface & Technology Detection:** Evidence-based technology detection with confidence scoring (no guessing from URL strings), page title extraction, form method/input inventory (no form submission or payload injection), and same-origin link discovery (external links cataloged but never scanned).
6. **Canonical Structured Evidence Model:** All reconnaissance observations are structured into an evidence list (`dns_record`, `tls_certificate`, `http_response`, `security_header`, `cookie_attribute`, `redirect`, `robots_entry`, `security_txt`, `sitemap_entry`, `options_method`, `technology`, `form`) persisted into `ReconResult.details`.
7. **Zero Synthetic Findings Policy:** Reconnaissance observations are strictly separated from vulnerability exploitation; missing headers or open banners do not generate synthetic findings or fake CVEs.
8. **Testing & Verification:** 18/18 tests in `scratch/verify_phase7c_real_recon.py` passed (100%). Regression suites across Phase 2 (Dashboard), Phase 4 (Findings), Phase 5 (Settings), and Phase 6 (Reports) passed with zero regressions. Frontend builds cleanly with zero TypeScript errors.

---

## 2. Architecture & Data Flow

```
[ User Input URL ]
        │
        ▼
[ Target Validation Layer ]  ──(Blocks loopback, RFC1918/4193, cloud metadata, internal TLDs)──► [ Reject 400 ]
        │ (Approved Target)
        ▼
[ DNS Intelligence (dnspython) ] ──► (Resolves A, AAAA, CNAME + Latency)
        │
        ▼
[ PinnedNetworkBackend ] ──(Constrains socket to validated destination IP)──► [ DNS Rebinding Defense ]
        │
        ├──► TLS Handshake (SNI: target_host, Socket: pinned_ip) ──► TLS Certificate & Cipher Audit
        │
        ├──► HTTP GET (SafeHttpClient) ──(Intercepts 3xx Redirects & Re-Validates Each Hop)
        │       │
        │       ├──► Status, Headers, Content-Type, Latency
        │       ├──► 9 Security Headers Audit (HSTS, CSP, X-Frame, etc.)
        │       ├──► Cookie Attributes Audit (Values [REDACTED])
        │       ├──► Technology Detection (DOM & Server Signatures)
        │       └──► Passive Surface Discovery (Forms, Scripts, Links)
        │
        ├──► Non-Destructive Metadata Endpoints (/robots.txt, /security.txt, /sitemap.xml)
        │
        └──► Non-Destructive HTTP OPTIONS (Allowed Methods)
        │
        ▼
[ Structured Evidence Assembly ] ──► (Redacted, Confidence-Scored Observations)
        │
        ▼
[ Database Persistence (ReconResult) ] ──► Scoped strictly to user_id and scan_id
        │
        ▼
[ WebSocket Progress Stream ] & [ ReportLab PDF Integration ]
```

---

## 3. Safe Transport & DNS Rebinding Protections

### Concept & Problem
Traditional HTTP clients resolve domain names dynamically during connection. An attacker controlling a DNS server can return a public IP during initial validation and a private/internal IP (e.g., `127.0.0.1` or `169.254.169.254`) when the client connects (Time-of-Check to Time-of-Use DNS Rebinding).

### Implementation in Cyvera (`app.services.safe_client`)
* **`PinnedNetworkBackend(httpcore.AsyncNetworkBackend)`:**
  1. Intercepts `connect_tcp(host, port)` before any network connection is opened.
  2. Runs `validate_target(f"http://{host}:{port}")`. If the destination resolves to a private IP, loopback, or metadata address, raises `SecurityPolicyViolation` and immediately aborts.
  3. Extracts the approved destination IP (`pinned_ip = val_res.resolved_ips[0]`).
  4. Delegates to `_backend.connect_tcp(pinned_ip, port)`.
  5. The TLS wrapper receives `server_hostname=host`, preserving SNI and HTTP `Host` headers while guaranteeing the socket connects strictly to the pre-validated public IP.

---

## 4. Redirect Protections

Implemented in `SafeHttpClient.request()`:
1. `follow_redirects=False` at the client level ensures automatic redirects cannot bypass validation.
2. For every 301, 302, 303, 307, 308 response:
   * Extracts `Location` header and computes `next_url = urllib.parse.urljoin(current_url, location)`.
   * Passes `next_url` through `validate_target()`. If destination is private or loopback, raises `UnsafeRedirectError`.
   * Enforces same-host scope by default (`allow_cross_domain_redirects=False`). External domain pivots are blocked.
   * Enforces `max_redirects = 5`.
   * Records every hop with status code, source, destination, and validation status in `redirect_history`.

---

## 5. Evidence-Based Reconnaissance Modules

| Module | Inspection Vector | Evidence Collected |
| :--- | :--- | :--- |
| **DNS Intelligence** | A, AAAA, CNAME via `dnspython` + socket fallback | IP addresses, canonical names, TTL, resolution timing (`ms`), query status |
| **TLS / SSL** | Public certificate & cipher suites via pinned socket | Subject, Issuer CA, NotBefore, NotAfter, Days remaining, SANs, TLS version (`TLSv1.3`), Cipher suite, verification status |
| **HTTP Response** | Status line, headers, transport | Status code, HTTP version, Content-Type, Content-Length, Server header, Elapsed seconds, compression |
| **Security Headers** | 9 canonical headers (HSTS, CSP, X-Content-Type, X-Frame, Referrer, Permissions, COOP, CORP, COEP) | Present/Missing status, actual directive values, security descriptions (Recorded as observations, **not** synthetic vulnerabilities) |
| **Cookie Audit** | `Set-Cookie` directives | Cookie name, Secure, HttpOnly, SameSite, Path, Domain, Expiry. **Values are strictly redacted as `[REDACTED]`** |
| **robots.txt** | `/robots.txt` | HTTP status, disallowed path rules, content snippet |
| **security.txt** | `/.well-known/security.txt` & `/security.txt` | Contact, Policy, Encryption, Expires fields |
| **sitemap.xml** | `/sitemap.xml` | XML URL count, sample indexed URLs (bounded to 10) |
| **HTTP Methods** | Non-destructive `OPTIONS` | `Allow` header directives, permitted HTTP verbs |
| **Technology Stack** | Headers (`Server`, `X-Powered-By`) & DOM anchors | Frameworks, Web servers, CMS, Frontend libraries, confidence level, evidence string |
| **Attack Surface** | HTML forms, links, script/CSS dependencies | Page title, form method/action/input names (zero form submission), same-origin link inventory, script sources |

---

## 6. Verification & Test Results

Executed automated test suite `scratch/verify_phase7c_real_recon.py`:

```
test_01_public_authorized_target_resolution ... ok
test_02_dns_results_are_real ... ok
test_03_tls_data_is_real ... ok
test_04_http_status_is_real ... ok
test_05_security_headers_come_from_actual_response ... ok
test_06_cookie_values_are_never_persisted ... ok
test_07_redirect_destinations_are_revalidated ... ok
test_08_private_ip_redirect_is_blocked ... ok
test_09_localhost_redirect_is_blocked ... ok
test_10_dns_resolution_returning_blocked_address_rejected ... ok
test_11_discovered_external_domain_links_not_scanned ... ok
test_12_response_size_limits_work ... ok
test_13_timeout_limits_work ... ok
test_14_cancellation_works ... ok
test_15_tenant_isolation_works ... ok
test_16_no_synthetic_finding_function_exists ... ok
test_17_no_fake_cves_generated ... ok
test_18_phase7b_validators_continue_passing ... ok

----------------------------------------------------------------------
Ran 18 tests in 20.504s

OK (18/18 passed, 100%)
```

### Regression Verification:
* **Phase 2 (Scans/Dashboard):** PASS (17 scans retrieved for user `Yash`).
* **Phase 4 (Findings):** PASS (17 findings retrieved for user `Yash`).
* **Phase 5 (Settings):** PASS (Settings intact).
* **Phase 6 (Reports):** PASS (16 reports intact).
* **Phase 7C Recon API (`/api/v1/recon/inspect`):** PASS (Recon succeeded on authorized target, rejected loopback target with HTTP 400).
* **Frontend Build (`npm.cmd run build`):** PASS (TypeScript compilation & Vite bundle complete in 52.92s with zero errors).

---

## 7. Known Limitations & Phase 7D Scope

1. **Active Crawling & Spidering:** Surface discovery in Phase 7C is passive (bounded to single-page DOM and metadata endpoints). Deep recursive crawling and attack-surface graphing will be introduced in Phase 7D.
2. **Form Exploitation:** Phase 7C intentionally inventories forms without submitting them. Active parameter testing will be implemented in Phase 7E with explicit operator authorization.
3. **JavaScript Execution (Headless Browser):** Reconnaissance analyzes raw HTML and hydration markers (`__NEXT_DATA__`, React/Vue root elements). Heavy client-side Single Page Applications without SSR will disclose limited DOM anchors during static HTTP requests.

---

**PHASE 7C: PASS**
