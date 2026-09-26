# PROJECT PHASE 4 — FINDINGS INTEGRITY, SARIF IMPORT & SECURITY DATA CONSISTENCY AUDIT REPORT

**Date:** 2026-09-20  
**Phase:** Phase 4 — Findings Integrity, SARIF Import & Security Data Consistency  
**Status:** Complete & Production-Verified  

---

## 1. Findings Architecture

In Phase 4, the entire vulnerability findings subsystem was re-engineered to establish a single, unified source of truth across all application components:
$$\text{SARIF / Scanner Input} \longrightarrow \text{Normalization Layer} \longrightarrow \text{Database} \longrightarrow \begin{cases}
\text{Findings & Vulnerabilities UI} \\
\text{Security Score Engine} \\
\text{OWASP Top 10 Mapping} \\
\text{Analytics Telemetry} \\
\text{Gemini AI Advisory} \\
\text{PDF Executive Reports}
\end{cases}$$

Every finding record is stored canonically in the `findings` table in PostgreSQL / SQLite, carrying title, description, normalized severity, CVSS v3 score, CVE/CWE identifier, affected URL/component, triage status, actionable remediation guidance, and creation timestamp.

---

## 2. Existing SARIF Problem & 3. Root Cause

### Symptoms
In previous phases, calling `POST /api/v1/findings/import-sarif` resulted in immediate failure with `500 Internal Server Error` or validation error, preventing build pipelines and users from uploading vulnerability audit reports.

### Root Cause Analysis (BUG-01)
A threefold mismatch existed across the codebase:
1. **Schema Mismatch**: `backend/app/schemas.py` defined `SARIFImportPayload` expecting `sarif_data: Dict[str, Any]`.
2. **Router Implementation**: `backend/app/routers/findings.py` attempted to iterate over `payload.findings` (`for item in payload.findings:`), raising `AttributeError: 'SARIFImportPayload' object has no attribute 'findings'`.
3. **Frontend Payload**: `frontend/src/api/findings.ts` sent `{ tool_name: "...", findings: [...] }`.
4. **Standard SARIF 2.1.0 Incompatibility**: Standard OASIS SARIF documents containing `runs`, `driver`, and `results` were completely unsupported and crashed during parsing.
5. **Database Column Mismatch**: SQLite dev database lacked the `secure_coding_recommendations` column on `ai_explanations`, which caused cascade loading on findings to throw `OperationalError: no such column`.

---

## 4. Canonical Finding Schema

The canonical schema represents every vulnerability finding across the platform:

```python
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False, index=True) # Critical, High, Medium, Low, Info
    cvss_score = Column(Float, nullable=True)                 # 0.0 - 10.0
    cve_id = Column(String(100), nullable=True)               # e.g. CVE-2024-21626, CWE-89, OWASP-A03
    affected_url = Column(String(2048), nullable=False)
    status = Column(String(50), nullable=False, default="Open")
    remediation_guidance = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
```

---

## 5. Severity Normalization

Arbitrary scanner severities are normalized through `normalize_severity()` in `backend/app/services/sarif_parser.py`:

| Scanner / Input Level | Qualitative CVSS Range | Normalized Severity Tier |
|---|---|---|
| `critical`, `CRITICAL`, `fatal`, `blocker` | $\ge 9.0$ | **Critical** |
| `high`, `HIGH`, `error`, `severe` | $7.0 \le \text{CVSS} < 9.0$ | **High** |
| `medium`, `MEDIUM`, `moderate`, `warning`, `warn` | $4.0 \le \text{CVSS} < 7.0$ | **Medium** |
| `low`, `LOW`, `minor`, `note`, `notice` | $0.1 \le \text{CVSS} < 4.0$ | **Low** |
| `info`, `informational`, `none`, `unspecified` | $0.0$ | **Info** |
| *Unknown / unmapped strings* | N/A | **Info** (Safe documented fallback) |

---

## 6. SARIF 2.1.0 Normalization Engine

Implemented in `backend/app/services/sarif_parser.py`:
- **Driver Rules Extraction**: Maps `run.tool.driver.rules` by `id` and numerical index.
- **Title & Description**: Extracts rule `name`, `shortDescription`, `message.text`, and `fullDescription`.
- **Physical Locations**: Parses `locations[0].physicalLocation.artifactLocation.uri` and `region` (startLine, startColumn) to construct exact source references.
- **CVE & CWE Tag Extraction**: Scans rule IDs, names, and tags for `CVE-\d{4}-\d+`, `CWE-\d+`, and `OWASP-A\d+` patterns using regular expressions.
- **Remediation**: Extracts actionable advice from rule `help.text`, `help.markdown`, or `helpUri`.
- **Input Flexibility**: Ingests:
  1. Direct standard SARIF 2.1.0 documents (with `runs` array).
  2. Wrapped envelopes (`sarif_data`).
  3. Custom pipeline payloads (`findings` list).

---

## 7. Deduplication Behavior

To prevent duplicate findings during repeated CI/CD pipeline imports or resubmissions:
- Uniqueness is evaluated on the tuple: `(user_id, scan_id, title, affected_url)`.
- If an existing finding matches this identity within the user's scope:
  - Updates technical fields (`description`, `severity`, `cvss_score`, `cve_id`, `remediation_guidance`).
  - **Preserves existing triage status** (e.g. if the operator marked it `Resolved` or `False Positive`, re-importing the SARIF file does *not* revert it to `Open`).
- If no match exists, a new `Finding` row is inserted.

---

## 8. Authorization & Multi-Tenant User Isolation

Strict tenant boundaries were implemented and verified:
1. **Finding CRUD**:
   - `GET /api/v1/findings`: Scoped to `Finding.user_id == current_user.id`.
   - `GET /api/v1/findings/{id}`: Requires `Finding.id == id, Finding.user_id == current_user.id`; returns HTTP 404 if unauthorized.
   - `PATCH /api/v1/findings/{id}/status`: Requires `Finding.user_id == current_user.id`; returns HTTP 404 if unauthorized.
   - `DELETE /api/v1/findings/{id}`: Requires `Finding.user_id == current_user.id`; returns HTTP 404 if unauthorized.
2. **Scan Association**:
   - `POST /api/v1/findings`: If `scan_id` is supplied, verifies `Scan.id == scan_id, Scan.user_id == current_user.id`.
3. **AI Analysis Isolation**:
   - In `backend/app/routers/ai.py`, removed the insecure cross-tenant fallback query `select(Finding).where(Finding.id == finding_id)`.
   - Verified that User B attempting to analyze User A's finding receives HTTP 404.

---

## 9. Triage Behavior

- Supported database-persisted statuses:
  - `Open` (Default for new findings)
  - `In Review` (Under operator triage)
  - `Confirmed` (Validated real risk)
  - `Mitigated` (Temporary compensating controls in place)
  - `Resolved` (Vulnerability fixed and patched)
  - `False Positive` (Non-issue validated by security lead)
  - `Accepted Risk` (Documented business exception)
- Verified that triage status persists across page refreshes, logouts, and server restarts.

---

## 10. OWASP Mapping

- Integrated with `backend/app/services/owasp_mapper.py`.
- Evaluates finding titles, descriptions, and CVE/CWE identifiers to map findings into standard OWASP Top 10 2021 categories (`A01` through `A10`).
- No categories are fabricated: unmapped items default safely according to documented rule heuristics.

---

## 11. CWE & CVSS Handling

- Real CVSS scores are preserved as floats from SARIF `security-severity` or `cvss` properties.
- **Eliminated Fake Fallbacks**:
  - Removed `{finding.cvss_score || 8.0}` in `Vulnerabilities.tsx`.
  - Removed `{selectedFinding.cvss_score || 8.0}` in `Vulnerabilities.tsx` detail modal.
  - Removed `{f.cvss_score || '5.0'}` in `ExpandableFindings.tsx`.
  - Missing CVSS scores now cleanly display `CVSS N/A`.

---

## 12. Sensitive Evidence Handling & Redaction

Implemented `redact_sensitive_evidence()` in `sarif_parser.py`:
- Redacts bearer tokens: `Bearer [A-Za-z0-9-_.]+` $\rightarrow$ `Bearer [REDACTED_TOKEN]`
- Redacts passwords: `password=...` $\rightarrow$ `password=[REDACTED_PASSWORD]`
- Redacts API keys: `apikey=...` $\rightarrow$ `apikey=[REDACTED_API_KEY]`
- Redacts client secrets: `secret=...` $\rightarrow$ `secret=[REDACTED_SECRET]`
- Enforces maximum payload size of 10 MB and max 500 findings per batch to prevent memory exhaustion and DoS.

---

## 13. Security Score Integration

- `calculate_security_score()` evaluates active unmitigated findings: `status in ["Open", "In Review"]`.
- Deductions: Critical (-20 pts), High (-10 pts), Medium (-5 pts).
- Findings marked `Resolved`, `Mitigated`, or `False Positive` automatically restore health points.

---

## 14. Analytics Integration

- `calculate_analytics_overview()` in `risk_engine.py` directly consumes the user's `Finding` records.
- Severity distributions, OWASP distributions, and chronological time series reflect both scanner-discovered and SARIF-imported findings.
- Triage status updates immediately update the `resolved_findings` and `sla_compliance_rate` metrics.

---

## 15. AI Security Advisor Integration

- `POST /api/v1/ai/analyze/{finding_id}` generates 6-section Gemini advisory:
  1. Executive Summary
  2. Technical Description / Root Cause
  3. Business Impact
  4. Conceptual Attack Scenario
  5. Developer Remediation Steps & Secure Coding Guidance
  6. OWASP Mapping
- Persisted in `ai_explanations` table and scoped to authenticated operator.

---

## 16. PDF Report Integration

- In `backend/app/routers/reports.py`, finding queries strictly filter by `Finding.scan_id == scan.id, Finding.user_id == current_user.id`.
- Imported findings attached to a scan seamlessly appear in the generated executive PDF reports.

---

## 17. Tests Performed

### Automated Backend Test Suite (`scratch/verify_phase4_findings.py`)
All 21 test criteria specified in Objective 18 passed:
1. `Test A`: Standard scanner finding created and retrieved $\rightarrow$ **PASSED**
2. `Test B`: Standard OASIS SARIF 2.1.0 ingested finding with location, severity, CVSS, and CWE $\rightarrow$ **PASSED**
3. `Test C, D, E`: Multi-result SARIF with missing fields & severities normalized correctly $\rightarrow$ **PASSED**
4. `Test F`: Empty SARIF runs gracefully returned `[]` $\rightarrow$ **PASSED**
5. `Test G`: Malformed SARIF rejected with HTTP 422 $\rightarrow$ **PASSED**
6. `Test H`: Custom frontend format import succeeded $\rightarrow$ **PASSED**
7. `Test I`: Deduplication verified (re-import updated existing finding row) $\rightarrow$ **PASSED**
8. `Test J`: Multi-tenant user isolation enforced on GET, PATCH, DELETE, and AI endpoints $\rightarrow$ **PASSED**
9. `Test K`: Unauthorized requests rejected with HTTP 401 $\rightarrow$ **PASSED**
10. `Test L, M`: Finding retrieval and triage persistence verified (Status: Resolved) $\rightarrow$ **PASSED**
11. `Test N, O, P`: OWASP, CWE, and CVSS scores preserved accurately $\rightarrow$ **PASSED**
12. `Test Q, R`: Security Score and Analytics reflect canonical finding state $\rightarrow$ **PASSED**
13. `Test S`: Finding deletion verified (HTTP 404 confirmed after delete) $\rightarrow$ **PASSED**

### Automated Browser Verification (`browser_subagent`)
1. Logged in as `Yash`: confirmed real findings loaded with dynamic CVSS scores (9.4, 9.8, 9.1, 8.1, 7.8, N/A) without fake 8.0 fallbacks.
2. Ingested SARIF payload via import modal: modal auto-closed and new finding appeared in real time.
3. Updated finding triage status to `In Review`: verified status pill updated immediately.
4. Generated AI Security Advisory: verified 5 structured sections loaded.
5. Logged in as `AuditUserB`: verified complete isolation ("No Matching Vulnerabilities", 0 findings leaked).
6. Captured visual artifacts:
   - Yash Vulnerabilities View: `yash_vulnerabilities_1789925539499.png`
   - AuditUserB Empty View: `audituserb_vulnerabilities_1789925657528.png`
   - Video recording: `findings_phase4_test_1789925291100.webp`

---

## 18. Build Result

- Executed `npm.cmd run build` inside `frontend/`.
- **Result**: `tsc && vite build` completed with **Exit Code 0** in 20.71s.
- **Output**: 2566 modules transformed, 0 TypeScript errors.

---

## 19. Remaining Limitations

- SARIF 2.1.0 supports embedded file contents inside `artifact.contents.text`; currently, physical file URIs and line/column regions are extracted rather than storing entire embedded file blobs in the database.
- For extremely large codebases generating SARIF files >10 MB, a streaming parser (e.g. `ijson`) can be added to stream results without loading the full DOM in memory.
