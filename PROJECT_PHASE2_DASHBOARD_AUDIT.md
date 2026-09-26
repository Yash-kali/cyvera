# PROJECT PHASE 2 — DASHBOARD DATA INTEGRITY & REAL BACKEND STATE AUDIT REPORT

**Date:** 2026-09-20  
**Phase:** Phase 2 — Dashboard Data Integrity & Real Backend State  
**Status:** Complete & Verified  

---

## 1. Executive Summary

During Phase 2, a comprehensive audit of the Cyvera Security Operations Center (SOC) Dashboard, global navigation headers, and associated widgets was conducted. The primary issue was that while the database contained an actual completed scan (`SCN-1` on `https://api.user-a-target.com` with real security findings, score of `5`, grade `F`, and 0 running scans), the frontend global navigation was hardcoded with `ACTIVE (1 RUNNING)`, `88 / 100`, `GRADE A`, and fake notification alerts. Furthermore, several dashboard and chart components had static defaults (e.g. `progress = 65%`, `score = 88`), and the backend findings endpoint had an automatic seeding routine that injected fake findings whenever a user's findings table was empty.

All hardcoded mock metrics and fake seeding mechanisms have been removed. A unified, reactive `ScanContext` and `useScanTelemetry` hook was established, bridging real-time WebSocket progress, the backend Security Score engine, and the authenticated user's scan repository directly to the global header, dashboard widgets, and history tables.

---

## 2. Files Inspected

### Frontend Components & Pages
- `frontend/src/components/Navbar.tsx` (Global navigation bar & header status pills)
- `frontend/src/components/Layout.tsx` (Protected layout wrapper)
- `frontend/src/components/scans/CinematicScanSequence.tsx` (5-stage pipeline progress sequence)
- `frontend/src/pages/Dashboard.tsx` (Main SOC Dashboard page)
- `frontend/src/pages/ScanHistory.tsx` (Scan history queue & actions)
- `frontend/src/pages/NewScan.tsx` (Target scope configuration & launcher)
- `frontend/src/pages/ScanDetails.tsx` (Scan deep-dive view)
- `frontend/src/pages/ReconResults.tsx` (Asset reconnaissance audit view)
- `frontend/src/pages/RiskAnalytics.tsx` (CVSS risk engine analytics page)
- `frontend/src/components/dashboard/SecurityScoreCore.tsx` (Reactor core gauge)
- `frontend/src/components/dashboard/SecurityScoreWidget.tsx` (Secondary posture score gauge)
- `frontend/src/components/dashboard/ScanActivityFeedWidget.tsx` (Activity telemetry feed)
- `frontend/src/components/dashboard/SeverityRadarChartWidget.tsx` (Compliance radar chart)
- `frontend/src/components/dashboard/VulnerabilityGalaxy.tsx` (3D canvas galaxy map)
- `frontend/src/components/dashboard/ReconNetworkGraph.tsx` (Neural topology canvas)
- `frontend/src/components/dashboard/OwaspDistributionWidget.tsx` (OWASP pie chart)
- `frontend/src/components/dashboard/AiRecommendationsWidget.tsx` (AI threat advisor card)
- `frontend/src/components/dashboard/VulnerabilityHeatmapWidget.tsx` (Matrix heatmap widget)
- `frontend/src/components/security/SecurityScoreEngine.tsx` (Score calculation breakdown)
- `frontend/src/components/charts/SecurityScoreMeter.tsx` (Legacy meter chart)

### Backend Routers & Services
- `backend/app/routers/scans.py` (`/api/v1/scans` CRUD, user isolation, WebSocket)
- `backend/app/routers/security_score.py` (`/api/v1/security-score/{scan_id}`)
- `backend/app/routers/findings.py` (`/api/v1/findings`)
- `backend/app/routers/recon.py` (`/api/v1/recon/*`)
- `backend/app/routers/owasp.py` (`/api/v1/owasp/*`)
- `backend/app/routers/analytics.py` (`/api/v1/analytics/*`)
- `backend/app/services/scan_progress.py` (Background scan execution & real-time WS broadcaster)
- `backend/app/services/security_score.py` (CVSS score, grade, and deduction calculation engine)
- `backend/app/database.py` (Database session & startup initialization)

---

## 3. Hardcoded / Mock Values Found & Remediation

| Location | Hardcoded Value Found | Root Cause | Remediation Applied |
|---|---|---|---|
| `Navbar.tsx:98` | `ACTIVE (1 RUNNING)` | Hardcoded text in JSX | Dynamically displays `ACTIVE (${runningScansCount} RUNNING)` when scans are running, or `STANDBY (0 RUNNING)` when none are running. |
| `Navbar.tsx:104` | `88 / 100` | Hardcoded text in JSX | Dynamically displays `${securityScore} / 100` derived from latest completed scan, or `-- / 100` on empty state. |
| `Navbar.tsx:105` | `GRADE A` | Hardcoded text in JSX | Dynamically displays `GRADE ${securityGrade}` (e.g. `GRADE F` for scan #1), or `STANDBY` on empty state. |
| `Navbar.tsx:59-63` | `mockNotifications` array | Static mock array with fake CVEs (`CVE-2024-21626`) | Dynamically derived from actual recent scans and findings belonging to the authenticated user. |
| `CinematicScanSequence.tsx:11` | `progress = 65` | Hardcoded default parameter | Changed default to `progress = 0` and stage to `'Security Pipeline Standby — Ready for Target Scan'`. |
| `Dashboard.tsx:39` | `useState('https://staging-api.autopentest.ai')` | Hardcoded initial state | Changed initial state to empty string `''` with clean HTML input placeholder. |
| `Dashboard.tsx:242` | Fallback score from `riskSummary` | Fallback defaulted to `100` / `Grade A+` even when user had 0 scans | When 0 scans exist, `currentScore`, `currentGrade`, and `currentRisk` are `null`, rendering clean honest empty state. |
| `findings.py:106-161` | Auto-seeding 5 fake demo findings | Silent DB commit when user findings were empty | Removed auto-seed block entirely; now cleanly returns `[]` when no findings exist. |
| `ReconNetworkGraph.tsx:106` | Missing dependency `[]` in `useEffect` | Graph never re-rendered when `recon` loaded | Added `[recon]` to `useEffect` dependency array so the canvas graph re-renders immediately upon telemetry load. |
| `SecurityScoreEngine.tsx:26` | Fallback mock object (`score: 82`) | Hardcoded catch block mock data | Replaced with explicit error state; displays backend error message without fake fallbacks. |
| `RiskAnalytics.tsx:135` | `{summary ? summary.security_score : 88.0}` | Hardcoded fallback `88.0` and `GRADE A` | Replaced fallbacks with `'--'`. |
| `SecurityScoreWidget.tsx:12` | Default props `score = 88`, `grade = 'A'` | Hardcoded default parameters | Changed defaults to `null` and handled non-existent score with `--` and `NO DATA`. |
| `SecurityScoreMeter.tsx:15` | Default props `score = 88.0`, `grade = 'GRADE A'` | Hardcoded default parameters | Changed defaults to `0` and `AWAITING`. |
| `ReconResults.tsx:32-73` | Hardcoded mock object in `useState` | Static initial state with `staging-api.autopentest.ai` | Changed initial state to `null` and load real historical recon from `getReconHistoryApi()`. |
| `NewScan.tsx:23` | `useState('https://staging-api.autopentest.ai')` | Hardcoded default target URL | Changed default to empty string `''` with clean placeholder. |

---

## 4. APIs Used & Confirmed

All metrics are now sourced from existing, user-isolated backend APIs:

1. **`GET /api/v1/scans`**:
   - Authenticated with user JWT.
   - Enforces `Scan.user_id == current_user.id`.
   - Returns scan status, profile, target URL, vulnerabilities count, critical count, security score, and security grade.
2. **`GET /api/v1/security-score/{scan_id}`**:
   - Calculates score (0–100), grade (A–F), and risk deductions strictly for the authenticated user's scan.
   - Persists score back to the scan table.
3. **`GET /api/v1/findings?scan_id={scan_id}`**:
   - Returns vulnerability findings strictly belonging to the given scan and authenticated user.
4. **`GET /api/v1/recon/history`**:
   - Returns defensive DNS/TLS/Header inspection results for the user's scans.
5. **`GET /api/v1/owasp/stats/{scan_id}`**:
   - Generates category distributions and compliance matrices for the scan's findings.
6. **`WS /ws/scans/{scan_id}`**:
   - Streams live scan execution stages (25%, 55%, 80%, 95%, 100%) and updates telemetry across components.

---

## 5. Summary of Code Changes

### Backend Changes
- **`backend/app/routers/findings.py`**:
  - Removed lines 106–161 containing the automatic demo findings seeding routine.
  - Ensures genuine database state and empty state integrity.

### Frontend Changes
- **`frontend/src/context/ScanContext.tsx`** *(New)*:
  - Global `ScanProvider` managing unified scan telemetry, running scan count, latest completed scan metrics, WebSocket progress listener, and cache synchronization.
- **`frontend/src/App.tsx`**:
  - Wrapped protected routes with `<ScanProvider>`.
- **`frontend/src/components/Navbar.tsx`**:
  - Replaced hardcoded `ACTIVE (1 RUNNING)` with dynamic `runningScansCount`.
  - Replaced hardcoded `88 / 100` and `GRADE A` with dynamic `securityScore` and `securityGrade`.
  - Converted static mock notifications into live alerts derived from user scans.
- **`frontend/src/pages/Dashboard.tsx`**:
  - Connected to `useScanTelemetry()`.
  - Removed local duplicate scan state and duplicate WebSocket listener.
  - Scoped findings and recon queries to the active or latest scan.
  - Fixed target URL initial value from hardcoded URL to `''`.
  - Ensured that when zero scans exist, metrics evaluate to `null` to display proper empty states.
- **`frontend/src/components/scans/CinematicScanSequence.tsx`**:
  - Set default `progress = 0` and stage to `'Security Pipeline Standby — Ready for Target Scan'`.
- **`frontend/src/components/dashboard/ReconNetworkGraph.tsx`**:
  - Added `[recon]` to `useEffect` dependency array so the canvas graph re-renders when recon telemetry loads.
- **`frontend/src/components/dashboard/SecurityScoreWidget.tsx`**:
  - Removed `score = 88` and `grade = 'A'`; added support for `null` score display.
- **`frontend/src/components/charts/SecurityScoreMeter.tsx`**:
  - Removed `88.0` and `GRADE A` defaults.
- **`frontend/src/components/security/SecurityScoreEngine.tsx`**:
  - Removed fake catch-block fallback payload (`score: 82`); renders explicit error banner.
- **`frontend/src/pages/RiskAnalytics.tsx`**:
  - Removed fallbacks `88.0` and `GRADE A`.
- **`frontend/src/pages/ReconResults.tsx`**:
  - Replaced hardcoded initial mock state with `null` and integrated real historical fetch.
- **`frontend/src/pages/NewScan.tsx`**:
  - Reset initial target input to `''` and added telemetry refresh upon scan creation.
- **`frontend/src/pages/ScanHistory.tsx`**:
  - Added telemetry refresh upon single and bulk scan deletion.

---

## 6. Verification & Testing Performed

| Test ID | Test Scenario | Expected Outcome | Result |
|---|---|---|---|
| **Test A** | Login as user `Yash` (`Yash@4050`) | Successful login and redirection to `/dashboard` | **PASS** |
| **Test B** | Global Header status inspection | Shows `STANDBY (0 RUNNING)` (not active 1 running) | **PASS** |
| **Test C** | Global Header score inspection | Shows `5 / 100` and `GRADE F` matching scan #1 | **PASS** |
| **Test D** | Security Core Reactor widget | Displays score `5`, `GRADE F`, and `Critical Risk` | **PASS** |
| **Test E** | Cinematic Scan Pipeline sequence | Displays `100% COMPLETED` (telemetry verified) | **PASS** |
| **Test F** | Active Penetration Scan Queue table | Lists `SCN-1`, `https://api.user-a-target.com`, 5/100 (F), 10 Total | **PASS** |
| **Test G** | Vulnerability Galaxy widget | Maps the 10 real findings for `https://api.user-a-target.com` | **PASS** |
| **Test H** | Browser page refresh (F5 / reload) | All metrics persist identically from backend state | **PASS** |
| **Test I** | Zero-Scan State test (User `AuditUserB`) | Header shows `STANDBY (0 RUNNING)` and `-- / 100 STANDBY`; Dashboard shows clean "No scans yet" card | **PASS** |
| **Test J** | User Isolation test | `AuditUserB` cannot see User `Yash`'s scans or findings; `/api/v1/security-score/1` returns HTTP 404 | **PASS** |
| **Test K** | Production build verification | `npm.cmd run build` completes with 0 errors | **PASS** |

---

## 7. Remaining Known Limitations & Next Steps

1. **Active Scan Simulation**: Background scan execution currently runs the async simulation pipeline in `scan_progress.py`. If a real external target is scanned, network firewalls on the local machine may limit raw ICMP/port inspection.
2. **WebSocket Reconnection**: In unstable mobile network conditions, WebSocket disconnects will silently fall back to HTTP polling via `refreshScans()`.
3. **Phase 3 Preparation**: Ready for subsequent phases (such as advanced report customization, copilot enhancements, or multi-target queueing) with verified backend data integrity.
