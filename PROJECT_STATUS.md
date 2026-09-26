# AutoPentest AI — PROJECT STATUS DOCUMENT
> **Project Name:** Cyvera / AutoPentest AI
> **Analyzed:** 2026-09-16
> **Status:** Partially operational — core infrastructure complete, several features broken or missing

---

## 1. Current Architecture

### Stack Overview

| Layer | Technology |
|---|---|
| Frontend | React 18 + TypeScript + Vite + TailwindCSS v3 |
| Routing | React Router DOM v6 |
| State | AuthContext (React Context API) + local component state |
| Charts | Recharts + Chart.js + react-chartjs-2 |
| Animations | Framer Motion |
| Icons | Lucide React |
| HTTP Client | Axios (with JWT interceptors) |
| Backend | FastAPI + Python 3.x (async) |
| Database ORM | SQLAlchemy 2.x (async) |
| Database | SQLite (local dev) / PostgreSQL (production) |
| Auth | JWT (PyJWT) + bcrypt password hashing |
| PDF Reports | ReportLab |
| AI Integration | Google Gemini 1.5 Flash (via REST API, with fallback) |
| Real-time | WebSocket + HTTP polling fallback |
| Deployment | Docker + Nginx (frontend) + Render (backend) |

### Directory Structure

```
Yash/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + WebSocket entry point
│   │   ├── config.py            # Settings / environment config
│   │   ├── database.py          # SQLAlchemy engine + session + seed user
│   │   ├── models.py            # 6 SQLAlchemy ORM models
│   │   ├── schemas.py           # Pydantic v2 request/response schemas
│   │   ├── auth.py              # JWT + bcrypt utilities
│   │   ├── logging_config.py    # Structured logging
│   │   ├── routers/             # 10 FastAPI router modules
│   │   └── services/            # 8 backend service modules
│   ├── requirements.txt
│   └── autopentest.db           # SQLite dev database (exists, 400KB)
└── frontend/
    └── src/
        ├── App.tsx              # Route definitions (15 routes)
        ├── api/                 # 11 API client modules
        ├── context/             # AuthContext.tsx
        ├── hooks/               # useScanProgress.ts
        ├── utils/               # soundEffects.ts
        ├── components/          # 30+ components across 7 subdirs
        └── pages/               # 16 page components
```

---

## 2. Database Models

All 6 models are fully defined and table-creating correctly via `init_db()`:

| Model | Table | Purpose | Status |
|---|---|---|---|
| `User` | `users` | Auth & account management | Working |
| `Scan` | `scans` | Scan records with score fields | Working |
| `ReconResult` | `recon_results` | DNS/TLS/Header audit data | Working |
| `Finding` | `findings` | Vulnerability findings | Working |
| `AIExplanation` | `ai_explanations` | AI analysis per finding | Working |
| `ChatMessage` | `chat_messages` | Copilot conversation history | Working |
| `Report` | `reports` | PDF report metadata + binary blob | Working |

**Seed user:** `Yash` / `yash@cyvera.ai` / `Yash@4050` — auto-created and password updated on every startup.

---

## 3. Existing API Endpoints

### Authentication — `/api/v1/auth`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Register new user, returns JWT | Working |
| POST | `/api/v1/auth/login` | JSON login (email or username) | Working |
| POST | `/api/v1/auth/login/form` | OAuth2 form login (hidden) | Working |
| GET | `/api/v1/auth/me` | Get current user from JWT | Working |

### Scans — `/api/v1/scans`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/scans` | Create scan + trigger background execution | Working |
| GET | `/api/v1/scans` | List all scans for user | Working |
| GET | `/api/v1/scans/{scan_id}` | Get scan details | Working |
| GET | `/api/v1/scans/status/{scan_id}` | HTTP poll scan progress | Working |
| DELETE | `/api/v1/scans/{scan_id}` | Delete scan + cascade | Working |
| POST | `/api/v1/scans/delete-bulk` | Bulk delete scans | Working |
| WS | `/ws/scans/{scan_id}` | WebSocket real-time progress stream | Working |
| WS | `/api/v1/scans/ws/{scan_id}` | Duplicate WS endpoint (redundant) | Redundant |

### Reconnaissance — `/api/v1/recon`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/recon/inspect` | Execute DNS/TLS/Header audit | Working |
| GET | `/api/v1/recon/history` | Recon history for user | Working |

### Findings — `/api/v1/findings`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/findings` | Create manual finding | Working |
| GET | `/api/v1/findings` | List findings (with filters) | Working |
| PATCH | `/api/v1/findings/{id}/status` | Update triage status | Working |
| POST | `/api/v1/findings/import-sarif` | Import SARIF batch | BROKEN (see bugs) |

### AI Advisor — `/api/v1/ai`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/ai/analyze/{finding_id}` | Generate AI explanation | Working (Gemini or fallback) |
| GET | `/api/v1/ai/result/{finding_id}` | Fetch stored AI result | Working |

### Analytics — `/api/v1/analytics`

| Method | Path | Description | Status |
|---|---|---|---|
| GET | `/api/v1/analytics/risk-summary` | CVSS-inspired risk metrics | Working |
| GET | `/api/v1/analytics/asset-risk` | Asset-level risk breakdown | Working |

### Security Score — `/api/v1/security-score`

| Method | Path | Description | Status |
|---|---|---|---|
| GET | `/api/v1/security-score/{scan_id}` | Calculate & return score | Working |

### OWASP Mapping — `/api/v1/owasp`

| Method | Path | Description | Status |
|---|---|---|---|
| GET | `/api/v1/owasp/{scan_id}` | Findings mapped to OWASP Top 10 | Working |
| GET | `/api/v1/owasp/stats/{scan_id}` | OWASP stats & matrix | Working |

### Chat Copilot — `/api/v1/chat`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/chat` | Send message, get AI reply | Working (Gemini or fallback) |
| GET | `/api/v1/chat/history` | Conversation history | Working |

### PDF Reports — `/api/v1/reports`

| Method | Path | Description | Status |
|---|---|---|---|
| POST | `/api/v1/reports/generate/{scan_id}` | Generate PDF report | Working |
| GET | `/api/v1/reports` | List user reports | Working |
| GET | `/api/v1/reports/{scan_id}` | Reports for scan | Working |
| GET | `/api/v1/reports/download/{report_id}` | Download PDF binary | Working |
| DELETE | `/api/v1/reports/{report_id}` | Delete report | Working |
| POST | `/api/v1/reports/delete-bulk` | Bulk delete reports | Working |

### Health

| Method | Path | Description | Status |
|---|---|---|---|
| GET | `/api/v1/health` | Health check | Working |

---

## 4. Backend Services

| Service File | Purpose | Status |
|---|---|---|
| `recon.py` | DNS resolution, TLS/SSL inspection, HTTP header audit | Complete with fallbacks |
| `scan_progress.py` | WebSocket manager + full async scan execution pipeline | Complete |
| `ai_advisor.py` | Gemini AI vulnerability explanation (7-section JSON) | Works (Gemini or fallback) |
| `chat_copilot.py` | Security copilot chat with keyword-based fallback | Works (Gemini or fallback) |
| `pdf_generator.py` | ReportLab PDF generation (Quick/Standard/Full profiles) | Complete (554 lines) |
| `risk_engine.py` | CVSS-inspired risk score calculation | Complete |
| `security_score.py` | Scan security score (0-100), grade, risk level | Complete |
| `owasp_mapper.py` | OWASP Top 10 2021 categorization & stats | Complete |

---

## 5. Frontend Pages

| Page Component | Route | Connected to Backend? | Status |
|---|---|---|---|
| `Landing.tsx` | `/` | No (public) | Complete |
| `Login.tsx` | `/login` | Yes — `/auth/login` | Working |
| `Register.tsx` | `/register` | Yes — `/auth/register` | Working |
| `Dashboard.tsx` | `/dashboard` | Yes — multiple endpoints | Working |
| `NewScan.tsx` | `/scans/new` | Yes — `/scans` POST | Working |
| `ScanHistory.tsx` | `/scans` | Yes — `/scans` GET | Working |
| `ScanDetails.tsx` | `/scans/:scanId` | Yes — WS + HTTP polling | Working |
| `ReconResults.tsx` | `/recon` | Yes — `/recon/*` | Working |
| `Vulnerabilities.tsx` | `/vulnerabilities` | Yes — `/findings` + `/ai/*` | Working |
| `FindingsDashboard.tsx` | `/findings-dashboard` | Yes — `/findings` | Working |
| `AnalyticsDashboard.tsx` | `/analytics` | Yes — `/analytics/*` | Working |
| `Reports.tsx` | `/reports` | Yes — `/reports/*` | Working |
| `Profile.tsx` | `/profile` | Partial — displays user, no API update | Partial |
| `Settings.tsx` | `/settings` | No — UI only, no persistence | UI Only |
| `RiskAnalytics.tsx` | NOT ROUTED | Yes — `/analytics/*` | Orphaned |
| `Scans.tsx` | NOT ROUTED | No — hardcoded mock data | Orphaned |

---

## 6. Frontend API Modules

| File | Endpoints Covered | Status |
|---|---|---|
| `auth.ts` | `/auth/login`, `/auth/register`, `/auth/me` | Complete |
| `scans.ts` | `/scans` CRUD + WS URL builder | Complete |
| `findings.ts` | `/findings` CRUD + SARIF import | Complete |
| `ai.ts` | `/ai/analyze`, `/ai/result` | Complete |
| `reports.ts` | `/reports` CRUD + download | Complete |
| `analytics.ts` | `/analytics/risk-summary`, `/analytics/asset-risk` | Complete |
| `recon.ts` | `/recon/inspect`, `/recon/history` | Complete |
| `chat.ts` | `/chat` POST + `/chat/history` GET | Complete |
| `owasp.ts` | `/owasp/{scan_id}`, `/owasp/stats/{scan_id}` | Complete |
| `securityScore.ts` | `/security-score/{scan_id}` | Complete |
| `client.ts` | Axios base client, JWT interceptor, auto-logout | Complete |

---

## 7. Frontend UI Components

### Shared Components
| Component | Status |
|---|---|
| `Layout.tsx` | Complete |
| `Navbar.tsx` | Complete |
| `Sidebar.tsx` | Complete |
| `ProtectedRoute.tsx` | Complete |
| `CyberBackground.tsx` | Complete |

### AI Components (`components/ai/`)
| Component | Status |
|---|---|
| `AiAnalysisPanel.tsx` | Complete |
| `AiRiskSummaryCards.tsx` | Complete |
| `ExpandableFindings.tsx` | Complete |

### Chart Components (`components/charts/`)
| Component | Status |
|---|---|
| `OwaspDistributionChart.tsx` | Complete |
| `ScanActivityChart.tsx` | Complete |
| `SecurityScoreMeter.tsx` | Complete |
| `SeverityDistributionChart.tsx` | Complete |
| `SeverityPieChart.tsx` | Complete |
| `VulnerabilityTrendChart.tsx` | Complete |

### Dashboard Widgets (`components/dashboard/`)
| Component | Status |
|---|---|
| `AiRecommendationsWidget.tsx` | Complete |
| `OwaspDistributionWidget.tsx` | Complete |
| `ReconNetworkGraph.tsx` | Complete |
| `ScanActivityFeedWidget.tsx` | Complete |
| `SecurityScoreCore.tsx` | Complete |
| `SecurityScoreWidget.tsx` | Complete |
| `SeverityRadarChartWidget.tsx` | Complete |
| `VulnerabilityGalaxy.tsx` | Complete |
| `VulnerabilityHeatmapWidget.tsx` | Complete |

### Scan Progress Components (`components/scans/`)
| Component | Status |
|---|---|
| `CinematicScanSequence.tsx` | Complete |
| `LiveProgressBar.tsx` | Complete |
| `RealTimeScanProgress.tsx` | Complete |
| `TerminalActivityFeed.tsx` | Complete |

### OWASP Components (`components/owasp/`)
| Component | Status |
|---|---|
| `CategoryDistributionChart.tsx` | Complete |
| `OwaspDrilldownView.tsx` | Complete |
| `OwaspRiskDashboard.tsx` | Complete |

### Security Components (`components/security/`)
| Component | Status |
|---|---|
| `CircularScoreGauge.tsx` | Complete |
| `RiskSummaryCards.tsx` | Complete |
| `SecurityGradeWidget.tsx` | Complete |
| `SecurityScoreEngine.tsx` | Complete |

### Copilot Components (`components/copilot/`)
| Component | Status |
|---|---|
| `FloatingChatPanel.tsx` | Complete |

---

## 8. Authentication System

- **JWT-based** using PyJWT + bcrypt (passlib)
- **Token storage:** `localStorage` (key: `autopentest_jwt_token`)
- **Token expiry:** 60 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)
- **Auto-logout:** Timer set on login, fires on expiry or 401 response from any API call
- **Auth guard:** `ProtectedRoute` component wraps all private routes
- **Session validation:** `GET /api/v1/auth/me` called on every app load to verify token
- **Global 401 handler:** Axios interceptor fires `AUTH_EXPIRED_EVENT` -> AuthContext logs out
- **Status:** Fully working

---

## 9. Scan Execution Pipeline

The scan lifecycle when a user submits a new scan:

1. `POST /api/v1/scans` -> Scan record created with `status = "Running"`
2. `ScanProgressManager.start_scan_simulation()` -> asyncio background task starts
3. **Stage 1 (5%):** Initialization broadcast via WebSocket
4. **Stage 2 (25%):** `perform_asset_recon_audit()` — real DNS, TLS, HTTP header inspection
5. **Stage 3 (55%):** `generate_target_findings()` — dynamic findings based on URL + scan type
6. **Stage 4 (80%):** `calculate_security_score()` + `calculate_owasp_stats()`
7. **Stage 5 (95%):** `generate_security_pdf_report()` — full ReportLab PDF stored as DB blob
8. **Stage 6 (100%):** Scan status set to "Completed", final WebSocket broadcast
9. Frontend: WebSocket receives updates -> `useScanProgress` hook -> visual progress UI

**Status:** Full pipeline operational

---

## 10. AI Integration

### Vulnerability Advisor (`ai_advisor.py`)
- **Real API:** Google Gemini 1.5 Flash via direct urllib REST call
- **Requires:** `GEMINI_API_KEY` environment variable
- **Fallback:** Built-in expert rules (CVE/BOLA/WebP pattern matching)
- **Output:** 7 sections — Executive Summary, Technical Description, Business Impact,
  Attack Scenario, Remediation Steps, Secure Coding Recommendations, OWASP Mapping

### Security Copilot Chat (`chat_copilot.py`)
- **Real API:** Google Gemini 1.5 Flash
- **Requires:** `GEMINI_API_KEY` environment variable
- **Fallback:** Keyword-based DevSecOps knowledge engine with code examples
- **Features:** Context-aware (passes finding/URL data), conversation history (50 messages), markdown output

---

## 11. Environment Variables

### Backend (`backend/.env`)

| Variable | Default | Notes |
|---|---|---|
| `PROJECT_NAME` | `Cyvera` | Displayed in API docs |
| `ENVIRONMENT` | `development` | |
| `SECRET_KEY` | `super-secret-...` | JWT signing key — MUST change in production |
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Token lifetime in minutes |
| `DATABASE_URL` | `sqlite+aiosqlite:///./autopentest.db` | Use PostgreSQL URL in production |
| `CORS_ORIGINS` | `["http://localhost:5173", ...]` | Adjust for production deployment |
| `GEMINI_API_KEY` | (not set) | Required for live AI; falls back gracefully if missing |

### Frontend (`frontend/.env`)

| Variable | Default | Notes |
|---|---|---|
| `VITE_API_URL` | `/api/v1` | Backend API base URL for production |

---

## 12. Package Dependencies

### Backend (`requirements.txt`)

```
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
sqlalchemy[asyncio]>=2.0.25
asyncpg>=0.29.0           # PostgreSQL async driver
psycopg2-binary>=2.9.9    # PostgreSQL sync driver (UNUSED in async mode)
pydantic>=2.6.0
pydantic-settings>=2.1.0
passlib[bcrypt]>=1.7.4
bcrypt==4.0.1             # Pinned version
pyjwt>=2.8.0
python-multipart>=0.0.6
email-validator>=2.1.0
aiosqlite>=0.19.0         # SQLite async driver (dev only)
reportlab>=4.0.0          # PDF generation
```

Missing: No `httpx` or `requests` library (uses stdlib `urllib.request` for Gemini API calls).
Missing: No `google-generativeai` SDK (direct REST calls instead).

### Frontend (`package.json`)

```
react: ^18.2.0
react-dom: ^18.2.0
react-router-dom: ^6.22.0
axios: ^1.6.7
chart.js: ^4.4.1
react-chartjs-2: ^5.2.0
recharts: ^3.10.1
framer-motion: ^13.1.0
lucide-react: ^0.323.0
jwt-decode: ^4.0.0
tailwind-merge: ^2.2.1
clsx: ^2.1.0
```

---

## 13. Working Features

| Feature | Status |
|---|---|
| User registration & login (email or username) | Working |
| JWT authentication with auto-logout | Working |
| Protected routes (redirect to login if not authenticated) | Working |
| Create new scan (Quick / Standard / Full profiles) | Working |
| Real-time scan progress via WebSocket | Working |
| HTTP polling fallback when WebSocket unavailable | Working |
| Automatic DNS/TLS/header recon during scan | Working |
| Dynamic vulnerability findings generated per scan | Working |
| Security score (0-100) + grade (A-F) calculation | Working |
| OWASP Top 10 2021 mapping of findings | Working |
| PDF report generation (Quick/Standard/Full) | Working |
| PDF report download as binary | Working |
| Bulk delete scans | Working |
| Bulk delete reports | Working |
| AI vulnerability explanation (Gemini + fallback) | Working |
| AI Security Copilot chat (Gemini + fallback) | Working |
| CVSS-inspired risk analytics | Working |
| Asset-level risk breakdown | Working |
| Manual finding creation | Working |
| Finding status updates (Open to Resolved etc.) | Working |
| Finding filters (severity, status, scan_id) | Working |
| Demo seed findings on empty state | Working |
| Seed user (Yash / Yash@4050) auto-created on startup | Working |
| Full-featured landing/marketing page | Working |
| Responsive Sidebar + Navbar layout | Working |
| Floating AI copilot chat panel | Working |
| Audit logging middleware (all requests logged) | Working |

---

## 14. Fully Operational Subsystems (Phases 1–5 Complete)

| Subsystem | Audit Status | Implementation Details |
|---|---|---|
| **Phase 1 — Auth & Configuration Security** | **COMPLETE** | Production JWT handling, secret key validation, zero-credential logging, CORS configuration. |
| **Phase 2 — Dashboard Data Integrity** | **COMPLETE** | Real DB metrics, dynamic grades/scores, zero-scan user isolation, eliminated all fake header states. |
| **Phase 3 — Analytics & Risk Intelligence** | **COMPLETE** | Dynamic analytics aggregation, target asset evaluations, multi-tenant isolation, real severity charts. |
| **Phase 4 — Findings Integrity & SARIF Import** | **COMPLETE** | OASIS SARIF 2.1.0 ingestion, deduplication, triage status updates, CVSS normalization, DELETE finding endpoint. |
| **Phase 5 — Settings, Account Security & Persistence** | **COMPLETE** | Persistent `user_settings` table, `GET`/`PATCH /settings`, `POST /auth/change-password`, `PATCH /auth/profile`, dynamic API key generation/roll, dirty tracking UX. |

---

## 15. Remaining Future Enhancements

| Feature | Details |
|---|---|
| Hardware 2FA / TOTP | UI honestly reports "NOT CONFIGURED". RFC 6238 TOTP QR code generation can be added. |
| Multi-user / team workspaces | Role-based tenant sharing across multiple enterprise user accounts. |
| Scan scheduling | Cron/automated timer triggers for recurring target security audits. |
| Webhook integrations | Outbound webhooks for Slack/Discord/SOC alerts upon scan completion. |


---

## 16. Known Problems / Bugs

### CRITICAL

**Bug 1: SARIF Import Broken [RESOLVED IN PHASE 4]**
- Standard OASIS SARIF 2.1.0 parser implemented in `backend/app/services/sarif_parser.py`
- Schema alignment in `findings.py` with multi-result normalization and deduplication.

**Bug 2: Duplicate WebSocket Endpoints**
- `/ws/scans/{scan_id}` defined in `main.py`
- `/api/v1/scans/ws/{scan_id}` defined in `routers/scans.py`
- Frontend uses only `/ws/scans/{scan_id}` — second endpoint is dead code

### MEDIUM

**Bug 3: Hardcoded IP Address in Report Generation**
- File: `backend/app/routers/reports.py` line 93
- `ip_address="104.21.32.109"` is hardcoded
- Fix: Use `recon.ip_address if recon else "N/A"`

**Bug 4: Hardcoded Date in Report ID String**
- File: `backend/app/routers/reports.py` line 100
- `f"REP-2026-0812-{scan_id:04d}-..."` — date `0812` is hardcoded
- Fix: Use `datetime.now().strftime('%m%d')`

**Bug 5: RiskAnalytics.tsx is Orphaned**
- Fully implemented page with real API calls to `/analytics/*`
- Not registered in `App.tsx` and not linked from Sidebar
- Users can never navigate to it
- Fix: Add route to App.tsx and add link in Sidebar

**Bug 6: Scans.tsx Uses Hardcoded Mock Data**
- Has a static `targetsList` array with no API calls
- Not routed in `App.tsx` (replaced by `ScanHistory.tsx`)
- Fix: Remove the file or wire it to real API

**Bug 7: Profile Password Change is UI-Only [RESOLVED IN PHASE 5]**
- Implemented `POST /api/v1/auth/change-password` with bcrypt verification, reuse check, and database update.
- Wired `Profile.tsx` and `Settings.tsx` to live backend endpoint.

**Bug 8: Settings Have No Persistence [RESOLVED IN PHASE 5]**
- Created `UserSettings` database model and `GET`/`PATCH /api/v1/settings` routes.
- Fully wired `Settings.tsx` with dirty tracking, Save/Cancel, and database persistence across reloads.


**Bug 9: WebSocket URL Production Unreliable**
- `getScanWebSocketUrl()` falls back to `localhost:8000` if `VITE_API_URL` is not a full URL
- In production (Render + Vercel), WebSocket URL construction will likely fail

### LOW

**Bug 10: Scan Type Duration Labels Misleading**
- UI says "Quick = ~3-5 min", "Standard = ~15-20 min", "Full = ~45+ min"
- Actual scan takes ~5-7 seconds total (asyncio.sleep with real HTTP calls)

**Bug 11: Dead Dependency in requirements.txt**
- `psycopg2-binary>=2.9.9` listed but async mode uses `asyncpg` only
- `psycopg2-binary` is never imported or used

**Bug 12: soundEffects.ts May Not Be Wired**
- Found in `src/utils/soundEffects.ts`
- Audio feedback feature appears incomplete or not connected to any UI events

---

## 17. Recommended Implementation Order

### Priority 1 — Critical Bug Fixes (Do First)
1. Fix SARIF import endpoint — reconcile `SARIFImportPayload` schema with router logic
2. Fix hardcoded IP address in report generation — use actual recon data
3. Fix hardcoded report ID date — use dynamic `datetime.now().strftime('%m%d')`
4. Route `RiskAnalytics.tsx` — add to `App.tsx` and Sidebar

### Priority 2 — Missing Core Features
5. Add `DELETE /api/v1/findings/{id}` endpoint + frontend delete button in Vulnerabilities page
6. Add `PUT /api/v1/auth/password` endpoint + wire Profile page password form
7. Add Settings persistence — store in DB or user-preferences model
8. Fix WebSocket URL construction for production environments

### Priority 3 — Quality Improvements
9. Remove or properly connect `Scans.tsx` — either wire to real API or delete
10. Add scan status filtering to Scan History page
11. Show real elapsed time in Scan Details
12. Implement token refresh / silent re-auth to avoid jarring logouts

### Priority 4 — New Features
13. API Key management backend — store real API keys in DB (new model + endpoints)
14. Profile update endpoint — allow username/email edits
15. CSV/JSON findings export
16. Scan filtering and search
17. Remove 2FA placeholder or implement real two-factor auth

### Priority 5 — Production Hardening
18. Fix WebSocket production config — use proper wss:// URL construction
19. Add GEMINI_API_KEY validation — warn on startup if missing
20. Add rate limiting to scan creation and AI endpoints
21. Remove dead dependency `psycopg2-binary` from requirements.txt

---

## 18. Files That May Be Safely Deleted

| File | Reason |
|---|---|
| `frontend/src/pages/Scans.tsx` | Orphaned — replaced by `ScanHistory.tsx`, uses hardcoded mock data, never routed |

---

*Document generated by automated code analysis — no application code was modified.*
