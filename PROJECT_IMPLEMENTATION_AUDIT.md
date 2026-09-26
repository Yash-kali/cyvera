# AutoPentest AI — COMPLETE IMPLEMENTATION AUDIT REPORT
> **Project:** Cyvera / AutoPentest AI
> **Audit Date:** 2026-09-16
> **Auditor:** Automated Deep Code Analysis

---

## TABLE OF CONTENTS
1. [Project Structure](#structure)
2. [Frontend Architecture](#frontend)
3. [Backend Architecture](#backend)
4. [Database Models](#models)
5. [Authentication Implementation](#auth)
6. [Scan Workflow Implementation](#scan-workflow)
7. [Scan Profile Deep-Dives](#scan-profiles)
8. [WebSocket Implementation](#websocket)
9. [API Client Layer](#api-layer)
10. [Security Score Implementation](#security-score)
11. [OWASP Mapping](#owasp)
12. [AI/Gemini Integration](#ai)
13. [AI Copilot](#copilot)
14. [PDF Report Generation](#pdf)
15. [Error Handling & Loading States](#errors)
16. [Environment Variables](#env)
17. [Frontend–Backend Connectivity](#connectivity)
18. [Mock/Placeholder Data Inventory](#mock-data)
19. [Component Reuse & Duplicates](#components)
20. [Dead/Unused Code](#dead-code)
21. [Bug Inventory](#bugs)
22. [Security Problems](#security)
23. [Dependency Issues](#dependencies)
24. [Implementation Status Summary](#summary)

---

## 1. Project Structure {#structure}

```
Yash/
├── PROJECT_STATUS.md              # Analysis document (generated)
├── backend/
│   ├── .env.example               # Sample env vars (no GEMINI_API_KEY defined!)
│   ├── requirements.txt           # Python dependencies
│   ├── autopentest.db             # SQLite dev database (~400KB, pre-populated)
│   └── app/
│       ├── main.py                # FastAPI app, CORS, middleware, WebSocket, routers
│       ├── config.py              # Pydantic Settings (reads .env)
│       ├── database.py            # SQLAlchemy async engine + seed user logic
│       ├── models.py              # 6 ORM models (User, Scan, Finding, Recon, AI, Chat, Report)
│       ├── schemas.py             # 30+ Pydantic v2 schemas
│       ├── auth.py                # JWT + bcrypt utilities
│       ├── logging_config.py      # Structured logger
│       ├── routers/
│       │   ├── auth.py            # 4 auth endpoints
│       │   ├── scans.py           # 6 scan endpoints + 1 WS (redundant)
│       │   ├── recon.py           # 2 recon endpoints
│       │   ├── findings.py        # 4 finding endpoints (SARIF BROKEN)
│       │   ├── analytics.py       # 2 risk analytics endpoints
│       │   ├── ai.py              # 2 AI advisor endpoints
│       │   ├── reports.py         # 6 report endpoints
│       │   ├── security_score.py  # 1 scoring endpoint
│       │   ├── owasp.py           # 2 OWASP endpoints
│       │   └── chat.py            # 2 copilot endpoints
│       └── services/
│           ├── recon.py           # DNS + TLS + Header inspection
│           ├── scan_progress.py   # WebSocket manager + full scan pipeline (451 lines)
│           ├── ai_advisor.py      # Gemini API + expert fallback (122 lines)
│           ├── chat_copilot.py    # Copilot Gemini + keyword fallback
│           ├── pdf_generator.py   # ReportLab PDF engine (554 lines)
│           ├── risk_engine.py     # CVSS risk metrics
│           ├── security_score.py  # Security scoring
│           └── owasp_mapper.py    # OWASP Top 10 2021 mapping
└── frontend/
    ├── package.json               # npm dependencies
    ├── vite.config.ts             # Vite + proxy config
    ├── tailwind.config.js         # TailwindCSS config
    ├── tsconfig.json              # TypeScript config
    └── src/
        ├── App.tsx                # Router (15 routes, 2 unregistered pages)
        ├── main.tsx               # React app mount
        ├── index.css              # Global CSS + Tailwind tokens
        ├── context/AuthContext.tsx
        ├── hooks/useScanProgress.ts
        ├── utils/soundEffects.ts
        ├── api/                   # 11 TypeScript API modules
        ├── pages/                 # 16 page components (2 orphaned)
        └── components/            # 30+ components in 7 subdirectories
```

---

## 2. Frontend Architecture {#frontend}

### Technology Stack
- **Framework:** React 18.2 + TypeScript 5.3
- **Bundler:** Vite 5.1 with `@vitejs/plugin-react`
- **Styling:** TailwindCSS 3.4 + custom design tokens in `tailwind.config.js`
- **Routing:** React Router DOM v6 (file: `App.tsx`)
- **State:** React Context API only (`AuthContext`) — no Redux, Zustand, or Jotai
- **HTTP:** Axios with JWT interceptors (`api/client.ts`)
- **Charts:** Both `recharts` AND `chart.js + react-chartjs-2` (dual chart library usage)
- **Animation:** Framer Motion v13
- **Icons:** Lucide React v0.323
- **JWT decode:** `jwt-decode` v4
- **Proxy:** Vite dev proxy routes `/api` → `http://localhost:8000`

### Route Architecture (`App.tsx`)
| Route | Component | Protected | Status |
|---|---|---|---|
| `/` | Landing | No | READY |
| `/login` | Login | No | READY |
| `/register` | Register | No | READY |
| `/dashboard` | Dashboard | Yes | PARTIAL (hardcoded data in scan table) |
| `/scans/new` | NewScan | Yes | READY |
| `/scans` | ScanHistory | Yes | READY |
| `/scans/:scanId` | ScanDetails | Yes | READY |
| `/recon` | ReconResults | Yes | PARTIAL (initial mock state) |
| `/analytics` | AnalyticsDashboard | Yes | PARTIAL (hardcoded pie chart data) |
| `/findings-dashboard` | FindingsDashboard | Yes | READY |
| `/vulnerabilities` | Vulnerabilities | Yes | READY (SARIF import broken) |
| `/reports` | Reports | Yes | READY |
| `/profile` | Profile | Yes | PARTIAL (no backend persistence) |
| `/settings` | Settings | Yes | UI ONLY |
| `*` | Redirect to `/dashboard` | — | — |

**UNREGISTERED pages** (exist but are not routed):
- `pages/RiskAnalytics.tsx` — 305 lines, fully connected to real API
- `pages/Scans.tsx` — hardcoded static mock data, replaced by ScanHistory

### Design System
- Custom Tailwind tokens: `cyber-cyan`, `cyber-rose`, `cyber-emerald`, `cyber-purple`, `cyber-amber`
- Custom CSS classes: `glass-card`, `glass-panel`, `shadow-glow-cyan`, `border-glow-gradient`
- Google Font: not explicitly loaded (browser defaults used)
- `font-display` class used extensively but Google Font not imported in `index.css`

---

## 3. Backend Architecture {#backend}

### Technology Stack
- **Framework:** FastAPI (async)
- **Server:** Uvicorn with standard extras
- **ORM:** SQLAlchemy 2.x async
- **Validation:** Pydantic v2 (`BaseModel`, `field_validator`, `ConfigDict`)
- **Auth:** PyJWT + passlib/bcrypt
- **Database:** SQLite (dev, via `aiosqlite`) / PostgreSQL (prod, via `asyncpg`)
- **Real-time:** Native FastAPI WebSocket (no Socket.IO, no Redis pub/sub)
- **PDF:** ReportLab
- **AI:** Direct urllib REST calls to Gemini API (no google-generativeai SDK)
- **Logging:** Custom structured logger (`logging_config.py`)

### Middleware Stack (in order)
1. CORS middleware (allow_origins from config)
2. Audit logging middleware (logs every request: method, path, status, duration)
3. Global HTTP exception handler
4. Global validation error handler (422)
5. Global unhandled exception handler (500)

### Router Registration (all registered in `main.py`)
```
/api/v1/auth      → auth.router
/api/v1/scans     → scans.router
/api/v1/recon     → recon.router
/api/v1/findings  → findings.router
/api/v1/analytics → analytics.router
/api/v1/ai        → ai.router
/api/v1/reports   → reports.router
/api/v1/security-score → security_score.router
/api/v1/owasp     → owasp.router
/api/v1/chat      → chat.router
```

**Extra (non-router):**
- WebSocket: `app.websocket("/ws/scans/{scan_id}")` in `main.py` (primary, used by frontend)
- WebSocket: `router.websocket("/ws/{scan_id}")` in `scans.py` (→ `/api/v1/scans/ws/{scan_id}`) — dead code

---

## 4. Database Models {#models}

### `User` (`users`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | autoincrement |
| username | String(50) | unique, indexed |
| email | String(255) | unique, indexed |
| hashed_password | String(255) | bcrypt |
| created_at | DateTime(tz) | UTC default |

Relationships: `scans`, `recon_results`, `findings`, `ai_explanations`, `chat_messages`, `reports` — all cascade delete

### `Scan` (`scans`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| target_url | String(2048) | |
| scan_type | String(50) | Quick / Standard / Full |
| status | String(50) | Pending / Running / Completed / Failed |
| security_score | Integer | nullable, filled after scan |
| security_grade | String(10) | nullable, A–F |
| risk_level | String(50) | nullable |
| score_details | JSON | nullable, full breakdown |
| created_at | DateTime(tz) | |

### `ReconResult` (`recon_results`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| scan_id | FK → scans | SET NULL |
| target_url | String(2048) | |
| ip_address | String(100) | |
| web_server | String(255) | |
| ssl_issuer | String(255) | |
| ssl_expires_days | Integer | |
| security_score | Integer | |
| details | JSON | Full DNS/TLS/header audit |
| created_at | DateTime(tz) | |

### `Finding` (`findings`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| scan_id | FK → scans | SET NULL |
| title | String(255) | |
| description | Text | |
| severity | String(50) | indexed — Critical/High/Medium/Low/Info |
| cvss_score | Float | nullable |
| cve_id | String(100) | nullable |
| affected_url | String(2048) | |
| status | String(50) | Open / In Review / Mitigated / Resolved / False Positive |
| remediation_guidance | Text | |
| created_at | DateTime(tz) | |

### `AIExplanation` (`ai_explanations`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| finding_id | FK → findings | CASCADE |
| executive_summary | Text | |
| technical_description | Text | |
| business_impact | Text | |
| attack_scenario | Text | |
| remediation_guidance | Text | |
| secure_coding_recommendations | Text | nullable |
| owasp_mapping | String(100) | |
| created_at | DateTime(tz) | |

### `ChatMessage` (`chat_messages`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| session_id | String(100) | indexed, default "default" |
| sender | String(20) | "user" or "assistant" |
| message | Text | |
| context | JSON | nullable |
| created_at | DateTime(tz) | |

### `Report` (`reports`)
| Column | Type | Notes |
|---|---|---|
| id | Integer PK | |
| user_id | FK → users | CASCADE |
| scan_id | FK → scans | SET NULL |
| report_id_str | String(100) | unique, e.g. REP-2026-0001-S |
| report_type | String(50) | Quick / Standard / Full |
| title | String(255) | |
| target_url | String(2048) | |
| pages | Integer | |
| file_path | String(1024) | nullable (not used) |
| pdf_bytes | LargeBinary | nullable (stores actual PDF bytes) |
| created_at | DateTime(tz) | |

**Note:** `file_path` column exists but is never populated — PDF is stored in `pdf_bytes` only.

### PostgreSQL Configuration
- **Default config:** SQLite (`sqlite+aiosqlite:///./autopentest.db`)
- **Production switch:** Set `DATABASE_URL=postgresql+asyncpg://user:pass@host/db` in `.env`
- **Auto-migration:** No Alembic — uses `Base.metadata.create_all()` on startup
- **PostgreSQL driver:** `asyncpg` for async, `psycopg2-binary` in requirements (dead dependency)
- **ISSUE:** No Alembic migrations — schema changes require manual intervention in production

---

## 5. Authentication Implementation {#auth}

### Backend (`app/auth.py`)
- **Algorithm:** HS256 JWT
- **Hashing:** bcrypt via passlib
- **Token claims:** `sub` (username), `user_id`, `email`, `exp`, `iat`
- **Dependency:** `get_current_user` Depends injects user from JWT into all protected routes
- **Token expiry:** 60 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`)
- **SECRET_KEY default:** `"super-secret-cyvera-jwt-key-change-in-production"` — hardcoded weak default

### Frontend (`context/AuthContext.tsx`)
- Token stored in `localStorage` (key: `autopentest_jwt_token`)
- User data cached in `localStorage` (key: `autopentest_user_data`)
- On app load: validates stored token via `GET /auth/me`
- `scheduleAutoLogout()`: decodes JWT with `jwt-decode`, sets `setTimeout` for token expiry
- Axios interceptor fires `AUTH_EXPIRED_EVENT` on 401 → AuthContext listens and auto-logs out
- **No token refresh** — user must re-login after expiry

### Auth Endpoints
- `POST /api/v1/auth/register` — creates user, returns JWT
- `POST /api/v1/auth/login` — JSON body with `email_or_username` + `password`
- `POST /api/v1/auth/login/form` — OAuth2 form login (hidden from docs)
- `GET /api/v1/auth/me` — returns current user (JWT required)

**Missing:**
- `PUT /api/v1/auth/password` — no password change endpoint
- `PUT /api/v1/auth/profile` — no profile update endpoint
- No email verification
- No rate limiting on login attempts (brute-force vulnerability)

---

## 6. Scan Workflow Implementation {#scan-workflow}

### Frontend → Backend Flow

**Step 1: User submits form** (`NewScan.tsx` or Dashboard modal)
```
POST /api/v1/scans
Body: { target_url, scan_type }
Returns: Scan object (id, status: "Running")
→ navigate to /scans/:scanId
```

**Step 2: ScanDetails.tsx mounts** 
```
GET /api/v1/scans/:scanId   ← metadata
GET /api/v1/findings?scan_id=X ← findings for scan
useScanProgress(scanId) hook → connects WebSocket
```

**Step 3: WebSocket hook (`useScanProgress.ts`)**
- Primary: WS connection to `/ws/scans/{scan_id}`
- If WS fails: fallback to `GET /api/v1/scans/status/{scan_id}` polling every 2500ms
- Parses JSON payloads → updates progress bar, stage label, log entries

**Step 4: After scan completes**
- `ScanDetails.tsx` shows findings table, SecurityScoreEngine, OwaspRiskDashboard
- PDF download button calls `POST /api/v1/reports/generate/{scan_id}` then downloads blob

### Backend Scan Execution (`scan_progress.py`)

Triggered by `progress_manager.start_scan_simulation(scan_id, target_url)` — creates `asyncio.Task`.

```
Stage 1 (5%):   Broadcast "Scan Started" → asyncio.sleep(1.0)
Stage 2 (25%):  perform_asset_recon_audit() → ReconResult saved to DB → sleep(1.2)
Stage 3 (55%):  generate_target_findings() → Finding objects saved to DB → sleep(1.5)
Stage 4 (80%):  calculate_security_score() + calculate_owasp_stats() → Scan score saved → sleep(1.2)
Stage 5 (95%):  generate_security_pdf_report() → Report saved as PDF blob → sleep(1.0)
Stage 6 (100%): Scan.status = "Completed" → DB commit → broadcast completion
```

**Total backend scan time:** ~6-7 seconds (due to `asyncio.sleep` calls summing ~5.9s + network I/O)

### Dashboard Mock Data Issue
`Dashboard.tsx` maintains a **local state array** `scansList` with 5 hardcoded scans:
```javascript
const [scansList, useState([
    { id: 'SCN-9024', target: '...', status: 'IN_PROGRESS', ... },
    { id: 'SCN-9023', ... }
])]
```
When a new scan is launched from the dashboard modal, it prepends to this local array — **the scan table on Dashboard does NOT reflect real database scans**. Only `ScanHistory.tsx` calls the real API.

---

## 7. Scan Profile Deep-Dives {#scan-profiles}

### Quick Scan (`scan_type = "Quick"`)
**UI Label:** "~3-5 minutes" — MISLEADING (actual: ~7 seconds)
**What it does:**
- Same full pipeline as Standard/Full
- PDF report: 8 estimated pages, "Quick Recon Audit Report" title
- `generate_target_findings()` uses `scan_type` to determine count:
  - Fewer findings generated for Quick profile
- Security score calculated the same way
- OWASP mapping applied

### Standard Vulnerability Audit (`scan_type = "Standard"`)
**UI Label:** "~15-20 minutes" — MISLEADING (actual: ~7 seconds)
**What it does:**
- Full pipeline identical to Quick
- PDF: 22 estimated pages, "Standard Vulnerability Audit Report" title
- More findings generated vs Quick

### Full Autonomous Pentest (`scan_type = "Full"`)
**UI Label:** "~45+ minutes" — MISLEADING (actual: ~7 seconds)
**What it does:**
- Full pipeline identical
- PDF: 58 estimated pages, "Full Penetration Testing Report" title
- Most findings generated
- Dashboard modal shows "api" as a third option — but `api` is not a recognized scan type in `ScanCreate.validate_scan_type()`, so it normalizes to "Standard"

**KEY FINDING:** All three scan profiles execute the SAME pipeline in the same time (~7s). The difference is only:
1. Number of findings generated
2. PDF title and estimated page count
3. Report ID suffix letter

**There is NO actual differentiation in scan depth, technique, or timing.**

---

## 8. WebSocket Implementation {#websocket}

### Backend
**Primary:** `@app.websocket("/ws/scans/{scan_id}")` in `main.py` line 103

**Duplicate (dead):** `@router.websocket("/ws/{scan_id}")` in `scans.py` line 150
- This creates `/api/v1/scans/ws/{scan_id}` — never used by frontend

**`ScanProgressManager`:**
- Maintains: `active_connections[scan_id]`, `scan_progress_cache[scan_id]`, `running_tasks[scan_id]`
- `connect()`: accepts WebSocket, adds to pool, sends cached state immediately
- `disconnect()`: removes from pool, cleans empty pools
- `broadcast_progress()`: updates cache, sends JSON to all connected sockets
- `broadcast_failure()`: marks scan as Failed

**Issue:** If a new WebSocket connects to a completed scan (e.g., user refreshes page), it receives the last cached progress (100%) correctly. But if the backend restarts, `scan_progress_cache` is cleared (in-memory only) — so historical scan progress is lost.

### Frontend (`useScanProgress.ts`)
- `connectWebSocket()`: creates WebSocket, sets up `onopen/onmessage/onerror/onclose` handlers
- On `onclose`: if scan not completed, calls `startPolling()` as fallback
- `startPolling()`: `setInterval` every 2500ms calling `GET /api/v1/scans/status/{scan_id}`
- `addLogEntry()`: deduplication logic (compares `lastLogMsgRef.current`)
- `mapStageToLevel()`: maps stage name to log color level

**WS URL construction:**
```typescript
const getScanWebSocketUrl = (scanId: number): string => {
  if (envApiUrl && envApiUrl.startsWith('http')) {
    // parse wsProtocol from VITE_API_URL
    return `${wsProtocol}//${urlObj.host}/ws/scans/${scanId}`;
  }
  return `${protocol}//localhost:8000/ws/scans/${scanId}`;  // ← hardcoded fallback
};
```
**Bug:** In production, if `VITE_API_URL` is set to `/api/v1` (relative), the fallback uses `localhost:8000` which will fail.

---

## 9. API Client Layer {#api-layer}

### `api/client.ts`
- Axios instance with `baseURL = VITE_API_URL || '/api/v1'`
- Request interceptor: reads `localStorage.getItem('autopentest_jwt_token')` → adds `Authorization: Bearer`
- Response interceptor: on 401 → clears localStorage → dispatches `AUTH_EXPIRED_EVENT`

### API Module Coverage
| Module | Endpoints | Mock Data? |
|---|---|---|
| `auth.ts` | login, register, me | No |
| `scans.ts` | CRUD + status + bulk delete + WS URL | No |
| `findings.ts` | list, create, status update, SARIF import | No |
| `ai.ts` | analyze, result | No |
| `reports.ts` | generate, list, scan reports, download, delete, bulk delete | No (downloadPdfReportApi stub → hardcoded id=1) |
| `analytics.ts` | risk-summary, asset-risk | No |
| `recon.ts` | inspect, history | No |
| `chat.ts` | send, history | No |
| `owasp.ts` | findings, stats | No |
| `securityScore.ts` | get score | No |

**Stub in `reports.ts` (line 62):**
```typescript
export const downloadPdfReportApi = async (targetUrl: string = '...'): Promise<void> => {
  return downloadReportByIdApi(1);  // ← always downloads report ID 1, ignores targetUrl
};
```
This function is exported but its behavior (hardcoded ID=1) is meaningless. Not used in main flows.

---

## 10. Security Score Implementation {#security-score}

### Backend (`services/security_score.py`)
- **Algorithm:** Starts at 100, applies deductions:
  - Critical vuln: -20 pts each
  - High vuln: -10 pts each
  - Medium vuln: -5 pts each
  - SSL issues: -10 pts (if cert invalid/expired/disabled)
  - Missing headers: -3 pts each
  - Open ports: -2 pts (always 1 = -2 pts, hardcoded)
- Clamps to [0, 100]
- Grades: A (≥80), B (≥70), C (≥55), D (≥40), F (<40)

### Backend (`services/risk_engine.py`)
- Separate CVSS-inspired engine used by `/api/v1/analytics/risk-summary`
- Calculates Risk Score (not the same as Security Score)
- `Grade A+` (≥95%), `Grade A` (≥85%), `Grade B` (≥70%), `Grade C` (≥50%), `Grade D` (≥30%), `Grade F`

**Two different scoring systems** exist side by side:
- `security_score.py` → used by `/api/v1/security-score/{scan_id}` and `SecurityScoreEngine.tsx`
- `risk_engine.py` → used by `/api/v1/analytics/risk-summary`

### Frontend
- `SecurityScoreEngine.tsx` → calls real API `GET /api/v1/security-score/{scan_id}`, has hardcoded fallback (score=82)
- `SecurityScoreCore.tsx` on Dashboard → receives `score=88, grade="A", riskLevel="Low"` as **hardcoded props** (not fetching real data)
- Dashboard widget displays hardcoded `88` score, not user's real scan data

---

## 11. OWASP Mapping {#owasp}

### Backend (`services/owasp_mapper.py`)
- Maps all 10 OWASP Top 10 2021 categories (A01–A10)
- `map_finding_to_owasp()`: keyword matching on title + description + CVE ID
- Default fallback: `A05` (Security Misconfiguration)
- `categorize_findings_by_owasp()`: groups findings by category
- `calculate_owasp_stats()`: returns counts, severity matrix, top category

### Endpoints
- `GET /api/v1/owasp/{scan_id}` → full finding groups per OWASP category
- `GET /api/v1/owasp/stats/{scan_id}` → category counts + severity matrix

### Frontend
- `OwaspRiskDashboard.tsx` component used in `ScanDetails.tsx` → calls real API
- `OwaspDistributionWidget.tsx` on Dashboard → likely hardcoded (dashboard widget)
- `CategoryDistributionChart.tsx` → chart component
- `OwaspDrilldownView.tsx` → detailed per-category view

---

## 12. AI/Gemini Integration {#ai}

### Backend (`services/ai_advisor.py`)
**Real Gemini call:**
```python
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
data = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
response = urllib.request.urlopen(req, timeout=15)
result = json.loads(response.read().decode())
text = result["candidates"][0]["content"]["parts"][0]["text"]
```

**Fallback system:** `generate_fallback_ai_explanation()` — pattern-matched expert responses for:
- runc/CVE-2024-21626 (container escape)
- BOLA/access control (API1-2023)
- WebP/CVE-2023-4863 (buffer overflow)
- HSTS/TLS header issues
- SQL injection
- Generic default fallback

**Output normalization:** extracts JSON from Gemini response, maps field aliases (`technical_explanation` → `technical_description`)

**Endpoint:** `POST /api/v1/ai/analyze/{finding_id}` — checks if `AIExplanation` exists for finding; if yes, returns cached; if no, generates and stores

### Missing from `.env.example`
`GEMINI_API_KEY` is NOT listed in `.env.example` — developers won't know to set it

---

## 13. AI Copilot {#copilot}

### Backend (`services/chat_copilot.py`)
- Same Gemini API call pattern as ai_advisor.py
- **Fallback:** keyword-based DevSecOps answers for: sql injection, xss, csrf, bola, jwt, docker, kubernetes, etc.
- Stores conversation history in `ChatMessage` table
- Returns last 50 messages as history
- Context-aware: receives `context` dict (route, scope, target_url) from frontend

### Frontend (`components/copilot/FloatingChatPanel.tsx`)
- Floating button in Layout — always visible on protected pages
- Opens slide-up panel via Framer Motion `AnimatePresence`
- Loads chat history on panel open via `getChatHistoryApi()`
- If no history, shows welcome message (hardcoded)
- Context derived from `useLocation()` — maps current route to a context object
- **Bug:** Route context mapping uses `/findings` (non-existent route) instead of `/vulnerabilities`

### Endpoint
- `POST /api/v1/chat` — sends message + context, returns AI reply + history
- `GET /api/v1/chat/history?session_id=default` — returns stored messages

---

## 14. PDF Report Generation {#pdf}

### Backend (`services/pdf_generator.py` — 554 lines)
Uses ReportLab's `SimpleDocTemplate` with custom `NumberedCanvas` for two-pass rendering.

**Cover page:** Navy blue full-bleed design with "CYVERA .AI — SECURITY OPERATIONS" branding

**Report profiles:**
- **Quick (~8 pages):** Cover + Executive Summary + Recon Results + Top Findings table
- **Standard (~22 pages):** Quick + OWASP Distribution + Severity Matrix + Full Findings section
- **Full (~58 pages):** Standard + AI Analysis cards + Deductions breakdown + Detailed remediation

**Data used:**
- `user_name`: from database
- `target_url`: from scan record
- `scan_id`: from scan
- `scan_type`: from scan
- `ip_address`: **HARDCODED as `"104.21.32.109"`** in `reports.py` line 93 (scan pipeline uses real IP from recon)
- `findings`: from DB
- `recon_result`: from DB
- `score_data`: computed live
- `owasp_stats`: computed live

### Two Generation Paths
1. **During scan** (in `scan_progress.py`): uses `audit_data["ip_address"]` — CORRECT
2. **On-demand via API** (`reports.py`): uses `ip_address="104.21.32.109"` — HARDCODED BUG

### Download Flow
```
POST /api/v1/reports/generate/{scan_id}
  → PDF bytes stored in Report.pdf_bytes (LargeBinary)
  → Returns ReportResponse with id

GET /api/v1/reports/download/{report_id}
  → Returns PDF as `application/pdf` streaming response
```

---

## 15. Error Handling & Loading States {#errors}

### Backend
- **Global HTTP exception handler:** returns `{"detail": "...", "status_code": X}`
- **Validation error handler:** returns `{"detail": "...", "errors": [...]}`
- **Unhandled exception handler:** returns generic 500 message, logs full traceback
- **Router-level:** uses `HTTPException` with appropriate status codes throughout
- **Missing:** No custom error codes or error type fields

### Frontend — Per-Page Error Handling
| Page | Loading State | Error State | Empty State |
|---|---|---|---|
| `ScanHistory.tsx` | Spinner | Error message | Empty state UI |
| `ScanDetails.tsx` | Spinner | Error message with back link | — |
| `Vulnerabilities.tsx` | Spinner | Error message | Seed findings auto-generated |
| `FindingsDashboard.tsx` | Spinner | Error message | — |
| `AnalyticsDashboard.tsx` | Loading → renders empty charts | Console.error only | — |
| `ReconResults.tsx` | Spinner on re-scan | Alert banner | Pre-populated mock state |
| `Reports.tsx` | Spinner | Console.error + alert popup | — |
| `Dashboard.tsx` | None (modal only) | alert() popup | — |

**Issues found:**
- `AnalyticsDashboard.tsx`: catch block only does `console.error` — no user-facing error display
- `Reports.tsx`: catch block uses `alert()` — poor UX for production
- `Dashboard.tsx`: uses `alert()` for scan creation errors

### Frontend — Axios Error Handling
All API calls that can fail use `try/catch`. Errors are surfaced via:
- Local `error` state + conditional rendering (most pages)
- `alert()` (Dashboard, Reports, ScanDetails modal — poor UX)
- No global error boundary component implemented

---

## 16. Environment Variables {#env}

### Backend Variables (from `config.py` + `.env.example`)
| Variable | Required | Default | Issue |
|---|---|---|---|
| `PROJECT_NAME` | No | `"Cyvera"` | — |
| `ENVIRONMENT` | No | `"development"` | — |
| `SECRET_KEY` | **YES** | `"super-secret-cyvera-jwt-key-change-in-production"` | Weak default exposes production |
| `ALGORITHM` | No | `"HS256"` | — |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `60` | — |
| `DATABASE_URL` | No | SQLite | PostgreSQL URL for production |
| `CORS_ORIGINS` | No | localhost list | Must update for production domain |
| `GEMINI_API_KEY` | For AI | *(not in .env.example!)* | Missing from example file |

### Frontend Variables
| Variable | Default | Notes |
|---|---|---|
| `VITE_API_URL` | `/api/v1` | Set to `https://backend.domain.com/api/v1` in production |

**MISSING:** No `frontend/.env.example` file exists.

---

## 17. Frontend–Backend Connectivity {#connectivity}

### Development Setup
- Vite proxy in `vite.config.ts`: `/api` → `http://localhost:8000`
- WebSocket does NOT go through Vite proxy (plain `ws://localhost:8000` or derived from `VITE_API_URL`)
- Frontend starts at `http://localhost:5173`
- Backend starts at `http://localhost:8000`

### API Base URL Logic
```typescript
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';
```
- In dev: `/api/v1` → proxied to `http://localhost:8000/api/v1` ✓
- In production: must be set to `https://backend.domain.com/api/v1`

### CORS Configuration
- Backend allows: `http://localhost:5173`, `http://localhost:3000`, `http://127.0.0.1:5173`, `http://127.0.0.1:3000`, `http://localhost`
- **Missing production domain** from CORS origins

---

## 18. Mock/Placeholder Data Inventory {#mock-data}

This is a comprehensive list of hardcoded/mock data that should be replaced with real API calls:

### Dashboard.tsx (HIGH PRIORITY)
```javascript
// Lines 29-35: Hardcoded 5-scan mock list
const [scansList, useState([
    { id: 'SCN-9024', target: '...', status: 'IN_PROGRESS', ... },
    ...5 items...
])]
```
When user creates scan from modal, it's prepended locally. Does NOT load from DB.

### Dashboard.tsx — SecurityScoreCore Widget
```jsx
<SecurityScoreCore score={88} grade="A" riskLevel="Low" />
```
Hardcoded props — not fetching user's actual scan scores.

### Dashboard.tsx — CinematicScanSequence
```jsx
<CinematicScanSequence currentStage="Vulnerability Scan Progress" progress={65} />
```
Progress `65` and stage are hardcoded constants.

### ReconResults.tsx — Initial State
```javascript
const [result, setResult] = useState<ReconResult | null>({
    id: 1,
    target_url: 'https://staging-api.autopentest.ai',
    ip_address: '104.21.32.109',
    // full hardcoded mock result...
})
```
Page loads with mock data. When user runs a real scan, state is updated. But on first load the mock is shown.

### AnalyticsDashboard.tsx — Severity Pie Chart
```javascript
const severityPieData = [
    { name: 'Critical', value: 37, color: '#ff2a6d' },
    { name: 'High', value: 45, ... },
    { name: 'Medium', value: 82, ... },
    { name: 'Low', value: 64, ... },
]
```
Hardcoded — never replaced with real data from API.

### Scans.tsx (orphaned page)
```javascript
const targetsList = [
    { id: 'SCN-9021', target: '...', ... }
    // 5 hardcoded items
]
```
Entirely static. Never routed.

### reports.ts — `downloadPdfReportApi` stub
```typescript
export const downloadPdfReportApi = async (targetUrl = '...'): Promise<void> => {
    return downloadReportByIdApi(1);  // always ID=1
}
```
Exports a broken stub function.

### reports.py — Hardcoded IP
```python
ip_address="104.21.32.109",  # line 93
```
Always `104.21.32.109` in on-demand report generation.

### reports.py — Hardcoded Date in Report ID
```python
report_id_str = f"REP-2026-0812-{scan_id:04d}-{profile_type[:1].upper()}"  # line 100
```
`0812` never changes.

### Profile.tsx — API Key
```javascript
const [apiKey, setApiKey] = useState<string>('ap_live_9f8d7c6b5a4e3f210987654321fedcba');
```
Random string, never connected to any backend.

### FloatingChatPanel.tsx — Context URL
```javascript
return { route: path, scope: 'Scan Details', target_url: 'https://staging-api.autopentest.ai' };
```
Hardcoded `target_url` for scan context — should read from actual scan data.

---

## 19. Component Reuse & Duplicates {#components}

### Duplicate Functionality
| Component A | Component B | Overlap |
|---|---|---|
| `FindingsDashboard.tsx` | `Vulnerabilities.tsx` | Both fetch `/findings`, both have AI modal, both filter by severity/status — very similar |
| `SecurityScoreCore.tsx` | `SecurityScoreEngine.tsx` | Both display security scores — Core has hardcoded props, Engine fetches real API |
| `Dashboard.tsx` scan modal | `NewScan.tsx` full page | Both create scans — different scan type options (modal: quick/full/api; page: Quick/Standard/Full) |
| `RiskAnalytics.tsx` | `AnalyticsDashboard.tsx` | Both display risk analytics from same API endpoints |
| `Scans.tsx` | `ScanHistory.tsx` | Same purpose, `Scans.tsx` is orphaned |

### Components That Accept Real API Data
| Component | Props/Fetching | Notes |
|---|---|---|
| `SecurityScoreEngine` | Fetches real API via `scanId` prop | Has good fallback |
| `OwaspRiskDashboard` | Fetches real API via `scanId` prop | Good |
| `RealTimeScanProgress` | Uses `useScanProgress` hook via `scanId` | Good |
| `FloatingChatPanel` | Fetches chat history on open | Good |

### Components That Use Hardcoded Data
| Component | Data Type |
|---|---|
| `SecurityScoreCore` | score=88, grade="A", hardcoded props always passed |
| `CinematicScanSequence` | progress=65, stage hardcoded in Dashboard |
| `ScanActivityFeedWidget` | Likely hardcoded activity items (not verified) |
| `OwaspDistributionWidget` | Likely hardcoded distribution data |
| `AiRecommendationsWidget` | Likely hardcoded recommendations |
| `SeverityRadarChartWidget` | Likely hardcoded radar values |
| `ReconNetworkGraph` | Likely hardcoded network topology |
| `VulnerabilityGalaxy` | Likely hardcoded vulnerability bubbles |
| `VulnerabilityHeatmapWidget` | Likely hardcoded heatmap data |

---

## 20. Dead/Unused Code {#dead-code}

| File/Symbol | Type | Notes |
|---|---|---|
| `pages/Scans.tsx` | Full page | Not routed, mock data, replaced by `ScanHistory.tsx` |
| `pages/RiskAnalytics.tsx` | Full page | Not routed (bug), but fully functional |
| `scans.py` L149–162 | WebSocket endpoint | `/api/v1/scans/ws/{scan_id}` — duplicate of primary WS in main.py |
| `models.py Report.file_path` | DB column | Column exists, never populated |
| `reports.ts downloadPdfReportApi` | Function | Exported but always downloads ID=1, meaningless |
| `requirements.txt psycopg2-binary` | Dependency | Not imported anywhere in async codebase |
| `schemas.py SARIFImportPayload.sarif_data` | Schema field | Defined but router uses `payload.findings` (schema mismatch) |
| `soundEffects.ts playAlert()` | Function | Defined but never called from any component |
| `dashboard scan modal` option `"api"` | Select option | Invalid scan type, normalizes to Standard |

---

## 21. Bug Inventory {#bugs}

### SEVERITY: CRITICAL

**BUG-01: SARIF Import AttributeError**
- File: `backend/app/routers/findings.py` line 58
- Code: `for item in payload.findings:`
- Schema: `SARIFImportPayload` in `schemas.py` line 166–168 defines `sarif_data: Dict[str, Any]` with NO `findings` field
- Result: `AttributeError: 'SARIFImportPayload' object has no attribute 'findings'` on ANY SARIF import attempt
- Frontend: `Vulnerabilities.tsx` has full SARIF import modal that calls this broken endpoint

**BUG-02: WebSocket URL Breaks in Production**
- File: `frontend/src/api/scans.ts` lines 57–68
- Problem: Fallback URL is `ws://localhost:8000/ws/scans/{scanId}`
- In production with Render + Vercel, `VITE_API_URL=/api/v1` (relative), so `envApiUrl.startsWith('http')` is false
- Result: WebSocket always uses `localhost:8000` — never connects in production

### SEVERITY: HIGH

**BUG-03: Dashboard Scan Table is Fake**
- File: `frontend/src/pages/Dashboard.tsx` lines 29–35
- Problem: 5 hardcoded scans never replaced by real DB data
- Result: Dashboard shows stale/fake scan history; newly created scans are prepended to local state only

**BUG-04: Dashboard Security Score Widget is Fake**
- File: `frontend/src/pages/Dashboard.tsx` line 104
- Code: `<SecurityScoreCore score={88} grade="A" riskLevel="Low" />`
- Result: Score always shows "88" regardless of actual scan data

**BUG-05: RiskAnalytics Page Unreachable**
- File: `frontend/src/App.tsx` — no route registered for `RiskAnalytics.tsx`
- Result: Fully implemented page (305 lines with real API calls) is inaccessible to users

**BUG-06: Hardcoded IP in On-Demand Report**
- File: `backend/app/routers/reports.py` line 93
- Code: `ip_address="104.21.32.109"`
- Result: All on-demand generated PDFs show wrong IP (104.21.32.109) instead of real target IP from recon data

**BUG-07: Hardcoded Date in Report ID**
- File: `backend/app/routers/reports.py` line 100
- Code: `f"REP-2026-0812-{scan_id:04d}-..."`
- Result: All on-demand reports have `0812` as date (August 12, 2026). Will always be wrong after that date.

### SEVERITY: MEDIUM

**BUG-08: Chat Context Wrong Route**
- File: `frontend/src/components/copilot/FloatingChatPanel.tsx` line 34
- Code: `if (path === '/findings')` — route is `/vulnerabilities`, not `/findings`
- Result: Copilot never detects Findings Triage context

**BUG-09: Password Change is UI-Only**
- File: `frontend/src/pages/Profile.tsx` lines 49–61
- Problem: `handleUpdatePassword()` shows success toast but makes no API call
- No backend endpoint exists

**BUG-10: Settings Have No Persistence**
- File: `frontend/src/pages/Settings.tsx`
- Problem: All three settings fields reset on page reload
- No `localStorage` save, no API call

**BUG-11: Duplicate WebSocket Endpoint**
- Files: `main.py` L103 + `scans.py` L150
- Creates two WS endpoints for same functionality
- Confusing for future maintenance

**BUG-12: Analytics Severity Filter Does Nothing**
- File: `frontend/src/pages/AnalyticsDashboard.tsx`
- `useEffect` depends on `[severityFilter, dateRangeFilter, scanTypeFilter]` and re-fetches on change
- But `getRiskSummaryApi()` and `getAssetRiskApi()` take no parameters — filters are sent nowhere
- The Severity pie chart uses a static `severityPieData` constant regardless

**BUG-13: Database Resets All User Passwords on Every Restart**
- File: `backend/app/database.py` lines 74–76
- Code: `for u in users: u.hashed_password = yash_hash`
- On every startup, ALL existing user passwords are overwritten with `Yash@4050`
- Any user who changed their password will lose it on next server restart

### SEVERITY: LOW

**BUG-14: Duplicate scan type options in Dashboard modal**
- Dashboard modal has `full`, `quick`, `api` — but `NewScan.tsx` has `Quick`, `Standard`, `Full`
- The `api` option normalizes to `Standard` silently

**BUG-15: Report page count estimates are estimates only**
- `est_pages` is never validated against actual PDF page count

**BUG-16: Token auto-logout uses `alert()`**
- File: `frontend/src/context/AuthContext.tsx` line 74
- `alert('Session Expired: Your authentication token has expired...')`
- Blocks UI with a native dialog popup

---

## 22. Security Problems {#security}

### CRITICAL SECURITY ISSUES

1. **Weak default SECRET_KEY** (`config.py` line 8)
   - Default: `"super-secret-cyvera-jwt-key-change-in-production"`
   - If deployed without setting `.env`, all JWTs can be forged
   - **Must be changed before any production deployment**

2. **`init_db()` overwrites ALL user passwords on every restart** (`database.py` lines 74-76)
   - Every user's password becomes `Yash@4050` on server restart
   - This is a catastrophic vulnerability in any multi-user scenario
   - Password change feature would be immediately broken on restart

3. **No rate limiting on auth endpoints**
   - `POST /api/v1/auth/login` has no brute-force protection
   - An attacker can attempt unlimited password combinations

4. **Gemini API key exposed via urllib calls**
   - API key is appended to URL as query parameter
   - May appear in logs if request logging includes full URLs
   
5. **No HTTPS enforcement in backend**
   - No redirect from HTTP to HTTPS
   - HSTS header not set by FastAPI

6. **JWT tokens stored in localStorage**
   - Vulnerable to XSS attacks (though no obvious XSS vectors currently exist)
   - Best practice: use httpOnly cookies

7. **Scan creation has no URL sanitization beyond format validation**
   - `ScanCreate.validate_url()` only checks `startswith('http')` and `.`
   - Could be used to scan internal network endpoints (SSRF via recon service)

### MEDIUM SECURITY ISSUES

8. **SARIF import is broken** (separately a bug, but security risk too)
   - When fixed, batch import should validate all fields

9. **No user isolation in SARIF import**
   - No `scan_id` ownership check in SARIF import router

10. **`file_path` column in Report model** — if ever used to store file paths, path traversal is possible

---

## 23. Dependency Issues {#dependencies}

### Backend `requirements.txt`

| Package | Version | Issue |
|---|---|---|
| `psycopg2-binary>=2.9.9` | Any | Dead dependency — never imported, async uses `asyncpg` |
| `bcrypt==4.0.1` | Pinned | May conflict with newer `passlib[bcrypt]` — bcrypt 4.0+ changed API |
| `asyncpg>=0.29.0` | Latest | No pin — breaking changes possible |
| `reportlab>=4.0.0` | Latest | No pin — breaking changes possible |
| *(missing)* `httpx` or `requests` | — | Uses stdlib urllib — no retry/timeout pooling |
| *(missing)* `google-generativeai` | — | Direct REST calls instead — fragile |

### Frontend `package.json`

| Package | Issue |
|---|---|
| `chart.js` + `react-chartjs-2` | AND `recharts` — both chart libraries imported |
| `tailwind-merge` | Imported but `clsx` also imported — could consolidate |
| `lucide-react@0.323` | Old version — newer versions have more icons |

---

## 24. Implementation Status Summary {#summary}

```
============================================================
FEATURE                              STATUS
============================================================
USER AUTHENTICATION
  User Registration                  READY
  User Login (JSON)                  READY
  Session persistence (localStorage) READY
  JWT auto-logout                    READY
  Password change                    BROKEN (UI only, no API)
  Profile update (username/email)    MISSING
  Rate limiting on login             MISSING
  Token refresh / silent re-auth     MISSING

SCAN WORKFLOW
  Create new scan (API)              READY
  Quick Scan profile                 PARTIAL (same as Standard, just label+page count)
  Standard Vulnerability Audit       PARTIAL (no real deeper scan; same pipeline)
  Full Autonomous Pentest            PARTIAL (no real autonomy; same pipeline)
  Real-time WebSocket progress       READY
  HTTP polling fallback              READY
  Scan deletion (single)             READY
  Scan deletion (bulk)               READY
  Scan filtering/search              PARTIAL (client-side only in ScanHistory)

ASSET RECON AUDIT
  DNS resolution                     READY (with fallback)
  TLS/SSL inspection                 READY (with fallback)
  HTTP security headers audit        READY (with fallback)
  Recon history page                 READY (initial mock state is a minor issue)

VULNERABILITY FINDINGS
  List findings (with filters)       READY
  Create finding manually            READY
  Update finding status              READY
  Delete finding                     MISSING (no endpoint, no UI)
  AI explanation per finding         READY (Gemini or fallback)
  SARIF/JSON import                  BROKEN (schema mismatch)
  Finding export (CSV/JSON)          MISSING

SECURITY SCORING
  Calculate score per scan           READY
  Display score on ScanDetails       READY
  Display score on Dashboard         BROKEN (hardcoded 88)

OWASP MAPPING
  Map findings to OWASP Top 10      READY
  OWASP stats/matrix                 READY
  OWASP dashboard view               READY

RISK ANALYTICS
  Risk summary (CVSS metrics)        READY
  Asset risk breakdown               READY
  Analytics page                     PARTIAL (hardcoded pie chart)
  Analytics filters                  BROKEN (filters sent to no API)
  RiskAnalytics page                 BROKEN (page exists but unreachable)

AI COPILOT
  Send/receive messages              READY
  Conversation history               READY
  Context from route                 PARTIAL (wrong route for /findings)
  Gemini integration                 READY (with fallback)

PDF REPORTS
  Generate report (Quick)            READY (IP hardcoded in on-demand path)
  Generate report (Standard)         READY (IP hardcoded)
  Generate report (Full)             READY (IP hardcoded)
  Download PDF                       READY
  Reports list                       READY
  Delete report (single)             READY
  Delete report (bulk)               READY
  Report ID format                   PARTIAL (hardcoded date 0812)

UI & PAGES
  Landing page                       READY
  Login/Register pages               READY
  Dashboard                          PARTIAL (hardcoded scan table, score widget)
  Scan History page                  READY
  Scan Details page                  READY
  New Scan page                      READY
  Vulnerabilities page               READY (SARIF import broken)
  Findings Dashboard page            READY
  Analytics Dashboard page           PARTIAL (hardcoded chart)
  Recon Results page                 PARTIAL (mock initial state)
  Reports page                       READY
  Profile page                       PARTIAL (display only, no edits)
  Settings page                      BROKEN (UI only, no persistence)
  Risk Analytics page                BROKEN (not routed in App.tsx)

SOUND EFFECTS
  playClick() / playScanStarted()    READY (used in Dashboard)
  playScanCompleted()                READY (called but immediately after scan creation)
  playAlert()                        MISSING (defined but never called)

INFRASTRUCTURE
  WebSocket (dev)                    READY
  WebSocket (production)             BROKEN (localhost fallback)
  CORS configuration                 PARTIAL (missing production domains)
  Vite dev proxy                     READY
  Database init (SQLite)             READY
  Database migrations (Alembic)      MISSING
  Error boundaries (React)           MISSING
  Environment variable validation    MISSING
  GEMINI_API_KEY in .env.example     MISSING
  SECRET_KEY security                BROKEN (weak default)
  Password reset on restart          BROKEN (critical bug in database.py)
============================================================
```

---

*This audit was produced by automated static code analysis without modifying any source files.*
