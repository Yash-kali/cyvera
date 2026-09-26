# PHASE 5 — SETTINGS, ACCOUNT SECURITY & PERSISTENCE AUDIT & IMPLEMENTATION REPORT

**Platform:** Cyvera (AutoPentest AI)  
**Phase:** Phase 5 — Settings, Account Security & Persistence  
**Status:** COMPLETE & VERIFIED  
**Date:** September 20, 2026  

---

## 1. Existing Settings Architecture & Audit

Prior to Phase 5, the Settings subsystem suffered from severe structural and security deficiencies identified during the baseline audit:
1. **Zero Database Persistence for Configuration**: `frontend/src/pages/Settings.tsx` maintained configuration in transient React `useState` hooks (`maxConcurrency`, `autoPatchValidation`, `dbBackupInterval`). When the user clicked "Save Configuration", the component executed a dummy `setTimeout` displaying a temporary success banner without making any network requests.
2. **Missing Password Change Mechanism**: No authenticated password-change API endpoint existed on the backend. In `frontend/src/pages/Profile.tsx`, changing a passcode simply set a local React message `"Passcode updated successfully"` without contacting any endpoint.
3. **Simulated API Keys**: The Profile page presented a hardcoded API key (`ap_live_9f8d7c6b5a4e3f210987654321fedcba`) and clicking "Roll Key" invoked `Math.random()`, producing a temporary client-only string that vanished upon page refresh.
4. **Lack of User Isolation for Preferences**: There was no `user_settings` table in SQLite/PostgreSQL to map configuration records to individual user accounts.

---

## 2. Root Causes of Previous Persistence Issues

- **Absence of a Dedicated Settings Model**: The database schema in `backend/app/models.py` had models for `User`, `Scan`, `ReconResult`, `Finding`, `AIExplanation`, `ChatMessage`, and `Report`, but lacked any model for tenant settings.
- **Mock Handlers on Frontend**: Frontend forms were decoupled from `apiClient` Axios instances.
- **Missing Validation & Hashing Pipeline for Credential Updates**: The authentication router had registration and login endpoints, but lacked a secure password-verification-before-update routine (`verify_password` -> policy check -> `get_password_hash` -> commit).

---

## 3. Database Model & Schema Architecture

A normalized database model `UserSettings` was designed and implemented in `backend/app/models.py`:

```python
class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    
    # Agent & Concurrency Preferences
    max_concurrency = Column(Integer, nullable=False, default=4)
    auto_patch_validation = Column(Boolean, nullable=False, default=True)
    db_backup_interval = Column(String(50), nullable=False, default="daily") # daily, weekly, monthly
    
    # Notification & Alert Routing
    email_notifications = Column(Boolean, nullable=False, default=True)
    scan_completion_alerts = Column(Boolean, nullable=False, default=True)
    critical_finding_alerts = Column(Boolean, nullable=False, default=True)
    weekly_digest = Column(Boolean, nullable=False, default=False)
    
    # Scan & Recon Preferences
    default_scan_profile = Column(String(50), nullable=False, default="Standard") # Quick, Standard, Full
    auto_recon_enabled = Column(Boolean, nullable=False, default=True)
    
    # Security Telemetry & API Key
    two_factor_enabled = Column(Boolean, nullable=False, default=False)
    api_key = Column(String(128), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    owner = relationship("User", back_populates="settings")
```

On `User`:
```python
settings = relationship("UserSettings", back_populates="owner", uselist=False, cascade="all, delete-orphan")
```

### Zero-Reset Startup Migration
- In `backend/app/database.py`, `import app.models` was added immediately before `conn.run_sync(Base.metadata.create_all)`, ensuring idempotent DDL table creation.
- Existing user rows and development seed accounts are never overwritten during startup.
- If an existing or newly registered user accesses `/settings` without a preexisting settings row, safe deterministic defaults are dynamically provisioned in `GET /api/v1/settings`.

---

## 4. Settings API Specification

All settings endpoints require a valid JWT Bearer token and are strictly scoped to `current_user.id`.

### `GET /api/v1/settings`
- **Authentication**: Bearer JWT (`current_user: User = Depends(get_current_user)`).
- **Behavior**: Retrieves settings row for `current_user.id`. If none exists, creates default record with safe defaults (`max_concurrency=4`, `auto_patch_validation=True`, `default_scan_profile="Standard"`, etc.) and commits.
- **Response**: `200 OK` with `UserSettingsResponse` payload.

### `PATCH /api/v1/settings`
- **Authentication**: Bearer JWT.
- **Behavior**: Performs partial update using `settings_in.model_dump(exclude_unset=True)`. Only supplied fields are updated; all other fields remain intact.
- **Response**: `200 OK` with updated `UserSettingsResponse`.

### `POST /api/v1/settings/roll-api-key`
- **Authentication**: Bearer JWT.
- **Behavior**: Generates a cryptographic token `ap_live_` + `secrets.token_urlsafe(24)`, persists it to `UserSettings.api_key` for `current_user.id`, and commits.
- **Response**: `200 OK` with `{"api_key": "...", "created_at": "..."}`.

---

## 5. Multi-Tenant User Isolation

Settings queries never accept an arbitrary `user_id` from the client. Every operation executes against `current_user.id` resolved securely by `get_current_user` from the cryptographically verified JWT token:
- **User A (`Yash`, UID: 1)** can only read, update, or roll keys for User A.
- **User B (`AuditUserB`, UID: 3)** settings mutations do not affect User A.
- Verified in automated test matrix (Tests G and H): User B mutated `max_concurrency` to 2; User A settings remained unchanged at 8.

---

## 6. Password Change API & Security Lifecycle

Implemented in `backend/app/routers/auth.py`:
`POST /api/v1/auth/change-password`

### Processing Pipeline:
1. **Authentication**: Enforced via OAuth2 Bearer token (`get_current_user`).
2. **Current Password Verification**: `verify_password(req.current_password, current_user.hashed_password)` using Passlib bcrypt. If incorrect, returns `400 Bad Request` (`"Current password is incorrect."`).
3. **Confirmation Match**: Pydantic validator `validate_confirmation` and router assertion reject mismatches with `422 Unprocessable Entity` or `400 Bad Request`.
4. **Password Policy Enforcement**: Minimum length of 6 characters required.
5. **Prohibition of Password Reuse**: Explicit check `req.current_password == req.new_password` and bcrypt verification prevents resetting to the existing password (`"New password cannot be identical to your current password."`).
6. **Bcrypt Hashing**: Generates fresh salted bcrypt hash via `get_password_hash(req.new_password)`.
7. **Persistence**: Sets `current_user.hashed_password = new_hashed` and commits to database.
8. **Credential Protection**: Plaintext passwords and password hashes are **never returned** in API responses and **never logged**.
9. **Audit Logging**: Logs `logger.info("Password changed successfully for user id=%s", current_user.id)` without logging secrets or credentials.

---

## 7. Profile API (`PATCH /api/v1/auth/profile`)

Implemented in `backend/app/routers/auth.py`:
- Allows authenticated users to update `username` or `email`.
- Enforces uniqueness across other tenant records before updating.
- Disallows arbitrary modification of protected attributes (`id`, `hashed_password`, `created_at`).

---

## 8. Frontend Integration & UX

### `frontend/src/pages/Settings.tsx`
- **Direct Backend Binding**: `getSettingsApi()` invoked on mount.
- **Interactive Controls**:
  - Agent Concurrency range slider (`1` to `16` workers).
  - Autonomous Exploit Validation checkbox.
  - Database Retention Policy select (`daily`, `weekly`, `monthly`).
  - Default Scan Profile select (`Quick`, `Standard`, `Full`).
  - Automated Reconnaissance toggle.
  - Security Alert Routing: Email Notifications, Scan Completion Alerts, Critical Findings Intercepts, Weekly Digest.
- **State Feedback & Dirty Tracking**:
  - "Save Configuration" button with spinner.
  - "Cancel Changes" button that appears whenever local modifications differ from the persisted state.
  - Subtle green confirmation alert upon database synchronization (`SYNCED: <time>`).
  - Inline Account Security / Change Password form with error and success messaging.
  - Honest Security Telemetry displaying `"NOT CONFIGURED"` for unintegrated 2FA and `"ACTIVE JWT SESSION"` for active session.

### `frontend/src/pages/Profile.tsx`
- **Dynamic API Key Provisioning**: Fetches persistent `api_key` from `getSettingsApi()`.
- **Live Key Rotation**: "Roll Key" button executes `rollApiKeyApi()`, persisting the new key to the database in real-time.
- **Passcode Update**: Connected directly to `changePasswordApi()`.
- **Account Identity**: Connected to `updateProfileApi()`.

---

## 9. Test Matrix & Results

Comprehensive automated test suite executed in `scratch/verify_phase5_settings.py`:

| # | Test Scenario | Expected Result | Actual Result | Status |
|---|---------------|-----------------|---------------|--------|
| A | GET settings authenticated | HTTP 200, valid `UserSettingsResponse` | HTTP 200, UID: 1 | **PASS** |
| B | GET settings unauthenticated | HTTP 401 Unauthorized | HTTP 401 | **PASS** |
| C | PATCH settings | HTTP 200, fields updated | HTTP 200 (`max_concurrency=8`, `weekly_digest=True`) | **PASS** |
| D | Verify persistence | Re-fetch returns updated values | HTTP 200, verified persisted | **PASS** |
| E | Partial update | Updates target field without resetting others | HTTP 200, other fields preserved | **PASS** |
| F | Default settings on first query | Deterministic defaults created dynamically | HTTP 200, fresh user defaults verified | **PASS** |
| G | User A isolation | User A settings isolated | HTTP 200, UID 1 distinct | **PASS** |
| H | User B isolation | User B mutation does not alter User A | User B=2, User A=8 | **PASS** |
| I | Correct password verification | Bcrypt verify succeeds | Verified during lifecycle | **PASS** |
| J | Incorrect current password | HTTP 400 Bad Request | HTTP 400 (`"Current password is incorrect."`) | **PASS** |
| K | Weak password rejection (< 6 chars) | HTTP 422 Unprocessable Entity | HTTP 422 | **PASS** |
| L | Password confirmation mismatch | HTTP 422 Unprocessable Entity | HTTP 422 (`"do not match"`) | **PASS** |
| M | Password reuse rejection | HTTP 400 Bad Request | HTTP 400 (`"cannot be identical"`) | **PASS** |
| N | Successful password change | HTTP 200, hash updated | HTTP 200 (`"status": "success"`) | **PASS** |
| O | Login with new password | HTTP 200, returns fresh JWT | HTTP 200, token issued | **PASS** |
| P | Old password rejected | HTTP 401 Unauthorized | HTTP 401 Unauthorized | **PASS** |
| Q | Password hash never returned | No `hashed_password` in `/auth/me` or `/settings` | Zero leakage | **PASS** |
| R | Passwords never logged | No plaintext passwords in log files | Zero credentials logged | **PASS** |
| S | Tampered JWT rejection | HTTP 401 Unauthorized | HTTP 401 Unauthorized | **PASS** |
| T | API Key roll and persistence | `ap_live_...` generated and persisted | Verified in DB | **PASS** |
| U | Profile update and persistence | Email and username updated | HTTP 200, restored cleanly | **PASS** |

**Verification Result:** `21/21 TESTS PASSED (100%)`

---

## 10. Regression Testing Across Phases 1–4

All prior subsystems were re-verified against the updated codebase:
1. **Phase 1 (Authentication & JWT Security)**: Verified.
2. **Phase 2 (Dashboard Data Integrity)**: Executed `scratch/verify_api.py`. Scan #1 metrics, deductions, findings count, and zero-scan isolation for User B confirmed.
3. **Phase 3 (Analytics & Risk Intelligence)**: Verified. Total scans, risk score, asset risk tables, and OWASP distribution operate on real DB state.
4. **Phase 4 (Findings Integrity & SARIF 2.1.0 Import)**: Executed `scratch/verify_phase4_findings.py`. All 21 tests passed (SARIF parsing, deduplication, triage status updates, CVSS scores, multi-tenant isolation).

---

## 11. Frontend Build Verification

Executed `npm.cmd run build` inside `frontend/`:
```bash
> autopentest-ai-frontend@1.0.0 build
> tsc && vite build

vite v5.4.21 building for production...
transforming...
✓ 2567 modules transformed.
rendering chunks...
dist/index.html                     1.25 kB │ gzip:   0.70 kB
dist/assets/index-B5svjKLg.css     48.81 kB │ gzip:   8.41 kB
dist/assets/index-q4nh8D2C.js   1,222.31 kB │ gzip: 353.87 kB
✓ built in 30.74s
```
**Build Exit Code:** `0` (Zero TypeScript or bundling errors).

---

## 12. Browser Verification Artifacts

Visual verification recorded and captured using the browser subagent:
- **Settings Page**: `settings_page_1789926551120.png` (Verified 12 workers slider, Full profile selection, persistence across refresh).
- **Profile Page**: `profile_page_1789926587756.png` (Verified live API key rolling `ap_live_Nlop3s_...`, Account Identity, Passcode change form).
- **Full Video Recording**: `phase5_settings_demo_1789926393221.webp`

---

## 13. Remaining Limitations & Architectural Scope

1. **Hardware 2FA / TOTP**: Two-factor authentication is accurately labeled as `"NOT CONFIGURED"` in the Security Telemetry section. Backend implementation of TOTP (RFC 6238) QR code generation and secret token validation can be integrated as a future enhancement.
2. **Database Migration Tooling**: The system uses SQLAlchemy declarative DDL (`Base.metadata.create_all`) for safe idempotent table creation. Alembic migrations are not yet configured; any future column alterations should be added through Alembic or careful non-destructive DDL scripts.
