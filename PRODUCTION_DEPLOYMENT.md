# PRODUCTION DEPLOYMENT GUIDE
# Cyvera / AutoPentest AI

## Overview

This document describes the complete production deployment procedure for
the Cyvera AutoPentest AI platform. The platform consists of:

- **Backend**: FastAPI + uvicorn + SQLAlchemy (PostgreSQL or SQLite)
- **Frontend**: React 18 SPA (Vite production build)
- **Worker**: Embedded asyncio scan worker (runs within the backend process)

---

## Prerequisites

- Python 3.11+ in a virtual environment
- Node.js 18+ (for frontend build)
- PostgreSQL 14+ (recommended for production; SQLite supported for single-node)
- A reverse proxy (nginx or Caddy) for TLS termination

---

## Step 1: Environment Configuration

Copy the example environment file:
```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` with production values:

```env
PROJECT_NAME="Cyvera"
ENVIRONMENT="production"

# REQUIRED — Generate with: python -c "import secrets; print(secrets.token_hex(48))"
JWT_SECRET_KEY="<your-64-char-hex-secret>"

ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=60

# PostgreSQL (recommended for production)
DATABASE_URL="postgresql+asyncpg://cyvera_user:strong_password@localhost:5432/cyvera_db"

# CORS: add your production frontend domain
CORS_ORIGINS=["https://cyvera.yourdomain.com"]

# Optional: Google Gemini for AI analysis
GEMINI_API_KEY=""

# Private application — no public registration
ALLOW_PUBLIC_REGISTRATION=false
ADMIN_BOOTSTRAP_TOKEN=""

# Single operator account
OPERATOR_USERNAME="YourOperatorName"
OPERATOR_EMAIL="operator@yourdomain.com"
OPERATOR_PASSWORD="<strong-unique-password>"

# Production hardening
DISABLE_API_DOCS=true
LOGIN_RATE_LIMIT_MAX_ATTEMPTS=10
LOGIN_RATE_LIMIT_WINDOW_SECONDS=300
SQLITE_WAL_MODE=true
STALE_SCAN_THRESHOLD_SECONDS=60
```

---

## Step 2: Backend Setup

```bash
cd backend/
python -m venv ../venv
source ../venv/bin/activate        # Linux/macOS
# OR
..\venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

---

## Step 3: Database Setup (PostgreSQL)

```sql
CREATE USER cyvera_user WITH PASSWORD 'strong_password';
CREATE DATABASE cyvera_db OWNER cyvera_user;
GRANT ALL PRIVILEGES ON DATABASE cyvera_db TO cyvera_user;
```

Tables are created automatically on first startup via `init_db()`.

---

## Step 4: Frontend Build

```bash
cd frontend/
npm install
npm run build
```

Static files output to `frontend/dist/`. Serve via nginx.

---

## Step 5: Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name cyvera.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/cyvera.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cyvera.yourdomain.com/privkey.pem;

    # Frontend SPA
    root /opt/cyvera/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600;
    }
}

server {
    listen 80;
    server_name cyvera.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

---

## Step 6: Systemd Service

```ini
[Unit]
Description=Cyvera AutoPentest AI Backend
After=network.target postgresql.service

[Service]
Type=simple
User=cyvera
WorkingDirectory=/opt/cyvera/backend
Environment="PATH=/opt/cyvera/venv/bin"
ExecStart=/opt/cyvera/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Log to journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyvera

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
systemctl daemon-reload
systemctl enable cyvera
systemctl start cyvera
systemctl status cyvera
```

---

## Step 7: Health Check Verification

After startup:
```bash
curl https://cyvera.yourdomain.com/api/v1/health
# Expected: {"status":"healthy","database":"healthy","version":"1.0.0",...}
```

---

## Step 8: Docker Deployment (Alternative)

```bash
docker-compose up -d
```

See `docker-compose.yml` for container configuration.

---

## Secrets Management

| Secret | Where | Notes |
|--------|-------|-------|
| JWT_SECRET_KEY | .env / OS env | Never commit; rotate annually |
| OPERATOR_PASSWORD | .env / OS env | Must be strong; never a default |
| DATABASE_URL | .env / OS env | Contains DB password |
| GEMINI_API_KEY | .env / OS env | Optional; can be empty |

**Rotation procedure for JWT_SECRET_KEY:**
1. Generate new key: `python -c "import secrets; print(secrets.token_hex(48))"`
2. Update .env / environment
3. Restart backend — all existing sessions will require re-login (expected)

---

## Backup & Recovery

### SQLite (Development/Single-Node)
```bash
# Daily backup
cp backend/autopentest.db backend/autopentest.db.$(date +%Y%m%d)
# Enable WAL mode (done automatically on startup via SQLITE_WAL_MODE=true)
```

### PostgreSQL (Production)
```bash
# Backup
pg_dump -U cyvera_user cyvera_db > backup_$(date +%Y%m%d).sql

# Restore
psql -U cyvera_user cyvera_db < backup_20260925.sql
```

---

## Monitoring

- **Logs**: `backend/autopentest.log` (rotating, 10MB x 5 files)
- **Health**: `GET /api/v1/health` — includes database connectivity probe
- **Audit**: Every request logged with `req_id`, method, path, status, latency, IP
- **Security events**: `SECURITY | LOGIN_SUCCESS`, `SECURITY | LOGIN_FAILED`, `SECURITY | LOGIN_RATE_LIMITED`

---

## Rollback Procedure

1. Stop service: `systemctl stop cyvera`
2. Restore previous code version
3. Restore database backup if schema changed
4. Start service: `systemctl start cyvera`
5. Verify health check passes

---

## Known Limitations (Production)

- **Single operator model**: Only one operator account is supported
- **SQLite**: Not recommended for multi-process production (use PostgreSQL)
- **No horizontal scaling**: WebSocket state is in-memory (single process)
- **Scan budget**: 150 HTTP requests max per scan (by design, safety control)
