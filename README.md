# AutoPentest AI - Automated Cybersecurity Operations & AI Risk Platform

**AutoPentest AI** is an automated cybersecurity operations platform designed to evaluate application security postures, track vulnerability remediation lifecycles, compute CVSS-inspired risk metrics, generate AI-powered security advisories, and export 9-section executive PDF reports.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python%203.11-009688.svg)
![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite%20%7C%20TypeScript-61DAFB.svg)
![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2016%20%7C%20SQLAlchemy%202.0-336791.svg)
![Docker](https://img.shields.io/badge/Container-Docker%20Compose-2496ED.svg)

---

## Technical Stack & Architecture

- **Frontend**: React 18, Vite, TypeScript, TailwindCSS v3 (Cyber SOC Dark Theme), Chart.js (`react-chartjs-2`), Lucide React Icons. Deployed on **Vercel Edge Network**.
- **Backend**: FastAPI (Python 3.11 with Uvicorn ASGI Server), Pydantic v2 Settings, Async SQLAlchemy 2.0 (`asyncpg`), Bcrypt password hashing, PyJWT authentication, ReportLab PDF Generator. Deployed on **Render Cloud Web Services**.
- **Database**: PostgreSQL 16 serverless infrastructure deployed on **Neon DB**.
- **AI Advisory Engine**: **Gemini API** (`google-generativeai`) with fallback security knowledge engine.

---

## 🚀 Quick Start (Local Docker Compose Environment)

To launch the full AutoPentest AI stack locally:

```bash
# 1. Clone repo & navigate to directory
cd Yash

# 2. Build and launch containers
docker-compose up --build
```

- **Frontend SOC Command Center**: `http://localhost`
- **FastAPI OpenAPI Swagger Docs**: `http://localhost:8000/docs`
- **PostgreSQL Database**: `localhost:5432`

---

## Key Modules & Features (Phases 1 – 10)

1. **Authentication & Session Security (Phase 1)**: JWT bearer tokens with auto-logout timers, bcrypt hashing (`passlib`), protected routing.
2. **Cyber SOC Dashboard (Phase 2)**: Obsidian dark theme, DEFCON threat level badges, live engine status widgets, Chart.js metrics.
3. **Target Scan Management (Phase 3)**: Target scan submission (`/scans/new`), history (`/scans`), lifecycle progression timelines (`/scans/:id`).
4. **Asset Posture Audit Engine (Phase 4)**: TLS/SSL certificate health, HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`), IPv4 DNS resolution.
5. **Vulnerability Remediation Center (Phase 5)**: Triage lifecycle management (`Open` $\rightarrow$ `Resolved`), SARIF report importer (`/vulnerabilities`).
6. **Risk Assessment Engine (Phase 6)**: CVSS-inspired weighted risk scores ($R$), Security Health Scores ($S$), Security Grade scale (`A+` to `F`).
7. **AI Security Advisor (Phase 7)**: Gemini API integration generating 6-section advisories (Executive Summary, Technical Cause, Business Impact, Attack Scenario, Remediation Steps, OWASP Top 10 Mapping).
8. **Visual Analytics Suite (Phase 8)**: Chart.js 4-card analytics suite (`/analytics`), Findings Dashboard (`/findings-dashboard`), multi-parameter filters (Severity, Date, Scan Type).
9. **ReportLab PDF Exporter (Phase 9)**: Executive 9-section PDF report generation service (`/reports`) with 1-click browser download API.
10. **Production Cloud Readiness (Phase 10)**: Vercel, Render & Neon cloud manifests, structured production logging, global exception handling, architecture diagrams (`ARCHITECTURE.md`), and presentation notes (`PRESENTATION_NOTES.md`).

---

## 📚 Complete Project Documentation

- **Architecture Blueprint**: Refer to [ARCHITECTURE.md](file:///c:/Users/PHANINDRA/Desktop/Yash/ARCHITECTURE.md) for Mermaid.js system diagrams.
- **Cloud Deployment Guide**: Refer to [DEPLOYMENT_GUIDE.md](file:///c:/Users/PHANINDRA/Desktop/Yash/DEPLOYMENT_GUIDE.md) for step-by-step Vercel, Render, and Neon setup.
- **Executive Presentation Script**: Refer to [PRESENTATION_NOTES.md](file:///c:/Users/PHANINDRA/Desktop/Yash/PRESENTATION_NOTES.md) for demonstration narrative and slide talk tracks.
- **Walkthrough Artifact**: Refer to [walkthrough.md](file:///C:/Users/PHANINDRA/.gemini/antigravity-ide/brain/7cf71445-b245-4ef5-90fc-d790a31d2930/walkthrough.md) for implementation history across all 10 phases.
