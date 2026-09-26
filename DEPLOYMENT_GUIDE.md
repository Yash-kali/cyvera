# AutoPentest AI - Cloud Production Deployment Guide

This guide provides step-by-step instructions for deploying **AutoPentest AI** to cloud infrastructure:
- **Database**: Managed Serverless PostgreSQL on **Neon DB**
- **Backend API**: FastAPI Service on **Render**
- **Frontend SPA**: React Single Page App on **Vercel**

---

## Step 1: Provision Managed PostgreSQL Database on Neon DB

1. Sign up / Log in to [Neon Console](https://console.neon.tech).
2. Click **Create Project** and name it `autopentest-production`.
3. Copy the Pooled Connection String provided in the dashboard. It will look like:
   ```env
   postgresql+asyncpg://neondb_owner:password123@ep-xyz-pooler.ap-southeast-1.aws.neon.tech/neondb?ssl=require
   ```
4. Save this connection string for the backend deployment step.

---

## Step 2: Deploy Backend FastAPI Service on Render

1. Sign up / Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\rightarrow$ **Web Service**.
3. Connect your GitHub repository containing the AutoPentest AI codebase.
4. Configure the service settings:
   - **Name**: `autopentest-backend`
   - **Root Directory**: `backend`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add the following **Environment Variables**:
   - `PROJECT_NAME`: `AutoPentest AI`
   - `ENVIRONMENT`: `production`
   - `SECRET_KEY`: `[Generate a secure 64-character hex string]`
   - `DATABASE_URL`: `[Your Neon PostgreSQL Pooled Connection String]`
   - `GEMINI_API_KEY`: `[Your Gemini API Key from Google AI Studio]`
   - `CORS_ORIGINS`: `["https://autopentest-ai.vercel.app", "http://localhost"]`
6. Click **Deploy Web Service**. Render will install dependencies and start FastAPI. Copy the public backend URL (e.g. `https://autopentest-backend.onrender.com`).

---

## Step 3: Deploy Frontend React SPA on Vercel

1. Sign up / Log in to [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** $\rightarrow$ **Project**.
3. Import your GitHub repository.
4. Configure project settings:
   - **Framework Preset**: `Vite`
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Add **Environment Variables**:
   - `VITE_API_BASE_URL`: `https://autopentest-backend.onrender.com/api/v1`
6. Click **Deploy**. Vercel will build the production React distribution and deploy it to a global CDN edge domain (e.g. `https://autopentest-ai.vercel.app`).

---

## Step 4: Verification & Live Health Check

1. Open your backend health check in browser:
   `https://autopentest-backend.onrender.com/api/v1/health`
   Should return: `{"status": "healthy", "environment": "production"}`
2. Open your Vercel frontend URL:
   `https://autopentest-ai.vercel.app`
3. Log in with an operator account, navigate to `/scans`, inspect `/recon` results, check `/analytics` Chart.js dashboards, and click **Download Executive PDF Report** on `/reports`.
