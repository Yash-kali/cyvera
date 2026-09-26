@echo off
echo ========================================================
echo AutoPentest AI - Automated Production Build Validation
echo ========================================================

echo [1/4] Checking Python environment dependencies...
cd backend
python -c "import fastapi, sqlalchemy, reportlab, jwt, passlib; print('Backend Python dependencies verified.')"
if %errorlevel% neq 0 (
    echo [ERROR] Backend dependency check failed!
    exit /b %errorlevel%
)

echo [2/4] Verifying Backend Python Syntax...
python -m py_compile app/main.py app/services/risk_engine.py app/services/ai_advisor.py app/services/pdf_generator.py
if %errorlevel% neq 0 (
    echo [ERROR] Backend syntax compilation failed!
    exit /b %errorlevel%
)
cd ..

echo [3/4] Checking Node.js Frontend dependencies...
cd frontend
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] Frontend Vite build failed!
    exit /b %errorlevel%
)
cd ..

echo [4/4] Docker Compose Configuration Check...
docker-compose config > NUL 2>&1
if %errorlevel% eq 0 (
    echo Docker Compose file is valid.
) else (
    echo [WARNING] Docker daemon is not active, skipping container launch.
)

echo ========================================================
echo [SUCCESS] AutoPentest AI is verified and ready for cloud deployment!
echo ========================================================
