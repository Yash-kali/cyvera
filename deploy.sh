#!/usr/bin/env bash
set -e

echo "========================================================"
echo "AutoPentest AI - Linux/macOS Production Build Check"
echo "========================================================"

echo "[1/3] Validating Backend Python Environment..."
cd backend
python3 -c "import fastapi, sqlalchemy, reportlab, jwt, passlib; print('Backend Python packages OK.')"
python3 -m py_compile app/main.py app/services/risk_engine.py app/services/ai_advisor.py app/services/pdf_generator.py
cd ..

echo "[2/3] Building Frontend Production Distribution..."
cd frontend
npm run build
cd ..

echo "[3/3] Validating Docker Compose Orchestration..."
if command -v docker-compose &> /dev/null; then
    docker-compose config --quiet && echo "Docker Compose configuration OK."
fi

echo "========================================================"
echo "[SUCCESS] AutoPentest AI is production ready!"
echo "========================================================"
