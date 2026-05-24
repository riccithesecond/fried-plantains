#!/usr/bin/env bash
# fried-plantains launcher — starts backend and frontend concurrently.
# Generates demo data automatically if storage/ is empty.
# Usage: ./start.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; GRAY='\033[0;90m'; NC='\033[0m'
step() { echo -e "${CYAN}  ▸ $*${NC}"; }
ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
fail() { echo -e "${RED}  ✗ $*${NC}"; exit 1; }

echo ""
echo "  fried-plantains"
echo "  ───────────────"
echo ""

# ── .env ──────────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    fail ".env not found."
    echo ""
    echo "  Run:  cp .env.example .env"
    echo "  Then fill in:"
    echo "    SECRET_KEY          — openssl rand -hex 32"
    echo "    ADMIN_USERNAME      — any username"
    echo "    ADMIN_PASSWORD_HASH — python3 -c \"import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())\""
    exit 1
fi
ok ".env found."

# ── venv ──────────────────────────────────────────────────────────────────────
PYTHON=".venv/bin/python"
UVICORN=".venv/bin/uvicorn"
if [ ! -f "$PYTHON" ]; then
    fail ".venv not found."
    echo ""
    echo "  Run:"
    echo "    python3 -m venv .venv"
    echo "    .venv/bin/pip install -r backend/requirements.txt"
    exit 1
fi
ok "Virtual environment found."

# ── backend dependencies ──────────────────────────────────────────────────────
step "Installing/verifying backend dependencies..."
"$ROOT/.venv/bin/pip" install -r backend/requirements.txt --quiet
ok "Backend dependencies ready."

# ── node_modules ──────────────────────────────────────────────────────────────
if [ ! -d frontend/node_modules ]; then
    step "Installing frontend dependencies..."
    (cd frontend && npm install)
fi
ok "Frontend dependencies ready."

# ── storage / demo data ───────────────────────────────────────────────────────
mkdir -p storage
parquet_count=$(find storage -name "*.parquet" 2>/dev/null | wc -l | tr -d ' ')
if [ "$parquet_count" -eq 0 ]; then
    step "No data found — generating demo dataset (~30 s)..."
    "$PYTHON" scripts/generate_logs.py --demo
    ok "Demo data ready."
else
    ok "Storage has ${parquet_count} parquet file(s)."
fi

# ── launch ────────────────────────────────────────────────────────────────────
echo ""
step "Starting backend on :8000..."
"$UVICORN" backend.main:app --reload --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

step "Starting frontend on :5173..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}  fried-plantains is running.${NC}"
echo ""
echo "    Backend   →  http://localhost:8000"
echo "    Frontend  →  http://localhost:5173"
echo "    API docs  →  http://localhost:8000/docs"
echo ""
echo -e "${GRAY}  Ctrl+C to stop both servers.${NC}"
echo ""

cleanup() {
    echo ""
    step "Shutting down..."
    kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true
    echo ""
}
trap cleanup INT TERM

wait
