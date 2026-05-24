#Requires -Version 5.1
<#
.SYNOPSIS
    Launch fried-plantains: backend API + frontend dev server.
.DESCRIPTION
    Checks prerequisites, seeds demo data if storage is empty, then opens
    the backend and frontend in separate PowerShell windows.
.EXAMPLE
    .\start.ps1
#>

$Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Write-Step([string]$msg) { Write-Host "  >> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  OK $msg" -ForegroundColor Green }
function Write-Fail([string]$msg) { Write-Host "  !! $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "  fried-plantains" -ForegroundColor White
Write-Host "  ---------------" -ForegroundColor DarkGray
Write-Host ""

try {

    # ── .env ──────────────────────────────────────────────────────────────────

    if (-not (Test-Path "$Root\.env")) {
        Write-Fail ".env not found."
        Write-Host ""
        Write-Host "  Run:  Copy-Item .env.example .env" -ForegroundColor Yellow
        Write-Host "  Then fill in:" -ForegroundColor Yellow
        Write-Host "    SECRET_KEY          - openssl rand -hex 32"
        Write-Host "    ADMIN_USERNAME      - any username"
        Write-Host "    ADMIN_PASSWORD_HASH - python -c ""import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"""
        Read-Host "`n  Press Enter to close"
        exit 1
    }
    Write-Ok ".env found."

    # ── venv ──────────────────────────────────────────────────────────────────

    $PyExe      = "$Root\.venv\Scripts\python.exe"
    $UvicornExe = "$Root\.venv\Scripts\uvicorn.exe"

    if (-not (Test-Path $PyExe)) {
        Write-Fail ".venv not found."
        Write-Host ""
        Write-Host "  Run:" -ForegroundColor Yellow
        Write-Host "    python -m venv .venv"
        Write-Host "    .venv\Scripts\pip install -r backend\requirements.txt"
        Read-Host "`n  Press Enter to close"
        exit 1
    }
    Write-Ok "Virtual environment found."

    # ── backend dependencies ───────────────────────────────────────────────────

    Write-Step "Installing/verifying backend dependencies..."
    & "$Root\.venv\Scripts\pip.exe" install -r "$Root\backend\requirements.txt" --quiet
    if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)." }
    Write-Ok "Backend dependencies ready."

    # ── node_modules ──────────────────────────────────────────────────────────

    if (-not (Test-Path "$Root\frontend\node_modules")) {
        Write-Step "Installing frontend dependencies..."
        Push-Location "$Root\frontend"
        npm install
        Pop-Location
        if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)." }
    }
    Write-Ok "Frontend dependencies ready."

    # ── storage / demo data ───────────────────────────────────────────────────

    if (-not (Test-Path "$Root\storage")) {
        New-Item -ItemType Directory -Path "$Root\storage" | Out-Null
    }

    $parquetFiles = Get-ChildItem -Path "$Root\storage" -Recurse -Filter "*.parquet" -ErrorAction SilentlyContinue
    if ($null -eq $parquetFiles -or $parquetFiles.Count -eq 0) {
        Write-Step "No data found - generating demo dataset (~30 s)..."
        & $PyExe "$Root\scripts\generate_logs.py" --demo
        if ($LASTEXITCODE -ne 0) { throw "Demo data generation failed (exit $LASTEXITCODE)." }
        Write-Ok "Demo data ready."
    } else {
        Write-Ok "Storage has $($parquetFiles.Count) parquet file(s)."
    }

    # ── launch backend ────────────────────────────────────────────────────────

    Write-Step "Opening backend window (:8000)..."
    $backendCmd = "Write-Host '  [backend]' -ForegroundColor Cyan; " +
                  "& '$UvicornExe' backend.main:app --reload --host 127.0.0.1 --port 8000; " +
                  "Write-Host '  Backend stopped.' -ForegroundColor Yellow; " +
                  "Read-Host 'Press Enter to close'"
    $backendProc = Start-Process powershell `
        -ArgumentList "-NoExit", "-Command", $backendCmd `
        -WorkingDirectory $Root `
        -PassThru

    # ── launch frontend ───────────────────────────────────────────────────────

    Write-Step "Opening frontend window (:5173)..."
    $frontendCmd = "Write-Host '  [frontend]' -ForegroundColor Cyan; " +
                   "npm run dev; " +
                   "Write-Host '  Frontend stopped.' -ForegroundColor Yellow; " +
                   "Read-Host 'Press Enter to close'"
    $frontendProc = Start-Process powershell `
        -ArgumentList "-NoExit", "-Command", $frontendCmd `
        -WorkingDirectory "$Root\frontend" `
        -PassThru

    # ── ready ─────────────────────────────────────────────────────────────────

    Write-Host ""
    Write-Host "  fried-plantains is running." -ForegroundColor Green
    Write-Host ""
    Write-Host "    Backend   ->  http://localhost:8000"
    Write-Host "    Frontend  ->  http://localhost:5173"
    Write-Host "    API docs  ->  http://localhost:8000/docs"
    Write-Host ""
    Write-Host "  Backend PID:  $($backendProc.Id)" -ForegroundColor DarkGray
    Write-Host "  Frontend PID: $($frontendProc.Id)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Close the backend and frontend windows to stop the servers." -ForegroundColor DarkGray
    Write-Host "  Or run: Stop-Process -Id $($backendProc.Id), $($frontendProc.Id)" -ForegroundColor DarkGray
    Write-Host ""
    Read-Host "  Press Enter to close this window"

} catch {
    Write-Host ""
    Write-Fail "Startup failed: $($_.Exception.Message)"
    Write-Host ""
    Read-Host "  Press Enter to close"
    exit 1
}
