@echo off
setlocal EnableDelayedExpansion
echo [%TIME%] MANTIS launcher started.

REM --- 0) Sanity: python must exist ---
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [%TIME%] [!] python not found on PATH. Install Python 3.10+ first.
    pause
    exit /b 1
)

REM --- 1) Dependencies: fast path skips pip when imports already work ---
REM Set MANTIS_SKIP_DEPS=1 to always skip, MANTIS_FORCE_DEPS=1 to always install.
echo [%TIME%] Checking dependencies...
if defined MANTIS_FORCE_DEPS (
    echo [%TIME%] MANTIS_FORCE_DEPS set, installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [%TIME%] [!] Failed to install dependencies.
        pause
        exit /b %errorlevel%
    )
) else if defined MANTIS_SKIP_DEPS (
    echo [%TIME%] MANTIS_SKIP_DEPS set, skipping dependency check.
) else (
    python -c "import fastapi, uvicorn, requests, pydantic" >nul 2>nul
    if !errorlevel! neq 0 (
        echo [%TIME%] Dependencies missing, installing from requirements.txt...
        pip install -r requirements.txt
        if !errorlevel! neq 0 (
            echo [%TIME%] [!] Failed to install dependencies. Make sure python and pip are installed.
            pause
            exit /b !errorlevel!
        )
    ) else (
        echo [%TIME%] Dependencies OK, skipping pip install.
    )
)

echo [%TIME%] Starting MANTIS Web Application...

REM Fixed local port. Override with MANTIS_PORT env var if needed.
if not defined MANTIS_PORT set "MANTIS_PORT=9999"
set "APP_PORT=%MANTIS_PORT%"

echo [%TIME%] The app will open in your default browser at http://127.0.0.1:%APP_PORT%

REM Open the browser in parallel without blocking the server start.
start "" /b cmd /c "timeout /t 2 >nul & start http://127.0.0.1:%APP_PORT%" >nul 2>nul

echo.
echo [%TIME%] Press Ctrl+C to stop the server...
echo [%TIME%] Startup timing per task is logged by the server. Query /api/meta/startup-status for per-task durations.
REM NOTE: --reload watches the whole tree (incl. data/) and slows startup.
REM It is off by default; set MANTIS_RELOAD=1 for development.
if defined MANTIS_RELOAD (
    echo [%TIME%] MANTIS_RELOAD set, starting with --reload.
    python -m uvicorn main:app --app-dir backend --reload --host 127.0.0.1 --port %APP_PORT%
) else (
    python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port %APP_PORT%
)

pause
