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

REM --- 2) Check CLI arguments for mode overrides ---
if "%1"=="--server" set "MANTIS_MODE=server"
if "%1"=="-s" set "MANTIS_MODE=server"
if "%1"=="--workstation" set "MANTIS_MODE=workstation"
if "%1"=="-w" set "MANTIS_MODE=workstation"
if "%1"=="--setup" set "MANTIS_RECONFIG=1"
if "%1"=="--reconfigure" set "MANTIS_RECONFIG=1"

REM --- 3) Deployment Mode: Default to workstation ---
for /f "tokens=*" %%i in ('python -c "import sys; sys.path.append('backend'); import deployment_config; print(deployment_config.get_deployment_mode())" 2^>nul') do set "EXISTING_MODE=%%i"

if defined MANTIS_RECONFIG goto :PROMPT_MODE
if defined MANTIS_MODE (
    python -c "import sys; sys.path.append('backend'); import deployment_config; deployment_config.set_deployment_mode('%MANTIS_MODE%')" >nul 2>nul
    goto :MODE_CONFIGURED
)

REM Check if .env already specifies MANTIS_MODE
findstr /i "^MANTIS_MODE=" .env >nul 2>nul
if %errorlevel% equ 0 (
    set "MANTIS_MODE=%EXISTING_MODE%"
    goto :MODE_CONFIGURED
)

REM By default, run as workstation
set "MANTIS_MODE=workstation"
python -c "import sys; sys.path.append('backend'); import deployment_config; deployment_config.set_deployment_mode('workstation')" >nul 2>nul
goto :MODE_CONFIGURED

:PROMPT_MODE
echo.
echo ======================================================================
echo   MANTIS Deployment Mode Selection
echo ======================================================================
echo   [1] Workstation Mode  (Default: local PC, host file pickers enabled)
echo   [2] Team Server Mode  (Shared server, auto-discovery, web staging)
echo ======================================================================
set /p "USER_MODE_CHOICE=Select mode [1 or 2] (Default is 1): "
if "%USER_MODE_CHOICE%"=="2" (
    set "MANTIS_MODE=server"
) else (
    set "MANTIS_MODE=workstation"
)
python -c "import sys; sys.path.append('backend'); import deployment_config; deployment_config.set_deployment_mode('%MANTIS_MODE%')" >nul 2>nul
echo [%TIME%] Deployment mode set to: %MANTIS_MODE% (saved to .env)
echo.

:MODE_CONFIGURED
if not defined MANTIS_MODE set "MANTIS_MODE=%EXISTING_MODE%"
if not defined MANTIS_MODE set "MANTIS_MODE=workstation"

echo [%TIME%] Active Deployment Mode: [%MANTIS_MODE%]

REM Fixed local port. Override with MANTIS_PORT env var if needed.
if not defined MANTIS_PORT set "MANTIS_PORT=9999"
set "APP_PORT=%MANTIS_PORT%"

if "%MANTIS_MODE%"=="server" (
    echo [%TIME%] Running in TEAM SERVER mode. Host file dialogs are disabled; web uploads and staging folders are active.
    echo [%TIME%] Access URL: http://0.0.0.0:%APP_PORT% (or your server's IP address)
) else (
    echo [%TIME%] The app will open in your default browser at http://127.0.0.1:%APP_PORT%
    REM Open the browser in parallel for workstation users
    start "" /b cmd /c "timeout /t 2 >nul & start http://127.0.0.1:%APP_PORT%" >nul 2>nul
)

echo.
echo [%TIME%] Press Ctrl+C to stop the server...
echo [%TIME%] Startup timing per task is logged by the server. Query /api/meta/startup-status for per-task durations.
REM NOTE: --reload watches the whole tree (incl. data/) and slows startup.
REM It is off by default; set MANTIS_RELOAD=1 for development.
if defined MANTIS_RELOAD (
    echo [%TIME%] MANTIS_RELOAD set, starting with --reload.
    python -m uvicorn main:app --app-dir backend --reload --host 0.0.0.0 --port %APP_PORT%
) else (
    python -m uvicorn main:app --app-dir backend --host 0.0.0.0 --port %APP_PORT%
)

pause
