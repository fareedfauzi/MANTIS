#!/bin/bash

# MANTIS Linux Startup Script
# Resolves repository paths dynamically so it can be executed from any working directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
BACKEND_DIR="$REPO_ROOT/backend"

echo "Starting MANTIS on Linux..."
echo "Repository root: $REPO_ROOT"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    echo "Warning: pip3 is not installed. You may need it to install dependencies."
fi

# Parse CLI arguments
MANTIS_MODE=""
MANTIS_RECONFIG=""
for arg in "$@"; do
    case "$arg" in
        --server|-s)
            MANTIS_MODE="server"
            ;;
        --workstation|-w)
            MANTIS_MODE="workstation"
            ;;
        --setup|--reconfigure)
            MANTIS_RECONFIG=1
            ;;
    esac
done

# Navigate to backend directory
cd "$BACKEND_DIR"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment in $BACKEND_DIR/venv..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Ensure Python can resolve modules from repo root as well as backend
export PYTHONPATH="$REPO_ROOT:$BACKEND_DIR:${PYTHONPATH:-}"

# Install dependencies from root requirements.txt
echo "Installing backend dependencies from $REPO_ROOT/requirements.txt..."
if [ -f "$REPO_ROOT/requirements.txt" ]; then
    pip install -r "$REPO_ROOT/requirements.txt"
elif [ -f "$BACKEND_DIR/requirements.txt" ]; then
    pip install -r "$BACKEND_DIR/requirements.txt"
else
    echo "Error: requirements.txt not found!"
    exit 1
fi

# Prompt for deployment mode if unset
EXISTING_MODE=$(python3 -c "import deployment_config; print(deployment_config.get_deployment_mode())" 2>/dev/null || echo "workstation")

if [ -n "$MANTIS_RECONFIG" ] || { [ -z "$MANTIS_MODE" ] && ! grep -q "^MANTIS_MODE=" "$REPO_ROOT/.env" 2>/dev/null; }; then
    if [ -t 0 ]; then
        echo ""
        echo "======================================================================"
        echo "  MANTIS Deployment Mode Selection"
        echo "======================================================================"
        echo "  [1] Workstation Mode  (Local desktop)"
        echo "  [2] Team Server Mode  (Shared server, auto-discovery, web staging)"
        echo "======================================================================"
        read -r -p "Select mode [1 or 2] (Default is 2 for Linux): " USER_CHOICE
        if [ "$USER_CHOICE" = "1" ]; then
            MANTIS_MODE="workstation"
        else
            MANTIS_MODE="server"
        fi
    else
        MANTIS_MODE="server"
    fi
fi

if [ -n "$MANTIS_MODE" ]; then
    python3 -c "import deployment_config; deployment_config.set_deployment_mode('$MANTIS_MODE')" 2>/dev/null
else
    MANTIS_MODE="$EXISTING_MODE"
fi

echo "Active Deployment Mode: [$MANTIS_MODE]"

# Set host/port defaults based on mode
if [ "$MANTIS_MODE" = "server" ]; then
    MANTIS_HOST="${MANTIS_HOST:-0.0.0.0}"
    MANTIS_PORT="${MANTIS_PORT:-9999}"
else
    MANTIS_HOST="${MANTIS_HOST:-127.0.0.1}"
    MANTIS_PORT="${MANTIS_PORT:-9999}"
fi

echo "Starting backend server (FastAPI) in foreground on $MANTIS_HOST:$MANTIS_PORT..."
# Using exec for clean signal propagation under process managers (systemd, docker, supervisor)
exec uvicorn main:app --host "$MANTIS_HOST" --port "$MANTIS_PORT"
