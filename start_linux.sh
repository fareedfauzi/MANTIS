#!/bin/bash

# MANTIS Linux Startup Script

echo "Starting MANTIS on Linux..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed. Please install Python 3."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Warning: pip3 is not installed. You may need it to install dependencies."
fi

# Parse CLI arguments
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

# Setup and run backend
echo "Setting up backend..."
cd backend || exit

# Create virtual environment if it doesn't exist (Optional but recommended)
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing backend dependencies..."
pip install -r requirements.txt

# Prompt for deployment mode if unset
EXISTING_MODE=$(python3 -c "import sys; sys.path.append('.'); import deployment_config; print(deployment_config.get_deployment_mode())" 2>/dev/null || echo "workstation")

if [ -n "$MANTIS_RECONFIG" ] || { [ -z "$MANTIS_MODE" ] && ! grep -q "^MANTIS_MODE=" ../.env 2>/dev/null; }; then
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
    python3 -c "import sys; sys.path.append('.'); import deployment_config; deployment_config.set_deployment_mode('$MANTIS_MODE')" 2>/dev/null
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

echo "Starting backend server (FastAPI) on $MANTIS_HOST:$MANTIS_PORT..."
uvicorn main:app --host "$MANTIS_HOST" --port "$MANTIS_PORT" &
BACKEND_PID=$!

# Wait a moment for backend to initialize
sleep 2

# Trap SIGINT (Ctrl+C) to gracefully stop
trap "echo 'Stopping MANTIS...'; kill $BACKEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM

echo "MANTIS is running. Press Ctrl+C to stop."
wait $BACKEND_PID
