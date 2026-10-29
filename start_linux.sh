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

# Start backend in the background. Default to localhost; set
# MANTIS_HOST=0.0.0.0 only behind a trusted reverse proxy/auth layer.
echo "Starting backend server (FastAPI)..."
MANTIS_HOST="${MANTIS_HOST:-127.0.0.1}"
MANTIS_PORT="${MANTIS_PORT:-8000}"
uvicorn main:app --host "$MANTIS_HOST" --port "$MANTIS_PORT" &
BACKEND_PID=$!

# Wait a moment for backend to initialize
sleep 2

# Navigate to frontend and start it
echo "Starting frontend server..."
cd ../frontend || exit
echo "MANTIS Frontend available at: http://localhost:8080"
python3 -m http.server 8080 &
FRONTEND_PID=$!

# Trap SIGINT (Ctrl+C) to gracefully stop both servers
trap "echo 'Stopping MANTIS...'; kill $BACKEND_PID; kill $FRONTEND_PID; exit 0" SIGINT SIGTERM

# Keep the script running to hold the trap
echo "MANTIS is running. Press Ctrl+C to stop."
wait $FRONTEND_PID $BACKEND_PID
