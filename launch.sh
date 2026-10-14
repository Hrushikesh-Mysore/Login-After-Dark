#!/usr/bin/env bash
# ==============================================================================
# Login After Dark — One-Click Automated Launcher & Browser Opener
# ==============================================================================

set -e

# Change directory to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================================="
echo "🌙 LOGIN AFTER DARK — MISSION CONTROL & AUTOMATED LAUNCHER"
echo "=================================================================="

# Check Python environment
if [ -d "venv" ]; then
    PYTHON_EXEC="$SCRIPT_DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXEC="python3"
else
    echo "❌ Error: Python 3 is required but was not found."
    exit 1
fi

PORT=5000

# Check if server is already running on port 5000
SERVER_RUNNING=0
if curl -s "http://127.0.0.1:$PORT/api/network-info" >/dev/null 2>&1; then
    SERVER_RUNNING=1
    echo "✔ Detected active backend running on port $PORT."
else
    echo "🚀 Starting Flask Enterprise Threat Backend on port $PORT..."
    nohup $PYTHON_EXEC app.py > server.log 2>&1 &
    SERVER_PID=$!
    disown $SERVER_PID 2>/dev/null || true
    echo "  ↳ Server started (PID: $SERVER_PID). Logging to server.log"
    
    # Wait for server to report healthy
    ATTEMPTS=0
    MAX_ATTEMPTS=15
    while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
        if curl -s "http://127.0.0.1:$PORT/api/network-info" >/dev/null 2>&1; then
            SERVER_RUNNING=1
            break
        fi
        sleep 0.5
        ATTEMPTS=$((ATTEMPTS+1))
    done

    if [ $SERVER_RUNNING -eq 0 ]; then
        echo "❌ Server failed to start within 7 seconds. Inspect server.log for details."
        exit 1
    fi
fi

# Query LAN IP and URLs
LAN_IP=$($PYTHON_EXEC -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('8.8.8.8', 80)); print(s.getsockname()[0]); s.close()" 2>/dev/null || echo "127.0.0.1")

LAUNCHER_URL="http://localhost:$PORT/launcher"
SOC_URL="http://localhost:$PORT/"
MOBILE_URL="http://$LAN_IP:$PORT/mobile"

echo ""
echo "=================================================================="
echo "✅ APPLICATION READY & ONLINE"
echo "=================================================================="
echo "  🖥️  SOC Threat Dashboard:  $SOC_URL"
echo "  📱  Mobile Companion (PC):  http://localhost:$PORT/mobile"
echo "  📲  Mobile Phone URL:       $MOBILE_URL"
echo "  ⚡  Mission Control Hub:    $LAUNCHER_URL"
echo "=================================================================="
echo ""

# Auto-open browser to Mission Control Hub
echo "🌐 Opening Mission Control Launcher in your browser..."
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$LAUNCHER_URL" >/dev/null 2>&1 &
elif command -v sensible-browser >/dev/null 2>&1; then
    sensible-browser "$LAUNCHER_URL" >/dev/null 2>&1 &
elif command -v google-chrome >/dev/null 2>&1; then
    google-chrome "$LAUNCHER_URL" >/dev/null 2>&1 &
elif command -v firefox >/dev/null 2>&1; then
    firefox "$LAUNCHER_URL" >/dev/null 2>&1 &
else
    $PYTHON_EXEC -m webbrowser "$LAUNCHER_URL" >/dev/null 2>&1 &
fi

echo "✔ Browser launched to $LAUNCHER_URL"
echo ""
echo "💡 TIP: On your phone, open: $MOBILE_URL"
echo "       or scan the QR code on the Mission Control screen."
echo ""

if [ -n "$SERVER_PID" ]; then
    echo "🛑 Press Ctrl+C at any time to safely shut down the server."
    trap "echo ''; echo 'Shutting down server...'; kill $SERVER_PID 2>/dev/null || true; exit 0" INT TERM
    wait $SERVER_PID
fi
