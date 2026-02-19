#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ANALYZE="./ghidra_12.0.2_PUBLIC/support/analyzeHeadless"
PROJECT_DIR="challenge"
PROJECT_NAME="test"
SCRIPT_PATH="./ghidra_tools/server"
POST_SCRIPT="ghidra_server.py"
DEBUG_SERVER="./ghidra_tools/gdb_server/server.py"
BINARY_PATH="${1:-./test/chall}"
PROGRAM_NAME="$(basename "$BINARY_PATH")"
HPORT=9999
DPORT=19090
DBG_PID=/tmp/ghidra_debug_bridge.pid
HEADLESS_PID=/tmp/ghidra_headless.pid

kill_port() {
  local port="$1" pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti "TCP:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    pids="$(fuser -n tcp "$port" 2>/dev/null || true)"
  fi
  [[ -z "$pids" ]] || { echo "[kill] tcp/${port}: $pids"; kill -9 $pids 2>/dev/null || true; }
}

has_program() {
  local idata="./${PROJECT_DIR}/${PROJECT_NAME}.rep/idata"
  [[ -d "$idata" ]] && grep -R -F "STATE NAME=\"NAME\" TYPE=\"string\" VALUE=\"${PROGRAM_NAME}\"" "$idata" --include='*.prp' >/dev/null 2>&1
}

kill_port "$DPORT"
kill_port "$HPORT"

# Launch GDB In-Process Server (headless)
# It binds to 0.0.0.0:19090 by default
gdb --quiet -x "$DEBUG_SERVER" &
echo $! > "$DBG_PID"

MODE=(-process "$PROGRAM_NAME")
if ! has_program; then
  [[ -f "$BINARY_PATH" ]] || { echo "[error] binary not found: $BINARY_PATH" >&2; exit 1; }
  MODE=(-import "$BINARY_PATH")
fi

# Remove potential project lock file
rm -f "${PROJECT_DIR}/${PROJECT_NAME}.lock"
rm -f "${PROJECT_DIR}/${PROJECT_NAME}.rep/*.lock"

env \
  GHIDRA_MCP_BIND_HOST="0.0.0.0" \
  GHIDRA_MCP_BIND_PORT="$HPORT" \
  GHIDRA_MCP_DEBUG_BIND_HOST="0.0.0.0" \
  GHIDRA_MCP_DEBUG_BIND_PORT="$DPORT" \
  GHIDRA_MCP_DEBUG_HOST="127.0.0.1" \
  GHIDRA_MCP_DEBUG_PORT="19090" \
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" "${MODE[@]}" \
  -scriptPath "$SCRIPT_PATH" -postScript "$POST_SCRIPT" &
echo $! > "$HEADLESS_PID"

stop_pid_file() {
  local pf="$1" pid=""
  [[ -f "$pf" ]] || return 0
  pid="$(cat "$pf" 2>/dev/null || true)"
  [[ -z "$pid" ]] || { kill "$pid" 2>/dev/null || true; sleep 0.2; kill -9 "$pid" 2>/dev/null || true; }
  rm -f "$pf"
}

wait_ready() {
  local name="$1" port="$2" pid="$3" i=0
  while ((i < 120)); do
    kill -0 "$pid" 2>/dev/null || { echo "[error] $name exited before ready" >&2; exit 1; }
    if python3 - "$port" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(0.3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except Exception:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
    then
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "[error] $name ready timeout (port $port)" >&2
  exit 1
}

wait_ready "debug_bridge" "$DPORT" "$(cat "$DBG_PID")"
wait_ready "headless" "$HPORT" "$(cat "$HEADLESS_PID")"
echo "[ok] debug_bridge pid=$(cat "$DBG_PID"), headless pid=$(cat "$HEADLESS_PID")"
echo "[info] press f to stop both servers and exit"

while IFS= read -rsn1 key; do
  [[ "$key" == "f" || "$key" == "F" ]] || continue
  stop_pid_file "$DBG_PID"
  stop_pid_file "$HEADLESS_PID"
  echo "[bye]"
  exit 0
done
