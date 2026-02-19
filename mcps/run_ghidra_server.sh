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
BINARY_ABS="$BINARY_PATH"
if [[ -e "$BINARY_PATH" ]]; then
  BINARY_ABS="$(realpath "$BINARY_PATH")"
fi
HPORT=9999
DPORT=19090
DBG_PID=/tmp/ghidra_debug_bridge.pid
DBG_STDIN_PID=/tmp/ghidra_debug_bridge_stdin.pid
DBG_STDIN_FIFO=/tmp/ghidra_debug_bridge_stdin.fifo
HEADLESS_PID=/tmp/ghidra_headless.pid

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || { echo "[error] missing command: $cmd" >&2; exit 1; }
}

terminate_pids() {
  local pids="$1"
  [[ -z "$pids" ]] && return 0
  kill $pids 2>/dev/null || true
  sleep 0.2
  kill -9 $pids 2>/dev/null || true
}

kill_port() {
  local port="$1" pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti "TCP:${port}" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v fuser >/dev/null 2>&1; then
    pids="$(fuser -n tcp "$port" 2>/dev/null || true)"
  fi
  [[ -z "$pids" ]] || { echo "[kill] tcp/${port}: $pids"; terminate_pids "$pids"; }
}

stop_pid() {
  local pf="$1" pid=""
  if [[ -f "$pf" ]]; then
    pid="$(cat "$pf" 2>/dev/null || true)"
  fi
  
  if [[ -n "$pid" ]]; then
    # Kill children first (important for Ghidra which spawns Java)
    echo "[cleanup] killing children of ${pid}..."
    pkill -P "$pid" 2>/dev/null || true
    
    # Kill the process
    kill "$pid" 2>/dev/null || true
    sleep 0.2
    kill -9 "$pid" 2>/dev/null || true
    pkill -9 -P "$pid" 2>/dev/null || true
  fi
  rm -f "$pf"
}

start_debug_bridge() {
  rm -f "$DBG_STDIN_FIFO"
  mkfifo "$DBG_STDIN_FIFO"

  # Keep GDB stdin open in non-interactive runs to prevent immediate EOF-exit.
  tail -f /dev/null > "$DBG_STDIN_FIFO" &
  echo $! > "$DBG_STDIN_PID"

  gdb --quiet -nx -nh -x "$DEBUG_SERVER" < "$DBG_STDIN_FIFO" > /dev/null 2>&1 &
  echo $! > "$DBG_PID"
}

validate_runtime() {
  require_cmd gdb
  [[ -x "$ANALYZE" ]] || { echo "[error] analyzeHeadless not found: $ANALYZE" >&2; exit 1; }
  local gdb_probe
  gdb_probe="$(gdb --batch --quiet -nx -nh -ex "python import sys" 2>&1 || true)"
  if grep -qi "python scripting is not supported" <<<"$gdb_probe"; then
    echo "[error] gdb python support required (current gdb does not support 'python')." >&2
    exit 1
  fi
}

cleanup_artifacts() {
  echo "[cleanup] removing __pycache__ and .class artifacts..."
  find "./ghidra_tools" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find "./ghidra_tools" -type f -name "*.class" -delete 2>/dev/null || true
}

cleanup() {
  echo "[cleanup] stopping servers..."
  trap - EXIT # prevent loop
  stop_pid "$DBG_PID"
  stop_pid "$DBG_STDIN_PID"
  stop_pid "$HEADLESS_PID"
  rm -f "$DBG_STDIN_FIFO"
  kill_port "$DPORT"
  kill_port "$HPORT"
  cleanup_artifacts
  echo "[cleanup] done."
}

trap cleanup EXIT INT TERM

has_program() {
  local idata="./${PROJECT_DIR}/${PROJECT_NAME}.rep/idata"
  [[ -d "$idata" ]] && grep -R -F "STATE NAME=\"NAME\" TYPE=\"string\" VALUE=\"${PROGRAM_NAME}\"" "$idata" --include='*.prp' >/dev/null 2>&1
}

kill_port "$DPORT"
kill_port "$HPORT"
validate_runtime

# Launch GDB In-Process Server (headless)
# It binds to 0.0.0.0:19090 by default
start_debug_bridge

MODE=(-process "$PROGRAM_NAME")
if ! has_program; then
  [[ -f "$BINARY_PATH" ]] || { echo "[error] binary not found: $BINARY_PATH" >&2; exit 1; }
  MODE=(-import "$BINARY_PATH")
fi

# Remove potential project lock file
rm -f "${PROJECT_DIR}/${PROJECT_NAME}.lock"
find "${PROJECT_DIR}/${PROJECT_NAME}.rep" -maxdepth 1 -name '*.lock' -delete 2>/dev/null || true

env \
  GHIDRA_MCP_BIND_HOST="0.0.0.0" \
  GHIDRA_MCP_BIND_PORT="$HPORT" \
  GHIDRA_MCP_DEBUG_BIND_HOST="0.0.0.0" \
  GHIDRA_MCP_DEBUG_BIND_PORT="$DPORT" \
  GHIDRA_MCP_DEBUG_HOST="127.0.0.1" \
  GHIDRA_MCP_DEBUG_PORT="19090" \
  GHIDRA_MCP_BINARY_PATH="$BINARY_ABS" \
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" "${MODE[@]}" \
  -scriptPath "$SCRIPT_PATH" -postScript "$POST_SCRIPT" &
echo $! > "$HEADLESS_PID"

wait_ready() {
  local name="$1" port="$2" pid="$3" i=0
  while ((i < 120)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
      exec 3>&-
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || { echo "[error] $name exited before ready" >&2; exit 1; }
    sleep 1
    i=$((i + 1))
  done
  echo "[error] $name ready timeout (port $port)" >&2
  exit 1
}

echo "[info] Waiting for GDB Server (port $DPORT)..."
wait_ready "debug_bridge" "$DPORT" "$(cat "$DBG_PID")"
echo "[ok] GDB Server ready."

echo "[info] Waiting for Ghidra Headless (port $HPORT)..."
wait_ready "headless" "$HPORT" "$(cat "$HEADLESS_PID")"
echo "[ok] Ghidra Headless ready."
echo "[ok] debug_bridge pid=$(cat "$DBG_PID"), headless pid=$(cat "$HEADLESS_PID")"
echo "[info] Services running. Press Ctrl+C to stop."

wait
