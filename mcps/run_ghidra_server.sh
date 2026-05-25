#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ANALYZE="./ghidra_12.0.2_PUBLIC/support/analyzeHeadless"
PROJECT_DIR="challenge"
PROJECT_NAME="test"
SCRIPT_PATH="./ghidra_tools/server"
POST_SCRIPT="ghidra_server.py"
PWN_SERVER="./pwntools_tools/server/server.py"
PWNO_SERVER="./run_pwno_mcp_stdio.sh"
DEFAULT_BINARY_PATH="${PWN_AUTOMATOR_BINARY_PATH:-./test/chall}"
if [[ -z "${1:-}" && -f "./test/.pwnautomator/current_binary" ]]; then
  DEFAULT_BINARY_PATH="$(cat ./test/.pwnautomator/current_binary)"
fi
BINARY_PATH="${1:-$DEFAULT_BINARY_PATH}"
PROGRAM_NAME="$(basename "$BINARY_PATH")"
BINARY_ABS="$BINARY_PATH"
if [[ -e "$BINARY_PATH" ]]; then
  BINARY_ABS="$(realpath "$BINARY_PATH")"
fi
HPORT=9999
PPORT=19191
PWNO_PORT="${PWNO_MCP_PORT:-5500}"
HEADLESS_READY_TIMEOUT="${GHIDRA_MCP_HEADLESS_READY_TIMEOUT:-300}"
PWNO_READY_TIMEOUT="${PWNO_MCP_READY_TIMEOUT:-120}"
HEADLESS_PID=/tmp/ghidra_headless.pid
PWN_PID=/tmp/pwntools_mcp.pid
PWNO_PID=/tmp/pwno_mcp.pid

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

kill_stale_headless() {
  local pids=""
  pids="$(pgrep -f "ghidra\\.app\\.util\\.headless\\.AnalyzeHeadless ${PROJECT_DIR} ${PROJECT_NAME}" 2>/dev/null || true)"
  [[ -z "$pids" ]] || { echo "[cleanup] stale headless: $pids"; terminate_pids "$pids"; }
}

cleanup_project_locks() {
  rm -f "${PROJECT_DIR}/${PROJECT_NAME}.lock" "${PROJECT_DIR}/${PROJECT_NAME}.lock~"
  find "${PROJECT_DIR}/${PROJECT_NAME}.rep" -maxdepth 2 \( -name '*.lock' -o -name '*.lock~' \) -delete 2>/dev/null || true
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

start_pwntools_mcp() {
  env \
    PWN_AUTOMATOR_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-$(pwd)/test}" \
    PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
    PWNTOOLS_MCP_BIND_HOST="0.0.0.0" \
    PWNTOOLS_MCP_BIND_PORT="$PPORT" \
    python3 "$PWN_SERVER" > /dev/null 2>&1 &
  echo $! > "$PWN_PID"
}

start_pwno_mcp() {
  env \
    PWN_AUTOMATOR_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-$(pwd)/test}" \
    PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
    PWNO_MCP_PORT="$PWNO_PORT" \
    bash "$PWNO_SERVER" http > /dev/null 2>&1 &
  echo $! > "$PWNO_PID"
}

validate_runtime() {
  require_cmd python3
  [[ -x "$ANALYZE" ]] || { echo "[error] analyzeHeadless not found: $ANALYZE" >&2; exit 1; }
  [[ -f "$PWN_SERVER" ]] || { echo "[error] pwntools server not found: $PWN_SERVER" >&2; exit 1; }
  [[ -f "$PWNO_SERVER" ]] || { echo "[error] pwno server launcher not found: $PWNO_SERVER" >&2; exit 1; }
}

cleanup() {
  echo "[cleanup] stopping servers..."
  trap - EXIT # prevent loop
  stop_pid "$PWNO_PID"
  stop_pid "$PWN_PID"
  stop_pid "$HEADLESS_PID"
  kill_stale_headless
  kill_port "$PWNO_PORT"
  kill_port "$PPORT"
  kill_port "$HPORT"
  cleanup_project_locks
  echo "[cleanup] done."
}

trap cleanup EXIT INT TERM

has_program() {
  local idata="./${PROJECT_DIR}/${PROJECT_NAME}.rep/idata"
  [[ -d "$idata" ]] && grep -R -F "STATE NAME=\"NAME\" TYPE=\"string\" VALUE=\"${PROGRAM_NAME}\"" "$idata" --include='*.prp' >/dev/null 2>&1
}

kill_port "$HPORT"
kill_port "$PPORT"
kill_port "$PWNO_PORT"
validate_runtime
kill_stale_headless
cleanup_project_locks

start_pwno_mcp
start_pwntools_mcp

MODE=(-process "$PROGRAM_NAME")
if ! has_program; then
  [[ -f "$BINARY_PATH" ]] || { echo "[error] binary not found: $BINARY_PATH" >&2; exit 1; }
  MODE=(-import "$BINARY_PATH")
fi

env \
  GHIDRA_MCP_BIND_HOST="0.0.0.0" \
  GHIDRA_MCP_BIND_PORT="$HPORT" \
  GHIDRA_MCP_BINARY_PATH="$BINARY_ABS" \
  PWN_AUTOMATOR_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-$(pwd)/test}" \
  PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" "${MODE[@]}" \
  -scriptPath "$SCRIPT_PATH" -postScript "$POST_SCRIPT" &
echo $! > "$HEADLESS_PID"

wait_ready() {
  local name="$1" port="$2" pid="$3" timeout_secs="${4:-120}" i=0
  while ((i < timeout_secs)); do
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

echo "[info] Waiting for Pwntools MCP (port $PPORT)..."
wait_ready "pwntools_mcp" "$PPORT" "$(cat "$PWN_PID")"
echo "[ok] Pwntools MCP ready."

echo "[info] Waiting for Pwno MCP (port $PWNO_PORT)..."
wait_ready "pwno_mcp" "$PWNO_PORT" "$(cat "$PWNO_PID")" "$PWNO_READY_TIMEOUT"
echo "[ok] Pwno MCP ready."

echo "[info] Waiting for Ghidra Headless (port $HPORT)..."
wait_ready "headless" "$HPORT" "$(cat "$HEADLESS_PID")" "$HEADLESS_READY_TIMEOUT"
echo "[ok] Ghidra Headless ready."
echo "[ok] pwno pid=$(cat "$PWNO_PID"), pwntools pid=$(cat "$PWN_PID"), headless pid=$(cat "$HEADLESS_PID")"
echo "[info] Services running. Press Ctrl+C to stop."

wait
