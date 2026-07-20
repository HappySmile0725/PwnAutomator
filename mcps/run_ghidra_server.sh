#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

ANALYZE="./ghidra_12.0.2_PUBLIC/support/analyzeHeadless"
SCRIPT_PATH="./ghidra_tools/server"
POST_SCRIPT="ghidra_server.py"
PWN_SERVER="./pwntools_tools/server/server.py"
PWNO_SERVER="./run_pwno_mcp_stdio.sh"
DEFAULT_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-$(pwd)/test}"
if [[ "${DEFAULT_CHALLENGE_DIR}" != /* ]]; then
  DEFAULT_CHALLENGE_DIR="$(realpath "${DEFAULT_CHALLENGE_DIR}")"
fi
META_DIR="${DEFAULT_CHALLENGE_DIR}/.pwnautomator"
PROJECT_DIR="${GHIDRA_MCP_PROJECT_DIR:-${META_DIR}/ghidra_project}"
PROJECT_NAME="${GHIDRA_MCP_PROJECT_NAME:-workspace}"
DEFAULT_BINARY_PATH="${PWN_AUTOMATOR_BINARY_PATH:-${DEFAULT_CHALLENGE_DIR}/chall}"
GHIDRA_INSTALL_DIR="$(realpath ./ghidra_12.0.2_PUBLIC)"
if [[ -z "${1:-}" && -f "${META_DIR}/current_binary" ]]; then
  DEFAULT_BINARY_PATH="$(cat "${META_DIR}/current_binary")"
fi
BINARY_PATH="${1:-$DEFAULT_BINARY_PATH}"
PROGRAM_NAME="$(basename "$BINARY_PATH")"
BINARY_ABS="$BINARY_PATH"
if [[ -e "$BINARY_PATH" ]]; then
  BINARY_ABS="$(realpath "$BINARY_PATH")"
fi
HPORT="${GHIDRA_PORT:-9999}"
PPORT="${GHIDRA_MCP_PWN_PORT:-19191}"
PWNO_PORT="${PWNO_MCP_PORT:-5601}"
HEADLESS_READY_TIMEOUT="${GHIDRA_MCP_HEADLESS_READY_TIMEOUT:-480}"
PWNO_READY_TIMEOUT="${PWNO_MCP_READY_TIMEOUT:-300}"
HEADLESS_PID=""
PWN_PID=""
PWNO_PID=""
PWNO_LOG=/tmp/pwno_mcp_runtime.log
PWN_LOG=/tmp/pwntools_mcp_runtime.log

is_windows_path() {
  local value="${1:-}"
  [[ -n "$value" ]] || return 1
  [[ "$value" == /mnt/[a-zA-Z]/* || "$value" == [a-zA-Z]:* ]]
}

linux_home_dir() {
  getent passwd "$(id -un)" | cut -d: -f6
}

normalize_runtime_dirs() {
  local linux_home
  linux_home="$(linux_home_dir)"
  [[ -n "$linux_home" ]] || return 0

  if is_windows_path "${HOME:-}"; then
    echo "[warn] HOME points to a Windows path. Resetting to ${linux_home}." >&2
    export HOME="$linux_home"
  fi

  if is_windows_path "${XDG_CONFIG_HOME:-}"; then
    echo "[warn] XDG_CONFIG_HOME points to a Windows path. Resetting to ${HOME}/.config." >&2
    export XDG_CONFIG_HOME="${HOME}/.config"
  fi

  if is_windows_path "${XDG_CACHE_HOME:-}"; then
    echo "[warn] XDG_CACHE_HOME points to a Windows path. Resetting to ${HOME}/.cache." >&2
    export XDG_CACHE_HOME="${HOME}/.cache"
  fi

  mkdir -p "${HOME}" "${XDG_CONFIG_HOME:-${HOME}/.config}" "${XDG_CACHE_HOME:-${HOME}/.cache}"
}

select_ghidra_jdk() {
  local candidate="${GHIDRA_JAVA_HOME:-${JAVA_HOME:-}}"
  local known=(
    "$candidate"
    /usr/lib/jvm/java-21-openjdk-amd64
    /usr/lib/jvm/default-java
  )
  local path=""
  for path in "${known[@]}"; do
    [[ -n "$path" ]] || continue
    [[ -x "$path/bin/javac" ]] || continue
    echo "$path"
    return 0
  done
  return 1
}

bootstrap_ghidra_java_home() {
  local jdk_home=""
  local settings_root=""
  local ghidra_settings_dir=""
  local save_file=""
  local launch_props="${GHIDRA_INSTALL_DIR}/support/launch.properties"

  jdk_home="$(select_ghidra_jdk || true)"
  [[ -n "$jdk_home" ]] || return 0

  export JAVA_HOME="$jdk_home"
  export GHIDRA_JAVA_HOME="$jdk_home"

  if [[ -f "$launch_props" ]]; then
    sed -i '/^JAVA_HOME_OVERRIDE=/d' "$launch_props"
  fi

  settings_root="${XDG_CONFIG_HOME:-${HOME}/.config}"
  ghidra_settings_dir="${settings_root}/ghidra/$(basename "${GHIDRA_INSTALL_DIR}")"
  save_file="${ghidra_settings_dir}/java_home.save"

  mkdir -p "$ghidra_settings_dir"
  printf '%s\n' "$jdk_home" > "$save_file"
}

if [[ "${PROJECT_DIR}" != /* ]]; then
  PROJECT_DIR="$(realpath -m "${PROJECT_DIR}")"
fi
mkdir -p "${META_DIR}" "${PROJECT_DIR}"

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
  local pid="${1:-}"
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
}

start_pwntools_mcp() {
  : > "$PWN_LOG"
  env \
    PWN_AUTOMATOR_CHALLENGE_DIR="${DEFAULT_CHALLENGE_DIR}" \
    PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
    PWN_AUTOMATOR_REMOTE_HOST="${PWN_AUTOMATOR_REMOTE_HOST:-}" \
    PWN_AUTOMATOR_REMOTE_PORT="${PWN_AUTOMATOR_REMOTE_PORT:-}" \
    PWNTOOLS_MCP_BIND_HOST="0.0.0.0" \
    PWNTOOLS_MCP_BIND_PORT="$PPORT" \
    python3 "$PWN_SERVER" >"$PWN_LOG" 2>&1 &
  PWN_PID="$!"
}

start_pwno_mcp() {
  : > "$PWNO_LOG"
  env \
    PWN_AUTOMATOR_CHALLENGE_DIR="${DEFAULT_CHALLENGE_DIR}" \
    PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
    PWN_AUTOMATOR_REMOTE_HOST="${PWN_AUTOMATOR_REMOTE_HOST:-}" \
    PWN_AUTOMATOR_REMOTE_PORT="${PWN_AUTOMATOR_REMOTE_PORT:-}" \
    PWNO_MCP_PORT="$PWNO_PORT" \
    bash "$PWNO_SERVER" http >"$PWNO_LOG" 2>&1 &
  PWNO_PID="$!"
}

validate_runtime() {
  require_cmd python3
  [[ -x "$ANALYZE" ]] || { echo "[error] analyzeHeadless not found: $ANALYZE" >&2; exit 1; }
  [[ -f "$PWN_SERVER" ]] || { echo "[error] pwntools server not found: $PWN_SERVER" >&2; exit 1; }
  [[ -f "$PWNO_SERVER" ]] || { echo "[error] pwno server launcher not found: $PWNO_SERVER" >&2; exit 1; }
}

cleanup() {
  echo "[cleanup] stopping servers..."
  trap - EXIT INT TERM
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
  local idata="${PROJECT_DIR}/${PROJECT_NAME}.rep/idata"
  [[ -d "$idata" ]] && grep -R -F "STATE NAME=\"NAME\" TYPE=\"string\" VALUE=\"${PROGRAM_NAME}\"" "$idata" --include='*.prp' >/dev/null 2>&1
}

kill_port "$HPORT"
kill_port "$PPORT"
kill_port "$PWNO_PORT"
normalize_runtime_dirs
bootstrap_ghidra_java_home
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
  PWN_AUTOMATOR_CHALLENGE_DIR="${DEFAULT_CHALLENGE_DIR}" \
  PWN_AUTOMATOR_BINARY_PATH="$BINARY_ABS" \
  PWN_AUTOMATOR_REMOTE_HOST="${PWN_AUTOMATOR_REMOTE_HOST:-}" \
  PWN_AUTOMATOR_REMOTE_PORT="${PWN_AUTOMATOR_REMOTE_PORT:-}" \
  "$ANALYZE" "$PROJECT_DIR" "$PROJECT_NAME" "${MODE[@]}" \
  -scriptPath "$SCRIPT_PATH" -postScript "$POST_SCRIPT" &
HEADLESS_PID="$!"

wait_ready() {
  local name="$1" port="$2" pid="$3" timeout_secs="${4:-120}" i=0
  while ((i < timeout_secs)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
      exec 3>&-
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      if [[ "$name" == "pwno_mcp" && -f "$PWNO_LOG" ]]; then
        echo "[error] $name exited before ready (last logs):" >&2
        tail -n 80 "$PWNO_LOG" >&2 || true
      elif [[ "$name" == "pwntools_mcp" && -f "$PWN_LOG" ]]; then
        echo "[error] $name exited before ready (last logs):" >&2
        tail -n 80 "$PWN_LOG" >&2 || true
      else
        echo "[error] $name exited before ready" >&2
      fi
      exit 1
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "[error] $name ready timeout (port $port)" >&2
  exit 1
}

echo "[info] Waiting for Pwntools MCP (port $PPORT)..."
wait_ready "pwntools_mcp" "$PPORT" "$PWN_PID"
echo "[ok] Pwntools MCP ready."

echo "[info] Waiting for Pwno MCP (port $PWNO_PORT)..."
wait_ready "pwno_mcp" "$PWNO_PORT" "$PWNO_PID" "$PWNO_READY_TIMEOUT"
echo "[ok] Pwno MCP ready."

echo "[info] Waiting for Ghidra Headless (port $HPORT)..."
wait_ready "headless" "$HPORT" "$HEADLESS_PID" "$HEADLESS_READY_TIMEOUT"
echo "[ok] Ghidra Headless ready."
echo "[ok] pwno pid=$PWNO_PID, pwntools pid=$PWN_PID, headless pid=$HEADLESS_PID"
echo "[info] Services running. Press Ctrl+C to stop."

wait
