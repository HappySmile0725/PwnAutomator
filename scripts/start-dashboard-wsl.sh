#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${REPO_ROOT}/pwnable-dashboard"

is_windows_path() {
  local value="${1:-}"
  [[ -n "${value}" ]] || return 1
  [[ "${value}" == /mnt/[a-zA-Z]/* || "${value}" == [a-zA-Z]:* ]]
}

linux_home_dir() {
  getent passwd "$(id -un)" | cut -d: -f6
}

normalize_wsl_user_dirs() {
  local linux_home
  linux_home="$(linux_home_dir)"
  [[ -n "${linux_home}" ]] || return 0

  if is_windows_path "${HOME:-}"; then
    echo "[warn] HOME points to a Windows path. Resetting to ${linux_home}." >&2
    export HOME="${linux_home}"
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

normalize_wsl_user_dirs

if is_windows_path "${CODEX_HOME:-}"; then
  echo "[warn] CODEX_HOME points to a Windows path. Resetting to WSL home." >&2
  unset CODEX_HOME
fi

export CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
mkdir -p "${CODEX_HOME}"
touch "${CODEX_HOME}/config.toml"

export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-3000}"
export CODEX_AGENT_AUTORUN="${CODEX_AGENT_AUTORUN:-true}"
export CODEX_AGENT_LOGIN_STATUS_WARNING="${CODEX_AGENT_LOGIN_STATUS_WARNING:-false}"
export CODEX_AGENT_COMMAND="${CODEX_AGENT_COMMAND:-codex}"
export CODEX_AGENT_MODEL="${CODEX_AGENT_MODEL:-gpt-5.5}"
export CODEX_LORA_ANALYSIS="${CODEX_LORA_ANALYSIS:-${CODEX_AGENT_MODEL}}"
export CODEX_LORA_CODER="${CODEX_LORA_CODER:-${CODEX_AGENT_MODEL}}"
export CODEX_STRICT_LOGIN_CHECK="${CODEX_STRICT_LOGIN_CHECK:-false}"
export CODEX_MCP_AUTOCONFIG="${CODEX_MCP_AUTOCONFIG:-true}"
export CODEX_MCP_PROFILE="${CODEX_MCP_PROFILE:-pwnautomator}"
export CODEX_MCP_SERVER_NAME="${CODEX_MCP_SERVER_NAME:-pwnautomator}"
export CODEX_MCP_WRAPPER="${CODEX_MCP_WRAPPER:-mcps/ghidra_tools/wrapper.py}"
export CODEX_PWNO_MCP_SERVER_NAME="${CODEX_PWNO_MCP_SERVER_NAME:-pwno}"
export CODEX_PWNO_MCP_REPO="${CODEX_PWNO_MCP_REPO:-mcps/pwno-mcp}"
export CODEX_PWNO_MCP_DOCKER_IMAGE="${CODEX_PWNO_MCP_DOCKER_IMAGE:-pwno-mcp-local:latest}"
if [[ -z "${CODEX_AGENT_ARGS:-}" ]]; then
  export CODEX_AGENT_ARGS="exec --json -m {model} --profile-v2 ${CODEX_MCP_PROFILE} -"
else
  export CODEX_AGENT_ARGS
fi
export CODEX_AGENT_JSON_TRACE="${CODEX_AGENT_JSON_TRACE:-true}"
export CODEX_SYSTEM_PROMPT_FILE="${CODEX_SYSTEM_PROMPT_FILE:-guidline_docs/codex-system-prompt.md}"
export CODEX_PROMPT_MAX_BYTES="${CODEX_PROMPT_MAX_BYTES:-262144}"
export PWN_AUTOMATOR_TRACE_ENABLED="${PWN_AUTOMATOR_TRACE_ENABLED:-true}"
export PWN_AUTOMATOR_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-mcps/test}"
export PWN_AUTOMATOR_MCP_AUTOSTART="${PWN_AUTOMATOR_MCP_AUTOSTART:-true}"
export PWN_AUTOMATOR_MCP_SERVER_SCRIPT="${PWN_AUTOMATOR_MCP_SERVER_SCRIPT:-mcps/run_ghidra_server.sh}"
export PWNO_MCP_HOST="${PWNO_MCP_HOST:-127.0.0.1}"
export PWNO_MCP_PORT="${PWNO_MCP_PORT:-5601}"

display_host() {
  if [[ "${HOST}" == "0.0.0.0" ]]; then
    echo "127.0.0.1"
    return
  fi
  echo "${HOST}"
}

port_listener_info() {
  ss -ltnp 2>/dev/null | grep -E "[[:space:]]${HOST//./\\.}:${PORT}[[:space:]]|[[:space:]]0\\.0\\.0\\.0:${PORT}[[:space:]]|[[:space:]]\\*:${PORT}[[:space:]]" || true
}

extract_listener_pids() {
  grep -o 'pid=[0-9]\+' | cut -d= -f2 | sort -u
}

describe_pid() {
  local pid="$1"
  local cmd cwd
  cmd="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
  cwd="$(readlink -f "/proc/${pid}/cwd" 2>/dev/null || true)"
  printf 'pid=%s cmd=%s cwd=%s\n' "${pid}" "${cmd:-unknown}" "${cwd:-unknown}"
}

if ! command -v node >/dev/null 2>&1; then
  echo "[error] node is required in WSL/Ubuntu." >&2
  exit 1
fi

if [[ "${CODEX_AGENT_AUTORUN}" != "false" ]] && ! command -v "${CODEX_AGENT_COMMAND}" >/dev/null 2>&1; then
  echo "[error] ${CODEX_AGENT_COMMAND} is required in WSL/Ubuntu for Codex autorun." >&2
  exit 1
fi

CODEX_PATH="$(command -v "${CODEX_AGENT_COMMAND}" 2>/dev/null || true)"
if [[ "${CODEX_AGENT_AUTORUN}" != "false" && "${CODEX_PATH}" == /mnt/c/* ]]; then
  echo "[error] ${CODEX_AGENT_COMMAND} resolves to a Windows path: ${CODEX_PATH}" >&2
  echo "[error] Install Codex inside WSL: npm install -g @openai/codex --include=optional" >&2
  exit 1
fi

if [[ "${CODEX_AGENT_AUTORUN}" != "false" ]]; then
  CODEX_LOGIN_OUTPUT=""
  CODEX_LOGIN_STATUS=0
  if CODEX_LOGIN_OUTPUT="$("${CODEX_AGENT_COMMAND}" login status 2>&1)"; then
    :
  else
    CODEX_LOGIN_STATUS=$?
  fi

  if [[ "${CODEX_LOGIN_OUTPUT}" != *"Logged in"* ]]; then
    if [[ "${CODEX_STRICT_LOGIN_CHECK}" == "true" ]]; then
      echo "[error] Codex login status check failed inside WSL/Ubuntu." >&2
      [[ -n "${CODEX_LOGIN_OUTPUT}" ]] && echo "[error] ${CODEX_LOGIN_OUTPUT}" >&2
      exit "${CODEX_LOGIN_STATUS:-1}"
    fi

    if [[ -f "${CODEX_HOME}/auth.json" ]]; then
      echo "[info] Codex auth artifacts found; keeping autorun enabled despite login status probe failure." >&2
      export CODEX_AGENT_LOGIN_STATUS_WARNING=false
      export CODEX_AGENT_AUTORUN=true
    else
      echo "[warn] Codex login status check failed. Dashboard will retry autorun at runtime." >&2
      [[ -n "${CODEX_LOGIN_OUTPUT}" ]] && echo "[warn] ${CODEX_LOGIN_OUTPUT}" >&2
      export CODEX_AGENT_LOGIN_STATUS_WARNING=true
      export CODEX_AGENT_AUTORUN=soft-disabled
    fi
  else
    export CODEX_AGENT_LOGIN_STATUS_WARNING=false
    if [[ "${CODEX_AGENT_AUTORUN}" == "soft-disabled" ]]; then
      export CODEX_AGENT_AUTORUN=true
    fi
  fi
fi

if [[ "${CODEX_MCP_AUTOCONFIG}" != "false" ]]; then
  MCP_WRAPPER_PATH="${CODEX_MCP_WRAPPER}"
  [[ "${MCP_WRAPPER_PATH}" = /* ]] || MCP_WRAPPER_PATH="${REPO_ROOT}/${MCP_WRAPPER_PATH}"
  [[ -f "${MCP_WRAPPER_PATH}" ]] || { echo "[error] Codex MCP wrapper not found: ${MCP_WRAPPER_PATH}" >&2; exit 1; }
fi

if [[ "${PWN_AUTOMATOR_MCP_AUTOSTART}" != "false" ]]; then
  PWNO_REPO_PATH="${CODEX_PWNO_MCP_REPO}"
  [[ "${PWNO_REPO_PATH}" = /* ]] || PWNO_REPO_PATH="${REPO_ROOT}/${PWNO_REPO_PATH}"
  if [[ ! -d "${PWNO_REPO_PATH}/.git" ]]; then
    echo "[error] pwno-mcp clone not found: ${PWNO_REPO_PATH}" >&2
    echo "[error] Run: git clone https://github.com/pwno-io/pwno-mcp.git ${PWNO_REPO_PATH}" >&2
    exit 1
  fi

  MCP_SERVER_SCRIPT_PATH="${PWN_AUTOMATOR_MCP_SERVER_SCRIPT}"
  [[ "${MCP_SERVER_SCRIPT_PATH}" = /* ]] || MCP_SERVER_SCRIPT_PATH="${REPO_ROOT}/${MCP_SERVER_SCRIPT_PATH}"
  [[ -f "${MCP_SERVER_SCRIPT_PATH}" ]] || { echo "[error] mcp server script not found: ${MCP_SERVER_SCRIPT_PATH}" >&2; exit 1; }
fi

cd "${APP_DIR}"
if [[ ! -d node_modules ]]; then
  npm install
fi

PORT_INFO="$(port_listener_info)"
if [[ -n "${PORT_INFO}" ]]; then
  EXISTING_PIDS="$(printf '%s\n' "${PORT_INFO}" | extract_listener_pids || true)"
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    CMDLINE="$(ps -p "${pid}" -o args= 2>/dev/null || true)"
    CWD="$(readlink -f "/proc/${pid}/cwd" 2>/dev/null || true)"
    if [[ "${CMDLINE}" == "node ./app.js"* && "${CWD}" == "${APP_DIR}" ]]; then
      echo "[info] Dashboard is already running on http://$(display_host):${PORT} (pid ${pid})." >&2
      exit 0
    fi
  done <<< "${EXISTING_PIDS}"

  echo "[error] Port ${PORT} is already in use." >&2
  while IFS= read -r pid; do
    [[ -n "${pid}" ]] || continue
    echo "[error] $(describe_pid "${pid}")" >&2
  done <<< "${EXISTING_PIDS}"
  echo "[error] Use a different port, e.g. PORT=3010 ./start-dashboard-wsl.sh" >&2
  exit 1
fi

exec node ./app.js
