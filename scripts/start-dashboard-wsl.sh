#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="${REPO_ROOT}/pwnable-dashboard"

export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-3000}"
export CODEX_AGENT_AUTORUN="${CODEX_AGENT_AUTORUN:-true}"
export CODEX_AGENT_COMMAND="${CODEX_AGENT_COMMAND:-codex}"
export CODEX_AGENT_MODEL="${CODEX_AGENT_MODEL:-gpt-5.3-codex}"
export CODEX_MCP_AUTOCONFIG="${CODEX_MCP_AUTOCONFIG:-true}"
export CODEX_MCP_PROFILE="${CODEX_MCP_PROFILE:-pwnautomator}"
export CODEX_MCP_SERVER_NAME="${CODEX_MCP_SERVER_NAME:-pwnautomator}"
export CODEX_MCP_WRAPPER="${CODEX_MCP_WRAPPER:-mcps/ghidra_tools/wrapper.py}"
export CODEX_AGENT_ARGS="${CODEX_AGENT_ARGS:-exec --json -m ${CODEX_AGENT_MODEL} --profile-v2 ${CODEX_MCP_PROFILE} -}"
export CODEX_AGENT_JSON_TRACE="${CODEX_AGENT_JSON_TRACE:-true}"
export CODEX_SYSTEM_PROMPT_FILE="${CODEX_SYSTEM_PROMPT_FILE:-guidline_docs/codex-system-prompt.md}"
export CODEX_PROMPT_MAX_BYTES="${CODEX_PROMPT_MAX_BYTES:-262144}"
export PWN_AUTOMATOR_TRACE_ENABLED="${PWN_AUTOMATOR_TRACE_ENABLED:-true}"
export PWN_AUTOMATOR_CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-mcps/test}"

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

if [[ "${CODEX_AGENT_AUTORUN}" != "false" ]] && ! "${CODEX_AGENT_COMMAND}" login status >/dev/null 2>&1; then
  echo "[error] Codex is not logged in inside WSL/Ubuntu. Run: codex login" >&2
  exit 1
fi

if [[ "${CODEX_AGENT_AUTORUN}" != "false" && "${CODEX_MCP_AUTOCONFIG}" != "false" ]]; then
  MCP_WRAPPER_PATH="${CODEX_MCP_WRAPPER}"
  [[ "${MCP_WRAPPER_PATH}" = /* ]] || MCP_WRAPPER_PATH="${REPO_ROOT}/${MCP_WRAPPER_PATH}"
  [[ -f "${MCP_WRAPPER_PATH}" ]] || { echo "[error] Codex MCP wrapper not found: ${MCP_WRAPPER_PATH}" >&2; exit 1; }
fi

cd "${APP_DIR}"
if [[ ! -d node_modules ]]; then
  npm install
fi

exec node ./app.js
