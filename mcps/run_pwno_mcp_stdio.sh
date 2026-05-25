#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PWNO_REPO_DIR="${CODEX_PWNO_MCP_REPO:-${SCRIPT_DIR}/pwno-mcp}"
CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-${SCRIPT_DIR}/test}"
IMAGE_TAG="${CODEX_PWNO_MCP_DOCKER_IMAGE:-pwno-mcp-local:latest}"
CONTAINER_NAME="${PWNO_MCP_CONTAINER_NAME:-pwnautomator-pwno-mcp}"
HOST_BIND="${PWNO_MCP_BIND_HOST:-127.0.0.1}"
PORT="${PWNO_MCP_PORT:-5500}"
MODE="${1:-http}"

command -v docker >/dev/null 2>&1 || { echo "[pwno-mcp] docker not found" >&2; exit 1; }
command -v realpath >/dev/null 2>&1 || { echo "[pwno-mcp] realpath not found" >&2; exit 1; }

if [[ "$MODE" != "http" && "$MODE" != "stdio" ]]; then
  echo "[pwno-mcp] unsupported mode: $MODE (use http or stdio)" >&2
  exit 1
fi

PWNO_REPO_DIR="$(realpath "$PWNO_REPO_DIR")"
[[ -d "$PWNO_REPO_DIR/.git" ]] || { echo "[pwno-mcp] clone missing: $PWNO_REPO_DIR" >&2; exit 1; }
[[ -f "$PWNO_REPO_DIR/Dockerfile" ]] || { echo "[pwno-mcp] Dockerfile missing: $PWNO_REPO_DIR" >&2; exit 1; }

mkdir -p "$CHALLENGE_DIR"
CHALLENGE_DIR="$(realpath "$CHALLENGE_DIR")"

docker build -t "$IMAGE_TAG" "$PWNO_REPO_DIR" >&2

if [[ "$MODE" == "stdio" ]]; then
  exec docker run --rm -i \
    --cap-add=SYS_PTRACE \
    --cap-add=SYS_ADMIN \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    -v "${CHALLENGE_DIR}:/workspace" \
    "$IMAGE_TAG" --stdio
fi

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

exec docker run --rm \
  --name "$CONTAINER_NAME" \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -p "${HOST_BIND}:${PORT}:5500" \
  -v "${CHALLENGE_DIR}:/workspace" \
  "$IMAGE_TAG"
