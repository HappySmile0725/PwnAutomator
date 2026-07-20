#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PWNO_REPO_DIR="${CODEX_PWNO_MCP_REPO:-${SCRIPT_DIR}/pwno-mcp}"
CHALLENGE_DIR="${PWN_AUTOMATOR_CHALLENGE_DIR:-${SCRIPT_DIR}/test}"
IMAGE_TAG="${CODEX_PWNO_MCP_DOCKER_IMAGE:-pwno-mcp-local:latest}"
CONTAINER_NAME="${PWNO_MCP_CONTAINER_NAME:-pwnautomator-pwno-mcp}"
HOST_BIND="${PWNO_MCP_BIND_HOST:-127.0.0.1}"
PORT="${PWNO_MCP_PORT:-5601}"
MODE="${1:-http}"
BUILD_PLATFORM="${PWNO_MCP_BUILD_PLATFORM:-${TARGETPLATFORM:-linux/amd64}}"
FORCE_BUILD="${PWNO_MCP_FORCE_BUILD:-false}"

command -v docker >/dev/null 2>&1 || { echo "[pwno-mcp] docker not found" >&2; exit 1; }
command -v realpath >/dev/null 2>&1 || { echo "[pwno-mcp] realpath not found" >&2; exit 1; }

if [[ "$MODE" != "http" && "$MODE" != "stdio" ]]; then
  echo "[pwno-mcp] unsupported mode: $MODE (use http or stdio)" >&2
  exit 1
fi

resolve_existing_dir() {
  local raw="$1"
  if [[ -z "$raw" ]]; then
    return 1
  fi
  if [[ "$raw" = /* ]]; then
    [[ -d "$raw" ]] || return 1
    realpath "$raw"
    return 0
  fi

  local candidates=(
    "$PWD/$raw"
    "$SCRIPT_DIR/$raw"
    "$REPO_ROOT/$raw"
  )
  local candidate=""
  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      realpath "$candidate"
      return 0
    fi
  done
  return 1
}

PWNO_REPO_DIR="$(resolve_existing_dir "$PWNO_REPO_DIR" || true)"
[[ -n "$PWNO_REPO_DIR" ]] || { echo "[pwno-mcp] repository path not found: ${CODEX_PWNO_MCP_REPO:-${SCRIPT_DIR}/pwno-mcp}" >&2; exit 1; }
[[ -d "$PWNO_REPO_DIR/.git" ]] || { echo "[pwno-mcp] clone missing: $PWNO_REPO_DIR" >&2; exit 1; }
[[ -f "$PWNO_REPO_DIR/Dockerfile" ]] || { echo "[pwno-mcp] Dockerfile missing: $PWNO_REPO_DIR" >&2; exit 1; }

mkdir -p "$CHALLENGE_DIR"
CHALLENGE_DIR="$(realpath "$CHALLENGE_DIR")"

if [[ "$FORCE_BUILD" == "true" || "$FORCE_BUILD" == "1" ]] || ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  docker build \
    --platform "$BUILD_PLATFORM" \
    --build-arg "TARGETPLATFORM=$BUILD_PLATFORM" \
    -t "$IMAGE_TAG" \
    "$PWNO_REPO_DIR" >&2
fi

PWNO_ENV_ARGS=(
  -e "PWN_AUTOMATOR_CHALLENGE_DIR=/workspace"
  -e "PWN_AUTOMATOR_BINARY_PATH=/workspace/$(basename "${PWN_AUTOMATOR_BINARY_PATH:-chall}")"
  -e "PWN_AUTOMATOR_REMOTE_HOST=${PWN_AUTOMATOR_REMOTE_HOST:-}"
  -e "PWN_AUTOMATOR_REMOTE_PORT=${PWN_AUTOMATOR_REMOTE_PORT:-}"
)

if [[ "$MODE" == "stdio" ]]; then
  exec docker run --rm -i \
    --cap-add=SYS_PTRACE \
    --cap-add=SYS_ADMIN \
    --security-opt seccomp=unconfined \
    --security-opt apparmor=unconfined \
    -v "${CHALLENGE_DIR}:/workspace" \
    "${PWNO_ENV_ARGS[@]}" \
    "$IMAGE_TAG" --stdio
fi

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
for i in {1..10}; do
  if ! docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    break
  fi
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  sleep "$i"
done

exec docker run --rm \
  --name "$CONTAINER_NAME" \
  --cap-add=SYS_PTRACE \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -p "${HOST_BIND}:${PORT}:5500" \
  -v "${CHALLENGE_DIR}:/workspace" \
  "${PWNO_ENV_ARGS[@]}" \
  "$IMAGE_TAG"
