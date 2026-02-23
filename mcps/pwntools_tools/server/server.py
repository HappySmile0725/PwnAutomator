#!/usr/bin/env python3
"""TCP server for pwntools MCP commands."""

from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
from typing import Any, Dict

from handlers import dispatch_command, list_registered_commands


DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_BIND_PORT = 19191
DEFAULT_MAX_REQUEST_BYTES = 2 * 1024 * 1024


def _parse_env_port(value: str | None, default: int) -> int:
    text = str(value if value is not None else "").strip()
    if text.isdigit():
        return int(text)
    return default


def _parse_env_int(value: str | None, default: int) -> int:
    text = str(value if value is not None else "").strip()
    if text.isdigit():
        return int(text)
    return default


def _get_default_host() -> str:
    return os.environ.get("PWNTOOLS_MCP_BIND_HOST", DEFAULT_BIND_HOST)


def _get_default_port() -> int:
    return _parse_env_port(
        os.environ.get("PWNTOOLS_MCP_BIND_PORT"),
        DEFAULT_BIND_PORT,
    )


def _get_default_max_request_bytes() -> int:
    return _parse_env_int(
        os.environ.get("PWNTOOLS_MCP_MAX_REQUEST_BYTES"),
        DEFAULT_MAX_REQUEST_BYTES,
    )


def _send_response(conn: socket.socket, payload: Dict[str, Any]) -> None:
    conn.sendall(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")


def _recv_request(conn: socket.socket, max_request_bytes: int) -> str:
    chunks = []
    total_bytes = 0
    while True:
        data = conn.recv(65536)
        if not data:
            break
        total_bytes += len(data)
        if total_bytes > max_request_bytes:
            raise ValueError("request exceeds max size: %d bytes" % max_request_bytes)
        chunks.append(data)
        if b"\n" in data:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _help_payload() -> Dict[str, Any]:
    return {
        "help": "show available pwntools commands",
        "pwn.payload.write": "write payload script with enforced template {payload_content, filename}",
        "pwn.payload.read": "read payload script {path}",
        "pwn.payload.list": "list payload scripts",
        "pwn.payload.execute": "execute payload on fixed target mcps/test/chall {path, pause_before_payload?, wait_ms?}",
        "pwn.session.poll": "poll session output/status {session_id}",
        "pwn.session.send": "send stdin to session {session_id, data, append_newline?}",
        "pwn.session.continue": "resume pause() by sending newline {session_id}",
        "pwn.session.stop": "stop session {session_id, kill?}",
        "pwn.session.list": "list active sessions",
        "_registered": list_registered_commands(),
    }


def _handle_request(req: Dict[str, Any]) -> Dict[str, Any]:
    cmd = req.get("cmd")
    args = req.get("args", {})
    if not cmd:
        return {"ok": False, "error": "cmd is required"}
    if cmd == "help":
        return {"ok": True, "result": _help_payload()}
    if not isinstance(args, dict):
        return {"ok": False, "error": "args must be an object"}
    try:
        result = dispatch_command(command=str(cmd), args=args)
        if isinstance(result, dict) and set(result.keys()) == {"error"}:
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class PwnTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler_class: type[socketserver.BaseRequestHandler],
        max_request_bytes: int,
    ) -> None:
        self.max_request_bytes = max(1024, int(max_request_bytes))
        super().__init__(server_address, request_handler_class)


class PwnRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - integration path
        response = None
        try:
            raw = _recv_request(self.request, self.server.max_request_bytes).strip()
            if not raw:
                return
            req = json.loads(raw)
            response = _handle_request(req)
        except ValueError as exc:
            response = {"ok": False, "error": "Invalid request: %s" % str(exc)}
        except BaseException as exc:
            response = {"ok": False, "error": str(exc)}
        if response is not None:
            try:
                _send_response(self.request, response)
            except socket.error:
                pass


def run_server(host: str, port: int, max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES) -> int:
    with PwnTCPServer((host, port), PwnRequestHandler, max_request_bytes=max_request_bytes) as server:
        print("=" * 50)
        print("Pwntools MCP TCP Server")
        print("Listening: %s:%d" % (host, port))
        print("Max request bytes: %d" % server.max_request_bytes)
        print("=" * 50)
        server.serve_forever()
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="pwntools MCP TCP server")
    parser.add_argument("--host", default=_get_default_host())
    parser.add_argument("--port", type=int, default=_get_default_port())
    parser.add_argument("--max-request-bytes", type=int, default=_get_default_max_request_bytes())
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return run_server(host=args.host, port=args.port, max_request_bytes=args.max_request_bytes)


if __name__ == "__main__":
    raise SystemExit(main())
