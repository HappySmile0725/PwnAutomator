#!/usr/bin/env python3
"""JSON bridge server for dynamic debugger commands."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socketserver
import sys
from typing import Any, Dict

if __package__ in (None, ""):
    import os

    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if THIS_DIR not in sys.path:
        sys.path.insert(0, THIS_DIR)
    from session_manager import SessionManager  # type: ignore
else:
    from .session_manager import SessionManager


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BridgeRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        srv: "BridgeServer" = self.server  # type: ignore[assignment]
        chunks = []
        while True:
            part = self.request.recv(65536)
            if not part:
                break
            chunks.append(part)
            if b"\n" in part:
                break
        raw = b"".join(chunks).strip()
        if not raw:
            return
        try:
            req = json.loads(raw.decode("utf-8"))
            cmd = req.get("cmd")
            args = req.get("args", {})
            result = srv.manager.dispatch(cmd, args)
            res = {"ok": True, "result": result}
        except Exception as exc:
            res = {"ok": False, "error": str(exc)}
        wire = (json.dumps(res) + "\n").encode("utf-8")
        self.request.sendall(wire)


class BridgeServer(ThreadedTCPServer):
    def __init__(self, host: str, port: int) -> None:
        self.manager = SessionManager()
        super().__init__((host, port), BridgeRequestHandler)

    def shutdown_server(self) -> None:
        self.manager.shutdown()
        self.shutdown()
        self.server_close()


def parse_args(argv: Any = None) -> argparse.Namespace:
    host_default = os.environ.get("GHIDRA_MCP_DEBUG_BIND_HOST") or os.environ.get("GHIDRA_MCP_DEBUG_HOST") or "0.0.0.0"
    port_raw = os.environ.get("GHIDRA_MCP_DEBUG_BIND_PORT") or os.environ.get("GHIDRA_MCP_DEBUG_PORT") or "19090"
    try:
        port_default = int(port_raw)
    except Exception:
        port_default = 19090
    parser = argparse.ArgumentParser(description="Ghidra MCP debug bridge")
    parser.add_argument("--host", default=host_default)
    parser.add_argument("--port", default=port_default, type=int)
    return parser.parse_args(argv)


def main(argv: Any = None) -> int:
    args = parse_args(argv)
    server = BridgeServer(args.host, args.port)

    def _stop(_signum: int, _frame: Any) -> None:
        server.shutdown_server()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(
        "Ghidra Debug Bridge listening on %s:%d"
        % (args.host, args.port),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.shutdown_server()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
