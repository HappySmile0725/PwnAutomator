#!/usr/bin/env python3
"""TCP client for pwntools MCP server."""

from __future__ import annotations

import json
import socket
from typing import Any, Dict


def _normalize_connect_host(host: str) -> str:
    text = str(host or "").strip()
    if text == "" or text == "0.0.0.0":
        return "127.0.0.1"
    return text


class PwntoolsMCP:
    def __init__(self, host: str = "127.0.0.1", port: int = 19191, timeout: float = 10.0):
        self.host = _normalize_connect_host(host)
        self.port = int(port)
        self.timeout = float(timeout)

    @staticmethod
    def _recv_one_json(sock: socket.socket) -> Dict[str, Any]:
        chunks = []
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
        except socket.timeout as exc:
            raise TimeoutError("timeout waiting for pwntools server response") from exc
        if not chunks:
            raise Exception("empty response (pwntools server closed connection)")
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not raw:
            raise Exception("empty response payload")
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise Exception("invalid JSON response from pwntools server") from exc

    def call(self, cmd: str, **args: Any) -> Any:
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            payload = json.dumps({"cmd": cmd, "args": args}).encode("utf-8") + b"\n"
            sock.sendall(payload)
            res = self._recv_one_json(sock)
        if res.get("ok"):
            return res.get("result")
        raise Exception(res.get("error", "pwntools server error"))
