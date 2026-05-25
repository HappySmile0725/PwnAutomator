#!/usr/bin/env python3
"""MCP stdio wrapper for ghidra_tools custom TCP server."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from typing import Any, Dict, List


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.join(THIS_DIR, "client")
if CLIENT_DIR not in sys.path:
    sys.path.insert(0, CLIENT_DIR)

PWNTOOLS_CLIENT_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "pwntools_tools", "client"))
if PWNTOOLS_CLIENT_DIR not in sys.path:
    sys.path.insert(0, PWNTOOLS_CLIENT_DIR)

from ghidra_client import GhidraMCP  # type: ignore  # noqa: E402
from pwntools_client import PwntoolsMCP  # type: ignore  # noqa: E402


DEFAULT_PROTOCOL_VERSION = "2025-11-25"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_PWN_HOST = "127.0.0.1"
DEFAULT_PWN_PORT = 19191
DEFAULT_PWN_TIMEOUT = 10.0
TRACE_SCHEMA = "pwnautomator.raw_trace.v1"


def _tool(
    name: str,
    description: str,
    properties: Dict[str, Any] | None = None,
    required: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
            "additionalProperties": False,
        },
    }


TOOLS: List[Dict[str, Any]] = [
    _tool(
        "ghidra_call",
        "Call raw ghidra command by name (e.g. func.list, decompile.name).",
        properties={
            "cmd": {"type": "string", "description": "Command name (e.g. func.list)"},
            "args": {
                "type": "object",
                "description": "Command arguments object",
                "additionalProperties": True,
            },
        },
        required=["cmd"],
    ),
    _tool("help", "List all supported ghidra commands."),
    _tool(
        "meta",
        "Get metadata for loaded binary. Optional binary_path overrides target.",
        properties={
            "binary_path": {
                "type": "string",
                "description": "Optional path passed to meta command",
            }
        },
    ),
    _tool("func_list", "List all functions."),
    _tool(
        "func_by_name",
        "Find function by name.",
        properties={"name": {"type": "string"}},
        required=["name"],
    ),
    _tool(
        "func_by_addr",
        "Get function by address string (hex).",
        properties={"addr": {"type": "string"}},
        required=["addr"],
    ),
    _tool(
        "mem_hex",
        "Read bytes as hex from address.",
        properties={
            "addr": {"type": "string"},
            "size": {"type": "integer", "minimum": 1, "default": 8},
        },
        required=["addr"],
    ),
    _tool(
        "mem_dec",
        "Read integer value from address (returns hex + value_dec).",
        properties={
            "addr": {"type": "string"},
            "size": {"type": "integer", "minimum": 1, "default": 8},
        },
        required=["addr"],
    ),
    _tool(
        "mem_str",
        "Read string at address.",
        properties={
            "addr": {"type": "string"},
            "maxlen": {"type": "integer", "minimum": 1, "default": 256},
        },
        required=["addr"],
    ),
    _tool(
        "mem_asm",
        "Read assembly lines at address.",
        properties={
            "addr": {"type": "string"},
            "count": {"type": "integer", "minimum": 1, "default": 5},
        },
        required=["addr"],
    ),
    _tool(
        "disassemble_function",
        "Compatibility tool: disassemble from start address (maps to mem.asm).",
        properties={
            "start_address": {"type": "string"},
            "count": {"type": "integer", "minimum": 1, "default": 64},
        },
        required=["start_address"],
    ),
    _tool(
        "decompile_by_addr",
        "Decompile function by address.",
        properties={"addr": {"type": "string"}},
        required=["addr"],
    ),
    _tool(
        "decompile_by_name",
        "Decompile function by name.",
        properties={"name": {"type": "string"}},
        required=["name"],
    ),
    _tool(
        "search_func",
        "Search functions by pattern.",
        properties={"pattern": {"type": "string"}},
        required=["pattern"],
    ),
    _tool(
        "search_str",
        "Search strings by pattern.",
        properties={"pattern": {"type": "string"}},
        required=["pattern"],
    ),
    _tool(
        "search_bytes",
        "Search bytes pattern.",
        properties={
            "pattern": {"type": "string"},
            "max": {"type": "integer", "minimum": 1, "default": 20},
        },
        required=["pattern"],
    ),
    _tool(
        "search_xrefs_to",
        "Find xrefs to address.",
        properties={"addr": {"type": "string"}},
        required=["addr"],
    ),
    _tool(
        "search_xrefs_from",
        "Find xrefs from address.",
        properties={"addr": {"type": "string"}},
        required=["addr"],
    ),
    _tool(
        "pwn_payload_write",
        "Create payload script with mandatory pwntools template (always writes hack.py).",
        properties={
            "payload_content": {"type": "string"},
        },
        required=["payload_content"],
    ),
    _tool(
        "pwn_payload_read",
        "Read active challenge workspace hack.py and parsed payload body.",
        properties={
            "path": {
                "type": "string",
                "description": "Optional. Only active challenge workspace hack.py is accepted.",
            }
        },
    ),
    _tool("pwn_payload_list", "List payload scripts in active challenge workspace."),
    _tool(
        "pwn_payload_execute",
        "Execute active challenge workspace hack.py against the current target binary.",
        properties={
            "path": {
                "type": "string",
                "description": "Optional. Only active challenge workspace hack.py is accepted.",
            },
            "wait_ms": {
                "type": "integer",
                "minimum": 0,
                "default": 300,
                "description": "Wait for initial stdout/stderr collection before returning.",
            },
        },
    ),
    _tool(
        "pwn_session_poll",
        "Poll stdout/stderr/status from a running payload session.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "pwn_session_send",
        "Send stdin data to a payload session.",
        properties={
            "session_id": {"type": "string"},
            "data": {"type": "string"},
            "append_newline": {"type": "boolean", "default": False},
        },
        required=["session_id", "data"],
    ),
    _tool(
        "pwn_session_continue",
        "Resume pause() state by sending newline to session stdin.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "pwn_session_stop",
        "Stop and remove payload session.",
        properties={
            "session_id": {"type": "string"},
            "kill": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
    _tool("pwn_session_list", "List active payload sessions."),
]


TOOL_TO_COMMAND = {
    "help": "help",
    "meta": "meta",
    "func_list": "func.list",
    "func_by_name": "func.name",
    "func_by_addr": "func.addr",
    "mem_hex": "mem.hex",
    "mem_dec": "mem.dec",
    "mem_str": "mem.str",
    "mem_asm": "mem.asm",
    "disassemble_function": "mem.asm",
    "decompile_by_addr": "decompile.addr",
    "decompile_by_name": "decompile.name",
    "search_func": "search.func",
    "search_str": "search.str",
    "search_bytes": "search.bytes",
    "search_xrefs_to": "search.xrefs_to",
    "search_xrefs_from": "search.xrefs_from",
}


PWN_TOOL_TO_COMMAND = {
    "pwn_payload_write": "pwn.payload.write",
    "pwn_payload_read": "pwn.payload.read",
    "pwn_payload_list": "pwn.payload.list",
    "pwn_payload_execute": "pwn.payload.execute",
    "pwn_session_poll": "pwn.session.poll",
    "pwn_session_send": "pwn.session.send",
    "pwn_session_continue": "pwn.session.continue",
    "pwn_session_stop": "pwn.session.stop",
    "pwn_session_list": "pwn.session.list",
}


def _json_dump(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return repr(value)


def _as_structured_content(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {"result": value}


def _detect_result_error(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    status = str(data.get("status", "")).lower()
    if status == "error":
        return True
    if data.get("ok") is False:
        return True
    if "error" in data and data.get("error") not in (None, ""):
        return True
    return False


def _parse_env_port(value: str | None, default: int) -> int:
    text = str(value if value is not None else "").strip()
    if text.isdigit():
        return int(text)
    return default


def _parse_env_float(value: str | None, default: float) -> float:
    text = str(value if value is not None else "").strip()
    if not text:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def _normalize_tool_args(arguments: Any) -> Dict[str, Any]:
    if isinstance(arguments, dict):
        return arguments
    return {}


def _trace_enabled() -> bool:
    value = os.environ.get("PWN_AUTOMATOR_TRACE_ENABLED", "true").strip().lower()
    return value not in ("0", "false", "no", "off")


def _trace_file() -> str:
    return os.environ.get("PWN_AUTOMATOR_TRACE_FILE", "").strip()


def _trace_event(event: Dict[str, Any]) -> None:
    trace_file = _trace_file()
    if not _trace_enabled() or not trace_file:
        return

    try:
        os.makedirs(os.path.dirname(trace_file), exist_ok=True)
        payload = {
            "schema": TRACE_SCHEMA,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + (".%03dZ" % int((time.time() % 1) * 1000)),
            "monotonic_ns": time.monotonic_ns(),
            "pid": os.getpid(),
            "runId": os.environ.get("PWN_AUTOMATOR_TRACE_RUN_ID", ""),
            "source": "mcp_wrapper",
            **event,
        }
        with open(trace_file, "a", encoding="utf-8") as fp:
            fp.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except Exception:
        return


class MCPServer:
    def __init__(
        self,
        host: str,
        port: int,
        pwn_host: str,
        pwn_port: int,
        pwn_timeout: float = DEFAULT_PWN_TIMEOUT,
        verbose: bool = False,
    ) -> None:
        self.verbose = bool(verbose)
        self.client = GhidraMCP(host=host, port=port)
        self.pwn_client = PwntoolsMCP(host=pwn_host, port=pwn_port, timeout=pwn_timeout)

    def run(self) -> int:
        while True:
            req = self._read_message()
            if req is None:
                return 0
            self._handle_request(req)

    def _log(self, message: str) -> None:
        if self.verbose:
            sys.stderr.write("[wrapper] %s\n" % message)
            sys.stderr.flush()

    def _read_message(self) -> Dict[str, Any] | None:
        while True:
            first = sys.stdin.buffer.readline()
            if first == b"":
                return None
            parsed = self._parse_framed_json(first)
            if parsed is not None:
                return parsed

    def _parse_framed_json(self, first_header_line: bytes) -> Dict[str, Any] | None:
        headers: Dict[str, str] = {}
        line = first_header_line
        while True:
            if line in (b"\r\n", b"\n"):
                break
            if b":" in line:
                key, value = line.decode("utf-8", errors="replace").split(":", 1)
                headers[key.strip().lower()] = value.strip()
            line = sys.stdin.buffer.readline()
            if line == b"":
                return None

        length_raw = headers.get("content-length")
        if not length_raw:
            self._log("missing content-length header")
            return None

        try:
            length = int(length_raw)
        except ValueError:
            self._log("invalid content-length: %r" % length_raw)
            return None

        body = sys.stdin.buffer.read(length)
        if len(body) != length:
            self._log("short body read: expected=%d got=%d" % (length, len(body)))
            return None

        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            self._log("failed to parse framed request: %s" % str(exc))
            return None

    def _write_message(self, obj: Dict[str, Any]) -> None:
        # Claude Desktop MCP expects one JSON-RPC object per line on stdio.
        payload = (json.dumps(obj, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()

    def _send_result(self, req_id: Any, result: Dict[str, Any]) -> None:
        self._write_message({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _send_error(self, req_id: Any, code: int, message: str, data: Any = None) -> None:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        self._write_message({"jsonrpc": "2.0", "id": req_id, "error": err})

    def _handle_request(self, req: Dict[str, Any]) -> None:
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params") or {}

        if not method:
            if req_id is not None:
                self._send_error(req_id, -32600, "Invalid Request: missing method")
            return

        self._log("method=%s" % method)

        try:
            if method == "initialize":
                requested_version = params.get("protocolVersion")
                if not isinstance(requested_version, str) or not requested_version:
                    requested_version = DEFAULT_PROTOCOL_VERSION
                result = {
                    "protocolVersion": requested_version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "ghidra-tools-wrapper",
                        "version": "0.1.0",
                    },
                }
                if req_id is not None:
                    self._send_result(req_id, result)
                return

            if method in ("notifications/initialized", "initialized"):
                return

            if method == "ping":
                if req_id is not None:
                    self._send_result(req_id, {})
                return

            if method == "tools/list":
                _trace_event({
                    "type": "mcp_tools_list",
                    "requestId": req_id,
                    "data": {"toolCount": len(TOOLS)},
                })
                if req_id is not None:
                    self._send_result(req_id, {"tools": TOOLS})
                return

            if method == "tools/call":
                name = params.get("name")
                args = _normalize_tool_args(params.get("arguments"))
                started_ns = time.monotonic_ns()
                _trace_event({
                    "type": "mcp_tool_call",
                    "requestId": req_id,
                    "tool": name,
                    "arguments": args,
                })
                result = self._call_tool(name, args)
                _trace_event({
                    "type": "mcp_tool_response",
                    "requestId": req_id,
                    "tool": name,
                    "durationMs": round((time.monotonic_ns() - started_ns) / 1_000_000, 3),
                    "isError": bool(result.get("isError")),
                    "response": result,
                })
                if req_id is not None:
                    self._send_result(req_id, result)
                return

            if req_id is not None:
                self._send_error(req_id, -32601, "Method not found: %s" % method)
        except Exception as exc:
            if req_id is None:
                return
            _trace_event({
                "type": "mcp_request_error",
                "requestId": req_id,
                "method": method,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            })
            self._send_error(
                req_id,
                -32000,
                str(exc),
                {"traceback": traceback.format_exc()},
            )

    def _call_pwn_tool(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        cmd = PWN_TOOL_TO_COMMAND.get(tool_name)
        if not cmd:
            raise ValueError("Unknown pwntools tool: %s" % tool_name)
        return self.pwn_client.call(cmd, **args)

    def _call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            tool_name = str(name or "").strip()
            if not tool_name:
                raise ValueError("name is required")
            if tool_name.startswith("pwn_"):
                data = self._call_pwn_tool(tool_name, args)
            elif tool_name == "ghidra_call":
                cmd = args.get("cmd")
                cmd_args = _normalize_tool_args(args.get("args"))
                if not cmd:
                    raise ValueError("cmd is required")
                data = self.client.call(str(cmd), **cmd_args)
            elif tool_name == "disassemble_function":
                start_address = args.get("start_address")
                if not start_address:
                    raise ValueError("start_address is required")
                count = args.get("count", 64)
                data = self.client.call("mem.asm", addr=start_address, count=count)
            else:
                cmd = TOOL_TO_COMMAND.get(tool_name)
                if not cmd:
                    raise ValueError("Unknown tool: %s" % tool_name)
                data = self.client.call(cmd, **args)

            is_error = _detect_result_error(data)
            return {
                "content": [{"type": "text", "text": _json_dump(data)}],
                "structuredContent": _as_structured_content(data),
                "isError": is_error,
            }
        except Exception as exc:
            err = str(exc)
            return {
                "content": [{"type": "text", "text": err}],
                "structuredContent": {"error": err},
                "isError": True,
            }


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Claude MCP wrapper for ghidra_tools")
    parser.add_argument("--host", default=os.environ.get("GHIDRA_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port",
        default=_parse_env_port(os.environ.get("GHIDRA_PORT"), DEFAULT_PORT),
        type=int,
    )
    parser.add_argument(
        "--pwn-host",
        default=os.environ.get("GHIDRA_MCP_PWN_HOST", DEFAULT_PWN_HOST),
    )
    parser.add_argument(
        "--pwn-port",
        default=_parse_env_port(
            os.environ.get("GHIDRA_MCP_PWN_PORT"),
            DEFAULT_PWN_PORT,
        ),
        type=int,
    )
    parser.add_argument(
        "--pwn-timeout",
        default=_parse_env_float(
            os.environ.get("GHIDRA_MCP_PWN_TIMEOUT"),
            DEFAULT_PWN_TIMEOUT,
        ),
        type=float,
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    server = MCPServer(
        host=args.host,
        port=args.port,
        pwn_host=args.pwn_host,
        pwn_port=args.pwn_port,
        pwn_timeout=args.pwn_timeout,
        verbose=args.verbose,
    )
    return server.run()


if __name__ == "__main__":
    raise SystemExit(main())
