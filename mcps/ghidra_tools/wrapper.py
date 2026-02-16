#!/usr/bin/env python3
"""MCP stdio wrapper for ghidra_tools custom TCP server."""

from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from typing import Any, Dict, List


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_DIR = os.path.join(THIS_DIR, "client")
if CLIENT_DIR not in sys.path:
    sys.path.insert(0, CLIENT_DIR)

from ghidra_client import GhidraMCP  # type: ignore  # noqa: E402


def _tool(
    name: str,
    description: str,
    properties: Dict[str, Any] | None = None,
    required: List[str] | None = None,
    additional_properties: bool = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
            "additionalProperties": additional_properties,
        },
    }


TOOLS: List[Dict[str, Any]] = [
    _tool(
        "ghidra_call",
        "Call raw ghidra command by name (e.g. func.list, decompile.name, debug.open).",
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
        "Read bytes as decimal value from address.",
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
        "debug_open",
        "Open dynamic debug session. Supports all debug.open args.",
        properties={
            "auto_run": {
                "type": "boolean",
                "description": "Run target immediately after open (default: false).",
                "default": False,
            }
        },
        additional_properties=True,
    ),
    _tool(
        "debug_open_current",
        "Open dynamic debug session for current program. Supports all debug.open.current args.",
        properties={
            "auto_run": {
                "type": "boolean",
                "description": "Run target immediately after open (default: false).",
                "default": False,
            }
        },
        additional_properties=True,
    ),
    _tool(
        "debug_attach",
        "Attach dynamic debug session. Supports all debug.attach args.",
        properties={"pid": {"type": "integer"}},
        required=["pid"],
        additional_properties=True,
    ),
    _tool(
        "debug_close",
        "Close dynamic debug session.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool("debug_list", "List debug sessions."),
    _tool(
        "debug_status",
        "Get debug session status.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_break_set",
        "Set breakpoint.",
        properties={
            "session_id": {"type": "string"},
            "location": {"type": "string"},
        },
        required=["session_id", "location"],
    ),
    _tool(
        "debug_break_del",
        "Delete breakpoint.",
        properties={
            "session_id": {"type": "string"},
            "breakpoint": {"type": "string"},
        },
        required=["session_id", "breakpoint"],
    ),
    _tool(
        "debug_break_list",
        "List breakpoints.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_cont",
        "Continue execution.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_stepi",
        "Single-step instruction.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_nexti",
        "Step over instruction.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_interrupt",
        "Interrupt execution.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_stdin_write",
        "Write input to inferior stdin.",
        properties={
            "session_id": {"type": "string"},
            "data": {"type": "string"},
            "append_newline": {"type": "boolean", "default": False},
        },
        required=["session_id", "data"],
    ),
    _tool(
        "debug_regs",
        "Read registers.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_mem",
        "Read memory from debug session.",
        properties={
            "session_id": {"type": "string"},
            "addr": {"type": "string"},
            "size": {"type": "integer", "minimum": 1, "default": 64},
        },
        required=["session_id", "addr"],
    ),
    _tool(
        "debug_bt",
        "Get stack backtrace.",
        properties={
            "session_id": {"type": "string"},
            "depth": {"type": "integer", "minimum": 1, "default": 32},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_events_poll",
        "Poll async debug events.",
        properties={
            "session_id": {"type": "string"},
            "max": {"type": "integer", "minimum": 1, "default": 20},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_trace_connect",
        "Connect debug session to Ghidra TraceRMI.",
        properties={
            "session_id": {"type": "string"},
            "trace_rmi_addr": {"type": "string"},
        },
        required=["session_id", "trace_rmi_addr"],
    ),
    _tool(
        "debug_trace_disconnect",
        "Disconnect Ghidra TraceRMI session.",
        properties={
            "session_id": {"type": "string"},
            "tolerate_error": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_trace_start",
        "Start Ghidra trace.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_trace_stop",
        "Stop Ghidra trace.",
        properties={
            "session_id": {"type": "string"},
            "tolerate_error": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_trace_sync_enable",
        "Enable trace sync.",
        properties={"session_id": {"type": "string"}},
        required=["session_id"],
    ),
    _tool(
        "debug_trace_sync_disable",
        "Disable trace sync.",
        properties={
            "session_id": {"type": "string"},
            "tolerate_error": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_trace_sync_synth_stopped",
        "Synthesize stopped state into trace.",
        properties={
            "session_id": {"type": "string"},
            "tolerate_error": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
    _tool(
        "debug_trace_put_all",
        "Publish inferiors/threads/frames/registers/memory to trace.",
        properties={
            "session_id": {"type": "string"},
            "tolerate_error": {"type": "boolean", "default": False},
        },
        required=["session_id"],
    ),
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
    "debug_open": "debug.open",
    "debug_open_current": "debug.open.current",
    "debug_attach": "debug.attach",
    "debug_close": "debug.close",
    "debug_list": "debug.list",
    "debug_status": "debug.status",
    "debug_break_set": "debug.break.set",
    "debug_break_del": "debug.break.del",
    "debug_break_list": "debug.break.list",
    "debug_cont": "debug.cont",
    "debug_stepi": "debug.stepi",
    "debug_nexti": "debug.nexti",
    "debug_interrupt": "debug.interrupt",
    "debug_stdin_write": "debug.stdin.write",
    "debug_regs": "debug.regs",
    "debug_mem": "debug.mem",
    "debug_bt": "debug.bt",
    "debug_events_poll": "debug.events.poll",
    "debug_trace_connect": "debug.trace.connect",
    "debug_trace_disconnect": "debug.trace.disconnect",
    "debug_trace_start": "debug.trace.start",
    "debug_trace_stop": "debug.trace.stop",
    "debug_trace_sync_enable": "debug.trace.sync_enable",
    "debug_trace_sync_disable": "debug.trace.sync_disable",
    "debug_trace_sync_synth_stopped": "debug.trace.sync_synth_stopped",
    "debug_trace_put_all": "debug.trace.put_all",
}


def _json_dump(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return repr(value)


def _as_structured_content(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {"result": value}


class MCPServer:
    def __init__(self, host: str, port: int, verbose: bool = False) -> None:
        self.verbose = bool(verbose)
        self.client = GhidraMCP(host=host, port=port)

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
        # Primary mode: MCP stdio framing (Content-Length headers).
        # Fallback mode: single-line JSON messages.
        first = sys.stdin.buffer.readline()
        if first == b"":
            return None

        stripped = first.strip()
        if stripped.startswith(b"{"):
            try:
                return json.loads(stripped.decode("utf-8"))
            except Exception as exc:
                self._log("failed to parse line-json request: %s" % str(exc))
                return None

        headers: Dict[str, str] = {}
        line = first
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
        except Exception:
            self._log("invalid content-length: %r" % length_raw)
            return None

        body = sys.stdin.buffer.read(length)
        if len(body) != length:
            self._log("short body read: expected=%d got=%d" % (length, len(body)))
            return None

        try:
            return json.loads(body.decode("utf-8"))
        except Exception as exc:
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
                    requested_version = "2025-11-25"
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
                if req_id is not None:
                    self._send_result(req_id, {"tools": TOOLS})
                return

            if method == "tools/call":
                name = params.get("name")
                args = params.get("arguments") or {}
                if not isinstance(args, dict):
                    args = {}
                result = self._call_tool(name, args)
                if req_id is not None:
                    self._send_result(req_id, result)
                return

            if req_id is not None:
                self._send_error(req_id, -32601, "Method not found: %s" % method)
        except Exception as exc:
            if req_id is None:
                return
            self._send_error(
                req_id,
                -32000,
                str(exc),
                {"traceback": traceback.format_exc()},
            )

    def _call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if name == "ghidra_call":
                cmd = args.get("cmd")
                cmd_args = args.get("args") or {}
                if not cmd:
                    raise ValueError("cmd is required")
                if not isinstance(cmd_args, dict):
                    raise ValueError("args must be an object")
                data = self.client.call(str(cmd), **cmd_args)
            elif name == "disassemble_function":
                start_address = args.get("start_address")
                if not start_address:
                    raise ValueError("start_address is required")
                count = args.get("count", 64)
                data = self.client.call("mem.asm", addr=start_address, count=count)
            else:
                cmd = TOOL_TO_COMMAND.get(str(name))
                if not cmd:
                    raise ValueError("Unknown tool: %s" % name)
                data = self.client.call(cmd, **args)

            return {
                "content": [{"type": "text", "text": _json_dump(data)}],
                "structuredContent": _as_structured_content(data),
                "isError": False,
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
    parser.add_argument("--host", default=os.environ.get("GHIDRA_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.environ.get("GHIDRA_PORT", "9999")), type=int)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    server = MCPServer(host=args.host, port=args.port, verbose=args.verbose)
    return server.run()


if __name__ == "__main__":
    raise SystemExit(main())
