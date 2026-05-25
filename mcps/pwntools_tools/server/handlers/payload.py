"""Payload-related MCP handlers."""

from __future__ import annotations
from typing import Any, Dict
import pwn_runtime as runtime
from .common import require_arg

def handle_payload_write(args: Dict[str, Any]) -> Dict[str, Any]:
    payload_content = require_arg(args, "payload_content")
    return runtime.write_payload(payload_content=str(payload_content))


def handle_payload_read(args: Dict[str, Any]) -> Dict[str, Any]:
    path = str(args.get("path") or runtime.FIXED_PAYLOAD_FILENAME)
    return runtime.read_payload(path=path)


def handle_payload_list(_: Dict[str, Any]) -> Dict[str, Any]:
    return runtime.list_payloads()


def handle_payload_execute(args: Dict[str, Any]) -> Dict[str, Any]:
    path = str(args.get("path") or runtime.FIXED_PAYLOAD_FILENAME)
    wait_ms = args.get("wait_ms", 300)
    return runtime.execute_payload(
        path=path,
        wait_ms=wait_ms,
    )


PAYLOAD_COMMAND_HANDLERS = {
    "pwn.payload.write": handle_payload_write,
    "pwn.payload.read": handle_payload_read,
    "pwn.payload.list": handle_payload_list,
    "pwn.payload.execute": handle_payload_execute,
}
