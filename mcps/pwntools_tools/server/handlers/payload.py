"""Payload-related MCP handlers."""

from __future__ import annotations

from typing import Any, Dict

import pwn_runtime as runtime

from .common import parse_bool, require_arg, require_text_arg


def handle_payload_write(args: Dict[str, Any]) -> Dict[str, Any]:
    payload_content = require_arg(args, "payload_content")
    return runtime.write_payload(payload_content=str(payload_content))


def handle_payload_read(args: Dict[str, Any]) -> Dict[str, Any]:
    path = require_text_arg(args, "path")
    return runtime.read_payload(path=path)


def handle_payload_list(args: Dict[str, Any]) -> Dict[str, Any]:
    _ = args
    return runtime.list_payloads()


def handle_payload_execute(args: Dict[str, Any]) -> Dict[str, Any]:
    path = require_text_arg(args, "path")
    pause_before_payload = parse_bool(args.get("pause_before_payload", False))
    wait_ms = args.get("wait_ms", 300)
    return runtime.execute_payload(
        path=path,
        pause_before_payload=pause_before_payload,
        wait_ms=wait_ms,
    )


PAYLOAD_COMMAND_HANDLERS = {
    "pwn.payload.write": handle_payload_write,
    "pwn.payload.read": handle_payload_read,
    "pwn.payload.list": handle_payload_list,
    "pwn.payload.execute": handle_payload_execute,
}
