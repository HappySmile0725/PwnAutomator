"""Session-related MCP handlers."""

from __future__ import annotations

from typing import Any, Dict

import pwn_runtime as runtime

from .common import parse_bool, require_arg, require_text_arg


def handle_session_poll(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = require_text_arg(args, "session_id")
    return runtime.poll_session(session_id=session_id)


def handle_session_send(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = require_text_arg(args, "session_id")
    data = require_arg(args, "data")
    append_newline = parse_bool(args.get("append_newline", False))
    return runtime.send_input(
        session_id=session_id,
        data=str(data if data is not None else ""),
        append_newline=append_newline,
    )


def handle_session_continue(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = require_text_arg(args, "session_id")
    return runtime.continue_pause(session_id=session_id)


def handle_session_stop(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = require_text_arg(args, "session_id")
    kill = parse_bool(args.get("kill", False))
    return runtime.stop_session(session_id=session_id, kill=kill)


def handle_session_list(args: Dict[str, Any]) -> Dict[str, Any]:
    _ = args
    return runtime.list_sessions()


SESSION_COMMAND_HANDLERS = {
    "pwn.session.poll": handle_session_poll,
    "pwn.session.send": handle_session_send,
    "pwn.session.continue": handle_session_continue,
    "pwn.session.stop": handle_session_stop,
    "pwn.session.list": handle_session_list,
}
