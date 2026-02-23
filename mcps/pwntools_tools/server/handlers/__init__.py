"""Handler registry for pwntools TCP commands."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from .payload import PAYLOAD_COMMAND_HANDLERS
from .session import SESSION_COMMAND_HANDLERS


PwnCommandHandler = Callable[[Dict[str, Any]], Dict[str, Any]]

PWN_COMMAND_HANDLERS: Dict[str, PwnCommandHandler] = {}
PWN_COMMAND_HANDLERS.update(PAYLOAD_COMMAND_HANDLERS)
PWN_COMMAND_HANDLERS.update(SESSION_COMMAND_HANDLERS)


def dispatch_command(command: str, args: Dict[str, Any] | None = None) -> Dict[str, Any]:
    key = str(command or "").strip()
    if not key:
        raise ValueError("command is required")
    handler = PWN_COMMAND_HANDLERS.get(key)
    if handler is None:
        raise ValueError("Unknown pwntools command: %s" % key)
    payload = args if isinstance(args, dict) else {}
    return handler(payload)


def list_registered_commands() -> List[str]:
    return sorted(PWN_COMMAND_HANDLERS.keys())

