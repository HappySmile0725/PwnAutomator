"""Shared helpers for pwntools MCP handlers."""

from __future__ import annotations

from typing import Any, Dict


def require_arg(args: Dict[str, Any], key: str) -> Any:
    if key not in args:
        raise ValueError("%s is required" % key)
    return args.get(key)


def require_text_arg(args: Dict[str, Any], key: str) -> str:
    value = require_arg(args, key)
    text = str(value if value is not None else "").strip()
    if not text:
        raise ValueError("%s is required" % key)
    return text


def parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    return bool(value)

