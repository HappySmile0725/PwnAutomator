#!/usr/bin/env python3
"""Backward-compatible facade for the GDB/MI adapter."""

from __future__ import annotations

try:
    from .errors import GdbMIError
    from .session import GdbMISession
except Exception:
    import os
    import sys

    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if THIS_DIR not in sys.path:
        sys.path.insert(0, THIS_DIR)
    from errors import GdbMIError  # type: ignore
    from session import GdbMISession  # type: ignore

__all__ = ["GdbMIError", "GdbMISession"]
