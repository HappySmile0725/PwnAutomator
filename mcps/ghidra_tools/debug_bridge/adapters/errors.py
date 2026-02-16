#!/usr/bin/env python3
"""Adapter error types."""


class GdbMIError(RuntimeError):
    """Raised when a GDB/MI command fails."""

