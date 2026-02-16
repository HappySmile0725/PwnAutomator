#!/usr/bin/env python3
"""Helpers for GDB/MI wire parsing."""

from __future__ import annotations

import re
from typing import Dict, Optional


RESULT_RE = re.compile(r"^(\d+)\^([a-zA-Z_-]+)(?:,(.*))?$")
ASYNC_RE = re.compile(r"^([*=+])([a-zA-Z_-]+)(?:,(.*))?$")


def quote_mi(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % escaped


def parse_mi_fields(payload: str) -> Dict[str, str]:
    """
    Parse top-level key="value" pairs from MI payload.
    This parser is intentionally shallow, good enough for reason/status fields.
    """
    fields: Dict[str, str] = {}
    i = 0
    n = len(payload)
    while i < n:
        while i < n and payload[i] in ", ":
            i += 1
        if i >= n:
            break

        k_start = i
        while i < n and payload[i] not in "=\n\r":
            if payload[i] == ",":
                break
            i += 1
        if i >= n or payload[i] != "=":
            while i < n and payload[i] != ",":
                i += 1
            continue

        key = payload[k_start:i]
        i += 1
        if i < n and payload[i] == '"':
            i += 1
            val = []
            while i < n:
                ch = payload[i]
                if ch == "\\" and i + 1 < n:
                    val.append(payload[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                val.append(ch)
                i += 1
            fields[key] = "".join(val)
        else:
            v_start = i
            depth = 0
            while i < n:
                ch = payload[i]
                if ch in "[{":
                    depth += 1
                elif ch in "]}":
                    depth = max(0, depth - 1)
                elif ch == "," and depth == 0:
                    break
                i += 1
            fields[key] = payload[v_start:i]

        while i < n and payload[i] != ",":
            i += 1
        if i < n and payload[i] == ",":
            i += 1

    return fields


def parse_result_record(line: str) -> Optional[Dict[str, object]]:
    m = RESULT_RE.match(line)
    if not m:
        return None
    payload = m.group(3) or ""
    return {
        "token": int(m.group(1)),
        "class": m.group(2),
        "payload": payload,
        "fields": parse_mi_fields(payload),
        "raw": line,
    }


def parse_async_record(line: str) -> Optional[Dict[str, object]]:
    m = ASYNC_RE.match(line)
    if not m:
        return None
    payload = m.group(3) or ""
    prefix = m.group(1)
    return {
        "prefix": prefix,
        "type": "exec" if prefix == "*" else "notify",
        "class": m.group(2),
        "payload": payload,
        "fields": parse_mi_fields(payload),
        "raw": line,
    }


def parse_stream_record(line: str) -> Optional[Dict[str, object]]:
    if line and line[0] in "~@&":
        return {"type": "stream", "channel": line[0], "raw": line}
    return None

