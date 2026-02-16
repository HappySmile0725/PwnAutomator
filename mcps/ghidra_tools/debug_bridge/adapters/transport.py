#!/usr/bin/env python3
"""Low-level GDB/MI process transport."""

from __future__ import annotations

import queue
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

try:
    from .errors import GdbMIError
    from .mi_protocol import parse_async_record, parse_result_record, parse_stream_record
except Exception:
    from errors import GdbMIError  # type: ignore
    from mi_protocol import parse_async_record, parse_result_record, parse_stream_record  # type: ignore


class GdbMITransport:
    """Owns a GDB process and speaks the MI protocol."""

    def __init__(
        self,
        gdb_path: str = "gdb",
        gdb_args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        command_timeout: float = 8.0,
    ) -> None:
        self.gdb_path = gdb_path
        self.gdb_args = list(gdb_args or [])
        self.env = dict(env or {})
        self.command_timeout = command_timeout
        self.proc: Optional[subprocess.Popen[str]] = None
        self._token = 0
        self._pending: Dict[int, queue.Queue[Dict[str, Any]]] = {}
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._reader_stop = threading.Event()
        self._reader: Optional[threading.Thread] = None
        self._events: "queue.Queue[Dict[str, Any]]" = queue.Queue()

    def start(self) -> None:
        if self.proc is not None:
            return

        argv = [self.gdb_path, "--quiet", "--interpreter=mi2"]
        argv.extend(self.gdb_args)
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=self.env or None,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise GdbMIError("Failed to start gdb: %s" % str(exc)) from exc
        self._reader_stop.clear()
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()
        self.emit_event({"type": "session", "state": "started"})

    def close(self) -> None:
        if self.proc is None:
            return

        try:
            self.execute("-gdb-exit", timeout=1.5, tolerate_error=True)
        except Exception:
            pass

        self._reader_stop.set()
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=2.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None
        self.emit_event({"type": "session", "state": "closed"})

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def poll_events(self, max_items: int = 20) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        limit = max(1, int(max_items))
        while len(items) < limit:
            try:
                items.append(self._events.get_nowait())
            except queue.Empty:
                break
        return items

    def emit_event(self, event: Dict[str, Any]) -> None:
        event["ts"] = time.time()
        self._events.put(event)

    def execute(
        self,
        command: str,
        timeout: Optional[float] = None,
        tolerate_error: bool = False,
    ) -> Dict[str, Any]:
        self._ensure_alive()
        assert self.proc is not None
        assert self.proc.stdin is not None

        token = self._next_token()
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[token] = q

        wire = "%d%s\n" % (token, command)
        with self._write_lock:
            self.proc.stdin.write(wire)
            self.proc.stdin.flush()

        wait_for = self.command_timeout if timeout is None else timeout
        try:
            result = q.get(timeout=wait_for)
        except queue.Empty as exc:
            with self._pending_lock:
                self._pending.pop(token, None)
            raise GdbMIError("Timeout waiting for GDB response: %s" % command) from exc

        klass = result.get("class")
        if klass == "error" and not tolerate_error:
            msg = result.get("fields", {}).get("msg") or result.get("payload") or "gdb error"
            raise GdbMIError(str(msg))
        return result

    def _ensure_alive(self) -> None:
        if self.proc is None:
            raise GdbMIError("GDB session is not started")
        if self.proc.poll() is not None:
            raise GdbMIError("GDB process is not alive")

    def _next_token(self) -> int:
        with self._pending_lock:
            self._token += 1
            return self._token

    def _reader_loop(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        while not self._reader_stop.is_set():
            line = self.proc.stdout.readline()
            if line == "":
                break
            line = line.strip()
            if not line or line == "(gdb)":
                continue
            self._handle_mi_line(line)

        self.emit_event({"type": "session", "state": "terminated"})
        with self._pending_lock:
            for _, q in list(self._pending.items()):
                try:
                    q.put_nowait({"class": "error", "payload": "session terminated", "fields": {}})
                except Exception:
                    pass
            self._pending.clear()

    def _handle_mi_line(self, line: str) -> None:
        result = parse_result_record(line)
        if result is not None:
            token = int(result["token"])
            response = {
                "class": result["class"],
                "payload": result["payload"],
                "fields": result["fields"],
                "raw": result["raw"],
            }
            with self._pending_lock:
                q = self._pending.pop(token, None)
            if q is not None:
                q.put(response)
            return

        async_rec = parse_async_record(line)
        if async_rec is not None:
            self.emit_event(
                {
                    "type": async_rec["type"],
                    "class": async_rec["class"],
                    "fields": async_rec["fields"],
                    "raw": async_rec["raw"],
                }
            )
            return

        stream_rec = parse_stream_record(line)
        if stream_rec is not None:
            self.emit_event(stream_rec)
            return

        self.emit_event({"type": "misc", "raw": line})
