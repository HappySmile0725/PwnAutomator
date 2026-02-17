#!/usr/bin/env python3
"""High-level GDB session API."""

from __future__ import annotations

import os
import select
import threading
from typing import Any, Dict, List, Optional

try:
    from .errors import GdbMIError
    from .mi_protocol import quote_mi
    from .transport import GdbMITransport
except Exception:
    from errors import GdbMIError  # type: ignore
    from mi_protocol import quote_mi  # type: ignore
    from transport import GdbMITransport  # type: ignore


class GdbMISession:
    """A single GDB process controlled via MI."""

    def __init__(
        self,
        gdb_path: str = "gdb",
        gdb_args: Optional[List[str]] = None,
        command_timeout: float = 8.0,
    ) -> None:
        self.transport = GdbMITransport(
            gdb_path=gdb_path,
            gdb_args=gdb_args,
            env=dict(os.environ),
            command_timeout=command_timeout,
        )
        self._target_started = False
        self._tty_master: Optional[int] = None
        self._tty_slave_path: Optional[str] = None
        self._tty_reader_stop = threading.Event()
        self._tty_reader: Optional[threading.Thread] = None
        self._tty_lock = threading.Lock()

    def start(self) -> None:
        self.transport.start()
        # Async mode is required for reliable -exec-interrupt behavior.
        self._cmd("-gdb-set mi-async on", tolerate_error=True)
        self._cmd("-gdb-set target-async on", tolerate_error=True)
        self._cmd("-gdb-set pagination off")
        self._cmd("-gdb-set confirm off")
        self._cmd("-enable-pretty-printing", tolerate_error=True)

    def close(self) -> None:
        self._close_inferior_tty()
        self.transport.close()

    def open_target(
        self,
        binary: str,
        argv: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        auto_run: bool = False,
    ) -> Dict[str, Any]:
        self._ensure_alive()
        if cwd:
            self._cmd("-environment-cd %s" % quote_mi(cwd))
        if env:
            for key, value in env.items():
                self._cmd(
                    "-gdb-set environment %s=%s"
                    % (quote_mi(str(key)), quote_mi(str(value))),
                    tolerate_error=True,
                )
        self._cmd("-file-exec-and-symbols %s" % quote_mi(binary))
        if argv:
            args = " ".join(quote_mi(str(a)) for a in argv)
            self._cmd("-exec-arguments %s" % args)
        self._setup_inferior_tty()

        if auto_run:
            result = self._cmd("-exec-run")
            self._target_started = True
        else:
            result = {
                "class": "done",
                "payload": "state=\"loaded\"",
                "fields": {"state": "loaded"},
                "raw": "local^done",
            }
        self.transport.emit_event(
            {"type": "command", "name": "open_target", "auto_run": bool(auto_run)}
        )
        return result

    def attach_target(self, pid: int) -> Dict[str, Any]:
        self._ensure_alive()
        result = self._cmd("-target-attach %d" % int(pid))
        self._target_started = True
        self.transport.emit_event(
            {"type": "command", "name": "attach_target", "pid": int(pid)}
        )
        return result

    def set_breakpoint(self, location: str) -> Dict[str, Any]:
        self._ensure_alive()
        cmd = "-break-insert %s" % quote_mi(location)
        try:
            return self._cmd(cmd, timeout=20.0)
        except GdbMIError as first_exc:
            # If target is still running/busy, interrupt once and retry.
            try:
                self.interrupt()
            except Exception:
                pass
            try:
                return self._cmd(cmd, timeout=20.0)
            except GdbMIError as second_exc:
                # Fallback for environments where MI breakpoint insertion stalls intermittently.
                cli = self._console("break %s" % str(location), tolerate_error=True)
                return {
                    "fallback": "console_break",
                    "warning": "%s; %s" % (str(first_exc), str(second_exc)),
                    "result": cli,
                }

    def delete_breakpoint(self, breakpoint_id: str) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-break-delete %s" % str(breakpoint_id))

    def list_breakpoints(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-break-list")

    def cont(self) -> Dict[str, Any]:
        self._ensure_alive()
        if not self._target_started:
            result = self._cmd("-exec-run")
            self._target_started = True
            return result
        return self._cmd("-exec-continue")

    def stepi(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-exec-step-instruction")

    def nexti(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-exec-next-instruction")

    def interrupt(self) -> Dict[str, Any]:
        self._ensure_alive()
        errors = []
        try:
            return self._cmd("-exec-interrupt --all", timeout=20.0)
        except GdbMIError as exc:
            errors.append(str(exc))
        try:
            return self._cmd("-exec-interrupt", timeout=20.0)
        except GdbMIError as exc:
            errors.append(str(exc))

        # Some gdb setups/plugins don't answer MI interrupt reliably.
        # Fall back to SIGINT so callers can continue workflow without hard failure.
        try:
            self.transport.send_interrupt_signal()
            return {
                "interrupted": False,
                "fallback": "sigint",
                "alive": self.transport.is_alive(),
                "warning": "; ".join(errors),
            }
        except Exception as exc:
            raise GdbMIError("; ".join(errors + ["interrupt fallback failed: %s" % str(exc)]))

    def get_registers(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-data-list-register-values x")

    def read_memory(self, addr: str, size: int) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-data-read-memory-bytes %s %d" % (addr, int(size)))

    def backtrace(self, depth: int = 32) -> Dict[str, Any]:
        self._ensure_alive()
        max_depth = max(1, int(depth))
        return self._cmd("-stack-list-frames 0 %d" % (max_depth - 1))

    def poll_events(self, max_items: int = 20) -> List[Dict[str, Any]]:
        return self.transport.poll_events(max_items=max_items)

    def write_stdin(self, data: str, append_newline: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._setup_inferior_tty()
        if self._tty_master is None:
            raise GdbMIError("inferior tty is not available")

        text = str(data or "")
        if append_newline and not text.endswith("\n"):
            text += "\n"
        raw = text.encode("utf-8")
        with self._tty_lock:
            written = os.write(self._tty_master, raw)
        return {"written": int(written)}

    def ping(self) -> Dict[str, Any]:
        return {"alive": self.transport.is_alive()}

    def _ensure_alive(self) -> None:
        if not self.transport.is_alive():
            raise GdbMIError("GDB process is not alive")

    def _setup_inferior_tty(self) -> None:
        if os.name == "nt":
            return
        if self._tty_master is not None:
            return

        master_fd, slave_fd = os.openpty()
        slave_path = os.ttyname(slave_fd)
        self._cmd("-inferior-tty-set %s" % quote_mi(slave_path), tolerate_error=True)
        os.close(slave_fd)

        self._tty_master = master_fd
        self._tty_slave_path = slave_path
        self._tty_reader_stop.clear()
        self._tty_reader = threading.Thread(target=self._inferior_tty_reader_loop, daemon=True)
        self._tty_reader.start()
        self.transport.emit_event({"type": "target_io", "state": "tty_ready", "tty": slave_path})

    def _close_inferior_tty(self) -> None:
        self._tty_reader_stop.set()
        if self._tty_reader is not None and self._tty_reader.is_alive():
            self._tty_reader.join(timeout=0.4)
        self._tty_reader = None

        if self._tty_master is not None:
            try:
                os.close(self._tty_master)
            except Exception:
                pass
        self._tty_master = None
        self._tty_slave_path = None
        self._target_started = False

    def _inferior_tty_reader_loop(self) -> None:
        while not self._tty_reader_stop.is_set():
            if self._tty_master is None:
                break
            try:
                ready, _, _ = select.select([self._tty_master], [], [], 0.2)
            except Exception:
                break
            if not ready:
                continue
            try:
                data = os.read(self._tty_master, 4096)
            except Exception:
                break
            if not data:
                break
            self.transport.emit_event(
                {
                    "type": "target_io",
                    "channel": "stdout",
                    "data": data.decode("utf-8", "replace"),
                }
            )

    def _console(self, command: str, tolerate_error: bool = False) -> Dict[str, Any]:
        return self._cmd(
            "-interpreter-exec console %s" % quote_mi(command),
            tolerate_error=tolerate_error,
        )

    def _cmd(
        self,
        command: str,
        timeout: Optional[float] = None,
        tolerate_error: bool = False,
    ) -> Dict[str, Any]:
        return self.transport.execute(
            command=command,
            timeout=timeout,
            tolerate_error=tolerate_error,
        )
