#!/usr/bin/env python3
"""High-level GDB session API with Ghidra TraceRMI integration."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

try:
    from .errors import GdbMIError
    from .ghidra_paths import build_ghidra_env
    from .mi_protocol import quote_mi
    from .transport import GdbMITransport
except Exception:
    from errors import GdbMIError  # type: ignore
    from ghidra_paths import build_ghidra_env  # type: ignore
    from mi_protocol import quote_mi  # type: ignore
    from transport import GdbMITransport  # type: ignore


def _quote_single(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


class GdbMISession:
    """A single GDB process controlled via MI + ghidragdb commands."""

    def __init__(
        self,
        gdb_path: str = "gdb",
        gdb_args: Optional[List[str]] = None,
        command_timeout: float = 8.0,
        ghidra_home: Optional[str] = None,
        use_ghidra: bool = True,
        require_ghidra: bool = False,
        trace_rmi_addr: Optional[str] = None,
    ) -> None:
        self.use_ghidra = bool(use_ghidra)
        self.require_ghidra = bool(require_ghidra)
        self.default_trace_rmi_addr = trace_rmi_addr or os.environ.get("GHIDRA_TRACE_RMI_ADDR")
        env = build_ghidra_env(ghidra_home) if self.use_ghidra else dict(os.environ)
        self.transport = GdbMITransport(
            gdb_path=gdb_path,
            gdb_args=gdb_args,
            env=env,
            command_timeout=command_timeout,
        )

    def start(self) -> None:
        self.transport.start()
        self._cmd("-gdb-set pagination off")
        self._cmd("-gdb-set confirm off")
        self._cmd("-enable-pretty-printing", tolerate_error=True)
        if self.use_ghidra:
            self._load_ghidra_agent()

    def close(self) -> None:
        self.transport.close()

    def open_target(
        self,
        binary: str,
        argv: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        trace_rmi_addr: Optional[str] = None,
        trace_start: bool = True,
        trace_sync: bool = True,
        trace_required: bool = False,
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

        trace_ok = self._setup_trace(
            trace_rmi_addr=trace_rmi_addr,
            trace_start=trace_start,
            trace_sync=trace_sync,
            trace_required=trace_required,
        )
        result = self._cmd("-exec-run")
        self.transport.emit_event({"type": "command", "name": "open_target", "trace": trace_ok})
        return result

    def attach_target(
        self,
        pid: int,
        trace_rmi_addr: Optional[str] = None,
        trace_start: bool = True,
        trace_sync: bool = True,
        trace_required: bool = False,
    ) -> Dict[str, Any]:
        self._ensure_alive()
        result = self._cmd("-target-attach %d" % int(pid))
        trace_ok = self._setup_trace(
            trace_rmi_addr=trace_rmi_addr,
            trace_start=trace_start,
            trace_sync=trace_sync,
            trace_required=trace_required,
        )
        if trace_ok and trace_sync:
            self.trace_sync_synth_stopped(tolerate_error=True)
        self.transport.emit_event(
            {"type": "command", "name": "attach_target", "pid": int(pid), "trace": trace_ok}
        )
        return result

    def set_breakpoint(self, location: str) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-break-insert %s" % quote_mi(location))

    def delete_breakpoint(self, breakpoint_id: str) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-break-delete %s" % str(breakpoint_id))

    def list_breakpoints(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-break-list")

    def cont(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-exec-continue")

    def stepi(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-exec-step-instruction")

    def nexti(self) -> Dict[str, Any]:
        self._ensure_alive()
        return self._cmd("-exec-next-instruction")

    def interrupt(self) -> Dict[str, Any]:
        self._ensure_alive()
        try:
            return self._cmd("-exec-interrupt --all")
        except GdbMIError:
            return self._cmd("-exec-interrupt")

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

    # Ghidra trace controls
    def trace_connect(self, address: str) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace connect '%s'" % _quote_single(address))

    def trace_disconnect(self, tolerate_error: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace disconnect", tolerate_error=tolerate_error)

    def trace_start(self) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace start")

    def trace_stop(self, tolerate_error: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace stop", tolerate_error=tolerate_error)

    def trace_sync_enable(self) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace sync-enable")

    def trace_sync_disable(self, tolerate_error: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace sync-disable", tolerate_error=tolerate_error)

    def trace_sync_synth_stopped(self, tolerate_error: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace sync-synth-stopped", tolerate_error=tolerate_error)

    def trace_put_all(self, tolerate_error: bool = False) -> Dict[str, Any]:
        self._ensure_alive()
        self._require_ghidra_enabled()
        return self._console("ghidra trace put-all", tolerate_error=tolerate_error)

    def poll_events(self, max_items: int = 20) -> List[Dict[str, Any]]:
        return self.transport.poll_events(max_items=max_items)

    def ping(self) -> Dict[str, Any]:
        return {"alive": self.transport.is_alive()}

    def _ensure_alive(self) -> None:
        if not self.transport.is_alive():
            raise GdbMIError("GDB process is not alive")

    def _require_ghidra_enabled(self) -> None:
        if not self.use_ghidra:
            raise GdbMIError(
                "ghidragdb is not loaded for this session. "
                "Open with require_ghidra=True and a compatible gdb."
            )

    def _load_ghidra_agent(self) -> None:
        try:
            self._console("python import ghidragdb")
        except Exception as exc:
            self.transport.emit_event(
                {
                    "type": "ghidra",
                    "state": "agent_load_failed",
                    "error": str(exc),
                }
            )
            if self.require_ghidra:
                raise GdbMIError(
                    "Failed to load ghidragdb (TraceRMI agent). "
                    "Check GHIDRA_HOME/PYTHONPATH and Ghidra debug modules."
                ) from exc
            self.use_ghidra = False
            return
        self.transport.emit_event({"type": "ghidra", "state": "agent_loaded"})

    def _setup_trace(
        self,
        trace_rmi_addr: Optional[str],
        trace_start: bool,
        trace_sync: bool,
        trace_required: bool,
    ) -> bool:
        if not self.use_ghidra:
            if trace_required:
                raise GdbMIError(
                    "TraceRMI is required but ghidragdb is not active for this session. "
                    "Use a compatible gdb and set require_ghidra=True."
                )
            return False
        addr = trace_rmi_addr or self.default_trace_rmi_addr
        if not addr:
            if trace_required:
                raise GdbMIError(
                    "TraceRMI address is required but missing. "
                    "Pass trace_rmi_addr or set GHIDRA_TRACE_RMI_ADDR."
                )
            return False

        self.trace_connect(addr)
        if trace_start:
            self.trace_start()
        if trace_sync:
            self.trace_sync_enable()
        return True

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
