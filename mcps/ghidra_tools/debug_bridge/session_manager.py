#!/usr/bin/env python3
"""Session manager for debug bridge."""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Dict

try:
    from .adapters.gdb_mi_adapter import GdbMISession
except Exception:
    from adapters.gdb_mi_adapter import GdbMISession


class SessionManager:
    """Holds debugger sessions and dispatches debug commands."""

    def __init__(self) -> None:
        self._sessions: Dict[str, GdbMISession] = {}
        self._lock = threading.RLock()

    def dispatch(self, cmd: str, args: Dict[str, Any]) -> Dict[str, Any]:
        args = args or {}
        if cmd == "bridge.ping":
            return {"alive": True, "sessions": self.list_sessions()}
        if cmd == "debug.open":
            return self.open_session(args)
        if cmd == "debug.attach":
            return self.attach_session(args)
        if cmd == "debug.close":
            return self.close_session(args)
        if cmd == "debug.break.set":
            sess = self._require(args)
            return sess.set_breakpoint(str(args.get("location")))
        if cmd == "debug.break.del":
            sess = self._require(args)
            return sess.delete_breakpoint(str(args.get("breakpoint")))
        if cmd == "debug.break.list":
            sess = self._require(args)
            return sess.list_breakpoints()
        if cmd == "debug.cont":
            sess = self._require(args)
            return sess.cont()
        if cmd == "debug.stepi":
            sess = self._require(args)
            return sess.stepi()
        if cmd == "debug.nexti":
            sess = self._require(args)
            return sess.nexti()
        if cmd == "debug.interrupt":
            sess = self._require(args)
            return sess.interrupt()
        if cmd == "debug.regs":
            sess = self._require(args)
            return sess.get_registers()
        if cmd == "debug.mem":
            sess = self._require(args)
            addr = args.get("addr")
            size = int(args.get("size", 64))
            return sess.read_memory(str(addr), size)
        if cmd == "debug.bt":
            sess = self._require(args)
            depth = int(args.get("depth", 32))
            return sess.backtrace(depth)
        if cmd == "debug.trace.connect":
            sess = self._require(args)
            addr = args.get("trace_rmi_addr") or args.get("address")
            if not addr:
                raise ValueError("trace_rmi_addr is required")
            return sess.trace_connect(str(addr))
        if cmd == "debug.trace.disconnect":
            sess = self._require(args)
            return sess.trace_disconnect(tolerate_error=self._to_bool(args.get("tolerate_error"), False))
        if cmd == "debug.trace.start":
            sess = self._require(args)
            return sess.trace_start()
        if cmd == "debug.trace.stop":
            sess = self._require(args)
            return sess.trace_stop(tolerate_error=self._to_bool(args.get("tolerate_error"), False))
        if cmd == "debug.trace.sync_enable":
            sess = self._require(args)
            return sess.trace_sync_enable()
        if cmd == "debug.trace.sync_disable":
            sess = self._require(args)
            return sess.trace_sync_disable(tolerate_error=self._to_bool(args.get("tolerate_error"), False))
        if cmd == "debug.trace.sync_synth_stopped":
            sess = self._require(args)
            return sess.trace_sync_synth_stopped(
                tolerate_error=self._to_bool(args.get("tolerate_error"), False)
            )
        if cmd == "debug.trace.put_all":
            sess = self._require(args)
            return sess.trace_put_all(tolerate_error=self._to_bool(args.get("tolerate_error"), False))
        if cmd == "debug.events.poll":
            sess = self._require(args)
            max_items = int(args.get("max", 20))
            return {"events": sess.poll_events(max_items=max_items)}
        if cmd == "debug.status":
            sess = self._require(args)
            return sess.ping()
        if cmd == "debug.list":
            return {"sessions": self.list_sessions()}
        raise ValueError("Unknown bridge command: %s" % cmd)

    def list_sessions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            out: Dict[str, Dict[str, Any]] = {}
            for sid, sess in self._sessions.items():
                out[sid] = sess.ping()
            return out

    def open_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        binary = args.get("binary")
        if not binary:
            raise ValueError("binary is required")
        argv = args.get("argv") or []
        cwd = args.get("cwd")
        env = args.get("env")
        gdb_path = args.get("gdb_path") or "gdb"
        gdb_args = args.get("gdb_args") or []
        ghidra_home = args.get("ghidra_home")
        use_ghidra = self._to_bool(args.get("use_ghidra"), True)
        trace_rmi_addr = args.get("trace_rmi_addr") or os.environ.get("GHIDRA_TRACE_RMI_ADDR")
        trace_start = self._to_bool(args.get("trace_start"), True)
        trace_sync = self._to_bool(args.get("trace_sync"), True)
        trace_required = self._to_bool(args.get("trace_required"), False)
        require_ghidra = self._to_bool(args.get("require_ghidra"), trace_required)
        sess = GdbMISession(
            gdb_path=gdb_path,
            gdb_args=gdb_args,
            ghidra_home=ghidra_home,
            use_ghidra=use_ghidra,
            require_ghidra=require_ghidra,
            trace_rmi_addr=trace_rmi_addr,
        )
        try:
            sess.start()
            res = sess.open_target(
                binary=binary,
                argv=argv,
                cwd=cwd,
                env=env,
                trace_rmi_addr=trace_rmi_addr,
                trace_start=trace_start,
                trace_sync=trace_sync,
                trace_required=trace_required,
            )
        except Exception:
            try:
                sess.close()
            except Exception:
                pass
            raise
        sid = self._new_session_id()
        with self._lock:
            self._sessions[sid] = sess
        return {"session_id": sid, "result": res}

    def attach_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        pid = args.get("pid")
        if pid is None:
            raise ValueError("pid is required")
        gdb_path = args.get("gdb_path") or "gdb"
        gdb_args = args.get("gdb_args") or []
        ghidra_home = args.get("ghidra_home")
        use_ghidra = self._to_bool(args.get("use_ghidra"), True)
        trace_rmi_addr = args.get("trace_rmi_addr") or os.environ.get("GHIDRA_TRACE_RMI_ADDR")
        trace_start = self._to_bool(args.get("trace_start"), True)
        trace_sync = self._to_bool(args.get("trace_sync"), True)
        trace_required = self._to_bool(args.get("trace_required"), False)
        require_ghidra = self._to_bool(args.get("require_ghidra"), trace_required)
        sess = GdbMISession(
            gdb_path=gdb_path,
            gdb_args=gdb_args,
            ghidra_home=ghidra_home,
            use_ghidra=use_ghidra,
            require_ghidra=require_ghidra,
            trace_rmi_addr=trace_rmi_addr,
        )
        try:
            sess.start()
            res = sess.attach_target(
                int(pid),
                trace_rmi_addr=trace_rmi_addr,
                trace_start=trace_start,
                trace_sync=trace_sync,
                trace_required=trace_required,
            )
        except Exception:
            try:
                sess.close()
            except Exception:
                pass
            raise
        sid = self._new_session_id()
        with self._lock:
            self._sessions[sid] = sess
        return {"session_id": sid, "result": res}

    def close_session(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sid = args.get("session_id")
        if not sid:
            raise ValueError("session_id is required")
        with self._lock:
            sess = self._sessions.pop(str(sid), None)
        if sess is None:
            raise ValueError("Unknown session_id: %s" % sid)
        sess.close()
        return {"closed": True, "session_id": str(sid)}

    def shutdown(self) -> None:
        with self._lock:
            sessions = list(self._sessions.items())
            self._sessions.clear()
        for _, sess in sessions:
            try:
                sess.close()
            except Exception:
                pass

    def _require(self, args: Dict[str, Any]) -> GdbMISession:
        sid = args.get("session_id")
        if not sid:
            raise ValueError("session_id is required")
        with self._lock:
            sess = self._sessions.get(str(sid))
        if sess is None:
            raise ValueError("Unknown session_id: %s" % sid)
        return sess

    @staticmethod
    def _new_session_id() -> str:
        return uuid.uuid4().hex[:12]

    @staticmethod
    def _to_bool(value: Any, default: bool) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "y", "on"):
            return True
        if text in ("0", "false", "no", "n", "off"):
            return False
        return default
