from . import GdbHandler, gdb_quote_path, loaded_binary_path
import gdb
import os
import shlex


class ManagementHandler(GdbHandler):
    """Handle bridge liveness and target process lifecycle."""

    @staticmethod
    def _is_binary_loaded(binary_path):
        loaded = loaded_binary_path()
        return bool(loaded and loaded == os.path.realpath(binary_path))

    def _find_session_id_by_binary(self, binary_path):
        for sid, session in self.server.sessions.items():
            if session.get("binary") == binary_path:
                return sid
        return None

    def _apply_launch_options(self, args, binary_path):
        argv = args.get("argv") or []
        if argv:
            quoted_args = " ".join(shlex.quote(str(arg)) for arg in argv)
            gdb.execute("set args " + quoted_args)
        else:
            gdb.execute("set args")

        if args.get("auto_run"):
            run_payload = {"binary": binary_path}
            if args.get("input") is not None:
                run_payload["input"] = args.get("input")
            return self.server.ex.handle_run(run_payload)

        return self.ok()

    def handle_ping(self, args):
        """Return static bridge health information."""
        return self.ok({"alive": True, "mode": "in-process-threaded-pty"})

    def handle_open(self, args):
        """Load a binary, set launch args, and optionally run it."""
        args = args or {}
        binary = args.get("binary")
        
        if not binary:
            return self.err("binary required")

        binary_path = os.path.realpath(binary)
        if not os.path.exists(binary_path):
            return self.err("binary not found: " + binary_path)

        reuse_sid = self._find_session_id_by_binary(binary_path)

        if reuse_sid and self._is_binary_loaded(binary_path):
            launch_result = self._apply_launch_options(args, binary_path)
            if not launch_result.get("ok"):
                return launch_result
            return self.ok({"status": "opened", "session_id": reuse_sid, "reused": True})

        gdb.execute("file " + gdb_quote_path(binary_path))
        launch_result = self._apply_launch_options(args, binary_path)
        if not launch_result.get("ok"):
            return launch_result

        sid = reuse_sid or str(len(self.server.sessions) + 1)
        self.server.sessions[sid] = {"binary": binary_path}

        return self.ok({"status": "opened", "session_id": sid})

    def handle_attach(self, args):
        """Attach GDB to a running process by PID."""
        args = args or {}
        pid = args.get("pid")
        
        if pid is None:
            return self.err("pid required")
        pid_text = str(pid).strip()
        if not pid_text.isdigit():
            return self.err("valid pid required")

        gdb.execute("attach " + pid_text)
        self.server.inferior_running = False
        
        return self.ok({"status": "attached"})

    def handle_list(self, args):
        """Return the current inferior status list."""
        inf = gdb.selected_inferior()
        pid = getattr(inf, "pid", 0) or 0
        running = bool(inf.is_valid() and pid > 0 and self.server.inferior_running)
        
        return self.ok([{
            "id": "1",
            "pid": pid,
            "pid_hex": "0x%x" % pid if pid > 0 else "0x0",
            "status": "running" if running else "stopped"
        }])

    def handle_close(self, args):
        """Terminate the current inferior and clear sessions."""
        inf = gdb.selected_inferior()
        pid = getattr(inf, "pid", 0) or 0
        if pid > 0:
            gdb.execute("kill")

        self.server.sessions.clear()
        self.server.inferior_running = False
        
        return self.ok({"status": "closed"})
