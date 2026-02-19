from . import GdbHandler, gdb_quote_path, loaded_binary_path
import gdb
import os
import shlex
import tempfile

GDB_ERROR = getattr(gdb, "error", RuntimeError)


class ExecutionHandler(GdbHandler):
    """Handle run/continue/step control commands."""

    def handle_run(self, args):
        args = args or {}
        ensure_result = self._ensure_executable(args)
        if ensure_result is not None:
            return ensure_result

        self.server.reset_tty()
        tty_target = self.server.tty_target_path() or self.server.tty_slave_path
        if not tty_target:
            return self.err("failed to initialize inferior tty")
        gdb.execute("set inferior-tty " + tty_target)
        run_cmd, tmp_path = self._build_run_command(args.get("input"))
        
        try:
            gdb.execute(run_cmd)
            self.server.inferior_running = True
        except GDB_ERROR as exc:
            self.server.inferior_running = False
            output = self.server.read_tty_output(65536).decode("utf-8", "replace")
            if output:
                return self.err(str(exc) + " | output: " + output.strip())
            return self.err(exc)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return self.ok({"status": "running"})

    def _ensure_executable(self, args):
        binary_path = self._resolve_binary_from_args(args)
        loaded = loaded_binary_path()

        if not binary_path:
            if loaded:
                return None
            return self.err("No executable file specified")

        if not os.path.exists(binary_path):
            return self.err("binary not found: " + binary_path)

        if loaded == binary_path:
            return None

        gdb.execute("file " + gdb_quote_path(binary_path))
        return None

    def _resolve_binary_from_args(self, args):
        binary = args.get("binary")
        if binary:
            return os.path.realpath(str(binary))

        session_id = str(args.get("session_id", "")).strip()
        if not session_id:
            return None

        session = self.server.sessions.get(session_id)
        if not session:
            return None

        session_binary = session.get("binary")
        if not session_binary:
            return None
        return os.path.realpath(str(session_binary))

    def handle_cont(self, args):
        """Continue the inferior asynchronously."""
        return self._run_and_ok("continue &", "running")

    def handle_interrupt(self, args):
        """Interrupt the running inferior."""
        return self._run_and_ok("interrupt", "interrupted")

    def handle_stepi(self, args):
        """Step exactly one machine instruction."""
        return self._run_and_ok("stepi", "stepped")

    def handle_nexti(self, args):
        """Execute next instruction without stepping into calls."""
        return self._run_and_ok("nexti", "stepped")

    def _run_and_ok(self, command, status):
        """Run one gdb command and map success to a status string."""
        gdb.execute(command)
        self.server.inferior_running = (status == "running")
        return self.ok({"status": status})

    def _build_run_command(self, user_input):
        """Build a `run` command and optional temporary stdin file."""

        if not user_input:
            return "run &", None
        
        with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmp:
            tmp.write(str(user_input))
            tmp_path = tmp.name
            
        return "run < " + shlex.quote(tmp_path) + " &", tmp_path
