from . import GdbHandler
import gdb
import errno
import os
import signal
import subprocess


def _to_positive_int(value, default_value):
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        if parsed > 0:
            return parsed
    return default_value


def _to_non_negative_int(value, default_value):
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        if parsed >= 0:
            return parsed
    return default_value


def _normalize_gdb_cmd(cmd_text):
    text = str(cmd_text or "").strip()
    if not text:
        return ""

    first = text.split(None, 1)[0].lower()
    if first == "start":
        # `start` can block on pending-main prompts; `starti` avoids that path.
        return "starti"

    if first in ("run", "r", "continue", "cont", "c") and not text.endswith("&"):
        return text + " &"
    return text


def _extract_shell_cmd(cmd):
    if cmd.startswith("shell "):
        return cmd[6:].strip()
    if cmd.startswith("!"):
        return cmd[1:].strip()
    return None


def _is_background_shell_cmd(shell_cmd):
    return str(shell_cmd).rstrip().endswith("&")


def _kill_process_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        proc.kill()


def _run_shell_command(shell_cmd, timeout_sec):
    background = _is_background_shell_cmd(shell_cmd)
    proc = subprocess.Popen(
        shell_cmd,
        shell=True,
        stdout=subprocess.DEVNULL if background else subprocess.PIPE,
        stderr=subprocess.DEVNULL if background else subprocess.STDOUT,
        start_new_session=True,
    )

    try:
        if background:
            proc.wait(timeout=timeout_sec)
            return {
                "ok": True,
                "output": "",
                "exit_code": proc.returncode,
                "shell": True,
                "background": True,
            }

        out, _ = proc.communicate(timeout=timeout_sec)
        return {
            "ok": True,
            "output": out.decode("utf-8", "replace"),
            "exit_code": proc.returncode,
            "shell": True,
        }
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        if background:
            return {"ok": False, "error": "shell command timed out"}

        try:
            out, _ = proc.communicate(timeout=0.2)
        except subprocess.TimeoutExpired:
            out = b""
        return {
            "ok": False,
            "error": "shell command timed out",
            "output": out.decode("utf-8", "replace"),
        }


class IOHandler(GdbHandler):
    """Handle stdin writes, command passthrough, and event polling."""

    def handle_read_stdout(self, args):
        """Return newly captured stdout/stderr text from inferior PTY."""
        args = args or {}
        max_bytes = _to_positive_int(args.get("max_bytes", 65536), 65536)
        data = self.server.read_tty_output(max_bytes)
        return self.ok({"output": data.decode("utf-8", "replace")})

    def handle_stdin_write(self, args):
        """Write text into the inferior PTY stdin."""
        args = args or {}
        data = str(args.get("data", ""))
        
        if args.get("append_newline"):
            data += "\n"

        inf = gdb.selected_inferior()
        pid = getattr(inf, "pid", 0) or 0
        if pid <= 0 or not inf.is_valid():
            return self.err("No inferior running")

        payload = data.encode("utf-8")
        try:
            written = self.server.write_tty_input(payload)
        except OSError as exc:
            if exc.errno in (errno.ENXIO, errno.EPIPE):
                return self.err("stdin reader not ready (tty)")
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return self.err("stdin write would block")
            return self.err(exc)

        return self.ok({"written": written})

    def handle_cmd(self, args):
        """Execute a raw GDB command and return textual output."""
        args = args or {}
        raw_cmd = args.get("gdb_cmd") or args.get("cmd")
        cmd = _normalize_gdb_cmd(raw_cmd)
        
        if not cmd:
            return self.err("cmd required")

        timeout_ms = _to_non_negative_int(args.get("timeout_ms", 3000), 3000)
        timeout_sec = timeout_ms / 1000.0

        # Capture shell command output explicitly because gdb.execute(..., to_string=True)
        # does not reliably capture `shell` output.
        shell_cmd = _extract_shell_cmd(cmd)
        if shell_cmd is not None:
            result = _run_shell_command(shell_cmd, timeout_sec)
            if not result.get("ok"):
                detail = result.get("error", "shell command failed")
                if result.get("output"):
                    detail = detail + " | output: " + str(result.get("output")).strip()
                return self.err(detail)
            result.pop("ok", None)
            return self.ok(result)

        output = gdb.execute(str(cmd), to_string=True)
        
        return self.ok({"output": output})

    def handle_events_poll(self, args):
        """Drain a bounded number of queued async events."""
        args = args or {}
        max_events = _to_positive_int(args.get("max", 20), 20)

        events = []
        
        with self.server.event_lock:
            while self.server.event_queue and len(events) < max_events:
                events.append(self.server.event_queue.popleft())
                
        return self.ok(events)
