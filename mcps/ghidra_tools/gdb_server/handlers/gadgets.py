from . import GdbHandler, loaded_binary_path
import os
import subprocess


DEFAULT_LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
DEFAULT_TIMEOUT_MS = 30000
TARGET_CHALL = "chall"
TARGET_LIBC = "libc"
SOURCE_EXPLICIT = "explicit"
SOURCE_CURRENT = "current"
SOURCE_LOCAL = "local"
SOURCE_SYSTEM = "system"
LIBC_SOURCE_CHOICES = (SOURCE_LOCAL, SOURCE_SYSTEM)

HANDLERS_DIR = os.path.dirname(os.path.abspath(__file__))
MCPS_DIR = os.path.normpath(os.path.join(HANDLERS_DIR, "..", "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(MCPS_DIR, ".."))
_CONFIGURED_CHALLENGE_DIR = os.environ.get("PWN_AUTOMATOR_CHALLENGE_DIR") or os.environ.get("PWNTOOLS_MCP_CHALLENGE_DIR")
if _CONFIGURED_CHALLENGE_DIR:
    if os.path.isabs(_CONFIGURED_CHALLENGE_DIR):
        _ACTIVE_CHALLENGE_DIR = os.path.abspath(_CONFIGURED_CHALLENGE_DIR)
    else:
        _ACTIVE_CHALLENGE_DIR = os.path.abspath(os.path.join(PROJECT_ROOT, _CONFIGURED_CHALLENGE_DIR))
else:
    _ACTIVE_CHALLENGE_DIR = os.path.join(MCPS_DIR, "test")
LOCAL_LIBC_DIRS = (_ACTIVE_CHALLENGE_DIR,)


def _normalize_timeout_ms(value, default_value):
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        if parsed > 0:
            return parsed
    return default_value


def _normalize_path(path):
    text = str(path or "").strip()
    if not text:
        return ""
    return os.path.realpath(text)


def _normalize_libc_source(value):
    text = str(value or "").strip().lower()
    if text in LIBC_SOURCE_CHOICES:
        return text
    return ""


def _looks_like_libc(path):
    return "libc" in os.path.basename(str(path or "")).lower()


def _scan_local_libc_dir(directory):
    fallback_path = ""
    if not os.path.isdir(directory):
        return ""

    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.is_file():
                continue

            lower_name = entry.name.lower()
            if lower_name == "libc.so.6":
                return os.path.realpath(entry.path)
            if not fallback_path and "libc" in lower_name and not lower_name.endswith(".py"):
                fallback_path = os.path.realpath(entry.path)

    return fallback_path


def _find_local_libc_path():
    for directory in LOCAL_LIBC_DIRS:
        path = _scan_local_libc_dir(directory)
        if path:
            return path
    return ""


def _run_ropgadget_command(path, timeout_ms):
    command = ["ROPgadget", "--binary", path]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_ms / 1000.0,
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": "failed to start ROPgadget: " + str(exc)}
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", "replace").strip()
        if output:
            return {"ok": False, "error": "ROPgadget timed out | output: " + output}
        return {"ok": False, "error": "ROPgadget timed out"}

    output = completed.stdout.decode("utf-8", "replace")
    if completed.returncode != 0:
        detail = output.strip() or ("ROPgadget failed with exit code %d" % completed.returncode)
        return {"ok": False, "error": detail}

    return {
        "ok": True,
        "command": command,
        "output": output,
        "exit_code": completed.returncode,
    }


class GadgetHandler(GdbHandler):
    """Run ROPgadget against the current chall binary or a libc path."""

    def handle_ropgadget_chall(self, args):
        return self._handle_ropgadget(args or {}, TARGET_CHALL)

    def handle_ropgadget_libc(self, args):
        return self._handle_ropgadget(args or {}, TARGET_LIBC)

    def _handle_ropgadget(self, args, target_kind):
        path, source, error = self._resolve_target_path(args, target_kind)
        if error:
            return self.err(error)

        timeout_ms = _normalize_timeout_ms(args.get("timeout_ms", DEFAULT_TIMEOUT_MS), DEFAULT_TIMEOUT_MS)
        result = _run_ropgadget_command(path, timeout_ms)
        if not result.get("ok"):
            return self.err(result.get("error", "ROPgadget failed"))

        return self.ok({
            "target": target_kind,
            "path": path,
            "source": source,
            "command": result["command"],
            "exit_code": result["exit_code"],
            "output": result["output"],
        })

    def _resolve_target_path(self, args, target_kind):
        if target_kind == TARGET_CHALL:
            return self._resolve_chall_target(args)
        return self._resolve_libc_target(args)

    def _resolve_chall_target(self, args):
        path = _normalize_path(args.get("path") or args.get("binary"))
        if path:
            if _looks_like_libc(path):
                return "", "", "libc path is not allowed for debug.ropgadget.chall"
            if not os.path.exists(path):
                return "", "", "binary not found: " + path
            return path, SOURCE_EXPLICIT, ""

        session_id = str(args.get("session_id", "")).strip()
        if session_id:
            session = self.server.sessions.get(session_id) or {}
            session_binary = _normalize_path(session.get("binary"))
            if session_binary:
                if not os.path.exists(session_binary):
                    return "", "", "binary not found: " + session_binary
                return session_binary, SOURCE_CURRENT, ""

        loaded = _normalize_path(loaded_binary_path())
        if loaded:
            if not os.path.exists(loaded):
                return "", "", "binary not found: " + loaded
            return loaded, SOURCE_CURRENT, ""

        return "", "", "chall path required"

    def _resolve_libc_target(self, args):
        path = _normalize_path(args.get("path"))
        if path:
            if not _looks_like_libc(path):
                return "", "", "libc path required for debug.ropgadget.libc"
            if not os.path.exists(path):
                return "", "", "binary not found: " + path
            return path, SOURCE_EXPLICIT, ""

        source = _normalize_libc_source(args.get("source"))
        if source == SOURCE_LOCAL:
            local_path = _find_local_libc_path()
            if not local_path:
                return "", "", "local libc not found under active challenge workspace"
            return local_path, SOURCE_LOCAL, ""
        if source == SOURCE_SYSTEM:
            path = _normalize_path(DEFAULT_LIBC_PATH)
            if not os.path.exists(path):
                return "", "", "binary not found: " + path
            return path, SOURCE_SYSTEM, ""
        if args.get("source") is not None:
            return "", "", "source must be one of: local, system"

        local_path = _find_local_libc_path()
        if local_path:
            return local_path, SOURCE_LOCAL, ""

        path = _normalize_path(DEFAULT_LIBC_PATH)
        if not os.path.exists(path):
            return "", "", "binary not found: " + path
        return path, SOURCE_SYSTEM, ""
