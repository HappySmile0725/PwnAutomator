#!/usr/bin/env python3
"""Pwntools payload runtime used by MCP wrappers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


FIXED_PAYLOAD_FILENAME = "hack.py"
TEMPLATE_IMPORT_LINE = "from pwn import *"
TEMPLATE_INTERACTIVE_LINE = "p.interactive()"
LIBC_FILENAME = "libc.so.6"
LIBC_NAME_REGEX = re.compile(r"^libc(?:[-_.A-Za-z0-9]*)?\.so(?:\.\d+)*$", re.I)
PID_LINE_REGEX = re.compile(r"\[MCP\]\[PID\]\s*([0-9]+)")
MAX_BUFFER_BYTES = 1_000_000

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MCPS_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(MCPS_DIR, ".."))


def _resolve_challenge_dir() -> str:
    configured = os.environ.get("PWN_AUTOMATOR_CHALLENGE_DIR")
    if configured:
        if os.path.isabs(configured):
            return os.path.abspath(configured)
        return os.path.abspath(os.path.join(PROJECT_ROOT, configured))
    return os.path.join(MCPS_DIR, "test")


TEST_DIR = _resolve_challenge_dir()
FIXED_PAYLOAD_PATH = os.path.join(TEST_DIR, FIXED_PAYLOAD_FILENAME)
DEFAULT_BINARY_NAME = os.environ.get("PWN_AUTOMATOR_BINARY_NAME", "chall")
DEFAULT_BINARY_PATH = os.path.join(TEST_DIR, DEFAULT_BINARY_NAME)


def _remote_host() -> str:
    return os.environ.get("PWN_AUTOMATOR_REMOTE_HOST", "").strip()


def _remote_port() -> int:
    try:
        return int(os.environ.get("PWN_AUTOMATOR_REMOTE_PORT", "0"))
    except ValueError:
        return 0


def _remote_enabled() -> bool:
    return bool(_remote_host() and _remote_port() > 0)


def _ok(**kwargs: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "success"}
    payload.update(kwargs)
    return payload


def _error(message: str, **kwargs: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "error", "message": str(message)}
    payload.update(kwargs)
    return payload


def _normalize_wait_ms(value: Any, default_ms: int = 300) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default_ms
    return max(0, parsed)


def _normalize_payload_body(payload_content: str) -> str:
    content = str(payload_content or "")
    if not content.strip():
        return "pass"
    return content.rstrip()


def _payload_policy_issues(payload_content: str) -> List[str]:
    body = _normalize_payload_body(payload_content)
    issues: List[str] = []
    if "/workspace/" in body:
        issues.append("do not hardcode /workspace paths; use the wrapper-provided e object or ./<active binary>")
    if re.search(r"\b(?:remote|process)\s*\(", body):
        issues.append("do not create tubes; use the wrapper-provided remote p tube")
    if re.search(r"\.interactive\s*\(|\.close\s*\(", body):
        issues.append("do not manage wrapper tube lifetime")
    if re.search(r"(?m)^\s*def\s+exploit\s*\(", body):
        without_definition = re.sub(r"(?m)^\s*def\s+exploit\s*\([^\n]*\):\s*$", "", body)
        if not re.search(r"(?m)^\s*exploit\s*\(", without_definition):
            issues.append("defined exploit(...) but never called it; call exploit(p) at top level")
    return issues


def _is_plain_filename(text: str) -> bool:
    return "/" not in text and "\\" not in text and not os.path.isabs(text)


def _normalize_path_text(text: str) -> str:
    return str(text or "").strip().replace("\\", "/")


def _default_binary_path() -> str:
    configured = os.environ.get("PWN_AUTOMATOR_BINARY_PATH")
    if configured:
        return os.path.abspath(configured)

    marker_path = os.path.join(TEST_DIR, ".pwnautomator", "current_binary")
    try:
        with open(marker_path, "r", encoding="utf-8") as handle:
            marked = handle.read().strip()
        if marked:
            return os.path.abspath(marked)
    except OSError:
        pass

    return os.path.abspath(DEFAULT_BINARY_PATH)


def _payload_cwd(binary_path: str) -> str:
    return os.path.dirname(os.path.abspath(binary_path)) or TEST_DIR


def _find_challenge_libc(binary_path: str) -> str:
    configured = os.environ.get("PWN_AUTOMATOR_LIBC_PATH")
    if configured and os.path.isfile(configured):
        return os.path.abspath(configured)

    binary_dir = _payload_cwd(binary_path)
    direct = os.path.join(binary_dir, LIBC_FILENAME)
    if os.path.isfile(direct):
        return direct

    for root, dirs, files in os.walk(TEST_DIR):
        dirs[:] = [name for name in dirs if name not in {".git", "__MACOSX", "node_modules", ".pwnautomator", "solution"}]
        for name in files:
            if LIBC_NAME_REGEX.match(name):
                return os.path.join(root, name)
    return ""


def _ensure_payload_libc(binary_path: str) -> str:
    source = _find_challenge_libc(binary_path)
    if not source:
        return ""
    target = os.path.join(_payload_cwd(binary_path), LIBC_FILENAME)
    if os.path.normcase(os.path.abspath(source)) != os.path.normcase(os.path.abspath(target)):
        shutil.copy2(source, target)
    return target


def _resolve_payload_path(path_or_name: str) -> str:
    text = str(path_or_name or "").strip()
    expected_path = os.path.abspath(FIXED_PAYLOAD_PATH)
    if not text:
        return expected_path

    if _is_plain_filename(text):
        if text != FIXED_PAYLOAD_FILENAME:
            raise ValueError("payload filename must be hack.py")
        return expected_path

    normalized = _normalize_path_text(text).lstrip("./")
    valid_relative = {
        FIXED_PAYLOAD_FILENAME,
        "test/" + FIXED_PAYLOAD_FILENAME,
        "mcps/test/" + FIXED_PAYLOAD_FILENAME,
    }
    if normalized in valid_relative:
        return expected_path

    candidate_paths = (
        os.path.abspath(text),
        os.path.abspath(os.path.join(MCPS_DIR, text)),
        os.path.abspath(os.path.join(PROJECT_ROOT, text)),
    )
    for candidate in candidate_paths:
        if os.path.normcase(candidate) == os.path.normcase(expected_path):
            return expected_path

    raise ValueError("payload path must be the active challenge workspace hack.py")


def render_payload_template(payload_content: str, binary_path: str | None = None) -> str:
    body = _normalize_payload_body(payload_content)
    binary_name = os.path.basename(binary_path or _default_binary_path()) or DEFAULT_BINARY_NAME
    if _remote_enabled():
        tube_line = (
            "p = remote(os.environ['PWN_AUTOMATOR_REMOTE_HOST'], "
            "int(os.environ['PWN_AUTOMATOR_REMOTE_PORT']))"
        )
    else:
        tube_line = "p = process('./%s')" % binary_name
    lines = [
        TEMPLATE_IMPORT_LINE,
        "import os",
        tube_line,
        "e = ELF('./%s', checksec=False)" % binary_name,
        "libc = ELF('./%s', checksec=False) if os.path.exists('./%s') else e.libc" % (LIBC_FILENAME, LIBC_FILENAME),
        "",
        body,
        "",
        TEMPLATE_INTERACTIVE_LINE,
    ]
    return "\n".join(lines) + "\n"


def is_template_payload(text: str) -> bool:
    data = str(text or "")
    required = (
        TEMPLATE_IMPORT_LINE,
        TEMPLATE_INTERACTIVE_LINE,
    )
    has_tube = "process('./" in data or "remote(os.environ['PWN_AUTOMATOR_REMOTE_HOST']" in data
    return all(token in data for token in required) and has_tube and "ELF('./" in data


def extract_payload_body(text: str) -> str:
    data = str(text or "")
    suffix = TEMPLATE_INTERACTIVE_LINE
    start = -1
    offset = 0
    for line in data.splitlines():
        offset += len(line) + 1
        if line.startswith("libc = "):
            start = offset
            break
        if line.startswith("e = ELF("):
            start = offset
    end = data.rfind(suffix)
    if start < 0 or end < 0 or end <= start:
        return ""
    body = data[start:end].strip("\n")
    return body.strip()


@dataclass
class PayloadSession:
    session_id: str
    payload_path: str
    binary_path: str
    command: List[str]
    process: subprocess.Popen
    created_at: float = field(default_factory=time.time)
    stdout_pending: str = ""
    stderr_pending: str = ""
    attach_pid: Optional[int] = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class PwntoolsRuntime:
    def __init__(self) -> None:
        self._sessions: Dict[str, PayloadSession] = {}
        self._sessions_lock = threading.Lock()

    def write_payload(self, payload_content: str) -> Dict[str, Any]:
        try:
            os.makedirs(TEST_DIR, exist_ok=True)
            output_path = os.path.abspath(FIXED_PAYLOAD_PATH)
            target_binary = _default_binary_path()
            policy_issues = _payload_policy_issues(payload_content)
            if policy_issues:
                return _error("payload policy violation", issues=policy_issues)
            libc_path = _ensure_payload_libc(target_binary)
            script = render_payload_template(payload_content, binary_path=target_binary)
            with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            return _ok(
                path=output_path,
                filename=FIXED_PAYLOAD_FILENAME,
                target_binary_default=target_binary,
                libc_path=libc_path,
            )
        except Exception as exc:
            return _error(str(exc))

    def read_payload(self, path: str) -> Dict[str, Any]:
        try:
            abs_path = _resolve_payload_path(path)
            if not os.path.exists(abs_path):
                return _error("payload file does not exist", path=abs_path)
            with open(abs_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            return _ok(
                path=abs_path,
                is_template=is_template_payload(content),
                payload_body=extract_payload_body(content),
                content=content,
            )
        except Exception as exc:
            return _error(str(exc))

    def list_payloads(self) -> Dict[str, Any]:
        try:
            os.makedirs(TEST_DIR, exist_ok=True)
            entries = []
            if os.path.exists(FIXED_PAYLOAD_PATH):
                entries.append(
                    {
                        "filename": FIXED_PAYLOAD_FILENAME,
                        "path": os.path.abspath(FIXED_PAYLOAD_PATH),
                        "size": os.path.getsize(FIXED_PAYLOAD_PATH),
                    }
                )
            return _ok(payloads=entries, directory=os.path.abspath(TEST_DIR))
        except Exception as exc:
            return _error(str(exc))

    def execute_payload(
        self,
        path: str,
        wait_ms: int = 300,
    ) -> Dict[str, Any]:
        try:
            payload_path = _resolve_payload_path(path)
            if not os.path.exists(payload_path):
                return _error("payload file does not exist", path=payload_path)

            with open(payload_path, "r", encoding="utf-8") as handle:
                payload_text = handle.read()
            if not is_template_payload(payload_text):
                return _error(
                    "payload format mismatch: use pwn_payload_write template",
                    path=payload_path,
                    expected_lines=[
                        TEMPLATE_IMPORT_LINE,
                        "import os",
                        "p = remote(<published docker host>, <published docker port>)",
                        "e = ELF('./<active binary>', checksec=False)",
                        "libc = ELF('./libc.so.6', checksec=False) if available, else e.libc",
                        TEMPLATE_INTERACTIVE_LINE,
                    ],
                )

            target_binary = _default_binary_path()
            if not os.path.exists(target_binary):
                return _error("target binary does not exist", binary_path=target_binary)

            process, command = self._spawn_process(
                payload_path=payload_path,
                binary_path=target_binary,
            )

            session_id = uuid.uuid4().hex[:12]
            session = PayloadSession(
                session_id=session_id,
                payload_path=payload_path,
                binary_path=target_binary,
                command=command,
                process=process,
            )
            self._start_reader_thread(session, stream_name="stdout")
            self._start_reader_thread(session, stream_name="stderr")
            with self._sessions_lock:
                self._sessions[session_id] = session

            delay = _normalize_wait_ms(wait_ms, default_ms=300)
            if delay > 0:
                time.sleep(delay / 1000.0)
            polled = self.poll_session(session_id)

            return _ok(
                session_id=session_id,
                payload_path=payload_path,
                binary_path=target_binary,
                command=command,
                runner_pid=process.pid,
                attach_pid=polled.get("attach_pid"),
                running=polled.get("running"),
                returncode=polled.get("returncode"),
                stdout=polled.get("stdout"),
                stderr=polled.get("stderr"),
            )
        except Exception as exc:
            return _error(str(exc))

    def poll_session(self, session_id: str) -> Dict[str, Any]:
        try:
            session = self._get_session(session_id)
            returncode = session.process.poll()
            with session.lock:
                stdout_new = session.stdout_pending
                stderr_new = session.stderr_pending
                session.stdout_pending = ""
                session.stderr_pending = ""
                attach_pid = session.attach_pid
            return _ok(
                session_id=session.session_id,
                running=returncode is None,
                returncode=returncode,
                attach_pid=attach_pid,
                runner_pid=session.process.pid,
                stdout=stdout_new,
                stderr=stderr_new,
            )
        except Exception as exc:
            return _error(str(exc))

    def send_input(self, session_id: str, data: str, append_newline: bool = False) -> Dict[str, Any]:
        try:
            session = self._get_session(session_id)
            if session.process.poll() is not None:
                return _error("session is not running", session_id=session_id)
            text = str(data or "")
            if append_newline:
                text += "\n"
            payload = text.encode("utf-8")
            if session.process.stdin is None:
                return _error("stdin is not available", session_id=session_id)
            session.process.stdin.write(payload)
            session.process.stdin.flush()
            return _ok(session_id=session_id, bytes_sent=len(payload))
        except Exception as exc:
            return _error(str(exc))

    def continue_pause(self, session_id: str) -> Dict[str, Any]:
        return self.send_input(session_id=session_id, data="", append_newline=True)

    def stop_session(self, session_id: str, kill: bool = False) -> Dict[str, Any]:
        try:
            session = self._get_session(session_id)
            proc = session.process
            if proc.poll() is None:
                if kill:
                    proc.kill()
                else:
                    proc.terminate()
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2.0)
            final_state = self.poll_session(session_id)
            with self._sessions_lock:
                self._sessions.pop(session_id, None)
            return _ok(
                session_id=session_id,
                returncode=proc.poll(),
                stdout=final_state.get("stdout", ""),
                stderr=final_state.get("stderr", ""),
            )
        except Exception as exc:
            return _error(str(exc))

    def list_sessions(self) -> Dict[str, Any]:
        try:
            with self._sessions_lock:
                sessions = list(self._sessions.values())
            result = []
            for session in sessions:
                returncode = session.process.poll()
                result.append(
                    {
                        "session_id": session.session_id,
                        "running": returncode is None,
                        "returncode": returncode,
                        "attach_pid": session.attach_pid,
                        "runner_pid": session.process.pid,
                        "payload_path": session.payload_path,
                        "binary_path": session.binary_path,
                        "created_at": session.created_at,
                    }
                )
            return _ok(sessions=result)
        except Exception as exc:
            return _error(str(exc))

    def _get_session(self, session_id: str) -> PayloadSession:
        key = str(session_id or "").strip()
        if not key:
            raise ValueError("session_id is required")
        with self._sessions_lock:
            session = self._sessions.get(key)
        if session is None:
            raise ValueError("unknown session_id: %s" % key)
        return session

    def _spawn_process(self, payload_path: str, binary_path: str) -> tuple[subprocess.Popen, List[str]]:
        python_exec = os.environ.get("PWNTOOLS_PYTHON", sys.executable)
        command = [python_exec, "-u", payload_path]
        process = subprocess.Popen(
            command,
            cwd=os.path.dirname(binary_path),
            env=os.environ,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        return process, command

    def _start_reader_thread(self, session: PayloadSession, stream_name: str) -> None:
        if stream_name == "stdout":
            stream = session.process.stdout
        elif stream_name == "stderr":
            stream = session.process.stderr
        else:
            raise ValueError("invalid stream_name: %s" % stream_name)
        if stream is None:
            return

        def _reader() -> None:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                with session.lock:
                    if stream_name == "stdout":
                        session.stdout_pending += text
                        if len(session.stdout_pending) > MAX_BUFFER_BYTES:
                            session.stdout_pending = session.stdout_pending[-MAX_BUFFER_BYTES:]
                    else:
                        session.stderr_pending += text
                        if len(session.stderr_pending) > MAX_BUFFER_BYTES:
                            session.stderr_pending = session.stderr_pending[-MAX_BUFFER_BYTES:]
                    if session.attach_pid is None:
                        match = PID_LINE_REGEX.search(text)
                        if match:
                            try:
                                session.attach_pid = int(match.group(1))
                            except ValueError:
                                session.attach_pid = None

        thread = threading.Thread(target=_reader, daemon=True)
        thread.start()


RUNTIME = PwntoolsRuntime()
