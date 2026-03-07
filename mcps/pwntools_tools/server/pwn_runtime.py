#!/usr/bin/env python3
"""Pwntools payload runtime used by MCP wrappers."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


FIXED_PAYLOAD_FILENAME = "hack.py"
TEMPLATE_IMPORT_LINE = "from pwn import *"
TEMPLATE_PROCESS_LINE = "p = process('./chall')"
TEMPLATE_ELF_LINE = "e = ELF('./chall', checksec=False)"
TEMPLATE_INTERACTIVE_LINE = "p.interactive()"
PID_LINE_REGEX = re.compile(r"\[MCP\]\[PID\]\s*([0-9]+)")
MAX_BUFFER_BYTES = 1_000_000

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MCPS_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(MCPS_DIR, ".."))
TEST_DIR = os.path.join(MCPS_DIR, "test")
FIXED_PAYLOAD_PATH = os.path.join(TEST_DIR, FIXED_PAYLOAD_FILENAME)
DEFAULT_BINARY_PATH = os.path.join(MCPS_DIR, "test", "chall")


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


def _is_plain_filename(text: str) -> bool:
    return "/" not in text and "\\" not in text and not os.path.isabs(text)


def _normalize_path_text(text: str) -> str:
    return str(text or "").strip().replace("\\", "/")


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

    raise ValueError("payload path must be mcps/test/hack.py")


def render_payload_template(payload_content: str) -> str:
    body = _normalize_payload_body(payload_content)
    lines = [
        TEMPLATE_IMPORT_LINE,
        TEMPLATE_PROCESS_LINE,
        TEMPLATE_ELF_LINE,
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
        TEMPLATE_PROCESS_LINE,
        TEMPLATE_ELF_LINE,
        TEMPLATE_INTERACTIVE_LINE,
    )
    return all(token in data for token in required)


def extract_payload_body(text: str) -> str:
    data = str(text or "")
    prefix = TEMPLATE_ELF_LINE
    suffix = TEMPLATE_INTERACTIVE_LINE
    start = data.find(prefix)
    end = data.rfind(suffix)
    if start < 0 or end < 0 or end <= start:
        return ""
    body = data[start + len(prefix) : end].strip("\n")
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
            script = render_payload_template(payload_content)
            with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            return _ok(
                path=output_path,
                filename=FIXED_PAYLOAD_FILENAME,
                target_binary_default=os.path.abspath(DEFAULT_BINARY_PATH),
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
        pause_before_payload: bool = False,
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
                        TEMPLATE_PROCESS_LINE,
                        TEMPLATE_ELF_LINE,
                        TEMPLATE_INTERACTIVE_LINE,
                    ],
                )

            target_binary = os.path.abspath(DEFAULT_BINARY_PATH)
            if not os.path.exists(target_binary):
                return _error("target binary does not exist", binary_path=target_binary)

            process, command = self._spawn_process(
                payload_path=payload_path,
                binary_path=target_binary,
                pause_before_payload=bool(pause_before_payload),
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

    def _spawn_process(
        self, payload_path: str, binary_path: str, pause_before_payload: bool
    ) -> tuple[subprocess.Popen, List[str]]:
        env = dict(os.environ)
        _ = pause_before_payload
        python_exec = os.environ.get("PWNTOOLS_PYTHON", sys.executable)
        command = [python_exec, "-u", payload_path]
        process = subprocess.Popen(
            command,
            cwd=os.path.dirname(binary_path),
            env=env,
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


def write_payload(payload_content: str) -> Dict[str, Any]:
    return RUNTIME.write_payload(payload_content=payload_content)


def read_payload(path: str) -> Dict[str, Any]:
    return RUNTIME.read_payload(path=path)


def list_payloads() -> Dict[str, Any]:
    return RUNTIME.list_payloads()


def execute_payload(
    path: str, pause_before_payload: bool = False, wait_ms: int = 300
) -> Dict[str, Any]:
    return RUNTIME.execute_payload(
        path=path,
        pause_before_payload=pause_before_payload,
        wait_ms=wait_ms,
    )


def poll_session(session_id: str) -> Dict[str, Any]:
    return RUNTIME.poll_session(session_id=session_id)


def send_input(session_id: str, data: str, append_newline: bool = False) -> Dict[str, Any]:
    return RUNTIME.send_input(session_id=session_id, data=data, append_newline=append_newline)


def continue_pause(session_id: str) -> Dict[str, Any]:
    return RUNTIME.continue_pause(session_id=session_id)


def stop_session(session_id: str, kill: bool = False) -> Dict[str, Any]:
    return RUNTIME.stop_session(session_id=session_id, kill=kill)


def list_sessions() -> Dict[str, Any]:
    return RUNTIME.list_sessions()
