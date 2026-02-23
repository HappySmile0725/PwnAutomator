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


TEMPLATE_TAG = "MCP_PWNTOOLS_TEMPLATE_V1"
PID_LINE_REGEX = re.compile(r"\[MCP\]\[PID\]\s*([0-9]+)")
MAX_BUFFER_BYTES = 1_000_000

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MCPS_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", ".."))
DEFAULT_PAYLOAD_DIR = os.path.join(THIS_DIR, "challenge")
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


def _sanitize_filename(filename: str) -> str:
    raw = str(filename or "").strip()
    if not raw:
        raise ValueError("filename is required")
    if "/" in raw or "\\" in raw:
        raise ValueError("filename must not include a directory path")
    if raw in (".", ".."):
        raise ValueError("invalid filename")
    if not raw.endswith(".py"):
        raw += ".py"
    return raw


def _is_plain_filename(text: str) -> bool:
    return "/" not in text and "\\" not in text and not os.path.isabs(text)


def _resolve_payload_path(path_or_name: str) -> str:
    text = str(path_or_name or "").strip()
    if not text:
        raise ValueError("payload path is required")
    if _is_plain_filename(text):
        text = os.path.join(DEFAULT_PAYLOAD_DIR, text)
    return os.path.abspath(text)


def render_payload_template(payload_content: str) -> str:
    body = _normalize_payload_body(payload_content)
    return (
        "# %s\n" % TEMPLATE_TAG
        + "from pwn import *\n"
        + "p = process('./chall')\n"
        + "e = ELF('./chall', checksec=False)\n\n"
        + "%s\n\n" % body
        + "p.interactive()\n"
    )


def is_template_payload(text: str) -> bool:
    data = str(text or "")
    return (
        TEMPLATE_TAG in data
        and "from pwn import *" in data
        and "p = process('./chall')" in data
        and "e = ELF('./chall', checksec=False)" in data
        and "p.interactive()" in data
    )


def extract_payload_body(text: str) -> str:
    data = str(text or "")
    prefix = "e = ELF('./chall', checksec=False)"
    suffix = "p.interactive()"
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

    def write_payload(self, payload_content: str, filename: str) -> Dict[str, Any]:
        try:
            os.makedirs(DEFAULT_PAYLOAD_DIR, exist_ok=True)
            safe_name = _sanitize_filename(filename)
            output_path = os.path.abspath(os.path.join(DEFAULT_PAYLOAD_DIR, safe_name))
            script = render_payload_template(payload_content)
            with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(script)
            return _ok(
                path=output_path,
                filename=safe_name,
                template=TEMPLATE_TAG,
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
            os.makedirs(DEFAULT_PAYLOAD_DIR, exist_ok=True)
            entries = []
            for name in sorted(os.listdir(DEFAULT_PAYLOAD_DIR)):
                if not name.endswith(".py"):
                    continue
                full_path = os.path.join(DEFAULT_PAYLOAD_DIR, name)
                entries.append(
                    {
                        "filename": name,
                        "path": os.path.abspath(full_path),
                        "size": os.path.getsize(full_path),
                    }
                )
            return _ok(payloads=entries, directory=os.path.abspath(DEFAULT_PAYLOAD_DIR))
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
                    expected_template=TEMPLATE_TAG,
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


def write_payload(payload_content: str, filename: str) -> Dict[str, Any]:
    return RUNTIME.write_payload(payload_content=payload_content, filename=filename)


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
