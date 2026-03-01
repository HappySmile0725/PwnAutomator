# -*- coding: utf-8 -*-
import os
import json
import socket
import subprocess
import time
import signal
import re
import jarray
from ghidra.app.decompiler import DecompInterface

try:
    INTEGER_TYPES = (int, long)
except NameError:
    INTEGER_TYPES = (int,)

HEX_CHARS = set("0123456789abcdefABCDEF")
WINDOWS_DRIVE_LETTERS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class GhidraContext(object):
    program = None
    fm = None
    mem = None
    listing = None
    addr_factory = None
    decomp = None
    bridge_client = None
    
    @staticmethod
    def init(program):
        GhidraContext.program = program
        GhidraContext.fm = program.getFunctionManager()
        GhidraContext.mem = program.getMemory()
        GhidraContext.listing = program.getListing()
        GhidraContext.addr_factory = program.getAddressFactory()
        # Decompiler setup is lazy. openProgram() may block during startup.
        GhidraContext.decomp = None
        
        # Debug Bridge setup
        GhidraContext.bridge_client = DebugBridgeClient()

    @staticmethod
    def ensure_decomp():
        if GhidraContext.decomp is None:
            decomp = DecompInterface()
            decomp.openProgram(GhidraContext.program)
            GhidraContext.decomp = decomp
        return GhidraContext.decomp

    @staticmethod
    def bridge_call(cmd, args):
        if not GhidraContext.bridge_client:
            return {"ok": False, "error": "Bridge client not initialized"}
        return GhidraContext.bridge_client.call(cmd, args)

    @staticmethod
    def addr(addr_str):
        space = GhidraContext.addr_factory.getDefaultAddressSpace()

        if addr_str is None:
            raise ValueError("address required")

        if isinstance(addr_str, INTEGER_TYPES):
            return space.getAddress(int(addr_str))

        text = str(addr_str).strip()
        if not text:
            raise ValueError("address required")

        # Prefer Ghidra native parser first to support plain hex like "401000".
        addr = GhidraContext.addr_factory.getAddress(text)
        if addr is not None:
            return addr

        if text.startswith("0x") and _is_hex_text(text[2:]):
            return space.getAddress(int(text, 16))

        if _is_hex_text(text):
            return space.getAddress(int(text, 16))

        if text.isdigit():
            return space.getAddress(int(text, 10))

        raise ValueError("invalid address: %s" % text)

    @staticmethod
    def read_bytes(addr, size):
        # Ghidra getBytes returns signed byte array
        buf = jarray.zeros(size, "b")
        GhidraContext.mem.getBytes(addr, buf)
        # Convert to unsigned python list/bytes
        return [(b & 0xff) for b in buf]


def _normalize_connect_host(host):
    text = str(host or "").strip()
    if text == "" or text == "0.0.0.0":
        return "127.0.0.1"
    return text


def _is_hex_text(text):
    if not text:
        return False
    for ch in text:
        if ch not in HEX_CHARS:
            return False
    return True


def _parse_port(value, default_port):
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return default_port


def _normalize_path_text(path):
    return str(path or "").strip().replace("\\", "/")


def _to_wsl_path(path):
    text = _normalize_path_text(path)
    if len(text) >= 3 and text[1] == ":" and text[0] in WINDOWS_DRIVE_LETTERS:
        drive = text[0].lower()
        tail = text[2:].lstrip("/")
        if tail:
            return "/mnt/%s/%s" % (drive, tail)
        return "/mnt/%s" % drive
    return text


def _candidate_paths(path):
    text = _to_wsl_path(path)
    if not text:
        return []

    base = os.path.basename(text)
    cwd = os.getcwd()
    project_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    candidates = [text, os.path.abspath(text), os.path.realpath(text)]
    if base:
        candidates.extend([
            os.path.join(cwd, base),
            os.path.join(cwd, "test", base),
            os.path.join(project_root, "test", base),
        ])

    ordered = []
    seen = set()
    for cand in candidates:
        norm = os.path.normpath(cand)
        if norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)
    return ordered


def find_existing_path(path):
    for cand in _candidate_paths(path):
        if os.path.exists(cand):
            return cand
    return None


def resolve_path(path):
    if not path:
        return None

    found = find_existing_path(path)
    if found:
        return found

    return os.path.normpath(_to_wsl_path(path))


class DebugBridgeClient(object):
    def __init__(self, host=None, port=None, auto_start=True):
        # Prefer env vars if not explicitly passed
        env_host = os.environ.get("GHIDRA_MCP_DEBUG_HOST", "127.0.0.1")
        env_port = _parse_port(os.environ.get("GHIDRA_MCP_DEBUG_PORT", 19090), 19090)
        
        self.host = _normalize_connect_host(host or env_host)
        self.port = _parse_port(port or env_port, env_port)
        self.proc = None
        self.auto_start = auto_start

    def _connect_host(self):
        connect_host = self.host
        if connect_host == "0.0.0.0":
            connect_host = "127.0.0.1"
        return connect_host

    def _spawn_bridge(self):
        base = os.path.dirname(os.path.abspath(__file__))
        server_script = os.path.normpath(os.path.join(base, "..", "gdb_server", "server.py"))

        cmd = ["gdb", "--quiet", "-nx", "-nh", "-x", server_script]
        cwd = os.path.dirname(server_script)

        with open(os.devnull, "wb") as devnull:
            self.proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=devnull,
                stderr=devnull,
            )

        time.sleep(0.5)
        if self.proc.poll() is not None:
            return False
        return self._wait_bridge_ready(6.0)

    def _raw_call(self, cmd, args, timeout_seconds=30.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)
        connect_host = self._connect_host()

        try:
            sock.connect((connect_host, self.port))
            req = json.dumps({"cmd": cmd, "args": args}) + "\n"
            sock.sendall(req.encode("utf-8"))

            resp_data = ""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_data += chunk.decode("utf-8", "replace")
                if "\n" in resp_data:
                    break
            if not resp_data.strip():
                return {"ok": False, "error": "empty response from bridge"}
            return json.loads(resp_data.strip())
        except (socket.error, ValueError) as e:
            return {"ok": False, "error": str(e)}
        finally:
            sock.close()

    def _bridge_healthy(self):
        ping = self._raw_call("bridge.ping", {}, 2.0)
        return bool(ping.get("ok"))

    def _wait_bridge_ready(self, timeout_seconds):
        deadline = time.time() + float(timeout_seconds)
        while time.time() < deadline:
            if self._bridge_healthy():
                return True
            time.sleep(0.2)
        return False

    def _listening_pids(self):
        pids = []
        cmds = [
            ["lsof", "-ti", "TCP:%d" % self.port, "-sTCP:LISTEN"],
            ["fuser", "-n", "tcp", str(self.port)],
            ["ss", "-ltnp"],
        ]

        for cmd in cmds:
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate()
            except OSError:
                continue

            text = out.decode("utf-8", "ignore")
            if cmd[0] == "ss":
                for line in text.splitlines():
                    if (":%d" % self.port) not in line:
                        continue
                    for number in re.findall(r"pid=(\d+)", line):
                        pid = int(number)
                        if pid not in pids:
                            pids.append(pid)
                if pids:
                    break
                continue

            for number in re.findall(r"\b\d+\b", text):
                pid = int(number)
                if pid != self.port and pid not in pids:
                    pids.append(pid)
            if pids:
                break
        return pids

    def _kill_pid(self, pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return

        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return
            time.sleep(0.05)

        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            return

    def _is_timeout_error(self, resp):
        if resp.get("ok"):
            return False
        msg = str(resp.get("error", "")).lower()
        return ("timed out" in msg) or ("errno 110" in msg)

    def _ensure_bridge(self):
        if self._bridge_healthy():
            return True

        if not self.auto_start:
            return False

        if self.proc and self.proc.poll() is None:
            return self.restart()

        print("[utils] Bridge not responding, spawning new instance...")
        return self._spawn_bridge()

    def restart(self):
        # Stop tracked bridge process first.
        if self.proc:
            if self.proc.poll() is None:
                print("[utils] Killing existing GDB process...")
                self._kill_pid(self.proc.pid)
            self.proc = None

        # Kill any stale external listener bound on the bridge port.
        for pid in self._listening_pids():
            self._kill_pid(pid)

        return self._spawn_bridge()

    def call(self, cmd, args):
        if not self._ensure_bridge():
            return {"ok": False, "error": "bridge unavailable"}

        resp = self._raw_call(cmd, args)
        if self._is_timeout_error(resp) and self.auto_start:
            if self.restart():
                return self._raw_call(cmd, args)
        return resp
