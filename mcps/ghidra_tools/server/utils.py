# -*- coding: utf-8 -*-
import os
import json
import socket
import subprocess
import time
import jarray


def _normalize_connect_host(host):
    text = str(host or "").strip()
    if text == "" or text == "0.0.0.0":
        return "127.0.0.1"
    return text


class DebugBridgeClient(object):
    """Python3 debug bridge client for Jython runtime."""

    def __init__(self, host='127.0.0.1', port=19090, auto_start=True, bind_host='0.0.0.0'):
        self.host = _normalize_connect_host(host)
        self.bind_host = str(bind_host or "0.0.0.0")
        self.port = int(port)
        self.auto_start = auto_start

    def _bridge_script_path(self):
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.normpath(os.path.join(base, "..", "debug_bridge", "server.py"))

    def _python_candidates(self):
        out = []
        env_py = os.environ.get("GHIDRA_MCP_PYTHON")
        if env_py:
            out.append([env_py])

        if os.name == "nt":
            out.append(["py", "-3"])

        out.append(["python3"])
        out.append(["python"])
        return out

    def _spawn_bridge(self):
        script = self._bridge_script_path()
        if not os.path.exists(script):
            return False

        cwd = os.path.dirname(script)
        devnull = open(os.devnull, "w")
        try:
            for cmd in self._python_candidates():
                argv = cmd + [script, "--host", self.bind_host, "--port", str(self.port)]
                try:
                    subprocess.Popen(argv, cwd=cwd, stdout=devnull, stderr=devnull)
                    time.sleep(0.35)
                    return True
                except:
                    continue
        finally:
            devnull.close()

        return False

    def _raw_call(self, cmd, args):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((self.host, self.port))
        try:
            wire = (json.dumps({"cmd": cmd, "args": args}) + "\n").encode("utf-8")
            sock.sendall(wire)

            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
            raw = b"".join(chunks).decode("utf-8").strip()
            if not raw:
                raise Exception("debug bridge empty response")

            res = json.loads(raw)
            if res.get("ok"):
                return res.get("result")
            raise Exception(res.get("error"))
        finally:
            sock.close()

    def ensure_alive(self):
        try:
            self._raw_call("bridge.ping", {})
            return
        except:
            pass

        if not self.auto_start:
            raise Exception("debug bridge is not running")

        if not self._spawn_bridge():
            raise Exception("failed to start debug bridge")

        last_err = None
        for _ in range(12):
            try:
                self._raw_call("bridge.ping", {})
                return
            except Exception as e:
                last_err = str(e)
                time.sleep(0.25)

        raise Exception("debug bridge startup timeout: %s" % last_err)

    def call(self, cmd, args):
        self.ensure_alive()
        return self._raw_call(cmd, args or {})


class GhidraContext:
    program = None
    mem = None
    listing = None
    fm = None
    af = None
    decomp = None
    dbg = None

    @classmethod
    def init(cls, currentProgram):
        from ghidra.app.decompiler import DecompInterface

        cls.program = currentProgram
        cls.mem = currentProgram.getMemory()
        cls.listing = currentProgram.getListing()
        cls.fm = currentProgram.getFunctionManager()
        cls.af = currentProgram.getAddressFactory()
        cls.decomp = DecompInterface()
        cls.decomp.openProgram(currentProgram)

        dbg_host = os.environ.get("GHIDRA_MCP_DEBUG_HOST", "127.0.0.1")
        dbg_bind_host = os.environ.get("GHIDRA_MCP_DEBUG_BIND_HOST", "0.0.0.0")
        try:
            dbg_port = int(os.environ.get("GHIDRA_MCP_DEBUG_PORT", "19090"))
        except:
            dbg_port = 19090
        cls.dbg = DebugBridgeClient(dbg_host, dbg_port, auto_start=True, bind_host=dbg_bind_host)

    @classmethod
    def addr(cls, s):
        """str to Address convert"""
        return cls.af.getAddress(s)

    @classmethod
    def read_bytes(cls, addr, size):
        """read byte array from memory"""
        data = jarray.zeros(size, 'b')
        cls.mem.getBytes(addr, data)
        return [(b & 0xff) for b in data]

    @classmethod
    def bridge_call(cls, cmd, args):
        if cls.dbg is None:
            raise Exception("Debug bridge is not initialized")
        return cls.dbg.call(cmd, args or {})
