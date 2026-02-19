# -*- coding: utf-8 -*-
import os
import json
import socket
import subprocess
import time
import jarray
from ghidra.app.decompiler import DecompInterface

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
        
        # Decompiler setup
        GhidraContext.decomp = DecompInterface()
        GhidraContext.decomp.openProgram(program)
        
        # Debug Bridge setup
        GhidraContext.bridge_client = DebugBridgeClient()

    @staticmethod
    def bridge_call(cmd, args):
        if not GhidraContext.bridge_client:
             return {"ok": False, "error": "Bridge client not initialized"}
        return GhidraContext.bridge_client.call(cmd, args)

    @staticmethod
    def addr(addr_str):
        if isinstance(addr_str, int) or isinstance(addr_str, long):
            return GhidraContext.addr_factory.getDefaultAddressSpace().getAddress(addr_str)
        try:
            # Handle hex strings
            if str(addr_str).startswith("0x"):
                val = long(addr_str, 16)
                return GhidraContext.addr_factory.getDefaultAddressSpace().getAddress(val)
            # Try parsing as address string
            return GhidraContext.addr_factory.getAddress(str(addr_str))
        except:
             # Fallback to default space
             return GhidraContext.addr_factory.getDefaultAddressSpace().getAddress(str(addr_str))

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

class DebugBridgeClient(object):
    def __init__(self, host=None, port=None, auto_start=True, bind_host='0.0.0.0'):
        # Prefer env vars if not explicitly passed
        env_host = os.environ.get("GHIDRA_MCP_DEBUG_HOST", "127.0.0.1")
        env_port = int(os.environ.get("GHIDRA_MCP_DEBUG_PORT", 19090))
        
        self.host = _normalize_connect_host(host or env_host)
        self.port = port or env_port
        
        self.bind_host = bind_host
        self.proc = None
        self.auto_start = auto_start

    def _spawn_bridge(self):
        base = os.path.dirname(os.path.abspath(__file__))
        server_script = os.path.normpath(os.path.join(base, "..", "gdb_server", "server.py"))
        
        # We are already in WSL/Linux, so just run gdb
        cmd = ["gdb", "--quiet", "-x", server_script]
        cwd = os.path.dirname(server_script)
        
        self.proc = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.PIPE)
        time.sleep(2.0)
        return True

    def _raw_call(self, cmd, args):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        timeout = 5.0
        sock.settimeout(timeout)

        # Force localhost if target is 0.0.0.0 (connect side)
        connect_host = self.host
        if connect_host == "0.0.0.0": connect_host = "127.0.0.1"

        try:
            sock.connect((connect_host, self.port))
            req = json.dumps({"cmd": cmd, "args": args}) + "\n"
            sock.sendall(req.encode('utf-8'))

            resp_data = ""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_data += chunk.decode('utf-8')
                if "\n" in resp_data:
                    break
            
            sock.close()
            return json.loads(resp_data.strip())
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _ensure_bridge(self):
        # Force localhost if target is 0.0.0.0
        connect_host = self.host
        if connect_host == "0.0.0.0": connect_host = "127.0.0.1"
        
        # Try checking multiple times to avoid false negatives
        for i in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0) # Increased timeout
                result = s.connect_ex((connect_host, self.port))
                s.close()

                if result == 0:
                    return True
                
                time.sleep(0.1)
            except:
                pass
        
        if self.auto_start:
            print("[utils] Bridge not responding, spawning new instance...")
            return self._spawn_bridge()
            
        return False

    def call(self, cmd, args):
        if not self._ensure_bridge():
             return {"ok": False, "error": "Bridge not running"}
        return self._raw_call(cmd, args)
