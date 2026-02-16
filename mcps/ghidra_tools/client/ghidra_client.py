<<<<<<< HEAD
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import socket


def _normalize_connect_host(host):
    text = str(host or "").strip()
    if text == "" or text == "0.0.0.0":
        return "127.0.0.1"
    return text


class GhidraMCP:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = _normalize_connect_host(host)
        self.port = port

    def call(self, cmd, **args):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        try:
            sock.sendall(json.dumps({"cmd": cmd, "args": args}).encode("utf-8"))
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
            raw = b"".join(chunks).decode("utf-8").strip()
            res = json.loads(raw)
            if res.get("ok"):
                return res.get("result")
            raise Exception(res.get("error"))
        finally:
            sock.close()

    # static analysis methods
    def meta(self, binary_path=None):
        if binary_path:
            return self.call("meta", binary_path=binary_path)
        return self.call("meta")

    def functions(self):
        return self.call("func.list")

    def func(self, name=None, addr=None):
        if name:
            return self.call("func.name", name=name)
        return self.call("func.addr", addr=addr)

    def hex(self, addr, size=8):
        return self.call("mem.hex", addr=addr, size=size)

    def dec(self, addr, size=8):
        return self.call("mem.dec", addr=addr, size=size)

    def string(self, addr, maxlen=256):
        return self.call("mem.str", addr=addr, maxlen=maxlen)

    def asm(self, addr, count=5):
        return self.call("mem.asm", addr=addr, count=count)

    def decompile(self, name=None, addr=None):
        if name:
            return self.call("decompile.name", name=name)
        return self.call("decompile.addr", addr=addr)

    def search_func(self, pattern):
        return self.call("search.func", pattern=pattern)

    def search_str(self, pattern):
        return self.call("search.str", pattern=pattern)

    def search_bytes(self, pattern, max=20):
        return self.call("search.bytes", pattern=pattern, max=max)

    def xrefs_to(self, addr):
        return self.call("search.xrefs_to", addr=addr)

    def xrefs_from(self, addr):
        return self.call("search.xrefs_from", addr=addr)

    # dynamic debug methods
    def debug_open(
        self,
        binary=None,
        argv=None,
        cwd=None,
        env=None,
        gdb_path=None,
        gdb_args=None,
        trace_rmi_addr=None,
        trace_sync=None,
        trace_start=None,
        trace_required=None,
        require_ghidra=None,
        ghidra_home=None,
        use_ghidra=None,
    ):
        payload = {}
        if binary is not None:
            payload["binary"] = binary
        if argv is not None:
            payload["argv"] = argv
        if cwd is not None:
            payload["cwd"] = cwd
        if env is not None:
            payload["env"] = env
        if gdb_path is not None:
            payload["gdb_path"] = gdb_path
        if gdb_args is not None:
            payload["gdb_args"] = gdb_args
        if trace_rmi_addr is not None:
            payload["trace_rmi_addr"] = trace_rmi_addr
        if trace_sync is not None:
            payload["trace_sync"] = trace_sync
        if trace_start is not None:
            payload["trace_start"] = trace_start
        if trace_required is not None:
            payload["trace_required"] = trace_required
        if require_ghidra is not None:
            payload["require_ghidra"] = require_ghidra
        if ghidra_home is not None:
            payload["ghidra_home"] = ghidra_home
        if use_ghidra is not None:
            payload["use_ghidra"] = use_ghidra
        return self.call("debug.open", **payload)

    def debug_open_current(
        self,
        argv=None,
        cwd=None,
        env=None,
        gdb_path=None,
        gdb_args=None,
        trace_rmi_addr=None,
        trace_sync=None,
        trace_start=None,
        trace_required=None,
        require_ghidra=None,
        ghidra_home=None,
        use_ghidra=None,
    ):
        payload = {}
        if argv is not None:
            payload["argv"] = argv
        if cwd is not None:
            payload["cwd"] = cwd
        if env is not None:
            payload["env"] = env
        if gdb_path is not None:
            payload["gdb_path"] = gdb_path
        if gdb_args is not None:
            payload["gdb_args"] = gdb_args
        if trace_rmi_addr is not None:
            payload["trace_rmi_addr"] = trace_rmi_addr
        if trace_sync is not None:
            payload["trace_sync"] = trace_sync
        if trace_start is not None:
            payload["trace_start"] = trace_start
        if trace_required is not None:
            payload["trace_required"] = trace_required
        if require_ghidra is not None:
            payload["require_ghidra"] = require_ghidra
        if ghidra_home is not None:
            payload["ghidra_home"] = ghidra_home
        if use_ghidra is not None:
            payload["use_ghidra"] = use_ghidra
        return self.call("debug.open.current", **payload)

    def debug_attach(
        self,
        pid,
        gdb_path=None,
        gdb_args=None,
        trace_rmi_addr=None,
        trace_sync=None,
        trace_start=None,
        trace_required=None,
        require_ghidra=None,
        ghidra_home=None,
        use_ghidra=None,
    ):
        payload = {"pid": pid}
        if gdb_path is not None:
            payload["gdb_path"] = gdb_path
        if gdb_args is not None:
            payload["gdb_args"] = gdb_args
        if trace_rmi_addr is not None:
            payload["trace_rmi_addr"] = trace_rmi_addr
        if trace_sync is not None:
            payload["trace_sync"] = trace_sync
        if trace_start is not None:
            payload["trace_start"] = trace_start
        if trace_required is not None:
            payload["trace_required"] = trace_required
        if require_ghidra is not None:
            payload["require_ghidra"] = require_ghidra
        if ghidra_home is not None:
            payload["ghidra_home"] = ghidra_home
        if use_ghidra is not None:
            payload["use_ghidra"] = use_ghidra
        return self.call("debug.attach", **payload)

    def debug_close(self, session_id):
        return self.call("debug.close", session_id=session_id)

    def debug_list(self):
        return self.call("debug.list")

    def debug_status(self, session_id):
        return self.call("debug.status", session_id=session_id)

    def debug_break_set(self, session_id, location):
        return self.call("debug.break.set", session_id=session_id, location=location)

    def debug_break_del(self, session_id, breakpoint):
        return self.call("debug.break.del", session_id=session_id, breakpoint=breakpoint)

    def debug_break_list(self, session_id):
        return self.call("debug.break.list", session_id=session_id)

    def debug_continue(self, session_id):
        return self.call("debug.cont", session_id=session_id)

    def debug_stepi(self, session_id):
        return self.call("debug.stepi", session_id=session_id)

    def debug_nexti(self, session_id):
        return self.call("debug.nexti", session_id=session_id)

    def debug_interrupt(self, session_id):
        return self.call("debug.interrupt", session_id=session_id)

    def debug_regs(self, session_id):
        return self.call("debug.regs", session_id=session_id)

    def debug_mem(self, session_id, addr, size=64):
        return self.call("debug.mem", session_id=session_id, addr=addr, size=size)

    def debug_bt(self, session_id, depth=32):
        return self.call("debug.bt", session_id=session_id, depth=depth)

    def debug_events(self, session_id, max=20):
        return self.call("debug.events.poll", session_id=session_id, max=max)

    def debug_trace_connect(self, session_id, trace_rmi_addr):
        return self.call("debug.trace.connect", session_id=session_id, trace_rmi_addr=trace_rmi_addr)

    def debug_trace_disconnect(self, session_id, tolerate_error=False):
        return self.call("debug.trace.disconnect", session_id=session_id, tolerate_error=tolerate_error)

    def debug_trace_start(self, session_id):
        return self.call("debug.trace.start", session_id=session_id)

    def debug_trace_stop(self, session_id, tolerate_error=False):
        return self.call("debug.trace.stop", session_id=session_id, tolerate_error=tolerate_error)

    def debug_trace_sync_enable(self, session_id):
        return self.call("debug.trace.sync_enable", session_id=session_id)

    def debug_trace_sync_disable(self, session_id, tolerate_error=False):
        return self.call("debug.trace.sync_disable", session_id=session_id, tolerate_error=tolerate_error)

    def debug_trace_sync_synth_stopped(self, session_id, tolerate_error=False):
        return self.call(
            "debug.trace.sync_synth_stopped",
            session_id=session_id,
            tolerate_error=tolerate_error,
        )

    def debug_trace_put_all(self, session_id, tolerate_error=False):
        return self.call("debug.trace.put_all", session_id=session_id, tolerate_error=tolerate_error)


if __name__ == "__main__":
    g = GhidraMCP()

    print("=== Meta ===")
    print(g.meta())

    print("\n=== Functions ===")
    for f in g.functions():
        print("%s\t%s" % (f['addr'], f['name']))

    print("\n=== Decompile main ===")
    print(g.decompile(name="main")["code"])

    print("\n=== Search 'main' ===")
    print(g.search_func("main"))
=======
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
from fastmcp import FastMCP

# Define the FastMCP server
mcp = FastMCP("Ghidra Tools")

HOST = '127.0.0.1'
PORT = 9999

def call_ghidra(cmd, **kwargs):
    """Internal helper to communicate with Ghidra socket server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        sock.connect((HOST, PORT))
        sock.send(json.dumps({"cmd": cmd, "args": kwargs}).encode())
        
        # Read until newline or data ends
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if chunk.endswith(b"\n"):
                break
        
        data = b"".join(chunks).decode().strip()
        sock.close()
        
        if not data:
            return json.dumps({"status": "error", "message": "No response from Ghidra server"})
            
        res = json.loads(data)
        if res.get("ok"):
            return json.dumps({"status": "success", "result": res.get("result")})
        return json.dumps({"status": "error", "message": res.get("error")})
    except ConnectionRefusedError:
        return json.dumps({"status": "error", "message": "Could not connect to Ghidra server. Is it running?"})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Communication error: {str(e)}"})

@mcp.tool()
def get_metadata(binary_path: str = None) -> str:
    """Get metadata about the currently analyzed binary (arch, pie, etc.)"""
    if binary_path:
        return call_ghidra("meta", binary_path=binary_path)
    return call_ghidra("meta")

@mcp.tool()
def list_functions() -> str:
    """List all functions in the binary"""
    return call_ghidra("func.list")

@mcp.tool()
def get_function_by_name(name: str) -> str:
    """Get function detailed info by name (start, end, size, etc.)"""
    return call_ghidra("func.name", name=name)

@mcp.tool()
def get_function_by_addr(addr: str) -> str:
    """Get function detailed info by address"""
    return call_ghidra("func.addr", addr=addr)

@mcp.tool()
def read_memory_hex(addr: str, size: int = 8) -> str:
    """Read memory at address as hex string"""
    return call_ghidra("mem.hex", addr=addr, size=size)

@mcp.tool()
def read_memory_decimal(addr: str, size: int = 8) -> str:
    """Read memory at address as decimal value"""
    return call_ghidra("mem.dec", addr=addr, size=size)

@mcp.tool()
def read_string(addr: str, maxlen: int = 256) -> str:
    """Read string from memory address"""
    return call_ghidra("mem.str", addr=addr, maxlen=maxlen)

@mcp.tool()
def read_assembly(addr: str, count: int = 5) -> str:
    """Read assembly instructions at address"""
    return call_ghidra("mem.asm", addr=addr, count=count)

@mcp.tool()
def decompile_address(addr: str) -> str:
    """Decompile function containing the address"""
    return call_ghidra("decompile.addr", addr=addr)

@mcp.tool()
def decompile_function(name: str) -> str:
    """Decompile function by name"""
    return call_ghidra("decompile.name", name=name)

@mcp.tool()
def search_functions(pattern: str) -> str:
    """Search for functions matching a regex pattern"""
    return call_ghidra("search.func", pattern=pattern)

@mcp.tool()
def search_string(pattern: str) -> str:
    """Search for strings matching a regex pattern"""
    return call_ghidra("search.str", pattern=pattern)

@mcp.tool()
def search_bytes(pattern: str, max_results: int = 20) -> str:
    """Search for byte pattern (e.g. '90 90 ?? E8')"""
    return call_ghidra("search.bytes", pattern=pattern, max=max_results)

@mcp.tool()
def get_xrefs_to(addr: str) -> str:
    """Get cross-references TO an address"""
    return call_ghidra("search.xrefs_to", addr=addr)

@mcp.tool()
def get_xrefs_from(addr: str) -> str:
    """Get cross-references FROM an address"""
    return call_ghidra("search.xrefs_from", addr=addr)

if __name__ == "__main__":
    mcp.run()
>>>>>>> f0bd6af7b0b69e8b3f0870d0398d2237ee8cccc2
