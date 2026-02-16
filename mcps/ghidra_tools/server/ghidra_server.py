# @author HappySmile
# @category MCP
# @runtime Jython
# -*- coding: utf-8 -*-

import socket
import json
import sys
import os
import subprocess

# modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "handlers"))

# context
from utils import GhidraContext
GhidraContext.init(currentProgram)

# load handlers
# Import directly from handler modules to avoid stale Jython package-cache issues
# (e.g., old handlers/__init__$py.class missing newly added exports).
from functions import FunctionsHandler
from memory import MemoryHandler
from decompile import DecompileHandler
from search import SearchHandler
from meta import MetaHandler
from debug import DebugHandler

# commands setup
class ServerCommands:
    def __init__(self):
        self.cmds = {}
        self.register_all()
        
    def register_all(self):
        # Register handlers
        self.cmds.update({
            # Functions
            "func.list": FunctionsHandler.list_all,
            "func.name": FunctionsHandler.get_by_name,
            "func.addr": FunctionsHandler.get_by_addr,
            
            # Memory
            "mem.hex": MemoryHandler.read_hex,
            "mem.dec": MemoryHandler.read_dec,
            "mem.str": MemoryHandler.read_str,
            "mem.asm": MemoryHandler.read_asm,
            
            # Decompile
            "decompile.addr": DecompileHandler.by_addr,
            "decompile.name": DecompileHandler.by_name,
            
            # Search
            "search.func": SearchHandler.func_by_pattern,
            "search.str": SearchHandler.string,
            "search.bytes": SearchHandler.bytes_pattern,
            "search.xrefs_to": SearchHandler.xrefs_to,
            "search.xrefs_from": SearchHandler.xrefs_from,
            
            # Meta
            "meta": MetaHandler.get_meta,

            # Dynamic Debug
            "debug.open": DebugHandler.open,
            "debug.open.current": DebugHandler.open_current,
            "debug.attach": DebugHandler.attach,
            "debug.close": DebugHandler.close,
            "debug.list": DebugHandler.list_sessions,
            "debug.status": DebugHandler.status,
            "debug.break.set": DebugHandler.break_set,
            "debug.break.del": DebugHandler.break_del,
            "debug.break.list": DebugHandler.break_list,
            "debug.cont": DebugHandler.cont,
            "debug.stepi": DebugHandler.stepi,
            "debug.nexti": DebugHandler.nexti,
            "debug.interrupt": DebugHandler.interrupt,
            "debug.stdin.write": DebugHandler.stdin_write,
            "debug.regs": DebugHandler.regs,
            "debug.mem": DebugHandler.mem,
            "debug.bt": DebugHandler.bt,
            "debug.events.poll": DebugHandler.events_poll,
            "debug.trace.connect": DebugHandler.trace_connect,
            "debug.trace.disconnect": DebugHandler.trace_disconnect,
            "debug.trace.start": DebugHandler.trace_start,
            "debug.trace.stop": DebugHandler.trace_stop,
            "debug.trace.sync_enable": DebugHandler.trace_sync_enable,
            "debug.trace.sync_disable": DebugHandler.trace_sync_disable,
            "debug.trace.sync_synth_stopped": DebugHandler.trace_sync_synth_stopped,
            "debug.trace.put_all": DebugHandler.trace_put_all,

            "help": self.get_help
        })
        
        # Inject commands list to MetaHandler
        MetaHandler.set_commands(self.cmds.keys())

    def get_help(self, args):
        return {
            "func.list": "list all functions",
            "func.name": "search function by name {name}",
            "func.addr": "get function info by address {addr}",
            "mem.hex": "read hex bytes {addr, size}",
            "mem.dec": "read decimal value {addr, size}",
            "mem.str": "read string {addr, maxlen}",
            "mem.asm": "read assembly {addr, count}",
            "decompile.addr": "decompile by address {addr}",
            "decompile.name": "decompile by name {name}",
            "search.func": "search functions by pattern {pattern}",
            "search.str": "search strings by pattern {pattern}",
            "search.bytes": "search bytes by pattern {pattern}",
            "search.xrefs_to": "find xrefs to address {addr}",
            "search.xrefs_from": "find xrefs from address {addr}",
            "meta": "get binary metadata (includes checksec, optional: {binary_path})",
            "debug.open": "launch binary under ghidragdb+gdb {binary?, argv?, cwd?, env?, gdb_path?, gdb_args?, trace_rmi_addr?, trace_sync?, trace_start?, trace_required?, require_ghidra?, ghidra_home?, use_ghidra?, auto_run?}",
            "debug.open.current": "launch current program with ghidragdb+gdb {argv?, cwd?, env?, gdb_path?, gdb_args?, trace_rmi_addr?, trace_sync?, trace_start?, trace_required?, require_ghidra?, ghidra_home?, use_ghidra?, auto_run?}",
            "debug.attach": "attach pid with ghidragdb+gdb {pid, gdb_path?, gdb_args?, trace_rmi_addr?, trace_sync?, trace_start?, trace_required?, require_ghidra?, ghidra_home?, use_ghidra?}",
            "debug.close": "close debug session {session_id}",
            "debug.list": "list debug sessions",
            "debug.status": "session state {session_id}",
            "debug.break.set": "set breakpoint {session_id, location}",
            "debug.break.del": "delete breakpoint {session_id, breakpoint}",
            "debug.break.list": "list breakpoints {session_id}",
            "debug.cont": "continue execution {session_id}",
            "debug.stepi": "step instruction {session_id}",
            "debug.nexti": "next instruction {session_id}",
            "debug.interrupt": "interrupt execution {session_id}",
            "debug.stdin.write": "write input to inferior stdin {session_id, data, append_newline?}",
            "debug.regs": "list register values {session_id}",
            "debug.mem": "read memory bytes {session_id, addr, size}",
            "debug.bt": "stack backtrace {session_id, depth?}",
            "debug.events.poll": "poll async debug events {session_id, max?}",
            "debug.trace.connect": "connect session to Ghidra TraceRMI {session_id, trace_rmi_addr}",
            "debug.trace.disconnect": "disconnect trace session {session_id, tolerate_error?}",
            "debug.trace.start": "start ghidra trace {session_id}",
            "debug.trace.stop": "stop ghidra trace {session_id, tolerate_error?}",
            "debug.trace.sync_enable": "enable ghidra trace sync {session_id}",
            "debug.trace.sync_disable": "disable ghidra trace sync {session_id, tolerate_error?}",
            "debug.trace.sync_synth_stopped": "synthesize stopped state to trace {session_id, tolerate_error?}",
            "debug.trace.put_all": "publish inferiors/threads/frames/regs/mem to trace {session_id, tolerate_error?}",
            "help": "show help message"
        }
    
    def execute(self, cmd, args):
        if cmd in self.cmds:
            return True, self.cmds[cmd](args)
        return False, "Unknown command: %s" % cmd

# server
HOST = os.environ.get("GHIDRA_MCP_BIND_HOST", os.environ.get("GHIDRA_HOST", "0.0.0.0"))
try:
    PORT = int(os.environ.get("GHIDRA_MCP_BIND_PORT", os.environ.get("GHIDRA_PORT", "9999")))
except:
    PORT = 9999

def run_server():
    server_cmds = ServerCommands()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    
    print("=" * 50)
    print("Ghidra MCP Server")
    print("Binary: %s" % currentProgram.getName())
    print("Listening: %s:%d" % (HOST, PORT))
    print("=" * 50)
    
    while True:
        conn, addr = sock.accept()
        try:
            data = conn.recv(65536)
            if not data: continue
            
            req = json.loads(data.decode('utf-8'))
            cmd = req.get("cmd")
            args = req.get("args", {})
            
            ok, result = server_cmds.execute(cmd, args)
            response = {"ok": ok}
            if ok: response["result"] = result
            else: response["error"] = result
            
            conn.sendall(json.dumps(response).encode('utf-8') + b"\n")
            
        except Exception as e:
            conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode('utf-8') + b"\n")
        finally:
            conn.close()

run_server()
