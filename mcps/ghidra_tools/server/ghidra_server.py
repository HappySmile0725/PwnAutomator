# @author HappySmile
# @category MCP
# @runtime Jython
# -*- coding: utf-8 -*-

import socket
import json
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "handlers"))

from utils import GhidraContext
GhidraContext.init(currentProgram)

from functions import FunctionsHandler
from memory import MemoryHandler
from decompile import DecompileHandler
from search import SearchHandler
from meta import MetaHandler
from debug import DebugHandler


class ServerCommands:
    def __init__(self):
        self.cmds = {}
        self.register_all()
        
    def register_all(self):
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
            "debug.run": DebugHandler.run,
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
            "debug.context": DebugHandler.context,
            "debug.read_stdout": DebugHandler.read_stdout,
            "debug.events.poll": DebugHandler.events_poll,
            "debug.cmd": DebugHandler.cmd,
            "debug.restart_server": DebugHandler.restart_server,
            "debug.ropgadget.chall": DebugHandler.ropgadget_chall,
            "debug.ropgadget.libc": DebugHandler.ropgadget_libc,

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
            "mem.dec": "read integer value {addr, size} (returns hex + value_dec)",
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
            "debug.open": "launch binary under gdb/mi {binary?, argv?, cwd?, env?, gdb_path?, gdb_args?, auto_run?}",
            "debug.open.current": "launch current program with gdb/mi {argv?, cwd?, env?, gdb_path?, gdb_args?, auto_run?}",
            "debug.run": "run binary {session_id, input?, binary?}",
            "debug.attach": "attach pid with gdb/mi {pid, gdb_path?, gdb_args?}",
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
            "debug.stdin.write": "write input to inferior stdin {session_id, data, append_newline?, wait_ms?, max_events?}",
            "debug.regs": "list register values in hex {session_id}",
            "debug.mem": "read memory bytes {session_id, addr, size}",
            "debug.bt": "stack backtrace {session_id, depth?}",
            "debug.context": "context snapshot (registers/code/stack) {session_id}",
            "debug.read_stdout": "read buffered stdout/stderr {max_bytes?}",
            "debug.events.poll": "poll async debug events {session_id, max?}",
            "debug.cmd": "execute raw gdb command {session_id, cmd, timeout_ms?}",
            "debug.restart_server": "restart gdb server process",
            "debug.ropgadget.chall": "run ROPgadget for chall binary {path?, session_id?, timeout_ms?}",
            "debug.ropgadget.libc": "run ROPgadget for libc {path?, timeout_ms?} (default: local challenge libc or /usr/lib/x86_64-linux-gnu/libc.so.6)",
            "help": "show help message"
        }
    
    def execute(self, cmd, args):
        handler = self.cmds.get(cmd)
        if handler is not None:
            return True, handler(args)
        return False, "Unknown command: %s" % cmd


HOST = "0.0.0.0"
PORT = 9999


def _send_response(conn, payload):
    conn.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _recv_request(conn):
    chunks = []
    while True:
        data = conn.recv(65536)
        if not data:
            break
        chunks.append(data)
        if b"\n" in data:
            break
    return b"".join(chunks).decode("utf-8")


def _handle_request(server_cmds, req):
    cmd = req.get("cmd")
    args = req.get("args", {})

    ok, result = server_cmds.execute(cmd, args)
    if ok:
        if isinstance(result, dict) and set(result.keys()) == set(["error"]):
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}
    return {"ok": False, "error": result}


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
        response = None
        try:
            raw = _recv_request(conn).strip()
            if not raw:
                conn.close()
                continue
            req = json.loads(raw)
            response = _handle_request(server_cmds, req)
        except ValueError as e:
            response = {"ok": False, "error": "Invalid JSON: %s" % str(e)}
        except BaseException as e:
            response = {"ok": False, "error": str(e)}
        finally:
            if response is not None:
                try:
                    _send_response(conn, response)
                except socket.error:
                    pass
            conn.close()

run_server()
