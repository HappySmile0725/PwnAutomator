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
            "meta": "get binary metadata (includes checksec, ubuntu info, optional: {binary_path})",
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
