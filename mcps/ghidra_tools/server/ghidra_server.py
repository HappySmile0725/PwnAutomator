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
from handlers import FunctionsHandler, MemoryHandler, DecompileHandler, SearchHandler, MetaHandler

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
            "help": "show help message"
        }
    
    def execute(self, cmd, args):
        if cmd in self.cmds:
            return True, self.cmds[cmd](args)
        return False, "Unknown command: %s" % cmd

# server
HOST = '127.0.0.1'
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
