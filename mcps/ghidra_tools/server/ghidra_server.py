# @author HappySmile
# @category MCP
# @runtime Jython
# -*- coding: utf-8 -*-

import socket
import json
import sys
import os

# modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(SCRIPT_DIR, "handlers"))

# context
from utils import GhidraContext
GhidraContext.init(currentProgram)

# load handlers
from functions import COMMANDS as func_cmds
from memory import COMMANDS as mem_cmds
from decompile import COMMANDS as dec_cmds
from search import COMMANDS as search_cmds

# commands
COMMANDS = {}
COMMANDS.update(func_cmds)
COMMANDS.update(mem_cmds)
COMMANDS.update(dec_cmds)
COMMANDS.update(search_cmds)

# meta
def get_meta(args):
    return {
        "name": currentProgram.getName(),
        "arch": str(currentProgram.getLanguage()),
        "base": str(currentProgram.getImageBase()),
        "commands": list(COMMANDS.keys())
    }

def get_help(args):
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
        "meta": "get binary metadata",
        "help": "show help message"
    }

COMMANDS["meta"] = get_meta
COMMANDS["help"] = get_help

# server
HOST = '127.0.0.1'
PORT = 9999

def run_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(5)
    
    print("=" * 50)
    print("Ghidra MCP Server")
    print("Binary: %s" % currentProgram.getName())
    print("Arch: %s" % currentProgram.getLanguage())
    print("Base: %s" % currentProgram.getImageBase())
    print("Listening: %s:%d" % (HOST, PORT))
    print("Commands: %d" % len(COMMANDS))
    print("=" * 50)
    
    while True:
        conn, addr = sock.accept()
        try:
            data = conn.recv(65536)
            if not data:
                continue
            
            req = json.loads(data.decode('utf-8'))
            cmd = req.get("cmd")
            args = req.get("args", {})
            
            if cmd in COMMANDS:
                result = COMMANDS[cmd](args)
                response = {"ok": True, "result": result}
            else:
                response = {"ok": False, "error": "Unknown command: %s" % cmd}
            
            conn.sendall(json.dumps(response).encode('utf-8') + b"\n")
            
        except Exception as e:
            conn.sendall(json.dumps({"ok": False, "error": str(e)}).encode('utf-8') + b"\n")
        finally:
            conn.close()

run_server()