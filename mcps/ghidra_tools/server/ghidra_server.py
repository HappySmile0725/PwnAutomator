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

def _to_text(data):
    if data is None:
        return ""
    try:
        return data.decode("utf-8", "ignore")
    except Exception:
        try:
            return data.decode("latin-1", "ignore")
        except Exception:
            return str(data)

def _parse_json_payload(raw):
    raw = raw.strip()
    if not raw:
        return None

    candidates = [raw]

    obj_start = raw.find("{")
    obj_end = raw.rfind("}")
    if obj_start >= 0 and obj_end >= 0 and obj_start < obj_end:
        candidates.append(raw[obj_start:obj_end + 1])

    arr_start = raw.find("[")
    arr_end = raw.rfind("]")
    if arr_start >= 0 and arr_end >= 0 and arr_start < arr_end:
        candidates.append(raw[arr_start:arr_end + 1])

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None

def _normalize_checksec_result(parsed, binary_path):
    if isinstance(parsed, list) and len(parsed) == 1:
        parsed = parsed[0]

    if isinstance(parsed, dict):
        if binary_path and binary_path in parsed:
            return parsed[binary_path]
        if binary_path:
            binary_name = os.path.basename(binary_path)
            if binary_name in parsed:
                return parsed[binary_name]

    return parsed

def _get_executable_path(args):
    args = args or {}

    arg_path = args.get("binary_path")
    if arg_path:
        return arg_path

    try:
        path = currentProgram.getExecutablePath()
        if path:
            return str(path)
    except Exception:
        pass

    return None

def _collect_checksec(binary_path):
    if not binary_path:
        return {
            "available": False,
            "error": "Executable path unavailable. Pass {binary_path} to meta."
        }

    commands = [
        ["checksec", "--output=json", "--file=%s" % binary_path],
        ["checksec", "--file=%s" % binary_path],
        ["pwn", "checksec", "--file", binary_path]
    ]

    last_error = None

    for cmd in commands:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except Exception as e:
            last_error = str(e)
            continue

        stdout_text = _to_text(stdout).strip()
        stderr_text = _to_text(stderr).strip()
        raw_output = stdout_text if stdout_text else stderr_text

        if proc.returncode != 0:
            last_error = raw_output or ("checksec failed (exit=%d)" % proc.returncode)
            continue

        if not raw_output:
            last_error = "checksec returned empty output"
            continue

        parsed = _parse_json_payload(raw_output)
        result = _normalize_checksec_result(parsed, binary_path) if parsed is not None else raw_output

        return {
            "available": True,
            "binary_path": binary_path,
            "command": " ".join(cmd),
            "result": result
        }

    return {
        "available": False,
        "binary_path": binary_path,
        "error": last_error or "Unable to execute checksec"
    }

# meta
def get_meta(args):
    executable_path = _get_executable_path(args)

    return {
        "name": currentProgram.getName(),
        "arch": str(currentProgram.getLanguage()),
        "base": str(currentProgram.getImageBase()),
        "executable_path": executable_path,
        "checksec": _collect_checksec(executable_path),
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
        "meta": "get binary metadata (includes checksec, optional: {binary_path})",
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
