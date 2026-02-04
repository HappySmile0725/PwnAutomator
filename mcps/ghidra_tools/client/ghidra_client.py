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
