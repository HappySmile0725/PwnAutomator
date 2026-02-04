from fastmcp import FastMCP
import sys
import os
import json

# Setup paths to import from other MCP servers
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", "..", ".."))

ghidra_client_path = os.path.join(project_root, "mcps", "ghidra_tools", "client")
pwn_server_path = os.path.join(project_root, "mcps", "pwntools_tools", "server")

sys.path.append(ghidra_client_path)
sys.path.append(pwn_server_path)

# Import functionalities
try:
    from ghidra_client import call_ghidra
    from server import _readPayload, _writePayload # Import underlying logic
except ImportError as e:
    raise ImportError(f"Failed to import MCP modules. Check paths: {e}")

mcp = FastMCP("M2 Main Server")

# === Ghidra Tools Wrappers ===

@mcp.tool()
def get_metadata(binary_path: str = None) -> str:
    """Get metadata about the currently analyzed binary"""
    if binary_path:
        return call_ghidra("meta", binary_path=binary_path)
    return call_ghidra("meta")

@mcp.tool()
def list_functions() -> str:
    """List all functions in the binary"""
    return call_ghidra("func.list")

@mcp.tool()
def search_functions(pattern: str) -> str:
    """Search functions by name pattern"""
    return call_ghidra("search.func", pattern=pattern)

@mcp.tool()
def read_assembly(addr: str, count: int = 5) -> str:
    """Read assembly instructions"""
    return call_ghidra("mem.asm", addr=addr, count=count)

@mcp.tool()
def decompile_function(name: str) -> str:
    """Decompile a function by name"""
    return call_ghidra("decompile.name", name=name)

@mcp.tool()
def read_memory_hex(addr: str, size: int = 8) -> str:
    """Read memory hex"""
    return call_ghidra("mem.hex", addr=addr, size=size)

@mcp.tool()
def search_string(pattern: str) -> str:
    """Search for strings"""
    return call_ghidra("search.str", pattern=pattern)

# === Pwntools Wrappers ===

@mcp.tool()
def read_exploit_payload(path: str) -> str:
    """Read a payload file content"""
    return _readPayload(path)

@mcp.tool()
def write_exploit_payload(payload_content: str, filename: str) -> str:
    """
    Write a payload to a python script with the standard template.
    Returns JSON with the path of the created file.
    """
    return _writePayload(payload_content, filename)

if __name__ == "__main__":
    mcp.run()
