from fastmcp import FastMCP
import os
import json

mcp = FastMCP("Pwntools Tools")

@mcp.tool()
def readPayload(path: str) -> str:
    """Reads the content of a file. Returns JSON."""
    return _readPayload(path)

def _readPayload(path: str) -> str:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            return json.dumps({"status": "success", "content": content})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

@mcp.tool()
def writePayload(payload_content: str, filename: str) -> str:
    """
    Creates a new python script in the 'challenge' directory with the mandatory template.
    The binary name is fixed to 'chall'.
    Returns JSON.
    
    Args:
        payload_content: The python code to insert between process creation and interactive mode.
        filename: The name of the output python file (e.g., 'solve.py').
    """
    return _writePayload(payload_content, filename)

def _writePayload(payload_content: str, filename: str) -> str:
    # Fixed binary name
    binary_name = "chall"
    
    # Path handling
    server_dir = os.path.dirname(os.path.abspath(__file__))
    challenge_dir = os.path.join(server_dir, "challenge")
    output_path = os.path.join(challenge_dir, filename)
    
    template = f'''from pwn import*
p = process("./{binary_name}")

{payload_content}

p.interactive()'''
    
    try:
        # ensuring directory exists
        if not os.path.exists(challenge_dir):
            os.makedirs(challenge_dir)
            
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(template)
        return json.dumps({"status": "success", "path": output_path})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

if __name__ == "__main__":
    mcp.run()
