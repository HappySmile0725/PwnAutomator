# Ghidra MCP Tools

## 1-1) Run Ghidra MCP server

- Static Debugging : use 9999 port
```bash
./ghidra_12.0.2_PUBLIC/support/analyzeHeadless challenge test \
  -process chall \
  -scriptPath ./ghidra_tools/server \
  -postScript ghidra_server.py
```

- Dynamic Debugging : use 19090 port
```bash
python3 debug_bridge/server.py --host 0.0.0.0 --port 19090
```

---

## 1-2) Run both in background

```bash
./run_ghidra_mcp_bg.sh
```

- Starts both `analyzeHeadless` and `debug_bridge/server.py` in background.
- If `challenge/test` does not contain program `chall`, it auto-imports from `./test/chall`.
- Optional custom binary path:

```bash
./run_ghidra_mcp_bg.sh ./test/another_binary
```

---

## 2) Claude MCP integration

Add this in `claude_desktop_config.json`
```json
    "ghidra-mcp": {
      "command": "[python Directory]",
      "args": [
        "[wrapper.py Directory]"
      ],
      "env": {
        "PYTHONDONTWRITEBYTECODE": "1",
        "GHIDRA_HOST": "[HOST IP]",
        "GHIDRA_PORT": "9999",
        "GHIDRA_MCP_DEBUG_HOST": "[HOST IP]",
        "GHIDRA_MCP_DEBUG_PORT": "19090"
      }
    }
```

---
