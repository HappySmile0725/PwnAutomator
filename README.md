# PwnAutomator
---

## Summary

CTF Pwnable Auto Solver
---

## How to run
1. You must have `gdb-peda`
 
2. ```pip install fastmcp pwntools```

3. Download ghidra in `mcps` directory (FYI : https://dokhakdubini.tistory.com/564)
    - `https://github.com/NationalSecurityAgency/ghidra/releases`

4. Add this in mcp config file
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
- These files have to run in Ubuntu, so HOST IP will be your wsl or ubuntu ip.

5. Fast run
```bash
./run_ghidra_server.sh
```

6. Individual exec
If you have to run these files individually for some reason, use these.
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