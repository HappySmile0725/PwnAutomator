# Ghidra MCP Tools

## 1) Run Ghidra MCP server

```bash
./ghidra_12.0.2_PUBLIC/support/analyzeHeadless challenge test \
  -process <binary_name> \
  -scriptPath ./ghidra_tools/server \
  -postScript ghidra_server.py
```

The server binds on `0.0.0.0:9999` by default.

With this single `analyzeHeadless` run, you can use both:

- static analysis commands: `meta`, `func.*`, `decompile.*`, `search.*`, `mem.*`
- dynamic debugging commands: `debug.*`

## 2) Python client

```python
from ghidra_client import GhidraMCP

g = GhidraMCP()
print(g.meta())
print(g.functions()[:3])
print(g.decompile(name="main")["code"])
```

## 3) Dynamic debugging (Ghidra TraceRMI)

Dynamic debugging is provided through a Python3 debug bridge that runs
`ghidragdb` (Ghidra Debugger agent for gdb).

- Bridge script: `debug_bridge/server.py`
- Default bridge bind address: `0.0.0.0:19090`
- It is auto-started by `server/utils.py` when a `debug.*` command is used.

### Optional environment variables

- `GHIDRA_MCP_PYTHON`: Python3 executable path used to launch bridge
- `GHIDRA_MCP_BIND_HOST`: ghidra server bind host (default `0.0.0.0`)
- `GHIDRA_MCP_BIND_PORT`: ghidra server bind port (default `9999`)
- `GHIDRA_MCP_DEBUG_BIND_HOST`: debug bridge bind host (default `0.0.0.0`)
- `GHIDRA_MCP_DEBUG_BIND_PORT`: debug bridge bind port (default `19090`)
- `GHIDRA_MCP_DEBUG_HOST`: debug bridge connect host from ghidra script (default `127.0.0.1`)
- `GHIDRA_MCP_DEBUG_PORT`: bridge port (default `19090`)
- `GHIDRA_TRACE_RMI_ADDR`: TraceRMI endpoint for `ghidra trace connect`
- `GHIDRA_HOME`: optional explicit Ghidra home path

### `debug.*` commands

- `debug.open`: launch binary with `ghidragdb+gdb` (`binary` optional)
- `debug.open.current`: launch current program executable with `ghidragdb+gdb`
- `debug.attach`: attach to pid with `ghidragdb+gdb`
- `debug.close`: close a debug session
- `debug.list`: list active debug sessions
- `debug.status`: session liveness
- `debug.break.set` / `debug.break.del` / `debug.break.list`
- `debug.cont` / `debug.stepi` / `debug.nexti` / `debug.interrupt`
- `debug.regs`: read registers
- `debug.mem`: read memory bytes
- `debug.bt`: backtrace
- `debug.events.poll`: poll async events (stopped, exited, stream)
- `debug.trace.connect` / `debug.trace.disconnect`
- `debug.trace.start` / `debug.trace.stop`
- `debug.trace.sync_enable` / `debug.trace.sync_disable`
- `debug.trace.sync_synth_stopped` / `debug.trace.put_all`

### Client example

```python
from ghidra_client import GhidraMCP

g = GhidraMCP()

# Open dynamic session for the same binary loaded in Ghidra.
# If GHIDRA_TRACE_RMI_ADDR is set, trace connection starts automatically.
# Set require_ghidra=True if you want hard failure when ghidragdb cannot load.
opened = g.debug_open_current(argv=["AAAA"], trace_required=False, require_ghidra=False)
sid = opened["session_id"]

# Static and dynamic can be mixed freely in one workflow
print(g.decompile(name="main")["code"])
g.debug_break_set(sid, "main")
g.debug_continue(sid)
print(g.debug_events(sid, max=10))
print(g.debug_regs(sid))
print(g.debug_bt(sid, depth=10))

# Optional explicit trace controls
# g.debug_trace_connect(sid, "127.0.0.1:PORT")
# g.debug_trace_sync_enable(sid)
# g.debug_trace_put_all(sid)

g.debug_close(sid)
```

## 4) Debug bridge dependencies

Install with:

```bash
python3 -m pip install -r debug_bridge/requirements.txt
```

Notes:

- `ghidragdb` requires a gdb build with modern Python support (Python 3.9+ recommended).
- If your gdb cannot import `ghidragdb`, use `require_ghidra=False` to keep MI debugging,
  or install a compatible gdb and retry with `require_ghidra=True`.

## 5) Claude MCP integration (manual server mode)

If you want to use this from Claude as an MCP server, note the protocol boundary first:

- `server/ghidra_server.py` is a custom TCP JSON server (`cmd`/`args`) on `0.0.0.0:9999` by default
- Claude MCP expects an MCP protocol server (tools/list, tools/call, etc.)
- So you need one thin MCP adapter that calls `client/ghidra_client.py`

In short: Claude -> MCP adapter -> `ghidra_server.py` (+ `debug_bridge/server.py` for dynamic debug)

### 5.1 What to run manually

Run these servers yourself before using Claude:

1. Debug bridge (Python3):

```bash
cd /mnt/d/work/Projects/PwnAutomator/mcps/ghidra_tools
python3 -m pip install -r debug_bridge/requirements.txt
python3 debug_bridge/server.py --host 0.0.0.0 --port 19090
```

2. Ghidra analyzeHeadless server:

```bash
cd /mnt/d/work/Projects/PwnAutomator/mcps
./ghidra_12.0.2_PUBLIC/support/analyzeHeadless challenge test \
  -process <binary_name> \
  -scriptPath ./ghidra_tools/server \
  -postScript ghidra_server.py
```

### 5.2 Claude-side MCP adapter expectations

Your MCP adapter should:

- expose tools matching this server command set (`meta`, `func.*`, `decompile.*`, `search.*`, `mem.*`, `debug.*`)
- forward tool input to `GhidraMCP.call(cmd, **args)` in `client/ghidra_client.py`
- return raw response as MCP tool result

### 5.3 Claude config example (adapter process)

Use this as a template for your Claude MCP config (adjust to your environment/client format):

```json
{
  "mcpServers": {
    "ghidra-tools": {
      "command": "python3",
      "args": ["/mnt/d/work/Projects/PwnAutomator/mcps/ghidra_tools/wrapper.py"],
      "env": {
        "GHIDRA_HOST": "127.0.0.1",
        "GHIDRA_PORT": "9999",
        "GHIDRA_MCP_BIND_HOST": "0.0.0.0",
        "GHIDRA_MCP_BIND_PORT": "9999",
        "GHIDRA_MCP_DEBUG_BIND_HOST": "0.0.0.0",
        "GHIDRA_MCP_DEBUG_BIND_PORT": "19090",
        "GHIDRA_MCP_DEBUG_HOST": "127.0.0.1",
        "GHIDRA_MCP_DEBUG_PORT": "19090"
      }
    }
  }
}
```

If Claude app runs on Windows and you want wrapper execution inside WSL, use:

```json
{
  "mcpServers": {
    "ghidra-tools": {
      "command": "wsl",
      "args": [
        "bash",
        "-lc",
        "python3 /mnt/d/work/Projects/PwnAutomator/mcps/ghidra_tools/wrapper.py"
      ],
      "env": {
        "GHIDRA_HOST": "127.0.0.1",
        "GHIDRA_PORT": "9999"
      }
    }
  }
}
```

### 5.4 Quick connectivity check

Before connecting Claude, verify raw access:

```bash
cd /mnt/d/work/Projects/PwnAutomator
python3 - <<'PY'
import sys
sys.path.insert(0, "/mnt/d/work/Projects/PwnAutomator")
from mcps.ghidra_tools.client.ghidra_client import GhidraMCP
g = GhidraMCP(host="127.0.0.1", port=9999)
print(g.meta())
PY
```

If this works, the MCP adapter layer is the only remaining step for Claude integration.

Note: if client host is set to `0.0.0.0`, `GhidraMCP` normalizes it to `127.0.0.1` for local TCP connect.
