# PwnAutomator

PwnAutomator is a web dashboard for running an automated pwnable challenge workflow with Codex and MCP tools.

The dashboard follows an MVC structure:

- `pwnable-dashboard/controllers`: HTTP request/response handling
- `pwnable-dashboard/routers`: route mapping
- `pwnable-dashboard/services`: pipeline, Codex, Docker, MCP, and dataset logic
- `pwnable-dashboard/models`: persisted dashboard state
- `pwnable-dashboard/views`: EJS pages

## Pipeline

```text
Challenge Upload
  -> Docker Build
  -> Container Start
  -> Inspect Runtime
  -> Codex Agent
       -> Ghidra MCP
       -> GDB MCP
       -> Pwntools MCP
  -> Dataset Save
```

MCP servers are external. The dashboard prepares the Codex prompt/profile and launches Codex, but it does not start MCP servers.

## Requirements

Run the dashboard, Docker, Codex CLI, and MCP servers in the same WSL/Ubuntu environment.

Required tools:

- Node.js 20 or newer
- Docker
- Codex CLI installed and logged in inside WSL/Ubuntu
- Python packages required by the MCP servers, such as `fastmcp` and `pwntools`
- Ghidra unpacked under `mcps`

Recommended Codex install inside WSL/Ubuntu:

```bash
npm install -g @openai/codex@latest --include=optional
codex login
codex login status
```

If `which codex` points to `/mnt/c/...`, install Codex again inside WSL. Do not use the Windows Codex install from WSL.

## Quick Start

```bash
cd /mnt/d/Coding/Projects/PwnAutomator
cd pwnable-dashboard
npm install
cp .env.example .env
cd ..
bash scripts/start-dashboard-wsl.sh
```

Dashboard URL:

```text
http://localhost:3000
```

After uploading a challenge from the dashboard, start MCP servers manually:

```bash
cd /mnt/d/Coding/Projects/PwnAutomator/mcps
./run_ghidra_server.sh
```

Then click `Start Pipeline` in the dashboard.

## Active Workspace

Uploaded challenge files are normalized into one shared workspace:

```text
mcps/test
```

When a new challenge is uploaded, the dashboard resets:

```text
mcps/test
pwnable-dashboard/data/storage/now/upload
pwnable-dashboard/data/storage/now/solution
pwnable-dashboard/data/storage/now/codex
pwnable-dashboard/data/storage/now/dataset
pwnable-dashboard/data/storage/now/trace
```

## Codex

Codex autorun is enabled by default.

Default command:

```bash
codex exec --json -m gpt-5.3-codex --profile-v2 pwnautomator -
```

Before Codex starts, the dashboard writes a Codex MCP profile:

```text
$CODEX_HOME/pwnautomator.config.toml
```

That profile points Codex to:

```text
mcps/ghidra_tools/wrapper.py
```

The generated LLM input files are written to:

```text
pwnable-dashboard/data/storage/now/codex/manifest.json
pwnable-dashboard/data/storage/now/codex/codex_task.md
```

`manifest.json` is intentionally small. It only stores runtime context Codex needs: challenge path, target binary, container reference, solution output paths, MCP endpoints, and the active JSONL trace path.

The system prompt is file-first:

```text
guidline_docs/codex-system-prompt.md
```

Override it with:

```bash
CODEX_SYSTEM_PROMPT_FILE=path/to/system-prompt.md
```

Short inline overrides are also supported:

```bash
CODEX_SYSTEM_PROMPT="system instructions"
CODEX_USER_PROMPT="solve the pwnable challenge"
```

To disable autorun and only write the Codex task files:

```bash
CODEX_AGENT_AUTORUN=false bash scripts/start-dashboard-wsl.sh
```

## MCP Servers

The default MCP ports are:

```text
Ghidra MCP:   9999
GDB MCP:      19090
Pwntools MCP: 19191
```

Start all MCP services with:

```bash
cd mcps
./run_ghidra_server.sh
```

The script reads the current uploaded binary from:

```text
mcps/test/.pwnautomator/current_binary
```

You can also pass a binary path explicitly:

```bash
./run_ghidra_server.sh ./test/chall
```

## Dataset Output

The raw fine-tuning trace is written as JSONL:

```text
pwnable-dashboard/data/storage/now/trace/codex_raw_trace.jsonl
datasets/raw/<runId>.jsonl
```

Clicking `Save Dataset` writes:

```text
datasets/packages/DataSet<number>_<problemName>.zip
pwnable-dashboard/data/storage/now/dataset/dataset_package.zip
```

The package includes:

- original uploaded files under `uploads/`
- `challenge_workspace.zip`
- exploit artifacts when present
- `raw/codex_raw_trace.jsonl`
- `codex/manifest.json`
- `codex/codex_task.md`

`dataset_draft.json` is not generated.

## Environment Variables

Common dashboard and Codex settings:

```bash
HOST=0.0.0.0
PORT=3000
CODEX_AGENT_AUTORUN=true
CODEX_AGENT_COMMAND=codex
CODEX_AGENT_MODEL=gpt-5.3-codex
CODEX_AGENT_ARGS="exec --json -m gpt-5.3-codex --profile-v2 pwnautomator -"
CODEX_AGENT_JSON_TRACE=true
CODEX_SYSTEM_PROMPT_FILE=guidline_docs/codex-system-prompt.md
CODEX_PROMPT_MAX_BYTES=262144
PWN_AUTOMATOR_TRACE_ENABLED=true
PWN_AUTOMATOR_CHALLENGE_DIR=mcps/test
UPLOAD_LIMIT_BYTES=209715200
```

Codex MCP profile settings:

```bash
CODEX_MCP_AUTOCONFIG=true
CODEX_MCP_PROFILE=pwnautomator
CODEX_MCP_SERVER_NAME=pwnautomator
CODEX_MCP_WRAPPER=mcps/ghidra_tools/wrapper.py
```

MCP endpoint overrides:

```bash
GHIDRA_HOST=127.0.0.1
GHIDRA_PORT=9999
GHIDRA_MCP_DEBUG_HOST=127.0.0.1
GHIDRA_MCP_DEBUG_PORT=19090
GHIDRA_MCP_PWN_HOST=127.0.0.1
GHIDRA_MCP_PWN_PORT=19191
```

## Runtime Notes

If a matching challenge container is already running, the pipeline reuses it and skips Docker build/container start.

Container matching uses:

- current container ID
- current container name
- `pwnautomator.runId` Docker label
- current image tag

## Stop Services

Dashboard in the foreground:

```bash
Ctrl+C
```

Dashboard started in tmux:

```bash
tmux kill-session -t pwnautomator-web
```

MCP server script in the foreground:

```bash
Ctrl+C
```

MCP server started in tmux:

```bash
tmux kill-session -t pwnautomator-mcp
```

## Troubleshooting

Check dashboard port:

```bash
ss -ltnp | grep ':3000'
```

Check MCP ports:

```bash
ss -ltnp | grep -E ':(9999|19090|19191)'
```

If Codex reports a missing Linux optional dependency, reinstall it inside WSL:

```bash
npm install -g @openai/codex@latest --include=optional
```

If Codex login refresh fails, log out and sign in again inside WSL:

```bash
codex logout
codex login
codex login status
```
