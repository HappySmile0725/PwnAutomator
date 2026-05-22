# PwnAutomator
---

## Summary
- CTF Pwnable Auto Solver
---

## Dashboard Pipeline
The web dashboard now follows this flow:

1. Challenge Upload
2. Docker Build
3. Container Start
4. Inspect Runtime
5. Codex Agent
   - Ghidra MCP
   - GDB MCP
   - Pwntools MCP
6. Dataset Save

MCP servers are treated as external services. Start them yourself before running Codex; the dashboard only prepares the Codex task manifest/prompt and optionally launches a configured Codex command.

Optional environment variables:

```bash
CODEX_AGENT_COMMAND=codex
CODEX_AGENT_MODEL=gpt-5.3-codex
CODEX_MCP_AUTOCONFIG=true
CODEX_MCP_PROFILE=pwnautomator
CODEX_MCP_SERVER_NAME=pwnautomator
CODEX_MCP_WRAPPER=mcps/ghidra_tools/wrapper.py
CODEX_AGENT_ARGS="exec --json -m gpt-5.3-codex --profile-v2 pwnautomator -"
CODEX_AGENT_JSON_TRACE=true
CODEX_SYSTEM_PROMPT_FILE=guidline_docs/codex-system-prompt.md
CODEX_PROMPT_MAX_BYTES=262144
PWN_AUTOMATOR_TRACE_ENABLED=true
EXPLOIT_VERIFY_COMMAND="python {exploitPath}"
UPLOAD_LIMIT_BYTES=209715200
```

Codex autorun is enabled by default. Set `CODEX_AGENT_AUTORUN=false` to pause at Codex Agent and only write the prompt/manifest under `pwnable-dashboard/data/storage/now/codex`.
Uploaded challenge files are extracted into the single MCP/web workspace: `mcps/test`.

Dataset schema is intentionally pending. The current save step writes a draft JSON under `pwnable-dashboard/data/storage/now/dataset`.
---

## WSL/Ubuntu run
Run the dashboard, Codex CLI, Docker, and MCP servers inside the same WSL/Ubuntu environment. Do not run the dashboard on Windows while trying to launch Codex in WSL; paths must stay in one Linux namespace.

1. Open WSL/Ubuntu and move to the repo.
```bash
cd /mnt/d/Coding/Projects/PwnAutomator
```

2. Install dashboard dependencies.
```bash
cd pwnable-dashboard
npm install
cp .env.example .env
cd ..
```

3. Make sure Codex is installed and authenticated inside WSL/Ubuntu.
```bash
which codex
codex login
```

4. Start the dashboard in WSL/Ubuntu.
```bash
bash scripts/start-dashboard-wsl.sh
```

Default dashboard URL:
```text
http://localhost:3000
```

5. Upload a challenge from the dashboard. The uploaded challenge becomes the single shared workspace:
```text
mcps/test
```

6. Start MCP servers manually from WSL/Ubuntu after upload.
```bash
cd mcps
./run_ghidra_server.sh
```

7. Click `Run Pipeline` in the dashboard. The dashboard runs Codex in WSL/Ubuntu with:
```bash
codex exec --json -m gpt-5.3-codex --profile-v2 pwnautomator -
```

If a matching challenge container is already running, the pipeline reuses it and skips Docker build/container start. Matching is based on the current run container name, `pwnautomator.runId` label, or the current run image tag.

Raw fine-tuning traces are written as JSONL:
```text
pwnable-dashboard/data/storage/now/trace/codex_raw_trace.jsonl
datasets/raw/<runId>.jsonl
```

The trace records Codex-visible output, Codex JSON events, MCP tool calls, and MCP tool responses in append order. Hidden model reasoning is not available unless Codex emits it as visible text or a reasoning summary.

Clicking `Save Dataset` writes a package zip:
```text
datasets/packages/<runId>.zip
```

The package includes the original uploaded files, `challenge_workspace.zip`, exploit Python artifacts when present, `codex_raw_trace.jsonl`, `codex_raw_trace.json`, and metadata.

Before Codex starts, the dashboard writes `$CODEX_HOME/pwnautomator.config.toml` so Codex can use the repo MCP wrapper:
```text
mcps/ghidra_tools/wrapper.py
```

The prompt instructs Codex to use MCP tools only for binary analysis, debugging, runtime inspection, and exploit trials. Start MCP services yourself before `Run Pipeline`; the dashboard does not start them.

The current prompt is intentionally minimal:
```text
pwnable 문제를 풀어라
```

System prompting is file-first. Edit `guidline_docs/codex-system-prompt.md`, or override it with:
```bash
CODEX_SYSTEM_PROMPT_FILE=path/to/system-prompt.md
```

Short one-off overrides are also supported:
```bash
CODEX_SYSTEM_PROMPT="system instructions"
CODEX_USER_PROMPT="pwnable 문제를 풀어라"
```

## How to run
1. You must have `gdb-peda`
 
2. `pip install fastmcp pwntools`

3. Download ghidra and unzip folder in `mcps` directory (FYI : https://dokhakdubini.tistory.com/564)
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

5. Upload the challenge from the dashboard. The dashboard writes the active challenge workspace to `mcps/test`.

6. Fast run
```bash
./run_ghidra_server.sh
```
  - if some files exists in `mcps/challenge`, delete them all

7. Individual exec
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

8. Close Server
- Just `Ctrl + C`. run_ghidra_server.sh will clear backup files and cache folders.
