const fs = require('fs').promises;
const path = require('path');

const paths = require('./paths');
const { appendLog } = require('./state.service');
const { applyTemplate, parseCommandLine, runCommand } = require('./command.service');
const { buildCodexPrompt } = require('./codexPrompt.service');
const {
    appendTraceEventSync,
    isTraceEnabled,
    publishRawTrace,
    resetTrace,
    tracePathsForRun
} = require('./trace.service');
const {
    ensureCodexMcpProfile,
    getCodexMcpProfileName,
    PWNO_ENABLED_TOOLS,
    WRAPPER_ENABLED_TOOLS,
    shouldConfigureCodexMcp
} = require('./codexMcpProfile.service');

const mcpEndpoint = (hostEnv, portEnv, defaultHost, defaultPort) => ({
    host: process.env[hostEnv] || defaultHost,
    port: Number(process.env[portEnv]) || defaultPort
});

const mcpServers = [
    {
        name: 'Ghidra MCP',
        key: 'ghidra-mcp',
        managedBy: 'dashboard',
        endpoint: mcpEndpoint('GHIDRA_HOST', 'GHIDRA_PORT', '127.0.0.1', 9999),
        tools: WRAPPER_ENABLED_TOOLS
    },
    {
        name: 'Pwno MCP',
        key: 'pwno-mcp',
        managedBy: 'dashboard',
        endpoint: mcpEndpoint('PWNO_MCP_HOST', 'PWNO_MCP_PORT', '127.0.0.1', 5500),
        tools: PWNO_ENABLED_TOOLS
    },
    {
        name: 'Pwntools MCP',
        key: 'pwntools-mcp',
        managedBy: 'dashboard',
        endpoint: mcpEndpoint('GHIDRA_MCP_PWN_HOST', 'GHIDRA_MCP_PWN_PORT', '127.0.0.1', 19191),
        tools: ['pwn_payload_write', 'pwn_payload_execute', 'pwn_session_poll', 'pwn_session_send']
    }
];
const [ghidraMcp, pwnoMcp, pwntoolsMcp] = mcpServers;

const defaultCodexServerName = () => String(process.env.CODEX_MCP_SERVER_NAME || 'pwnautomator').trim() || 'pwnautomator';
const defaultPwnoServerName = () => String(process.env.CODEX_PWNO_MCP_SERVER_NAME || 'pwno').trim() || 'pwno';

const resolveMcpServerRouting = (servers) => {
    const codexServerName = defaultCodexServerName();
    const pwnoServerName = defaultPwnoServerName();

    return (servers || []).map((server) => ({
        ...server,
        codexServer: server?.key === 'pwno-mcp' ? pwnoServerName : codexServerName
    }));
};

const writeJson = async (filePath, payload) => {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
};

const buildCodexManifest = (state, resolvedMcpServers) => {
    const tracePaths = tracePathsForRun(state.runId);
    return {
        version: 1,
        runId: state.runId,
        createdAt: new Date().toISOString(),
        challenge: {
            dir: paths.challengeDir,
            contextDir: state.challenge?.contextDir || paths.challengeDir,
            targetBinaryPath: state.challenge?.mcpWorkspace?.targetBinaryPath || '',
            trackingFiles: state.challenge?.trackingFiles || [],
            currentBinaryMarker: path.join(paths.challengeMetaDir, 'current_binary')
        },
        container: {
            name: state.docker?.containerName || '',
            id: state.docker?.containerId || '',
            ports: state.runtime?.network?.ports || []
        },
        solution: {
            solutionDir: paths.solutionDir,
            exploitPath: path.join(paths.solutionDir, 'exploit.py'),
            writeupPath: path.join(paths.solutionDir, 'writeup.md'),
            notesPath: path.join(paths.solutionDir, 'notes.md')
        },
        mcpServers: (resolvedMcpServers || []).map((server) => ({
            key: server.key,
            name: server.name,
            codexServer: server.codexServer,
            endpoint: server.endpoint,
            tools: server.tools
        })),
        trace: {
            jsonlPath: tracePaths.currentTracePath
        }
    };
};

const prepareCodexTask = async (state) => {
    await fs.mkdir(paths.codexDir, { recursive: true });
    await fs.mkdir(paths.solutionDir, { recursive: true });

    const resolvedMcpServers = resolveMcpServerRouting(mcpServers);
    const manifest = buildCodexManifest(state, resolvedMcpServers);
    const manifestPath = path.join(paths.codexDir, 'manifest.json');
    const promptPath = path.join(paths.codexDir, 'codex_task.md');

    await writeJson(manifestPath, manifest);
    const prompt = await buildCodexPrompt({ state, manifest, manifestPath, mcpServers: resolvedMcpServers });
    const trace = await resetTrace({
        runId: state.runId,
        metadata: {
            manifestPath,
            promptPath,
            mcpServers: resolvedMcpServers,
            promptMetadata: prompt.metadata
        }
    });
    const mcpProfile = await ensureCodexMcpProfile(state, mcpServers, trace);
    await fs.writeFile(promptPath, prompt.content, 'utf8');
    appendTraceEventSync(trace.currentTracePath, {
        runId: state.runId,
        source: 'dashboard',
        type: 'codex_prompt',
        text: prompt.content,
        data: {
            promptPath,
            manifestPath,
            promptMetadata: prompt.metadata
        }
    });

    return { manifest, manifestPath, promptPath, promptMetadata: prompt.metadata, mcpProfile, trace };
};

const shouldAutorunCodex = () => String(process.env.CODEX_AGENT_AUTORUN || 'true').toLowerCase() !== 'false';

const defaultCodexModel = () => process.env.CODEX_AGENT_MODEL || 'gpt-5.3-codex';

const defaultCodexArgs = () => {
    const profileArgs = shouldConfigureCodexMcp() ? ` --profile-v2 ${getCodexMcpProfileName()}` : '';
    return `exec -m ${defaultCodexModel()}${profileArgs} -`;
};

const ensureMcpProfileArgs = (args) => {
    if (!shouldConfigureCodexMcp() || args.includes('--profile-v2') || args.some((arg) => arg.startsWith('--profile-v2='))) {
        return args;
    }
    if (args[0] !== 'exec') {
        return args;
    }
    return ['exec', '--profile-v2', getCodexMcpProfileName(), ...args.slice(1)];
};

const ensureJsonTraceArgs = (args) => {
    if (!isTraceEnabled() || String(process.env.CODEX_AGENT_JSON_TRACE || 'true').toLowerCase() === 'false') {
        return args;
    }
    if (args[0] !== 'exec' || args.includes('--json')) {
        return args;
    }
    return ['exec', '--json', ...args.slice(1)];
};

const resolveCodexArgs = (variables) => {
    const configuredArgs = process.env.CODEX_AGENT_ARGS;
    const rawArgs = configuredArgs && configuredArgs.trim() ? configuredArgs : defaultCodexArgs();
    const args = parseCommandLine(rawArgs).map((arg) => applyTemplate(arg, variables));
    return ensureJsonTraceArgs(ensureMcpProfileArgs(args));
};

const shouldPipePromptToStdin = (args) => {
    const configured = process.env.CODEX_AGENT_STDIN;
    if (configured !== undefined) {
        return String(configured).toLowerCase() !== 'false';
    }
    return args.length === 0 || args.includes('-');
};

const classifyCodexLogLevel = (line) => {
    const normalized = String(line || '').toLowerCase();
    if (normalized.includes('error:') || normalized.includes('"type":"error"') || normalized.includes('"status":400')) {
        return 'error';
    }
    if (normalized.includes('warning:') || normalized.startsWith('warn ')) {
        return 'warn';
    }
    return 'info';
};

const toJson = (value) => JSON.stringify(value, null, 2);

const parseJsonLine = (line) => {
    try {
        return JSON.parse(line);
    } catch (_) {
        return null;
    }
};

const formatCodexEventForOutput = (line, event) => {
    if (!event) {
        return line;
    }

    const item = event.item || {};
    if (item.type === 'agent_message') {
        return item.text || '';
    }

    if (item.type === 'mcp_tool_call') {
        const server = item.server || 'mcp';
        const tool = item.tool || 'tool';
        const status = item.status || (event.type === 'item.started' ? 'started' : 'completed');
        const parts = [`mcp: ${server}/${tool} ${status}`];
        if (event.type === 'item.started' && item.arguments && Object.keys(item.arguments).length > 0) {
            parts.push(`args:\n${toJson(item.arguments)}`);
        }
        if (item.error) {
            parts.push(`error:\n${toJson(item.error)}`);
        }
        return parts.join('\n');
    }

    if (event.type === 'turn.completed') {
        const usage = event.usage || {};
        return [
            'codex turn completed',
            `input_tokens: ${usage.input_tokens ?? 0}`,
            `output_tokens: ${usage.output_tokens ?? 0}`,
            `reasoning_output_tokens: ${usage.reasoning_output_tokens ?? 0}`
        ].join('\n');
    }

    if (item.text) {
        return item.text;
    }


    if (event.message) {
        return event.message;
    }

    return `codex event: ${event.type || 'unknown'}`;
};

const traceCodexLine = ({ tracePath, runId, stream, line, parsed }) => {
    appendTraceEventSync(tracePath, {
        runId,
        source: 'codex',
        type: parsed ? 'llm_json_event' : 'llm_line',
        stream,
        text: line,
        data: parsed
    });
};

const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

const summarizeGdb = (gdbStdout) => {
    const lines = (gdbStdout || '').split('\n');
    const bt = lines.filter(l => l.startsWith('#') || l.includes('in ') || l.includes('at ')).slice(0, 5);
    const regs = lines.filter(l => /^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|eflags|cs|ss|ds|es|fs|gs)\b/i.test(l)).slice(0, 5);
    return [...bt, ...regs].join('\n') || lines.slice(0, 10).join('\n');
};

const extractExploitMetadata = async (exploitPath, diagLogs) => {
    const exists = await fs.access(exploitPath).then(() => true).catch(() => false);
    const content = exists ? await fs.readFile(exploitPath, 'utf8') : '';
    const metadata = {
        canary: 'Not Leaked',
        libcBase: 'Not Leaked',
        systemAddr: 'Not Leaked'
    };

    if (content) {
        const canaryMatch = content.match(/canary\s*=\s*(0x[0-9a-fA-F]+)/);
        if (canaryMatch) metadata.canary = canaryMatch[1];

        const libcMatch = content.match(/(libc_base|libc\.address)\s*=\s*(0x[0-9a-fA-F]+)/);
        if (libcMatch) metadata.libcBase = libcMatch[2];

        const systemMatch = content.match(/(system_addr|system)\s*=\s*(0x[0-9a-fA-F]+)/);
        if (systemMatch) metadata.systemAddr = systemMatch[2];
    }

    if (diagLogs) {
        const cleanLogs = String(diagLogs);
        const logCanary = cleanLogs.match(/(canary|leaked\s+canary)\s*[:=]\s*(0x[0-9a-fA-F]+)/i) || cleanLogs.match(/canary:\s*(0x[0-9a-fA-F]+)/i);
        if (logCanary && metadata.canary === 'Not Leaked') metadata.canary = logCanary[2] || logCanary[1];

        const logLibc = cleanLogs.match(/(libc|libc_base|libc\s+base|leaked\s+libc)\s*[:=]\s*(0x[0-9a-fA-F]+)/i);
        if (logLibc && metadata.libcBase === 'Not Leaked') metadata.libcBase = logLibc[2];

        const logSystem = cleanLogs.match(/(system|system_addr|system\s+address)\s*[:=]\s*(0x[0-9a-fA-F]+)/i);
        if (logSystem && metadata.systemAddr === 'Not Leaked') metadata.systemAddr = logSystem[2];
    }

    return metadata;
};

const executeAndDiagnose = async (exploitPath, binaryPath) => {
    const result = await execAsync(`timeout 5 python3 ${exploitPath}`, { cwd: paths.solutionDir })
        .then(() => ({ success: true }))
        .catch(async (err) => {
            const logs = `STDOUT:\n${err.stdout || ''}\nSTDERR:\n${err.stderr || ''}`;
            let category = 'Unknown Failure';
            let description = 'The exploit script failed during execution.';

            if ((err.stderr || '').includes('stack smashing detected')) {
                category = 'Canary Bypass Failure';
                description = 'Stack smashing was detected. Canary value was overwritten with incorrect value.';
            } else if ((err.stderr || '').includes('Segmentation fault') || (err.stderr || '').includes('SIGSEGV') || err.signal === 'SIGSEGV') {
                category = 'Memory Corruption (SIGSEGV)';
                description = 'The binary crashed with SIGSEGV. Check ROP chain addresses and stack alignment/offsets.';
            } else if (err.code === 124) {
                category = 'Execution Timeout';
                description = 'The exploit hung or timed out. Check if interactive shell is locked or size is wrong.';
            }

            const gdbRes = await execAsync(`gdb -batch -ex "run" -ex "bt" -ex "info registers" -ex "quit" ${binaryPath}`).catch((gdbErr) => gdbErr);
            return {
                success: false,
                category,
                description,
                logs: `${logs}\nGDB Traceback (Summary):\n${summarizeGdb(gdbRes.stdout || gdbRes.message)}`
            };
        });
    return result;
};

const runSingleTurn = async (state, promptFile, model, extraPrompt = '', options = {}) => {
    process.env.CODEX_SYSTEM_PROMPT_FILE = promptFile;
    process.env.CODEX_AGENT_MODEL = model;

    const prepared = await prepareCodexTask(state);
    if (extraPrompt) {
        await fs.appendFile(prepared.promptPath, `\n\n${extraPrompt}`, 'utf8');
    }

    const command = process.env.CODEX_AGENT_COMMAND || 'codex';
    const variables = {
        promptFile: prepared.promptPath,
        manifestFile: prepared.manifestPath,
        contextDir: state.challenge?.contextDir || paths.challengeDir,
        solutionDir: paths.solutionDir,
        runId: state.runId,
        containerName: state.docker?.containerName || '',
        containerId: state.docker?.containerId || '',
        mcpProfile: prepared.mcpProfile?.profileName || getCodexMcpProfileName(),
        mcpServer: prepared.mcpProfile?.serverName || 'pwnautomator'
    };
    const args = resolveCodexArgs(variables);
    const prompt = await fs.readFile(prepared.promptPath, 'utf8');

    let rawOutput = '';
    let jsonOutput = '';
    const isJsonMode = args.includes('--json');

    const result = await runCommand({
        command,
        args,
        cwd: state.challenge?.contextDir || paths.challengeDir,
        env: {
            ...process.env,
            PWN_AUTOMATOR_RUN_ID: state.runId || '',
            PWN_AUTOMATOR_PROMPT: prepared.promptPath,
            PWN_AUTOMATOR_SOLUTION_DIR: paths.solutionDir,
            PWN_AUTOMATOR_BINARY_PATH: state.challenge?.mcpWorkspace?.targetBinaryPath || '',
            PWN_AUTOMATOR_TRACE_FILE: prepared.trace.currentTracePath,
            PWN_AUTOMATOR_TRACE_RUN_ID: state.runId || '',
            CODEX_MCP_PROFILE: prepared.mcpProfile?.profileName || '',
            CODEX_MCP_SERVER: prepared.mcpProfile?.serverName || '',
            GHIDRA_HOST: ghidraMcp.endpoint.host,
            GHIDRA_PORT: String(ghidraMcp.endpoint.port),
            PWNO_MCP_HOST: pwnoMcp.endpoint.host,
            PWNO_MCP_PORT: String(pwnoMcp.endpoint.port),
            GHIDRA_MCP_PWN_HOST: pwntoolsMcp.endpoint.host,
            GHIDRA_MCP_PWN_PORT: String(pwntoolsMcp.endpoint.port)
        },
        stdin: shouldPipePromptToStdin(args) ? prompt : null,
        signal: options.signal,
        onData: (stream, text) => {
            if (stream === 'stdout') {
                rawOutput += text;
            }
            appendTraceEventSync(prepared.trace.currentTracePath, {
                runId: state.runId,
                source: 'codex',
                type: 'llm_output_chunk',
                stream,
                text
            });
        },
        onLine: (stream, line) => {
            const parsed = parseJsonLine(line);
            if (parsed && stream === 'stdout') {
                const item = parsed.item || {};
                if (item.type === 'agent_message' && item.text) {
                    jsonOutput += item.text;
                } else if (item.text) {
                    jsonOutput += item.text;
                }
            }
            traceCodexLine({
                tracePath: prepared.trace.currentTracePath,
                runId: state.runId,
                stream,
                line,
                parsed
            });
            const displayLine = formatCodexEventForOutput(line, parsed);
            if (displayLine) {
                appendLog(classifyCodexLogLevel(line), `codex: ${displayLine}`);
            }
        }
    });

    if (result.code !== 0) {
        throw new Error(`Agent turn exited with code ${result.code}`);
    }

    return isJsonMode ? jsonOutput : rawOutput;
};

const parseDiscoveryWithCorrection = async (state, options) => {
    let retries = 0;
    let extraPrompt = '';
    const model = process.env.CODEX_LORA_ANALYSIS || 'pwn-discovery';
    const promptFile = 'guidline_docs/system-prompt-discovery.md';

    while (retries < 3) {
        const output = await runSingleTurn(state, promptFile, model, extraPrompt, options);
        const start = output.indexOf('{');
        const end = output.lastIndexOf('}');
        
        if (start === -1 || end === -1 || start >= end) {
            extraPrompt = 'Error: No JSON object block found in the output. Wrap the JSON structure in {...}.';
            retries++;
            continue;
        }

        const jsonCandidate = output.substring(start, end + 1).trim();
        try {
            const parsed = JSON.parse(jsonCandidate);
            if (parsed.targets && Array.isArray(parsed.targets)) {
                return parsed;
            }
            extraPrompt = 'Error: Expected "targets" key array is missing. Review the schema guidelines.';
        } catch (err) {
            extraPrompt = `Error: Invalid JSON structure inside output. Error: ${err.message}. Provide raw valid JSON only.`;
        }
        retries++;
    }
    throw new Error('Discovery phase failed to yield valid JSON.');
};

const runCoderWithDiagnosis = async (state, discoveryResult, options) => {
    let retries = 0;
    let extraPrompt = `Discovery Targets:\n${JSON.stringify(discoveryResult, null, 2)}`;
    const model = process.env.CODEX_LORA_CODER || 'pwn-coder';
    const promptFile = 'guidline_docs/system-prompt-coder.md';
    const exploitPath = path.join(paths.solutionDir, 'exploit.py');

    while (retries < 3) {
        await runSingleTurn(state, promptFile, model, extraPrompt, options);
        
        const exploitExists = await fs.access(exploitPath).then(() => true).catch(() => false);
        if (!exploitExists) {
            const hackPath = path.join(paths.challengeDir, 'hack.py');
            const hackExists = await fs.access(hackPath).then(() => true).catch(() => false);
            if (hackExists) {
                await fs.copyFile(hackPath, exploitPath).catch(() => {});
            }
        }

        const exploitReady = await fs.access(exploitPath).then(() => true).catch(() => false);
        if (!exploitReady) {
            extraPrompt = 'Error: exploit.py was not created. Ensure exploit file is saved.';
            retries++;
            continue;
        }

        const diag = await executeAndDiagnose(exploitPath, state.challenge?.mcpWorkspace?.targetBinaryPath);
        if (diag.success) {
            return;
        }

        const exploitMeta = await extractExploitMetadata(exploitPath, diag.logs);
        const metaHeader = exploitMeta ? `[Exploit Memory Map Status]\n- Canary: ${exploitMeta.canary}\n- Libc Base: ${exploitMeta.libcBase}\n- System Address: ${exploitMeta.systemAddr}\n\n` : '';
        extraPrompt = `${metaHeader}Exploit Failure Diagnosis:\n- Category: ${diag.category}\n- Description: ${diag.description}\n- Execution Logs:\n${diag.logs}\nAdjust offsets or payload structure to fix.`;
        retries++;
    }
    throw new Error('Coder phase failed to produce a working exploit.');
};

const runCodexAgent = async (state, options = {}) => {
    if (options.signal?.aborted) {
        return { status: 'canceled', mode: 'autorun', exitCode: null, promptPath: null, manifestPath: null };
    }

    const initialPrompt = 'guidline_docs/system-prompt-discovery.md';
    const prepared = await prepareCodexTask(state);
    appendLog('info', `Multi-Agent Pipeline prepared: ${prepared.promptPath}`);

    if (options.signal?.aborted) {
        return { status: 'canceled', mode: 'autorun', exitCode: null, promptPath: prepared.promptPath, manifestPath: prepared.manifestPath };
    }

    if (!shouldAutorunCodex()) {
        return {
            status: 'waiting',
            mode: 'manual',
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace: prepared.trace,
            message: 'Codex autorun is disabled.'
        };
    }

    let rawTrace;
    try {
        appendLog('info', 'Phase 1: Starting vulnerability discovery scan.');
        const discoveryResult = await parseDiscoveryWithCorrection(state, options);
        appendLog('info', `Discovery phase completed. Targets: ${discoveryResult.targets.map(t => t.function_name).join(', ')}`);

        appendLog('info', 'Phase 2: Starting exploit code generation and verification.');
        await runCoderWithDiagnosis(state, discoveryResult, options);
        appendLog('info', 'Multi-Agent pipeline completed successfully.');

        rawTrace = await publishRawTrace({ runId: state.runId, status: 'success' });
        return {
            status: 'success',
            mode: 'autorun',
            exitCode: 0,
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace
        };
    } catch (error) {
        appendLog('error', `Pipeline execution error: ${error.message}`);
        appendTraceEventSync(prepared.trace.currentTracePath, {
            runId: state.runId,
            source: 'dashboard',
            type: 'codex_error',
            data: { message: error.message }
        });
        rawTrace = await publishRawTrace({ runId: state.runId, status: 'failure' });
        return {
            status: 'failure',
            mode: 'autorun',
            exitCode: 1,
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace
        };
    }
};

module.exports = {
    runCodexAgent
};
