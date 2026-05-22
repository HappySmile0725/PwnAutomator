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
        managedBy: 'external',
        endpoint: mcpEndpoint('GHIDRA_HOST', 'GHIDRA_PORT', '127.0.0.1', 9999),
        tools: ['help', 'meta', 'func_list', 'decompile_by_name', 'decompile_by_addr', 'search_str']
    },
    {
        name: 'GDB MCP',
        key: 'gdb-mcp',
        managedBy: 'external',
        endpoint: mcpEndpoint('GHIDRA_MCP_DEBUG_HOST', 'GHIDRA_MCP_DEBUG_PORT', '127.0.0.1', 19090),
        tools: ['debug_open_current', 'debug_run', 'debug_regs', 'debug_mem', 'debug_context', 'debug_cmd']
    },
    {
        name: 'Pwntools MCP',
        key: 'pwntools-mcp',
        managedBy: 'external',
        endpoint: mcpEndpoint('GHIDRA_MCP_PWN_HOST', 'GHIDRA_MCP_PWN_PORT', '127.0.0.1', 19191),
        tools: ['pwn_payload_write', 'pwn_payload_execute', 'pwn_session_poll', 'pwn_session_send']
    }
];

const writeJson = async (filePath, payload) => {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
};

const buildManifest = (state) => ({
    version: 1,
    runId: state.runId,
    createdAt: new Date().toISOString(),
    challenge: state.challenge,
    docker: state.docker,
    runtime: state.runtime,
    mcpServers,
    mcpWorkspace: {
        challengeDir: paths.challengeDir,
        metadataDir: paths.challengeMetaDir,
        manifestPath: path.join(paths.challengeMetaDir, 'manifest.json'),
        currentBinaryPathFile: path.join(paths.challengeMetaDir, 'current_binary'),
        payloadPath: path.join(paths.challengeDir, 'hack.py')
    },
    rawTrace: {
        currentTracePath: tracePathsForRun(state.runId).currentTracePath,
        rawDatasetPath: tracePathsForRun(state.runId).rawDatasetPath,
        schema: 'pwnautomator.raw_trace.v1'
    },
    expectedOutputs: {
        solutionDir: paths.solutionDir,
        exploitPath: path.join(paths.solutionDir, 'exploit.py'),
        writeupPath: path.join(paths.solutionDir, 'writeup.md'),
        notesPath: path.join(paths.solutionDir, 'notes.md')
    },
    constraints: {
        startMcpServers: false,
        datasetSchema: 'pending'
    }
});

const prepareCodexTask = async (state) => {
    await fs.mkdir(paths.codexDir, { recursive: true });
    await fs.mkdir(paths.solutionDir, { recursive: true });

    const manifest = buildManifest(state);
    const manifestPath = path.join(paths.codexDir, 'manifest.json');
    const promptPath = path.join(paths.codexDir, 'codex_task.md');

    await writeJson(manifestPath, manifest);
    const prompt = await buildCodexPrompt({ state, manifest, manifestPath, mcpServers });
    const trace = await resetTrace({
        runId: state.runId,
        metadata: {
            manifestPath,
            promptPath,
            mcpServers,
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

const safeJson = (value) => {
    try {
        return JSON.stringify(value, null, 2);
    } catch (_) {
        return String(value);
    }
};

const parseJsonLine = (line) => {
    try {
        return JSON.parse(line);
    } catch (_) {
        return null;
    }
};

const formatCodexEventForOutput = (line) => {
    const event = parseJsonLine(line);
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
            parts.push(`args:\n${safeJson(item.arguments)}`);
        }
        if (item.error) {
            parts.push(`error:\n${safeJson(item.error)}`);
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

const traceCodexLine = ({ tracePath, runId, stream, line }) => {
    const parsed = parseJsonLine(line);
    appendTraceEventSync(tracePath, {
        runId,
        source: 'codex',
        type: parsed ? 'llm_json_event' : 'llm_line',
        stream,
        text: line,
        data: parsed
    });
};

const runCodexAgent = async (state, options = {}) => {
    if (options.signal?.aborted) {
        return {
            status: 'canceled',
            mode: 'autorun',
            exitCode: null,
            promptPath: null,
            manifestPath: null
        };
    }

    const prepared = await prepareCodexTask(state);
    appendLog('info', `Codex task prepared: ${prepared.promptPath}`);
    if (prepared.mcpProfile?.enabled) {
        appendLog('info', `Codex MCP profile prepared: ${prepared.mcpProfile.profileName} (${prepared.mcpProfile.serverName})`);
    }

    if (options.signal?.aborted) {
        return {
            status: 'canceled',
            mode: 'autorun',
            exitCode: null,
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath
        };
    }

    if (!shouldAutorunCodex()) {
        return {
            status: 'waiting',
            mode: 'manual',
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace: prepared.trace,
            message: 'Codex autorun is disabled. Run Codex with the generated task prompt.'
        };
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

    appendLog('info', `Starting Codex agent: ${command} ${args.join(' ')}`.trim());
    appendTraceEventSync(prepared.trace.currentTracePath, {
        runId: state.runId,
        source: 'dashboard',
        type: 'codex_start',
        data: {
            command,
            args,
            cwd: state.challenge?.contextDir || paths.challengeDir
        }
    });

    let result;
    try {
        result = await runCommand({
            command,
            args,
            cwd: state.challenge?.contextDir || paths.challengeDir,
            env: {
                PWN_AUTOMATOR_RUN_ID: state.runId || '',
                PWN_AUTOMATOR_MANIFEST: prepared.manifestPath,
                PWN_AUTOMATOR_PROMPT: prepared.promptPath,
                PWN_AUTOMATOR_SOLUTION_DIR: paths.solutionDir,
                PWN_AUTOMATOR_CONTAINER: state.docker?.containerName || '',
                PWN_AUTOMATOR_CHALLENGE_DIR: paths.challengeDir,
                PWN_AUTOMATOR_BINARY_PATH: state.challenge?.mcpWorkspace?.targetBinaryPath || '',
                PWN_AUTOMATOR_TRACE_ENABLED: process.env.PWN_AUTOMATOR_TRACE_ENABLED || 'true',
                PWN_AUTOMATOR_TRACE_FILE: prepared.trace.currentTracePath,
                PWN_AUTOMATOR_TRACE_RUN_ID: state.runId || '',
                CODEX_MCP_PROFILE: prepared.mcpProfile?.profileName || '',
                CODEX_MCP_SERVER: prepared.mcpProfile?.serverName || '',
                GHIDRA_HOST: mcpServers[0].endpoint.host,
                GHIDRA_PORT: String(mcpServers[0].endpoint.port),
                GHIDRA_MCP_DEBUG_HOST: mcpServers[1].endpoint.host,
                GHIDRA_MCP_DEBUG_PORT: String(mcpServers[1].endpoint.port),
                GHIDRA_MCP_PWN_HOST: mcpServers[2].endpoint.host,
                GHIDRA_MCP_PWN_PORT: String(mcpServers[2].endpoint.port)
            },
            stdin: shouldPipePromptToStdin(args) ? prompt : null,
            signal: options.signal,
            onData: (stream, text) => appendTraceEventSync(prepared.trace.currentTracePath, {
                runId: state.runId,
                source: 'codex',
                type: 'llm_output_chunk',
                stream,
                text
            }),
            onLine: (stream, line) => {
                traceCodexLine({
                    tracePath: prepared.trace.currentTracePath,
                    runId: state.runId,
                    stream,
                    line
                });
                const displayLine = formatCodexEventForOutput(line);
                if (displayLine) {
                    appendLog(classifyCodexLogLevel(line), `codex: ${displayLine}`);
                }
            }
        });
    } catch (error) {
        appendTraceEventSync(prepared.trace.currentTracePath, {
            runId: state.runId,
            source: 'dashboard',
            type: 'codex_error',
            data: { message: error.message }
        });
        await publishRawTrace({ runId: state.runId, status: 'codex_error' });
        throw error;
    }

    appendTraceEventSync(prepared.trace.currentTracePath, {
        runId: state.runId,
        source: 'dashboard',
        type: 'codex_exit',
        data: {
            exitCode: result.code,
            canceled: Boolean(result.canceled)
        }
    });
    const rawTrace = await publishRawTrace({
        runId: state.runId,
        status: result.canceled ? 'canceled' : (result.code === 0 ? 'success' : 'failure')
    });

    if (result.canceled) {
        appendLog('warn', 'Codex agent canceled by user.');
        return {
            status: 'canceled',
            mode: 'autorun',
            exitCode: result.code,
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace
        };
    }

    if (result.code !== 0) {
        throw new Error(`Codex agent exited with code ${result.code}.`);
    }

    return {
        status: 'success',
        mode: 'autorun',
        exitCode: result.code,
        promptPath: prepared.promptPath,
        manifestPath: prepared.manifestPath,
        rawTrace
    };
};

module.exports = {
    mcpServers,
    prepareCodexTask,
    runCodexAgent
};
