const fs = require('fs').promises;
const path = require('path');

const paths = require('./paths');
const { applyTemplate } = require('./command.service');

const DEFAULT_SYSTEM_PROMPT = 'You are the autonomous pwnable solver for PwnAutomator.';
const DEFAULT_USER_PROMPT = 'pwnable \uBB38\uC81C\uB97C \uD480\uC5B4\uB77C';
const DEFAULT_PROMPT_MAX_BYTES = 256 * 1024;
const DEFAULT_SYSTEM_PROMPT_FILE = path.join(paths.repoRoot, 'guidline_docs', 'codex-system-prompt.md');

const promptEnv = {
    systemPrompt: 'CODEX_SYSTEM_PROMPT',
    systemPromptFile: 'CODEX_SYSTEM_PROMPT_FILE',
    userPrompt: 'CODEX_USER_PROMPT',
    userPromptFile: 'CODEX_USER_PROMPT_FILE',
    maxBytes: 'CODEX_PROMPT_MAX_BYTES'
};

const nonEmpty = (value) => typeof value === 'string' && value.trim().length > 0;

const resolveRepoPath = (value) => {
    const raw = String(value || '').trim();
    return path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(paths.repoRoot, raw);
};

const maxPromptBytes = () => {
    const configured = Number(process.env[promptEnv.maxBytes]);
    return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_PROMPT_MAX_BYTES;
};

const enforcePromptSize = (label, value) => {
    const bytes = Buffer.byteLength(value || '', 'utf8');
    const limit = maxPromptBytes();
    if (bytes > limit) {
        throw new Error(`${label} is ${bytes} bytes, above CODEX_PROMPT_MAX_BYTES=${limit}.`);
    }
};

const readOptionalFile = async (filePath) => {
    try {
        return await fs.readFile(filePath, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        throw error;
    }
};

const readPromptSource = async ({ fileEnv, inlineEnv, fallback, defaultFile, variables, label }) => {
    const configuredFile = process.env[fileEnv];
    const configuredInline = process.env[inlineEnv];

    let value = fallback;
    let source = 'default';
    let filePath = null;

    if (nonEmpty(configuredInline)) {
        value = configuredInline;
        source = 'env';
    }

    if (nonEmpty(configuredFile)) {
        filePath = resolveRepoPath(configuredFile);
        value = await fs.readFile(filePath, 'utf8');
        source = 'file';
    } else if (defaultFile) {
        const defaultFileValue = await readOptionalFile(defaultFile);
        if (defaultFileValue !== null) {
            filePath = defaultFile;
            value = defaultFileValue;
            source = 'default-file';
        }
    }

    const rendered = applyTemplate(value, variables).trim();
    enforcePromptSize(label, rendered);
    return { value: rendered, source, filePath };
};

const compactValue = (value, fallback = '-') => {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }
    return String(value);
};

const formatMcpServers = (servers) => servers.map((server) => {
    const endpoint = `${server.endpoint.host}:${server.endpoint.port}`;
    const tools = Array.isArray(server.tools) ? server.tools.join(', ') : '-';
    return `- ${server.name}: ${endpoint}; managed=${server.managedBy}; tools=${tools}`;
}).join('\n');

const buildPromptVariables = ({ state, manifest, manifestPath }) => ({
    runId: state.runId || '',
    manifestPath,
    challengeDir: manifest.challenge.dir,
    solutionDir: manifest.solution.solutionDir,
    exploitPath: manifest.solution.exploitPath,
    writeupPath: manifest.solution.writeupPath,
    notesPath: manifest.solution.notesPath,
    containerName: manifest.container.name,
    containerId: manifest.container.id,
    targetBinaryPath: manifest.challenge.targetBinaryPath
});

const buildRuntimeContext = ({ state, manifest, manifestPath, mcpServers }) => [
    '# Runtime Context',
    `- Run ID: ${compactValue(state.runId)}`,
    `- Manifest: ${manifestPath}`,
    `- Challenge directory: ${manifest.challenge.dir}`,
    `- Current binary marker: ${manifest.challenge.currentBinaryMarker}`,
    `- Target binary: ${compactValue(manifest.challenge.targetBinaryPath)}`,
    `- Container name: ${compactValue(manifest.container.name)}`,
    `- Container ID: ${compactValue(manifest.container.id)}`,
    `- Solution directory: ${manifest.solution.solutionDir}`,
    `- Exploit path: ${manifest.solution.exploitPath}`,
    `- Writeup path: ${manifest.solution.writeupPath}`,
    `- Notes path: ${manifest.solution.notesPath}`,
    '',
    '# MCP Servers',
    formatMcpServers(mcpServers),
    '',
    '# Constraints',
    '- Use MCP tools for all challenge analysis: binary metadata, disassembly, decompilation, debugging, memory/register inspection, payload trials, and runtime behavior checks.',
    '- If active MCP tools are deferred or hidden, use tool discovery only to expose those MCP tools; do not use discovery output as challenge analysis.',
    '- Emit concise visible reasoning summaries before and after important MCP calls so the raw trace can capture why a tool was used and what was learned.',
    '- Do not use shell commands or local CLI tools such as file, checksec, readelf, objdump, gdb, python scripts, or direct process execution for analysis.',
    '- If MCP tools are unavailable or return errors, stop and report the MCP blocker instead of falling back to non-MCP analysis.',
    '- Shell usage is only acceptable for saving final artifacts to the requested output paths when an MCP tool cannot write that artifact.',
    '- MCP servers are external; do not start them from this task.'
].join('\n');

const buildCodexPrompt = async ({ state, manifest, manifestPath, mcpServers }) => {
    const variables = buildPromptVariables({ state, manifest, manifestPath });
    const [system, user] = await Promise.all([
        readPromptSource({
            fileEnv: promptEnv.systemPromptFile,
            inlineEnv: promptEnv.systemPrompt,
            fallback: DEFAULT_SYSTEM_PROMPT,
            defaultFile: DEFAULT_SYSTEM_PROMPT_FILE,
            variables,
            label: 'Codex system prompt'
        }),
        readPromptSource({
            fileEnv: promptEnv.userPromptFile,
            inlineEnv: promptEnv.userPrompt,
            fallback: DEFAULT_USER_PROMPT,
            variables,
            label: 'Codex user prompt'
        })
    ]);

    const content = [
        '# System Instructions',
        system.value,
        '',
        '# User Task',
        user.value,
        '',
        buildRuntimeContext({ state, manifest, manifestPath, mcpServers }),
        ''
    ].join('\n');

    enforcePromptSize('Codex task prompt', content);
    return {
        content,
        metadata: {
            systemSource: system.source,
            systemPromptFile: system.filePath,
            userSource: user.source,
            userPromptFile: user.filePath,
            maxBytes: maxPromptBytes()
        }
    };
};

module.exports = {
    buildCodexPrompt,
    promptEnv
};
