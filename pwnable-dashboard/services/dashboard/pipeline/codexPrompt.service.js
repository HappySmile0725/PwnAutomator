const fs = require('fs').promises;
const path = require('path');
const { TextDecoder } = require('util');

const paths = require('./paths');
const { applyTemplate } = require('./command.service');
const { policy: trainingPolicy } = require('./trainingPolicy.service');

const DEFAULT_SYSTEM_PROMPT = 'You are the autonomous pwnable solver for PwnAutomator.';
const DEFAULT_USER_PROMPT = 'Solve the pwnable challenge.';
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

const isFullPromptMode = () => ['full', 'verbose'].includes(
    String(process.env.PWN_AUTOMATOR_PROMPT_MODE || 'compact').trim().toLowerCase()
);

const promptMode = () => (isFullPromptMode() ? 'full' : 'compact');

const activePromptConstraints = () => {
    if (isFullPromptMode()) {
        return trainingPolicy.promptConstraints || [];
    }
    return trainingPolicy.compactPromptConstraints || trainingPolicy.promptConstraints || [];
};

const enforcePromptSize = (label, value) => {
    const bytes = Buffer.byteLength(value || '', 'utf8');
    const limit = maxPromptBytes();
    if (bytes > limit) {
        throw new Error(`${label} is ${bytes} bytes, above CODEX_PROMPT_MAX_BYTES=${limit}.`);
    }
};

const decodeTextBuffer = (buffer) => {
    const input = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer || '');
    const decoders = [
        new TextDecoder('utf-8', { fatal: true }),
        new TextDecoder('euc-kr', { fatal: true })
    ];

    for (const decoder of decoders) {
        try {
            return decoder.decode(input);
        } catch (_) {
            // Try next decoder.
        }
    }

    return input.toString('utf8');
};

const recoverLatin1Utf8 = (value) => {
    const text = String(value || '');
    if (!/[ÃÂìíë]|[\u0080-\u00ff]/.test(text)) {
        return text;
    }
    try {
        const recovered = Buffer.from(text, 'latin1').toString('utf8');
        return /[가-힣]/.test(recovered) && !recovered.includes('�') ? recovered : text;
    } catch (_) {
        return text;
    }
};

const repairPromptText = (value) => recoverLatin1Utf8(value)
    .replace(/pwnable\s+(?:\ubb38\uc81c|\u81fe\ubabd\uc824|challenge).{0,12}(?:\ud480\uc5b4\ub77c|\ub300\uc52a|solve)/gi, DEFAULT_USER_PROMPT)
    .replace(/(?:\ubb38\uc81c|\u81fe\ubabd\uc824).{0,12}(?:\ud480\uc5b4\ub77c|\ub300\uc52a)/gi, 'solve the challenge');

const readOptionalFile = async (filePath) => {
    try {
        const buffer = await fs.readFile(filePath);
        return decodeTextBuffer(buffer);
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
        value = decodeTextBuffer(await fs.readFile(filePath));
        source = 'file';
    } else if (defaultFile) {
        const defaultFileValue = await readOptionalFile(defaultFile);
        if (defaultFileValue !== null) {
            filePath = defaultFile;
            value = defaultFileValue;
            source = 'default-file';
        }
    }

    const rendered = repairPromptText(applyTemplate(value, variables)).trim();
    enforcePromptSize(label, rendered);
    return { value: rendered, source, filePath };
};

const compactValue = (value, fallback = '-') => {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }
    return String(value);
};

const sanitizePromptText = (value, replacements) => {
    let output = repairPromptText(value);
    const entries = Object.entries(replacements || {})
        .filter(([, actual]) => nonEmpty(actual))
        .sort((a, b) => String(b[1]).length - String(a[1]).length);
    for (const [placeholder, actual] of entries) {
        output = output.split(String(actual)).join(placeholder);
    }
    return output;
};

const formatMcpServers = (servers, { sanitize = false } = {}) => servers.map((server) => {
    const endpoint = sanitize
        ? `<${(server.codexServer || server.key || 'mcp').toUpperCase()}_ENDPOINT>`
        : `${server.endpoint.host}:${server.endpoint.port}`;
    const serverId = server.codexServer || server.key || '-';
    if (!isFullPromptMode()) {
        return `- ${server.name}: id=${serverId}; ${endpoint}; managed=${server.managedBy}`;
    }
    const tools = Array.isArray(server.tools) ? server.tools.join(', ') : '-';
    return `- ${server.name}: id=${serverId}; ${endpoint}; managed=${server.managedBy}; tools=${tools}`;
}).join('\n');

const buildTraceReplacements = ({ state, manifest, manifestPath, mcpServers }) => {
    const replacements = {
        '<RUN_ID>': state.runId,
        '<MANIFEST_PATH>': manifestPath,
        '<CHALLENGE_DIR>': manifest.challenge.dir,
        '<CURRENT_BINARY_MARKER>': manifest.challenge.currentBinaryMarker,
        '<TARGET_BINARY>': manifest.challenge.targetBinaryPath,
        '<CONTAINER_NAME>': manifest.container.name,
        '<CONTAINER_ID>': manifest.container.id,
        '<SOLUTION_DIR>': manifest.solution.solutionDir,
        '<EXPLOIT_PATH>': manifest.solution.exploitPath,
        '<WRITEUP_PATH>': manifest.solution.writeupPath,
        '<NOTES_PATH>': manifest.solution.notesPath
    };

    for (const server of mcpServers || []) {
        const key = (server.codexServer || server.key || 'mcp').toUpperCase();
        replacements[`<${key}_ENDPOINT>`] = `${server.endpoint.host}:${server.endpoint.port}`;
    }

    return replacements;
};

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

const hasStructuredValue = (value) => {
    if (value === null || value === undefined) {
        return false;
    }
    if (Array.isArray(value)) {
        return value.length > 0;
    }
    if (typeof value === 'object') {
        return Object.keys(value).length > 0;
    }
    return String(value).trim().length > 0;
};

const appendScalarLine = (lines, label, value) => {
    if (hasStructuredValue(value)) {
        lines.push(`- ${label}: ${compactValue(value)}`);
    }
};

const appendListSection = (lines, title, items) => {
    if (!Array.isArray(items) || items.length === 0) {
        return;
    }
    lines.push('', `## ${title}`);
    for (const item of items) {
        lines.push(`- ${compactValue(item)}`);
    }
};

const appendJsonSection = (lines, title, value) => {
    if (!hasStructuredValue(value)) {
        return;
    }
    lines.push('', `## ${title}`, '```json', JSON.stringify(value, null, 2), '```');
};

const appendPhaseContract = (lines, contract, compact) => {
    if (!contract) {
        return;
    }
    lines.push('', '## Phase Contract');
    appendScalarLine(lines, 'Agent head', contract.agentHead);
    appendScalarLine(lines, 'Artifact schema', contract.artifactSchema);
    appendScalarLine(lines, 'Role', contract.role);
    appendScalarLine(lines, 'Output contract', contract.outputContract);
    if (!compact) {
        appendScalarLine(lines, 'Supervision target', contract.supervisionTarget);
        appendScalarLine(lines, 'Failure policy', contract.failurePolicy);
        appendScalarLine(lines, 'Artifact policy', contract.artifactPolicy);
    }
    if (contract.toolBudget && Object.keys(contract.toolBudget).length > 0) {
        appendJsonSection(lines, 'Tool Budget', contract.toolBudget);
    }
    appendListSection(lines, 'Allowed MCP Tools', contract.allowedTools);
    appendListSection(lines, 'Forbidden Actions', contract.forbiddenTools);
    if (!compact) {
        appendListSection(lines, 'Required Evidence', contract.requiredEvidence);
        appendListSection(lines, 'Success Criteria', contract.successCriteria);
    }
};

const buildPhaseContext = (phaseMeta) => {
    if (!phaseMeta) {
        return '';
    }

    const lines = [
        '# Phase Context',
        `- Phase: ${compactValue(phaseMeta.phase)}`,
        `- Attempt: ${compactValue(phaseMeta.attempt)}`,
        `- Objective: ${compactValue(phaseMeta.objective)}`,
        `- Goal: ${compactValue(phaseMeta.goal)}`,
        `- Requires shell: ${phaseMeta.requiresShell ? 'yes' : 'no'}`,
        `- Discovery target count: ${compactValue(phaseMeta.discoveryTargetCount, '0')}`,
        `- Repair pass: ${phaseMeta.phase === 'repair' ? 'yes' : 'no'}`,
        `- Artifact schema: ${compactValue(phaseMeta.contract?.artifactSchema)}`
    ];

    if (!isFullPromptMode()) {
        appendPhaseContract(lines, phaseMeta.contract, true);
        appendJsonSection(lines, 'Static Analysis Artifact', phaseMeta.staticAnalysis);
        appendJsonSection(lines, 'Dynamic Analysis Artifact', phaseMeta.dynamicAnalysis);
        if (!phaseMeta.staticAnalysis) appendJsonSection(lines, 'Selected Discovery Targets', phaseMeta.selectedTargets);
        appendJsonSection(lines, 'Previous Failure Summary', phaseMeta.previousFailure);
        appendListSection(lines, 'Self-Derived Hint (not a solution; verify independently before use)', phaseMeta.hint?.notes);
        return lines.join('\n');
    }

    appendPhaseContract(lines, phaseMeta.contract, false);

    appendListSection(lines, 'Expected Inputs', phaseMeta.expectedInputs);
    appendListSection(lines, 'Required Artifacts', phaseMeta.requiredArtifacts);
    appendJsonSection(lines, 'Discovery Protections', phaseMeta.protections);
    appendJsonSection(lines, 'Static Analysis Artifact', phaseMeta.staticAnalysis);
    appendJsonSection(lines, 'Dynamic Analysis Artifact', phaseMeta.dynamicAnalysis);
    if (!phaseMeta.staticAnalysis) appendJsonSection(lines, 'Selected Discovery Targets', phaseMeta.selectedTargets);
    appendJsonSection(lines, 'Previous Failure Summary', phaseMeta.previousFailure);
    appendListSection(lines, 'Self-Derived Hint (not a solution; verify independently before use)', phaseMeta.hint?.notes);

    return lines.join('\n');
};

const buildRuntimeContext = ({ state, manifest, manifestPath, mcpServers, sanitize = false }) => [
    '# Runtime Context',
    `- Run ID: ${sanitize ? '<RUN_ID>' : compactValue(state.runId)}`,
    `- Manifest: ${sanitize ? '<MANIFEST_PATH>' : manifestPath}`,
    `- Challenge directory: ${sanitize ? '<CHALLENGE_DIR>' : manifest.challenge.dir}`,
    `- Current binary marker: ${sanitize ? '<CURRENT_BINARY_MARKER>' : manifest.challenge.currentBinaryMarker}`,
    `- Target binary: ${sanitize ? '<TARGET_BINARY>' : compactValue(manifest.challenge.targetBinaryPath)}`,
    `- Container name: ${sanitize ? '<CONTAINER_NAME>' : compactValue(manifest.container.name)}`,
    `- Container ID: ${sanitize ? '<CONTAINER_ID>' : compactValue(manifest.container.id)}`,
    `- Solution directory: ${sanitize ? '<SOLUTION_DIR>' : manifest.solution.solutionDir}`,
    `- Exploit path: ${sanitize ? '<EXPLOIT_PATH>' : manifest.solution.exploitPath}`,
    `- Writeup path: ${sanitize ? '<WRITEUP_PATH>' : manifest.solution.writeupPath}`,
    `- Notes path: ${sanitize ? '<NOTES_PATH>' : manifest.solution.notesPath}`,
    '',
    '# MCP Servers',
    formatMcpServers(mcpServers, { sanitize }),
    '',
    '# Constraints',
    activePromptConstraints().map((constraint) => `- ${constraint}`).join('\n')
].join('\n');

const buildCodexPrompt = async ({ state, manifest, manifestPath, mcpServers, phaseMeta = null, extraSections = [] }) => {
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

    const phaseContext = buildPhaseContext(phaseMeta);
    const userTask = user.value;
    const actualRuntimeContext = buildRuntimeContext({ state, manifest, manifestPath, mcpServers, sanitize: false });
    const traceRuntimeContext = buildRuntimeContext({ state, manifest, manifestPath, mcpServers, sanitize: true });
    const renderedExtraSections = (extraSections || [])
        .map((section) => applyTemplate(section, variables).trim())
        .filter(Boolean);
    const traceReplacements = buildTraceReplacements({ state, manifest, manifestPath, mcpServers });
    const sanitizedExtraSections = renderedExtraSections.map((section) => sanitizePromptText(section, traceReplacements));

    const contentSections = [
        '# System Instructions',
        system.value,
        '',
        '# User Task',
        userTask,
        '',
        actualRuntimeContext
    ];
    const traceSections = [
        '# System Instructions',
        sanitizePromptText(system.value, traceReplacements),
        '',
        '# User Task',
        sanitizePromptText(userTask, traceReplacements),
        '',
        traceRuntimeContext
    ];

    if (phaseContext) {
        contentSections.push('', phaseContext);
        traceSections.push('', sanitizePromptText(phaseContext, traceReplacements));
    }

    for (let index = 0; index < renderedExtraSections.length; index += 1) {
        contentSections.push('', renderedExtraSections[index]);
        traceSections.push('', sanitizedExtraSections[index]);
    }

    contentSections.push('');
    traceSections.push('');

    const content = contentSections.join('\n');
    const traceContent = traceSections.join('\n');

    enforcePromptSize('Codex task prompt', content);
    return {
        content,
        traceContent,
        metadata: {
            systemSource: system.source,
            systemPromptFile: system.filePath,
            userSource: user.source,
            userPromptFile: user.filePath,
            maxBytes: maxPromptBytes(),
            promptMode: promptMode(),
            constraintCount: activePromptConstraints().length,
            trainingPolicyVersion: trainingPolicy.version || 1,
            phaseMeta
        }
    };
};

module.exports = {
    buildCodexPrompt
};
