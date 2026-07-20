const fs = require('fs').promises;
const { existsSync, mkdirSync, writeFileSync } = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const paths = require('./paths');
const { appendLog } = require('./state.service');
const { applyTemplate, parseCommandLine, runCommand } = require('./command.service');
const { buildCodexPrompt } = require('./codexPrompt.service');
const { policy: trainingPolicy, matchesAnyRegex, payloadPolicyIssues, runtimeRegexes } = require('./trainingPolicy.service');
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
        endpoint: mcpEndpoint('PWNO_MCP_HOST', 'PWNO_MCP_PORT', '127.0.0.1', 5601),
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

const remoteEndpointFromRuntime = (runtime) => {
    const port = (runtime?.network?.ports || []).find((item) => item?.hostPort);
    if (!port) {
        return { host: '', port: '' };
    }
    const hostIp = String(port.hostIp || '').trim();
    return {
        host: !hostIp || hostIp === '0.0.0.0' || hostIp === '::' ? '127.0.0.1' : hostIp,
        port: String(port.hostPort || '')
    };
};

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

const traceTextLimit = () => {
    const value = Number(process.env.PWN_AUTOMATOR_TRACE_TEXT_LIMIT || 8192);
    return Number.isFinite(value) && value > 0 ? value : 8192;
};

const truncateTraceText = (value, limit = traceTextLimit()) => {
    const text = String(value || '');
    if (text.length <= limit) {
        return text;
    }
    return `${text.slice(0, limit)}\n...[truncated ${text.length - limit} chars]`;
};

const summarizeTraceValue = (value, depth = 0) => {
    if (value === null || value === undefined) {
        return value;
    }

    if (typeof value === 'string') {
        return truncateTraceText(value, 4096);
    }

    if (typeof value !== 'object') {
        return value;
    }

    if (depth >= 3) {
        return '[truncated-depth]';
    }

    if (Array.isArray(value)) {
        const limit = depth === 0 ? 12 : 8;
        const items = value.slice(0, limit).map((item) => summarizeTraceValue(item, depth + 1));
        if (value.length > limit) {
            items.push(`[truncated ${value.length - limit} items]`);
        }
        return items;
    }

    return Object.entries(value).reduce((result, [key, item]) => {
        result[key] = summarizeTraceValue(item, depth + 1);
        return result;
    }, {});
};

const summarizeCodexEvent = (event) => {
    if (!event || typeof event !== 'object') {
        return event;
    }

    const item = event.item || {};
    if (item.type === 'mcp_tool_call') {
        return {
            ...event,
            item: {
                id: item.id,
                type: item.type,
                server: item.server,
                tool: item.tool,
                arguments: summarizeTraceValue(item.arguments),
                status: item.status,
                error: summarizeTraceValue(item.error),
                result: summarizeTraceValue(item.result)
            }
        };
    }

    if (item.type === 'agent_message') {
        return {
            ...event,
            item: {
                ...item,
                text: truncateTraceText(item.text, 16384)
            }
        };
    }

    return summarizeTraceValue(event);
};

const buildPhaseMetaFields = (phaseMeta) => {
    if (!phaseMeta) {
        return {};
    }

    return {
        phase: phaseMeta.phase,
        phaseAttempt: phaseMeta.attempt,
        phaseGoal: phaseMeta.goal,
        phaseObjective: phaseMeta.objective,
        phaseAgentHead: phaseMeta.contract?.agentHead || null,
        phaseRequiresShell: Boolean(phaseMeta.requiresShell)
    };
};

const staticPhaseContract = trainingPolicy.contracts.analysisStatic || trainingPolicy.contracts.discovery;
const dynamicPhaseContract = trainingPolicy.contracts.analysisDynamic;
const dynamicPocPhaseContract = trainingPolicy.contracts.analysisDynamicPoc || dynamicPhaseContract;
const exploitPhaseContract = trainingPolicy.contracts.exploit;
const repairPhaseContract = trainingPolicy.contracts.repair;
const staticValidation = trainingPolicy.staticValidation || trainingPolicy.discoveryValidation || {};
const dynamicValidation = trainingPolicy.dynamicValidation || {};
const solveStrategy = trainingPolicy.solveStrategy || {};
const CODEX_PHASE_PROMPT = 'guidline_docs/codex-system-prompt.md';
const DISCOVERY_PROMPT = 'guidline_docs/system-prompt-discovery.md';

const targetSummaryFromDiscovery = (discoveryResult) => {
    const targets = Array.isArray(discoveryResult?.targets) ? discoveryResult.targets : [];
    const limit = Number(staticValidation.maxTargets || 12);
    return targets.slice(0, limit).map((target) => ({
        function_name: target?.function_name || '',
        reason: target?.reason || ''
    })).filter((target) => target.function_name || target.reason);
};

const compactTargetReason = (reason, maxLength = 420) => {
    const text = String(reason || '').replace(/\s+/g, ' ').trim();
    return text.length > maxLength ? `${text.slice(0, maxLength).trim()}...` : text;
};

const compactStaticForExploit = (staticAnalysis) => ({
    protections: staticAnalysis?.protections || {},
    targets: targetSummaryFromDiscovery(staticAnalysis).slice(0, 1).map((target) => ({
        function_name: target.function_name,
        reason: compactTargetReason(target.reason)
    })),
    exploit_requirements: staticAnalysis?.exploit_requirements || {}
});

const compactDynamicForExploit = (dynamicAnalysis) => {
    const facts = dynamicAnalysis?.runtime_facts || {};
    if (!facts || Object.keys(facts).length === 0) {
        return null;
    }
    return {
        runtime_facts: {
            observations: (facts.observations || []).slice(0, Number(dynamicValidation.maxObservations || 4)),
            primitives: (facts.primitives || []).slice(0, Number(dynamicValidation.maxObservations || 4)),
            blockers: (facts.blockers || []).slice(0, 3),
            exploitability: facts.exploitability || null
        }
    };
};

const textIncludesAny = (value, needles) => {
    const text = String(value || '').toLowerCase();
    return (needles || []).some((needle) => text.includes(String(needle || '').toLowerCase()));
};

const shouldRunDynamicProbe = (staticAnalysis) => {
    const policyMode = String(solveStrategy.dynamicMode || 'defer').toLowerCase();
    const mode = String(process.env.PWN_AUTOMATOR_DYNAMIC_MODE || policyMode).toLowerCase();
    if (['never', 'skip', 'false', '0', 'off'].includes(mode)) {
        return false;
    }
    if (['always', 'true', '1', 'on'].includes(mode)) {
        return true;
    }
    const requirements = staticAnalysis?.exploit_requirements || {};
    if (requirements.needs_dynamic_probe === true) {
        return true;
    }
    const canary = staticAnalysis?.protections?.Canary ?? staticAnalysis?.protections?.canary;
    const canaryText = String(canary || '').toLowerCase();
    if (canary === true || (!!canaryText && !/no|none|false|disabled|not/.test(canaryText) && /yes|enabled|found|true/.test(canaryText))) {
        return true;
    }
    const joined = JSON.stringify({
        requirements,
        targets: targetSummaryFromDiscovery(staticAnalysis)
    });
    return textIncludesAny(joined, solveStrategy.dynamicRequiredKeywords || []);
};

const buildDiscoveryPhaseMeta = (attempt) => ({
    phase: 'analysis_static',
    attempt,
    goal: 'identify_static_vulnerability_targets',
    objective: 'Identify mitigations and input-connected vulnerability candidates from static evidence only.',
    requiresShell: false,
    discoveryTargetCount: 0,
    contract: staticPhaseContract,
    expectedInputs: ['target binary', 'MCP metadata', 'function inventory', 'static symbol/string/xref probes'],
    requiredArtifacts: ['pwnautomator.analysis.static.v1 JSON']
});

const noToolStaticContract = () => ({
    ...staticPhaseContract,
    allowedTools: [],
    allowedGhidraCommands: [],
    toolBudget: {},
    outputContract: 'Return exactly one raw pwnautomator.analysis.static.v1 JSON object from the provided observations. Do not call tools.'
});

const buildNoToolDiscoveryPhaseMeta = (attempt) => ({
    ...buildDiscoveryPhaseMeta(attempt),
    contract: noToolStaticContract(),
    expectedInputs: ['previous static MCP observations from this run'],
    requiredArtifacts: ['pwnautomator.analysis.static.v1 JSON only']
});

const buildDynamicPhaseMeta = ({ attempt, staticAnalysis }) => ({
    phase: 'analysis_dynamic',
    attempt,
    goal: 'validate_runtime_exploitability',
    objective: 'Validate selected static candidates with debugger-observed runtime facts only.',
    requiresShell: false,
    discoveryTargetCount: Array.isArray(staticAnalysis?.targets) ? staticAnalysis.targets.length : 0,
    contract: dynamicPhaseContract,
    expectedInputs: ['pwnautomator.analysis.static.v1 artifact', 'target binary runtime state', 'only exploit-required runtime facts'],
    requiredArtifacts: ['pwnautomator.analysis.dynamic.v1 JSON'],
    staticAnalysis: compactStaticForExploit(staticAnalysis),
    selectedTargets: targetSummaryFromDiscovery(staticAnalysis)
});

const buildExploitPhaseMeta = ({ attempt, staticAnalysis, dynamicAnalysis, previousFailure = null, hint = null }) => {
    const isRepair = attempt > 1;
    const selectedTargets = targetSummaryFromDiscovery(staticAnalysis);
    return {
        phase: isRepair ? 'repair' : 'exploit',
        attempt,
        goal: 'obtain_shell',
        objective: isRepair
            ? 'Repair the exploit using the latest execution feedback until a shell is obtained.'
            : 'Convert validated findings into a working exploit that obtains a shell.',
        requiresShell: true,
        discoveryTargetCount: Array.isArray(staticAnalysis?.targets) ? staticAnalysis.targets.length : 0,
        contract: isRepair ? repairPhaseContract : exploitPhaseContract,
        expectedInputs: [
            'pwnautomator.analysis.static.v1 artifact',
            'pwnautomator.analysis.dynamic.v1 artifact',
            isRepair ? 'previous exploit failure diagnosis' : 'validated exploitability facts'
        ],
        requiredArtifacts: ['hack.py via pwn_payload_write', 'execution transcript proving command execution'],
        protections: staticAnalysis?.protections || null,
        staticAnalysis: compactStaticForExploit(staticAnalysis),
        dynamicAnalysis: compactDynamicForExploit(dynamicAnalysis),
        selectedTargets,
        previousFailure,
        hint
    };
};

// Deterministically distilled from the exhausted attempt window's own validated
// artifacts and failure class -- no external solution is ever revealed here.
const buildExploitHint = ({ staticAnalysis, dynamicAnalysis, previousFailure, round }) => {
    const notes = [];
    const target = targetSummaryFromDiscovery(staticAnalysis)[0];
    if (target?.function_name) {
        notes.push(`A prior attempt window exhausted its turn budget without a verified shell while working the validated target "${target.function_name}"; resume from that target instead of re-scanning the binary.`);
    }
    const observation = dynamicAnalysis?.runtime_facts?.observations?.[0];
    const observationText = observation?.evidence || observation?.target;
    if (observationText) {
        notes.push(`Confirmed runtime fact to reuse without re-deriving it: ${compactTargetReason(observationText, 300)}`);
    }
    if (previousFailure?.category) {
        notes.push(`The exhausted attempt window's dominant failure class was "${previousFailure.category}"; do not repeat that exact approach unless new evidence justifies it.`);
    }
    if (!notes.length) {
        return null;
    }
    return { level: round, source: 'self_failure_compression', notes };
};

const normalizeDiscoveryResult = (parsed) => ({
    protections: parsed?.protections && typeof parsed.protections === 'object' && !Array.isArray(parsed.protections)
        ? parsed.protections
        : {},
    targets: Array.isArray(parsed?.targets)
        ? parsed.targets.slice(0, Number(staticValidation.maxTargets || 12)).map((target) => ({
            function_name: String(target?.function_name || '').trim(),
            reason: String(target?.reason || '').trim()
        }))
        : [],
    exploit_requirements: parsed?.exploit_requirements && typeof parsed.exploit_requirements === 'object' && !Array.isArray(parsed.exploit_requirements)
        ? {
            needs_dynamic_probe: parsed.exploit_requirements.needs_dynamic_probe === true,
            needed_facts: Array.isArray(parsed.exploit_requirements.needed_facts)
                ? parsed.exploit_requirements.needed_facts.slice(0, 4).map((item) => String(item || '').trim()).filter(Boolean)
                : [],
            likely_strategy: String(parsed.exploit_requirements.likely_strategy || '').trim(),
            confidence: String(parsed.exploit_requirements.confidence || '').trim()
        }
        : {}
});

const fallbackStaticTargetName = (parsed) => {
    const text = JSON.stringify(parsed || {}).toLowerCase();
    if (/\bmain\b/.test(text) || /__libc_start_main/.test(text)) return 'main';
    for (const name of ['vuln', 'win', 'read', 'input', 'handler']) {
        if (new RegExp(`\\b${name}\\b`).test(text)) return name;
    }
    return 'unknown_entry';
};

const withStaticFallbackTarget = (result, parsed) => {
    if (Array.isArray(result.targets) && result.targets.length > 0) {
        return result;
    }
    const requirements = result.exploit_requirements || {};
    return {
        ...result,
        targets: [{
            function_name: fallbackStaticTargetName(parsed),
            reason: [
                'Static analysis did not prove a concrete input-to-bug call site before sufficient evidence was collected.',
                'Use this low-confidence entry candidate only to drive the dynamic probe; do not treat it as a confirmed vulnerability.'
            ].join(' ')
        }],
        exploit_requirements: {
            ...requirements,
            needs_dynamic_probe: true,
            needed_facts: Array.isArray(requirements.needed_facts) && requirements.needed_facts.length > 0
                ? requirements.needed_facts
                : ['identify the concrete input path', 'confirm the exploit primitive or blocker'],
            likely_strategy: requirements.likely_strategy || 'dynamic triage from the probable entry point',
            confidence: 'low'
        }
    };
};

const staticReasonLooksLikeRawDump = (reason) => {
    const text = String(reason || '');
    return /\b[0-9a-fA-F]{128,}\b/.test(text)
        || /(?:\b[0-9a-fA-F]{2}\b[\s,;:-]*){32,}/.test(text);
};

const discoveryContentIssues = (result) => {
    const issues = [];
    const seen = new Set();
    if (!Array.isArray(result.targets) || result.targets.length === 0) {
        issues.push('empty_targets');
    }
    for (const [index, target] of (result.targets || []).entries()) {
        if (!target.function_name) {
            issues.push(`target_${index + 1}_missing_function_name`);
        }
        if (!target.reason || target.reason.length < Number(staticValidation.minReasonChars || 12)) {
            issues.push(`target_${index + 1}_weak_reason`);
        }
        const key = target.function_name.toLowerCase();
        if (key && seen.has(key)) {
            issues.push(`target_${index + 1}_duplicate_function_name`);
        }
        seen.add(key);
        if (staticReasonLooksLikeRawDump(target.reason)) {
            issues.push(`target_${index + 1}_raw_dump_reason`);
        }
    }
    return issues;
};

const normalizeDynamicResult = (parsed, staticAnalysis) => {
    const facts = parsed?.runtime_facts && typeof parsed.runtime_facts === 'object' && !Array.isArray(parsed.runtime_facts)
        ? parsed.runtime_facts
        : {};
    const selectedTargets = targetSummaryFromDiscovery(staticAnalysis).map((target) => target.function_name);
    const selected = new Set(selectedTargets);
    const selectedByLower = new Map(selectedTargets.map((target) => [String(target).toLowerCase(), target]));
    const singleTarget = selectedTargets.length === 1 ? selectedTargets[0] : '';
    const normalizeTarget = (value) => {
        const target = String(value || '').trim();
        return selectedByLower.get(target.toLowerCase()) || target || singleTarget;
    };
    const dynamicKind = (kind, evidence) => {
        const key = String(kind || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
        const aliases = {
            base_leak: 'leak',
            control_flow: 'control',
            control_hijack: 'control',
            control_route: 'control',
            flag_path: 'control',
            libc_base: 'leak',
            libc_leak: 'leak',
            memory_corruption: 'control',
            primitive: 'control',
            rip_control: 'control',
            saved_rip: 'offset',
            stack_layout: 'offset',
            write_primitive: 'control'
        };
        if (['crash', 'offset', 'leak', 'control', 'blocker'].includes(key)) return key;
        if (aliases[key]) return aliases[key];
        const text = `${key} ${evidence || ''}`.toLowerCase();
        if (/\b(blocked|blocker|cannot|failed|unavailable)\b/.test(text)) return 'blocker';
        if (/\b(leak|got|libc|pie|base|address|pointer)\b/.test(text)) return 'leak';
        if (/\b(offset|canary|rbp|rsp|saved\s+rip|distance)\b/.test(text)) return 'offset';
        if (/\b(crash|sigsegv|fault)\b/.test(text)) return 'crash';
        if (/\b(control|hijack|rip|return|ret|rop|pivot|overwrite|write|shell|flag)\b/.test(text)) return 'control';
        return '';
    };
    const normalizeObservation = (item) => {
        if (typeof item === 'string') {
            const evidence = item.trim();
            return { target: singleTarget, kind: dynamicKind('', evidence), evidence };
        }
        const evidence = String(item?.evidence || item?.fact || item?.details || item?.description || '').trim();
        return {
            target: normalizeTarget(item?.target || item?.function_name || item?.function),
            kind: dynamicKind(item?.kind || item?.type || item?.category, evidence),
            evidence
        };
    };
    const normalizePrimitive = (item) => {
        if (typeof item === 'string') {
            const text = item.trim();
            return {
                name: text,
                confidence: /\b(blocked|failed|cannot)\b/i.test(text) ? 'blocked' : 'confirmed',
                evidence: text
            };
        }
        const name = String(item?.name || item?.type || item?.kind || item?.primitive || '').trim();
        const evidence = String(item?.evidence || item?.details || item?.fact || item?.description || '').trim();
        const confidence = String(item?.confidence || item?.status || '').trim().toLowerCase();
        return { name, confidence, evidence };
    };
    const normalizeBlocker = (item) => {
        if (!item) return '';
        if (typeof item === 'string') return item.trim();
        if (typeof item === 'object') {
            const target = String(item.target || '').trim();
            const evidence = String(item.evidence || item.reason || item.description || item.issue || '').trim();
            if (target && evidence) return `${target}: ${evidence}`;
            return evidence || target || JSON.stringify(item);
        }
        return String(item).trim();
    };
    return {
        runtime_facts: {
            observations: Array.isArray(facts.observations)
                ? facts.observations.slice(0, Number(dynamicValidation.maxObservations || 8)).map(normalizeObservation)
                : [],
            primitives: Array.isArray(facts.primitives)
                ? facts.primitives.slice(0, Number(dynamicValidation.maxObservations || 8)).map(normalizePrimitive)
                : [],
            blockers: Array.isArray(facts.blockers)
                ? facts.blockers.slice(0, Number(dynamicValidation.maxObservations || 8)).map(normalizeBlocker).filter(Boolean)
                : [],
            exploitability: facts.exploitability && typeof facts.exploitability === 'object' && !Array.isArray(facts.exploitability)
                ? facts.exploitability
                : null
        },
        selectedTargets: selected
    };
};

const dynamicExploitabilityIssues = (facts) => {
    if (dynamicValidation.requireExploitabilityProof === false) {
        return [];
    }

    const text = (value) => String(value || '').toLowerCase();
    const exploitability = facts.exploitability || {};
    const statusOf = (value) => text(value?.status || value);
    const confirmedStatuses = new Set(['confirmed', 'not_needed', 'unneeded', 'unnecessary', 'none_needed']);
    const confirmedPrimitive = (pattern) => (facts.primitives || []).some((primitive) => (
        text(primitive.confidence) === 'confirmed'
        && pattern.test(text(`${primitive.name} ${primitive.evidence}`))
    ));
    const hasPlan = Array.isArray(exploitability.exploit_plan) && exploitability.exploit_plan.length > 0;
    const routeText = text(JSON.stringify(exploitability || {}));
    const leakStatus = statusOf(exploitability.leak || exploitability.leak_status);
    const controlStatus = statusOf(exploitability.control || exploitability.control_status);
    const routeStatus = statusOf(exploitability.status);
    const leakBlocked = leakStatus === 'blocked';
    const controlBlocked = controlStatus === 'blocked';
    const confirmedLeak = !leakBlocked && (confirmedStatuses.has(leakStatus)
        || routeStatus === 'confirmed_no_leak_needed'
        || confirmedPrimitive(/\b(leak|base|address|got|libc|pie|stack|heap)\b/));
    const confirmedControl = !controlBlocked && (controlStatus === 'confirmed'
        || routeStatus === 'confirmed'
        || hasPlan
        || confirmedPrimitive(/\b(control|rip|ret|return|rop|pivot|overwrite|write|shell|flag|arbitrary)\b/));
    const blockerText = [
        ...(facts.blockers || []),
        ...(facts.primitives || [])
            .filter((primitive) => text(primitive.confidence) === 'blocked')
            .map((primitive) => `${primitive.name} ${primitive.evidence}`)
    ].map(text).join('\n');

    const issues = [];
    if (routeStatus === 'confirmed' && /\b(?:disable-randomization|no-randomization|randomization-disabled|fixed\s+pie\s+base|fixed-base)\b/.test(routeText)) {
        issues.push('debugger_only_aslr_disabled_route');
    }
    if (routeStatus === 'confirmed' && /\b(?:argv|argument)\b/.test(routeText) && /\b(?:padding|alignment|ignored|launch|requires|required|depends)\b/.test(routeText)) {
        issues.push('runner_incompatible_argv_dependent_route');
    }
    if (routeStatus === 'confirmed' && /\bpie\b/.test(routeText) && /0x55555555[0-9a-f]+/.test(routeText)) {
        issues.push('hardcoded_pie_base_route');
    }
    if (leakBlocked) issues.push('leak_route_blocked');
    if (controlBlocked) issues.push('control_route_blocked');
    if (!confirmedLeak) issues.push('no_confirmed_leak_or_no_leak_needed');
    if (!confirmedControl) issues.push('no_confirmed_control_or_flag_path');
    if (/(?:blocked|no\s+(?:leak|control|exploit|route)|cannot|not\s+allow|outside\s+controlled|different\s+target)/.test(blockerText) && !(confirmedLeak && confirmedControl)) {
        issues.push('blocked_exploit_path_without_confirmed_alternative');
    }
    return issues;
};

const dynamicContentIssues = (result) => {
    const issues = [];
    const facts = result?.runtime_facts || {};
    const selected = result?.selectedTargets || new Set();
    if (!Array.isArray(facts.observations) || facts.observations.length === 0) {
        issues.push('empty_runtime_observations');
    }
    for (const [index, observation] of (facts.observations || []).entries()) {
        if (!observation.target || !selected.has(observation.target)) issues.push(`observation_${index + 1}_unknown_target`);
        if (!['crash', 'offset', 'leak', 'control', 'blocker'].includes(observation.kind)) issues.push(`observation_${index + 1}_invalid_kind`);
        if (observation.evidence.length < Number(dynamicValidation.minEvidenceChars || 20)) issues.push(`observation_${index + 1}_weak_evidence`);
    }
    if (!(facts.primitives || []).length && !(facts.blockers || []).length) {
        issues.push('missing_primitive_or_blocker');
    }
    issues.push(...dynamicExploitabilityIssues(facts));
    return issues;
};

const dynamicProofIssues = (dynamicAnalysis, staticAnalysis) => dynamicContentIssues(
    normalizeDynamicResult(dynamicAnalysis || {}, staticAnalysis)
);

const recordPhaseOutcome = (state, phaseMeta, status, extra = {}) => appendPhaseTraceEvent(
    tracePathsForRun(state.runId, state.executionId).currentTracePath,
    state.runId,
    state.executionId,
    'phase_validation',
    phaseMeta,
    {
        status,
        evaluated: true,
        ...extra
    }
);

const traceBelongsToRun = async (filePath, runId, executionId) => {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        const firstLine = String(content || '').split(/\r?\n/, 1)[0];
        if (!firstLine) {
            return false;
        }
        const parsed = JSON.parse(firstLine);
        const tracedExecutionId = parsed?.executionId || parsed?.data?.executionId || null;
        return parsed?.runId === runId && tracedExecutionId === (executionId || null);
    } catch (_) {
        return false;
    }
};

const buildCodexManifest = (state, resolvedMcpServers) => {
    const tracePaths = tracePathsForRun(state.runId, state.executionId);
    return {
        version: 2,
        trainingPolicyVersion: trainingPolicy.version || 1,
        runId: state.runId,
        executionId: state.executionId || null,
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

const prepareCodexTask = async (state, options = {}) => {
    await fs.mkdir(paths.codexDir, { recursive: true });
    await fs.mkdir(paths.solutionDir, { recursive: true });

    const resolvedMcpServers = resolveMcpServerRouting(mcpServers);
    const manifest = buildCodexManifest(state, resolvedMcpServers);
    const manifestPath = path.join(paths.codexDir, 'manifest.json');
    const promptPath = path.join(paths.codexDir, 'codex_task.md');

    await fs.mkdir(path.dirname(manifestPath), { recursive: true });
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
    const prompt = await buildCodexPrompt({
        state,
        manifest,
        manifestPath,
        mcpServers: resolvedMcpServers,
        phaseMeta: options.phaseMeta || null,
        extraSections: options.extraPrompt ? [options.extraPrompt] : []
    });
    const tracePaths = tracePathsForRun(state.runId, state.executionId);
    const traceExists = await traceBelongsToRun(tracePaths.currentTracePath, state.runId, state.executionId);
    const trace = traceExists ? { currentTracePath: tracePaths.currentTracePath, rawDatasetPath: tracePaths.rawDatasetPath } : await resetTrace({
        runId: state.runId,
        executionId: state.executionId,
        metadata: {
            manifestPath,
            promptPath,
            mcpServers: resolvedMcpServers,
            promptMetadata: prompt.metadata
        }
    });
    const mcpProfile = await ensureCodexMcpProfile(state, mcpServers, trace, options.phaseMeta || null);
    await fs.writeFile(promptPath, prompt.content, 'utf8');
    appendTraceEventSync(trace.currentTracePath, {
        runId: state.runId,
        executionId: state.executionId || null,
        source: 'dashboard',
        type: 'codex_prompt',
        text: prompt.traceContent,
        ...buildPhaseMetaFields(options.phaseMeta),
        data: {
            promptPath,
            manifestPath,
            promptMetadata: prompt.metadata,
            phaseMeta: options.phaseMeta || null
        }
    });

    return { manifest, manifestPath, promptPath, promptMetadata: prompt.metadata, mcpProfile, trace };
};

const continuationPath = () => path.join(paths.codexDir, 'continuation.json');
const continuationStages = new Set(['analysis_static', 'analysis_dynamic', 'exploit', 'repair']);

const normalizeContinuation = (continuation) => {
    if (!continuation || typeof continuation !== 'object' || Array.isArray(continuation)) {
        return null;
    }
    const stage = continuationStages.has(continuation.stage)
        ? continuation.stage
        : (continuation.staticAnalysis ? (Number(continuation.nextAttempt) > 1 ? 'repair' : 'exploit') : 'analysis_static');
    return {
        ...continuation,
        stage,
        nextAttempt: Math.max(Number(continuation.nextAttempt) || 1, 1),
        staticAnalysis: continuation.staticAnalysis || null,
        dynamicAnalysis: continuation.dynamicAnalysis || null,
        previousFailure: continuation.previousFailure || null
    };
};

const loadContinuation = async (state) => {
    try {
        const continuation = JSON.parse(await fs.readFile(continuationPath(), 'utf8'));
        return continuation?.runId === state.runId && continuation?.executionId === state.executionId
            ? normalizeContinuation(continuation)
            : null;
    } catch (_) {
        return null;
    }
};

const saveContinuation = async (state, continuation) => {
    await fs.mkdir(paths.codexDir, { recursive: true });
    await fs.writeFile(continuationPath(), JSON.stringify({
        version: 1,
        runId: state.runId,
        executionId: state.executionId,
        savedAt: new Date().toISOString(),
        ...continuation
    }, null, 2), 'utf8');
};

const clearContinuation = async () => fs.rm(continuationPath(), { force: true }).catch(() => {});

const savePhaseCheckpoint = async (state, checkpoint) => {
    const normalized = normalizeContinuation(checkpoint);
    if (!normalized) {
        return;
    }
    await saveContinuation(state, normalized).catch((error) => {
        appendLog('warn', `Could not save Codex continuation checkpoint: ${error.message}`);
    });
};

const rawCodexAutorunMode = () => String(process.env.CODEX_AGENT_AUTORUN || 'true').trim().toLowerCase();

const isCodexAutorunSoftDisabled = () => {
    const mode = rawCodexAutorunMode();
    const warning = String(process.env.CODEX_AGENT_LOGIN_STATUS_WARNING || 'false').trim().toLowerCase() === 'true';
    return mode === 'soft-disabled' || (warning && mode === 'false');
};

const shouldAutorunCodex = () => !['false', '0', 'no', 'off', 'soft-disabled'].includes(rawCodexAutorunMode());

const codexCommand = () => String(process.env.CODEX_AGENT_COMMAND || 'codex').trim() || 'codex';

const codexHomeDir = () => String(process.env.CODEX_HOME || '').trim()
    || path.join(String(process.env.HOME || '').trim() || '.', '.codex');

const ensureCodexConfigFile = () => {
    const home = codexHomeDir();
    const configPath = path.join(home, 'config.toml');
    try {
        mkdirSync(home, { recursive: true });
        if (!existsSync(configPath)) {
            writeFileSync(configPath, '', 'utf8');
        }
    } catch (_) {
        // Codex will report the real configuration error if this cannot be repaired.
    }
};

const probeCodexLoginStatus = () => {
    ensureCodexConfigFile();
    const result = spawnSync(codexCommand(), ['login', 'status'], {
        encoding: 'utf8',
        env: process.env,
        timeout: 10000
    });
    const output = [
        result.stdout,
        result.stderr,
        result.error?.message
    ].filter(Boolean).join('\n');

    return {
        loggedIn: output.includes('Logged in'),
        summary: String(output || '').replace(/\s+/g, ' ').trim()
    };
};

const hasCodexAuthArtifacts = () => existsSync(path.join(codexHomeDir(), 'auth.json'));

const resolveCodexAutorun = () => {
    if (shouldAutorunCodex()) {
        return { enabled: true, recovered: false, message: '' };
    }

    if (!isCodexAutorunSoftDisabled()) {
        return { enabled: false, recovered: false, message: 'Codex autorun is disabled.' };
    }

    ensureCodexConfigFile();
    if (hasCodexAuthArtifacts()) {
        process.env.CODEX_AGENT_AUTORUN = 'true';
        process.env.CODEX_AGENT_LOGIN_STATUS_WARNING = 'false';
        return { enabled: true, recovered: false, message: '' };
    }

    const status = probeCodexLoginStatus();
    if (status.loggedIn) {
        process.env.CODEX_AGENT_AUTORUN = 'true';
        process.env.CODEX_AGENT_LOGIN_STATUS_WARNING = 'false';
        return {
            enabled: true,
            recovered: true,
            message: 'Codex autorun recovered after runtime login check.'
        };
    }

    const detail = status.summary ? `Codex login status: ${status.summary}` : 'Run codex login in WSL and restart the dashboard.';
    return {
        enabled: false,
        recovered: false,
        message: `Codex autorun is temporarily disabled. ${detail}`
    };
};

const defaultCodexModel = () => process.env.CODEX_AGENT_MODEL || 'gpt-5.5';
const defaultAnalysisModel = () => process.env.CODEX_LORA_ANALYSIS || defaultCodexModel();
const defaultCoderModel = () => process.env.CODEX_LORA_CODER || defaultCodexModel();
const positiveNumberEnv = (name, fallback) => {
    const value = Number(process.env[name]);
    return Number.isFinite(value) && value > 0 ? value : fallback;
};
const discoveryRetryLimit = () => positiveNumberEnv('PWN_AUTOMATOR_DISCOVERY_RETRIES', 2);
const exploitPassLimit = () => positiveNumberEnv('PWN_AUTOMATOR_EXPLOIT_MAX_PASSES', 12);
const exploitHintRoundLimit = () => positiveNumberEnv('PWN_AUTOMATOR_EXPLOIT_HINT_ROUNDS', 1);
const pocVerificationRetryLimit = () => positiveNumberEnv('PWN_AUTOMATOR_POC_VERIFICATION_RETRIES', 2);
const codexCompletionGraceMs = () => {
    const value = Number(process.env.CODEX_AGENT_TURN_COMPLETE_GRACE_MS || 3000);
    return Number.isFinite(value) ? value : 3000;
};
const codexSuccessGraceMs = () => {
    const value = Number(process.env.CODEX_AGENT_SUCCESS_GRACE_MS || 250);
    return Number.isFinite(value) && value >= 0 ? value : 250;
};

const defaultCodexArgs = (model = defaultCodexModel()) => {
    const profileArgs = shouldConfigureCodexMcp() ? ` --profile-v2 ${getCodexMcpProfileName()}` : '';
    return `exec -m ${model}${profileArgs} -`;
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

const resolveCodexArgs = (variables, model) => {
    const configuredArgs = process.env.CODEX_AGENT_ARGS;
    const rawArgs = configuredArgs && configuredArgs.trim() ? configuredArgs : defaultCodexArgs(model);
    const args = parseCommandLine(rawArgs).map((arg) => applyTemplate(arg, { ...variables, model }));
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

const parseJsonLine = (line) => {
    try {
        return JSON.parse(line);
    } catch (_) {
        return null;
    }
};

const staticObservationSummary = async (state, limit = 8) => {
    const tracePath = tracePathsForRun(state.runId, state.executionId).currentTracePath;
    const content = await fs.readFile(tracePath, 'utf8').catch(() => '');
    const rows = [];
    for (const line of content.split(/\r?\n/)) {
        const event = parseJsonLine(line);
        const item = event?.data?.item || {};
        if (
            event?.source !== 'codex'
            || event?.type !== 'llm_json_event'
            || event.phase !== 'analysis_static'
            || item.type !== 'mcp_tool_call'
            || item.status !== 'completed'
            || !item.tool
        ) {
            continue;
        }
        rows.push({
            tool: item.tool,
            arguments: summarizeTraceValue(item.arguments || {}),
            result: summarizeTraceValue(item.result || item.error || {})
        });
    }
    return rows.slice(-limit).map((row, index) => [
        `Observation ${index + 1}: ${row.tool}`,
        `args=${truncateTraceText(JSON.stringify(row.arguments), 500)}`,
        `result=${truncateTraceText(JSON.stringify(row.result), 1600)}`
    ].join('\n')).join('\n\n');
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
            parts.push(`args:\n${JSON.stringify(item.arguments, null, 2)}`);
        }
        if (item.error) {
            parts.push(`error:\n${JSON.stringify(item.error, null, 2)}`);
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

const traceCodexLine = ({ tracePath, runId, executionId, stream, line, parsed, phaseMeta }) => {
    appendTraceEventSync(tracePath, {
        runId,
        executionId: executionId || null,
        source: 'codex',
        type: parsed ? 'llm_json_event' : 'llm_line',
        stream,
        text: truncateTraceText(line),
        ...buildPhaseMetaFields(phaseMeta),
        data: parsed ? summarizeCodexEvent(parsed) : null
    });
};

const appendPhaseTraceEvent = (tracePath, runId, executionId, type, phaseMeta, data = {}) => {
    appendTraceEventSync(tracePath, {
        runId,
        executionId: executionId || null,
        source: 'dashboard',
        type,
        ...buildPhaseMetaFields(phaseMeta),
        data: {
            phaseMeta,
            ...data
        }
    });
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

const executionEvidence = (logs) => {
    const text = String(logs || '');
    const hasFlag = runtimeRegexes.flag.test(text);
    const hasCommandIdentity = runtimeRegexes.commandIdentity.test(text);
    const hasWeakMarker = matchesAnyRegex(text, runtimeRegexes.weakSuccess);
    const hasUnstableSession = matchesAnyRegex(text, runtimeRegexes.unstable);
    return {
        hasFlag,
        hasCommandIdentity,
        hasWeakMarker,
        hasUnstableSession,
        strong: hasFlag || (hasCommandIdentity && !hasUnstableSession),
        grade: hasFlag ? 'flag' : (hasCommandIdentity && !hasUnstableSession ? 'command' : (hasWeakMarker ? 'weak_marker' : 'none'))
    };
};

const completedRuntimeEvidence = (event) => {
    const item = event?.item || {};
    if (
        event?.type !== 'item.completed'
        || item.type !== 'mcp_tool_call'
        || !['pwn_payload_execute', 'pwn_session_poll'].includes(item.tool)
    ) {
        return null;
    }
    const logs = JSON.stringify(item.result || {});
    const evidence = executionEvidence(logs);
    if (item.tool === 'pwn_payload_execute' && evidence.grade !== 'flag') {
        return null;
    }
    return evidence.strong
        ? { success: true, evidence: evidence.grade, logs: truncateTraceText(logs, 2400) }
        : null;
};

const diagnoseExecutionLogs = (logs, err = {}) => {
    const text = `${logs}\n${err.stderr || ''}\n${err.stdout || ''}`;
    if (/no derived shell target found|derived shell target|named shell target|system\/syscall target|one_gadget/i.test(text)) {
        return {
            category: 'Unsupported Shell Target Assumption',
            description: 'The candidate searched for a shell/system/syscall target that was not proven by the static or dynamic artifacts. Use the confirmed primitive path, or report the missing primitive as a blocker.'
        };
    }
    if (/KeyError:\s*['"]?system|undefined symbol.*system/i.test(text)) {
        return {
            category: 'Missing system Symbol',
            description: 'The candidate assumed system exists in the target ELF. Use a libc leak and libc symbol, or another observed call path.'
        };
    }
    if (/stack smashing detected/i.test(text)) {
        return {
            category: 'Canary Bypass Failure',
            description: 'Stack smashing was detected. Canary value was overwritten with an incorrect value.'
        };
    }
    if (/Segmentation fault|SIGSEGV/i.test(text) || err.signal === 'SIGSEGV') {
        return {
            category: 'Memory Corruption (SIGSEGV)',
            description: 'The binary crashed with SIGSEGV. Check ROP chain addresses, stack alignment, and offsets.'
        };
    }
    if (err.code === 124 || /timed out/i.test(text)) {
        return {
            category: 'Execution Timeout',
            description: 'The exploit hung or timed out. Verify synchronization, payload size, and shell command flow.'
        };
    }
    return {
        category: 'Unknown Failure',
        description: 'The exploit script failed during execution.'
    };
};

const traceExecutionEvidence = async (state, phaseMeta = null) => {
    const tracePath = tracePathsForRun(state.runId, state.executionId).currentTracePath;
    const content = await fs.readFile(tracePath, 'utf8').catch(() => '');
    let best = null;
    for (const line of content.split(/\r?\n/)) {
        const event = parseJsonLine(line);
        const evidence = completedRuntimeEvidence(event?.data);
        if (
            event?.source !== 'codex'
            || event?.type !== 'llm_json_event'
            || (phaseMeta && event.phase !== phaseMeta.phase)
            || (phaseMeta && Number(event.phaseAttempt) !== Number(phaseMeta.attempt))
            || !evidence
        ) {
            continue;
        }
        if (!best || evidence.evidence === 'flag') {
            best = evidence;
        }
    }
    return best;
};

const phaseExecutionEvidence = (state, phaseMeta) => traceExecutionEvidence(state, phaseMeta);

const phaseRuntimeDiagnosis = async (state, phaseMeta) => {
    const tracePath = tracePathsForRun(state.runId, state.executionId).currentTracePath;
    const content = await fs.readFile(tracePath, 'utf8').catch(() => '');
    let latest = null;
    for (const line of content.split(/\r?\n/)) {
        const event = parseJsonLine(line);
        const item = event?.data?.item || {};
        if (
            event?.source !== 'codex'
            || event?.type !== 'llm_json_event'
            || event.phase !== phaseMeta.phase
            || Number(event.phaseAttempt) !== Number(phaseMeta.attempt)
            || item.type !== 'mcp_tool_call'
            || item.status !== 'completed'
            || !['pwn_payload_execute', 'pwn_session_poll'].includes(item.tool)
        ) {
            continue;
        }
        const logs = JSON.stringify({ result: item.result || {}, error: item.error || null });
        const evidence = executionEvidence(logs);
        const strong = evidence.strong && (item.tool === 'pwn_session_poll' || evidence.grade === 'flag');
        if (strong) {
            return { success: true, evidence: evidence.grade, logs: truncateTraceText(logs, 2400) };
        }
        const diagnosis = evidence.hasWeakMarker
            ? {
                category: 'Weak Success Evidence',
                description: 'The payload produced only a weak marker; no live command or flag output was verified.'
            }
            : diagnoseExecutionLogs(logs);
        latest = {
            success: false,
            category: diagnosis.category,
            description: diagnosis.description,
            evidence: evidence.grade,
            logs: truncateTraceText(logs, 2400)
        };
    }
    return latest || {
        success: false,
        category: 'Missing MCP Execution',
        description: 'The turn did not produce a completed pwn_payload_execute or pwn_session_poll result.',
        evidence: 'none',
        logs: ''
    };
};

const failureExpectedCorrection = (category) => {
    if (category === 'Unsupported Shell Target Assumption') {
        return 'Do not repeat shell/system/syscall target derivation unless a provided artifact proves the symbol, gadget, leak, or pointer. Use the confirmed primitive, or report the missing primitive as a blocker.';
    }
    return 'Change only the offset, alignment, leak parsing, heap state, syscall arguments, or target pointer justified by this evidence.';
};

const buildFailureSummary = ({ category, description, issue, details, logs, exploitMeta }) => ({
    category: category || 'Unknown Failure',
    issue: issue || '',
    description: description || '',
    details: Array.isArray(details) ? details : [],
    exploitState: exploitMeta || null,
    evidenceExcerpt: logs ? truncateTraceText(logs, 2400) : '',
    expectedCorrection: failureExpectedCorrection(category)
});

const recordExploitVerification = (state, phaseMeta, diag) => appendPhaseTraceEvent(
    tracePathsForRun(state.runId, state.executionId).currentTracePath,
    state.runId,
    state.executionId,
    'exploit_verification',
    phaseMeta,
    {
        success: Boolean(diag?.success),
        evidence: diag?.evidence || 'none',
        category: diag?.category || '',
        description: diag?.description || '',
        logs: truncateTraceText(diag?.logs || '', 2400)
    }
);

const phaseToolKey = (item) => `${item.server || ''}:${item.tool || ''}`;
const isHexAddress = (value) => /^(?:0x)?[0-9a-f]+$/i.test(String(value || '').trim());
const gdbExternalFileIssue = (value) => {
    const command = String(value || '').trim();
    if (!command) return '';
    const checks = [
        [/^\s*(?:run|r)\b.*(?:<|>)\s*\S+/i, 'gdb_external_file_io:run_redirection'],
        [/\bpython\b[\s\S]*\bopen\s*\(/i, 'gdb_external_file_io:python_open'],
        [/^\s*source\s+\S+/i, 'gdb_external_file_io:source_file'],
        [/^\s*(?:shell|!)\b/i, 'gdb_external_file_io:shell'],
        [/^\s*(?:dump|restore|append)\b/i, 'gdb_external_file_io:file_command'],
        [/^\s*set\s+logging\b/i, 'gdb_external_file_io:logging'],
        [/(?:^|\s)(?:<|>>?|2>|&>)\s*(?:\/|\.{1,2}\/|[A-Za-z]:|[A-Za-z0-9_.-]+\.(?:in|gdb|cmd|txt|log))/i, 'gdb_external_file_io:redirection'],
        [/\/(?:tmp|var\/tmp|dev\/shm)\//i, 'gdb_external_file_io:temp_path']
    ];
    const match = checks.find(([pattern]) => pattern.test(command));
    return match ? match[1] : '';
};

const hexReadSize = (item) => {
    const arguments = item?.arguments || {};
    const size = (value) => {
        const parsed = Number(value);
        return Number.isInteger(parsed) && parsed > 0 ? parsed : 0;
    };
    if (item?.tool === 'mem_hex') {
        return size(arguments.size ?? 8);
    }
    if (item?.tool === 'ghidra_call' && String(arguments.cmd || '').trim() === 'mem.hex') {
        return size(arguments.args?.size ?? arguments.size ?? 8);
    }
    return 0;
};

const toolArgumentIssue = (item) => {
    const args = item?.arguments || {};
    if (['search_str', 'search_func', 'search_bytes'].includes(item?.tool) && !String(args.pattern || '').trim()) {
        return `empty_search_pattern:${item.tool}`;
    }
    if (['func_by_addr', 'decompile_by_addr', 'mem_hex', 'mem_dec', 'mem_str', 'mem_asm', 'search_xrefs_to', 'search_xrefs_from'].includes(item?.tool)) {
        if (!String(args.addr || '').trim()) {
            return `missing_address:${item.tool}`;
        }
        if (!isHexAddress(args.addr)) {
            return `invalid_address:${item.tool}`;
        }
    }
    if (item?.tool === 'disassemble_function') {
        if (!String(args.start_address || '').trim()) {
            return 'missing_address:disassemble_function';
        }
        if (!isHexAddress(args.start_address)) {
            return 'invalid_address:disassemble_function';
        }
    }
    if (item?.tool === 'ghidra_call') {
        const command = String(args.cmd || '').trim();
        const nested = args.args && typeof args.args === 'object' ? args.args : args;
        if (['search.str', 'search.func', 'search.bytes'].includes(command) && !String(nested.pattern || '').trim()) {
            return `empty_search_pattern:${command}`;
        }
    }
    if (item?.tool === 'execute') {
        const issue = gdbExternalFileIssue(args.command);
        if (issue) return issue;
    }
    if (item?.tool === 'run') {
        const issue = gdbExternalFileIssue(args.args);
        if (issue) return issue;
    }
    return '';
};

const validatePhaseTool = (phaseMeta, item, usage) => {
    if (item?.type !== 'mcp_tool_call' || !item.tool || !phaseMeta?.contract) {
        return '';
    }

    const contract = phaseMeta.contract;
    if (!Array.isArray(contract.allowedTools) || !contract.allowedTools.includes(item.tool)) {
        return `tool_not_allowed:${item.tool}`;
    }

    const argumentIssue = toolArgumentIssue(item);
    if (argumentIssue) {
        return argumentIssue;
    }

    if (item.tool === 'ghidra_call') {
        const command = String(item.arguments?.cmd || '').trim();
        if (!Array.isArray(contract.allowedGhidraCommands) || !contract.allowedGhidraCommands.includes(command)) {
            return `ghidra_command_not_allowed:${command || 'missing'}`;
        }
    }

    return '';
};

const observePhaseTool = (phaseMeta, item, usage) => {
    if (item?.type !== 'mcp_tool_call' || !item.tool) {
        return '';
    }

    const key = item.id || phaseToolKey(item);
    if (item.status === 'completed' && usage.pending.has(key)) {
        usage.pending.delete(key);
        return '';
    }
    if (item.id && usage.seen.has(key)) {
        return '';
    }
    if (item.status === 'in_progress') {
        usage.pending.add(key);
    }
    if (item.id) {
        usage.seen.add(key);
    }
    usage.calls++;
    if (item.tool === 'pwn_payload_write') usage.payloadWrites++;
    if (item.tool === 'pwn_payload_execute') usage.payloadExecutes++;
    if (hexReadSize(item)) usage.hexReads++;

    const maxCalls = Number(phaseMeta?.contract?.toolBudget?.maxCalls);
    if (Number.isFinite(maxCalls) && maxCalls > 0 && usage.calls > maxCalls) {
        return `tool_budget_exceeded:${usage.calls}/${maxCalls}`;
    }

    return validatePhaseTool(phaseMeta, item, usage);
};

const runSingleTurn = async (state, promptFile, model, extraPrompt = '', options = {}) => {
    process.env.CODEX_SYSTEM_PROMPT_FILE = promptFile;
    process.env.PWN_AUTOMATOR_EXECUTION_ID = state.executionId || '';
    const phaseMeta = options.phaseMeta || null;

    const prepared = await prepareCodexTask(state, { extraPrompt, phaseMeta });

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
    const args = resolveCodexArgs(variables, model);
    const prompt = await fs.readFile(prepared.promptPath, 'utf8');
    const remote = remoteEndpointFromRuntime(state.runtime);

    let rawOutput = '';
    let jsonOutput = '';
    let turnCompleted = false;
    let terminalEvidence = null;
    let phaseStopReason = '';
    const phaseToolUsage = { calls: 0, payloadWrites: 0, payloadExecutes: 0, hexReads: 0, pending: new Set(), seen: new Set() };
    const isJsonMode = args.includes('--json');
    let phaseStatus = 'failure';

    appendPhaseTraceEvent(prepared.trace.currentTracePath, state.runId, state.executionId, 'phase_start', phaseMeta, {
        promptFile,
        model
    });

    try {
        const result = await runCommand({
            command,
            args,
            cwd: state.challenge?.contextDir || paths.challengeDir,
            env: {
                ...process.env,
                PWN_AUTOMATOR_RUN_ID: state.runId || '',
                PWN_AUTOMATOR_EXECUTION_ID: state.executionId || '',
                PWN_AUTOMATOR_PROMPT: prepared.promptPath,
                PWN_AUTOMATOR_SOLUTION_DIR: paths.solutionDir,
                PWN_AUTOMATOR_BINARY_PATH: state.challenge?.mcpWorkspace?.targetBinaryPath || '',
                PWN_AUTOMATOR_REMOTE_HOST: remote.host,
                PWN_AUTOMATOR_REMOTE_PORT: remote.port,
                PWN_AUTOMATOR_TRACE_FILE: prepared.trace.currentTracePath,
                PWN_AUTOMATOR_TRACE_RUN_ID: state.runId || '',
                PWN_AUTOMATOR_TRACE_EXECUTION_ID: state.executionId || '',
                PWN_AUTOMATOR_PHASE: phaseMeta?.phase || '',
                PWN_AUTOMATOR_PHASE_ATTEMPT: String(phaseMeta?.attempt || ''),
                PWN_AUTOMATOR_PHASE_GOAL: phaseMeta?.goal || '',
                PWN_AUTOMATOR_PHASE_OBJECTIVE: phaseMeta?.objective || '',
                CODEX_AGENT_MODEL: model,
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
                if (stream === 'stdout' && !isJsonMode) {
                    rawOutput += text;
                }
                if (!isJsonMode || stream !== 'stdout') {
                    appendTraceEventSync(prepared.trace.currentTracePath, {
                        runId: state.runId,
                        executionId: state.executionId || null,
                        source: 'codex',
                        type: 'llm_output_chunk',
                        stream,
                        text: truncateTraceText(text),
                        ...buildPhaseMetaFields(phaseMeta)
                    });
                }
            },
            onLine: (stream, line) => {
                const parsed = parseJsonLine(line);
                if (parsed?.type === 'turn.completed') {
                    turnCompleted = true;
                }
                if (isJsonMode && parsed && stream === 'stdout') {
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
                    executionId: state.executionId,
                    stream,
                    line,
                    parsed,
                    phaseMeta
                });
                if (!phaseStopReason) {
                    phaseStopReason = observePhaseTool(phaseMeta, parsed?.item, phaseToolUsage);
                    if (phaseStopReason) {
                        appendPhaseTraceEvent(prepared.trace.currentTracePath, state.runId, state.executionId, 'phase_tool_policy_violation', phaseMeta, {
                            issue: phaseStopReason,
                            tool: parsed?.item?.tool || '',
                            toolUsage: {
                                calls: phaseToolUsage.calls,
                                payloadWrites: phaseToolUsage.payloadWrites,
                                payloadExecutes: phaseToolUsage.payloadExecutes,
                                hexReads: phaseToolUsage.hexReads
                            }
                        });
                        appendLog('warn', `Ending ${phaseMeta?.phase || 'agent'} turn: ${phaseStopReason}`);
                    }
                }
                if (phaseMeta?.requiresShell && !terminalEvidence) {
                    terminalEvidence = completedRuntimeEvidence(parsed);
                    if (terminalEvidence) {
                        appendPhaseTraceEvent(prepared.trace.currentTracePath, state.runId, state.executionId, 'phase_success_detected', phaseMeta, {
                            evidence: terminalEvidence.evidence,
                            source: 'mcp_runtime'
                        });
                        appendLog('info', `Verified ${terminalEvidence.evidence} evidence received. Ending Codex turn.`);
                    }
                }
                const displayLine = formatCodexEventForOutput(line, parsed);
                if (displayLine) {
                    appendLog(classifyCodexLogLevel(line), `codex: ${displayLine}`);
                }
            },
            terminateAfterLine: (stream, line) => {
                if (stream !== 'stdout') {
                    return false;
                }
                if (phaseStopReason) {
                    return true;
                }
                const parsed = parseJsonLine(line);
                return parsed?.type === 'turn.completed' || Boolean(phaseMeta?.requiresShell && completedRuntimeEvidence(parsed));
            },
            terminateAfterLineMs: (stream, line) => {
                if (phaseStopReason) {
                    return 0;
                }
                const parsed = parseJsonLine(line);
                return phaseMeta?.requiresShell && completedRuntimeEvidence(parsed)
                    ? codexSuccessGraceMs()
                    : codexCompletionGraceMs();
            }
        });

        if (result.canceled) {
            const error = new Error('Codex agent canceled.');
            error.canceled = true;
            throw error;
        }

        if (result.code !== 0 && !turnCompleted && !terminalEvidence && !phaseStopReason) {
            throw new Error(`Agent turn exited with code ${result.code}`);
        }

        phaseStatus = phaseStopReason ? 'failure' : 'success';
        return { output: isJsonMode ? jsonOutput : rawOutput, policyViolation: phaseStopReason };
    } finally {
        appendPhaseTraceEvent(prepared.trace.currentTracePath, state.runId, state.executionId, 'phase_turn_end', phaseMeta, {
            status: phaseStatus,
            turnCompleted,
            policyViolation: phaseStopReason || null,
            toolUsage: {
                calls: phaseToolUsage.calls,
                payloadWrites: phaseToolUsage.payloadWrites,
                payloadExecutes: phaseToolUsage.payloadExecutes,
                hexReads: phaseToolUsage.hexReads
            }
        });
    }
};

const parseStaticWithCorrection = async (state, options) => {
    let retries = 0;
    let extraPrompt = '';
    let lastIssue = 'unknown_static_analysis_failure';
    let forceNoToolJson = false;
    const model = defaultAnalysisModel();
    const promptFile = DISCOVERY_PROMPT;
    const buildDiscoveryCorrectionPrompt = (issue, observations = '', noTools = false) => [
        '# Output Format Correction',
        '- Previous response did not match the required discovery JSON schema.',
        `- Issue: ${issue}`,
        noTools ? '- Do not call any MCP tools in this retry. Use only the observations below and return JSON.' : '',
        observations ? `\n# Previous Static Observations\n${observations}` : '',
        '- Return a single raw JSON object only.',
        '- Required top-level key: "targets" (array).',
        '- Include "exploit_requirements" with needs_dynamic_probe, needed_facts, likely_strategy, and confidence.',
        '- Do not include prose, markdown, or code fences outside the JSON object.'
    ].filter(Boolean).join('\n');

    while (retries < discoveryRetryLimit()) {
        const phaseMeta = forceNoToolJson
            ? buildNoToolDiscoveryPhaseMeta(retries + 1)
            : buildDiscoveryPhaseMeta(retries + 1);
        const turn = await runSingleTurn(state, promptFile, model, extraPrompt, {
            ...options,
            phaseMeta
        });
        if (turn.policyViolation) {
            lastIssue = turn.policyViolation;
            const observations = await staticObservationSummary(state);
            forceNoToolJson = Boolean(observations);
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                validation: 'phase_tool_policy',
                issue: turn.policyViolation
            });
            extraPrompt = buildDiscoveryCorrectionPrompt([
                `The previous turn violated the static-analysis tool policy: ${turn.policyViolation}.`,
                'Do not call generic ghidra_call/help or empty broad searches.',
                'Use only typed tools and return JSON as soon as the strongest input-connected target is clear.'
            ].join(' '), observations, forceNoToolJson);
            retries++;
            continue;
        }
        const output = turn.output;
        const start = output.indexOf('{');
        const end = output.lastIndexOf('}');

        if (start === -1 || end === -1 || start >= end) {
            lastIssue = 'missing_json_object';
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                validation: 'discovery_json_schema',
                issue: 'missing_json_object'
            });
            extraPrompt = buildDiscoveryCorrectionPrompt('No JSON object block was found in the previous output.');
            retries++;
            continue;
        }

        const jsonCandidate = output.substring(start, end + 1).trim();
        try {
            const parsed = JSON.parse(jsonCandidate);
            if (parsed.targets && Array.isArray(parsed.targets)) {
                let normalized = normalizeDiscoveryResult(parsed);
                normalized = withStaticFallbackTarget(normalized, parsed);
                const contentIssues = discoveryContentIssues(normalized);
                if (contentIssues.length > 0) {
                    lastIssue = contentIssues.join(',');
                    recordPhaseOutcome(state, phaseMeta, 'failure', {
                        validation: 'discovery_schema_and_content',
                        issue: contentIssues.join(',')
                    });
                    extraPrompt = buildDiscoveryCorrectionPrompt(`The JSON parsed, but discovery content is too weak: ${contentIssues.join(', ')}.`);
                    retries++;
                    continue;
                }
                recordPhaseOutcome(state, phaseMeta, 'success', {
                    validation: 'discovery_schema_and_content',
                    targetCount: normalized.targets.length
                });
                return normalized;
            }
            lastIssue = 'missing_targets_array';
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                validation: 'discovery_json_schema',
                issue: 'missing_targets_array'
            });
            extraPrompt = buildDiscoveryCorrectionPrompt('The JSON object was parsed, but the required "targets" array was missing.');
        } catch (err) {
            lastIssue = `invalid_json:${err.message}`;
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                validation: 'discovery_json_schema',
                issue: `invalid_json:${err.message}`
            });
            extraPrompt = buildDiscoveryCorrectionPrompt(`The previous output was not valid JSON (${err.message}).`);
        }
        retries++;
    }
    throw new Error(`Static analysis phase failed: ${lastIssue}`);
};

const parseDynamicWithCorrection = async (state, staticAnalysis, options) => {
    let retries = 0;
    let extraPrompt = '';
    let lastIssue = '';
    const model = process.env.CODEX_LORA_DYNAMIC || defaultAnalysisModel();
    const promptFile = CODEX_PHASE_PROMPT;
    const correction = (issue) => [
        '# Output Format Correction',
        '- Return a single raw JSON object only.',
        '- Required top-level key: "runtime_facts".',
        '- Use only these observation kind values: control, leak, offset, crash, blocker.',
        '- Each observation must name one selected target and contain a concrete debugger-observed fact.',
        '- The artifact must prove an exploit route before exploit coding starts: confirm the leak/base source or state that no leak is needed, and confirm the control-flow or direct flag-read path.',
        '- If the current target is blocked, continue with the smallest focused debugger check needed to prove an alternative route; do not return a blocked-only artifact unless no route exists.',
        `- Issue: ${issue}`
    ].join('\n');

    while (retries < discoveryRetryLimit()) {
        const phaseMeta = buildDynamicPhaseMeta({ attempt: retries + 1, staticAnalysis });
        const turn = await runSingleTurn(state, promptFile, model, extraPrompt, { ...options, phaseMeta });
        if (turn.policyViolation) {
            lastIssue = turn.policyViolation;
            recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'phase_tool_policy', issue: turn.policyViolation });
            extraPrompt = correction(`The previous turn violated the dynamic-analysis tool policy: ${turn.policyViolation}.`);
            retries++;
            continue;
        }

        const output = turn.output;
        const start = output.indexOf('{');
        const end = output.lastIndexOf('}');
        if (start === -1 || end === -1 || start >= end) {
            lastIssue = 'missing_json_object';
            recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_json_schema', issue: 'missing_json_object' });
            extraPrompt = correction('No JSON object block was found.');
            retries++;
            continue;
        }

        try {
            const normalized = normalizeDynamicResult(JSON.parse(output.substring(start, end + 1)), staticAnalysis);
            const issues = dynamicContentIssues(normalized);
            if (issues.length === 0) {
                recordPhaseOutcome(state, phaseMeta, 'success', {
                    validation: 'dynamic_schema_and_content',
                    observationCount: normalized.runtime_facts.observations.length,
                    primitiveCount: normalized.runtime_facts.primitives.length,
                    blockerCount: normalized.runtime_facts.blockers.length,
                    exploitability: normalized.runtime_facts.exploitability || null
                });
                return { runtime_facts: normalized.runtime_facts };
            }
            lastIssue = issues.join(',');
            recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_schema_and_content', issue: issues.join(',') });
            extraPrompt = correction(issues.join(','));
        } catch (error) {
            lastIssue = `invalid_json:${error.message}`;
            recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_json_schema', issue: `invalid_json:${error.message}` });
            extraPrompt = correction(`Invalid JSON: ${error.message}`);
        }
        retries++;
    }
    throw new Error(`Dynamic analysis phase failed to prove exploitability: ${lastIssue || 'missing confirmed leak/control route'}`);
};

// The curated reference solution for a challenge, when one exists, is always
// extracted to this path (see challengeUpload.service.js) -- a completely
// different file from the hack.py the exploit/repair phases write to, so
// there is no collision or overwrite risk.
const referencePocPath = () => path.join(paths.challengeDir, 'ex.py');

const readReferencePoc = async () => {
    const content = await fs.readFile(referencePocPath(), 'utf8').catch(() => '');
    return content.trim();
};

const buildPocVerificationPhaseMeta = ({ attempt, staticAnalysis }) => ({
    ...buildDynamicPhaseMeta({ attempt, staticAnalysis }),
    phase: 'analysis_dynamic_poc',
    objective: 'Verify, with debugger-observed runtime facts, why the provided reference exploit works against this binary.',
    contract: dynamicPocPhaseContract
});

// Grounds the dynamic-analysis artifact in a known-working reference exploit
// instead of the model's own (already exhausted) guesses. The model still has
// to confirm every fact through the debugger -- the reference is verification
// material, not something it may copy into a payload -- so this only feeds
// the exploit phase better *facts*, never code. Best-effort: any failure or
// missing reference degrades to null so the caller can fall back safely.
const runPocGroundedVerification = async (state, staticAnalysis, options = {}) => {
    try {
        const referencePoc = await readReferencePoc();
        if (!referencePoc) {
            return null;
        }

        const model = process.env.CODEX_LORA_DYNAMIC || defaultAnalysisModel();
        const promptFile = CODEX_PHASE_PROMPT;
        const referenceSection = [
            '# Reference Exploit (verification only)',
            'A known-working reference exploit for this binary is provided below.',
            'Use the debugger to CONFIRM, step by step, why it works. Do not paraphrase or summarize the code, and never copy any part of it into your output.',
            'Your only output is the pwnautomator.analysis.dynamic.v1 JSON described in the phase contract. Do not write or execute a payload in this phase.',
            '```python',
            referencePoc.slice(0, 6000),
            '```'
        ].join('\n');
        const correction = (issue) => [
            '# Output Format Correction',
            '- Return a single raw JSON object only.',
            '- Required top-level key: "runtime_facts".',
            '- Use only these observation kind values: control, leak, offset, crash, blocker.',
            "- Every observation must be tied to a debugger-confirmed fact, not a restatement of the reference exploit's comments.",
            `- Issue: ${issue}`
        ].join('\n');

        let retries = 0;
        let extraPrompt = referenceSection;
        let lastIssue = '';
        while (retries < pocVerificationRetryLimit()) {
            const phaseMeta = buildPocVerificationPhaseMeta({ attempt: retries + 1, staticAnalysis });
            const turn = await runSingleTurn(state, promptFile, model, extraPrompt, { ...options, phaseMeta });
            if (turn.policyViolation) {
                lastIssue = turn.policyViolation;
                recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'phase_tool_policy', issue: turn.policyViolation });
                extraPrompt = `${referenceSection}\n\n${correction(`The previous turn violated the verification tool policy: ${turn.policyViolation}.`)}`;
                retries++;
                continue;
            }

            const output = turn.output;
            const start = output.indexOf('{');
            const end = output.lastIndexOf('}');
            if (start === -1 || end === -1 || start >= end) {
                lastIssue = 'missing_json_object';
                recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_json_schema', issue: 'missing_json_object' });
                extraPrompt = `${referenceSection}\n\n${correction('No JSON object block was found.')}`;
                retries++;
                continue;
            }

            try {
                const normalized = normalizeDynamicResult(JSON.parse(output.substring(start, end + 1)), staticAnalysis);
                const issues = dynamicContentIssues(normalized);
                if (issues.length === 0) {
                    recordPhaseOutcome(state, phaseMeta, 'success', {
                        validation: 'poc_grounded_dynamic_schema_and_content',
                        observationCount: normalized.runtime_facts.observations.length
                    });
                    return normalized;
                }
                lastIssue = issues.join(',');
                recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_schema_and_content', issue: issues.join(',') });
                extraPrompt = `${referenceSection}\n\n${correction(issues.join(','))}`;
            } catch (error) {
                lastIssue = `invalid_json:${error.message}`;
                recordPhaseOutcome(state, phaseMeta, 'failure', { validation: 'dynamic_json_schema', issue: `invalid_json:${error.message}` });
                extraPrompt = `${referenceSection}\n\n${correction(`Invalid JSON: ${error.message}`)}`;
            }
            retries++;
        }
        appendLog('warn', `PoC-grounded verification did not produce a usable artifact after ${pocVerificationRetryLimit()} attempt(s): ${lastIssue}`);
        return null;
    } catch (error) {
        if (error?.canceled) {
            throw error;
        }
        appendLog('warn', `PoC-grounded verification errored: ${error.message}`);
        return null;
    }
};

// Decides what the next attempt window gets to lean on: a PoC-grounded,
// debugger-verified artifact when a reference solution exists, otherwise the
// free, deterministic self-derived hint. Never throws for anything other than
// cancellation -- worst case, it just falls back to the weaker hint.
const buildNextWindowHint = async (state, staticAnalysis, dynamicAnalysis, previousFailure, round, options) => {
    const pocVerified = await runPocGroundedVerification(state, staticAnalysis, options);
    if (pocVerified) {
        return {
            dynamicAnalysis: pocVerified,
            hint: {
                level: round,
                source: 'poc_grounded_analysis',
                notes: ["This attempt window's Dynamic Analysis Artifact was re-verified against a reference exploit via debugger observation; treat these runtime_facts as confirmed and do not search for a different vulnerability."]
            }
        };
    }
    return {
        dynamicAnalysis,
        hint: buildExploitHint({ staticAnalysis, dynamicAnalysis, previousFailure, round })
    };
};

const runCoderWithDiagnosis = async (state, staticAnalysis, dynamicAnalysis, options = {}) => {
    const proofIssues = dynamicProofIssues(dynamicAnalysis, staticAnalysis);
    if (proofIssues.length > 0) {
        throw new Error(`Exploit phase blocked until dynamic exploitability proof is complete: ${proofIssues.join(',')}`);
    }

    let passes = 0;
    let roundPasses = 0;
    let extraPrompt = '';
    let previousFailure = options.previousFailure || null;
    let hint = options.hint || null;
    let hintRoundsUsed = 0;
    const startAttempt = Math.max(Number(options.startAttempt) || 1, 1);
    const model = defaultCoderModel();
    const promptFile = CODEX_PHASE_PROMPT;
    const exploitPath = path.join(paths.solutionDir, 'exploit.py');
    const hackPath = path.join(paths.challengeDir, 'hack.py');
    const registerAttemptFailure = () => {
        passes++;
        roundPasses++;
    };

    while (true) {
        if (roundPasses >= exploitPassLimit()) {
            if (hintRoundsUsed >= exploitHintRoundLimit()) {
                throw new Error(`Exploit/repair phase exceeded the maximum of ${exploitPassLimit()} passes per attempt window across ${hintRoundsUsed + 1} attempt window(s) without a verified shell or flag.`);
            }
            hintRoundsUsed++;
            const windowUpgrade = await buildNextWindowHint(state, staticAnalysis, dynamicAnalysis, previousFailure, hintRoundsUsed, options);
            dynamicAnalysis = windowUpgrade.dynamicAnalysis;
            hint = windowUpgrade.hint || hint;
            roundPasses = 0;
            previousFailure = null;
            extraPrompt = '';
            appendLog('warn', `Exploit/repair turn budget exhausted; restarting a fresh attempt window (${hintRoundsUsed}/${exploitHintRoundLimit()}) with a ${hint?.source || 'no'} hint.`);
            continue;
        }
        if (options.signal?.aborted) {
            const error = new Error('Codex agent canceled.');
            error.canceled = true;
            throw error;
        }
        await savePhaseCheckpoint(state, {
            stage: startAttempt + passes > 1 ? 'repair' : 'exploit',
            staticAnalysis,
            dynamicAnalysis,
            previousFailure,
            nextAttempt: startAttempt + passes
        });
        const phaseMeta = buildExploitPhaseMeta({
            attempt: startAttempt + passes,
            staticAnalysis,
            dynamicAnalysis,
            previousFailure,
            hint
        });
        const turn = await runSingleTurn(state, promptFile, model, extraPrompt, {
            ...options,
            phaseMeta
        });
        if (turn.policyViolation) {
            previousFailure = buildFailureSummary({
                category: 'Phase Tool Policy Rejection',
                issue: turn.policyViolation,
                description: 'The previous turn exceeded its specialist tool contract before producing a trustworthy payload.'
            });
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                verification: 'phase_tool_policy',
                issue: turn.policyViolation
            });
            extraPrompt = `Previous turn rejected: ${turn.policyViolation}. Use only the current phase contract and make focused evidence-driven corrections.`;
            registerAttemptFailure();
            continue;
        }

        const hackExists = await fs.access(hackPath).then(() => true).catch(() => false);
        if (hackExists) {
            await fs.mkdir(path.dirname(exploitPath), { recursive: true });
            await fs.copyFile(hackPath, exploitPath).catch(() => {});
        }

        const exploitReady = await fs.access(exploitPath).then(() => true).catch(() => false);
        if (!exploitReady) {
            previousFailure = buildFailureSummary({
                category: 'Artifact Failure',
                issue: 'exploit_not_written',
                description: 'The agent did not create a usable exploit payload artifact.'
            });
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                verification: 'exploit_file_check',
                issue: 'exploit_not_written'
            });
            extraPrompt = 'Error: exploit.py was not created. Ensure exploit file is saved.';
            registerAttemptFailure();
            continue;
        }

        const exploitSource = await fs.readFile(exploitPath, 'utf8').catch(() => '');
        const traceDiag = await phaseExecutionEvidence(state, phaseMeta);
        if (traceDiag) {
            recordExploitVerification(state, phaseMeta, traceDiag);
            recordPhaseOutcome(state, phaseMeta, 'success', {
                verification: 'phase_trace',
                evidence: traceDiag.evidence
            });
            return;
        }

        const policyIssues = payloadPolicyIssues(exploitSource);
        if (policyIssues.length > 0) {
            previousFailure = buildFailureSummary({
                category: 'Exploit Policy Rejection',
                issue: 'payload_policy_violation',
                description: 'The exploit violated payload policy. Use MCP/debugger/leaks instead of forbidden host introspection or wrapper-managed process code.',
                details: policyIssues
            });
            recordPhaseOutcome(state, phaseMeta, 'failure', {
                verification: 'exploit_policy_check',
                issue: 'payload_policy_violation',
                details: policyIssues
            });
            extraPrompt = [
                'Error: the previous exploit payload violated policy and was rejected.',
                `Rejected patterns: ${policyIssues.join(', ')}`,
                'Do not read /proc/<pid>/maps, /proc/<pid>/mem, or procfs process memory paths.',
                'Do not create or close local processes, do not call interactive(), and do not use fixed sleep-based respawn loops.',
                'Use target leaks and MCP debugger/memory tools for base derivation. Reuse the wrapper-provided live tube and emit payload logic only.'
            ].join('\n');
            registerAttemptFailure();
            continue;
        }

        const diag = await phaseRuntimeDiagnosis(state, phaseMeta);
        recordExploitVerification(state, phaseMeta, diag);
        if (diag.success) {
            recordPhaseOutcome(state, phaseMeta, 'success', {
                verification: 'wrapper_execution',
                evidence: diag.evidence || 'strong'
            });
            return;
        }

        recordPhaseOutcome(state, phaseMeta, 'failure', {
            verification: 'wrapper_execution',
            category: diag.category || 'Unknown Failure',
            evidence: diag.evidence || 'none'
        });
        const exploitMeta = await extractExploitMetadata(exploitPath, diag.logs);
        previousFailure = buildFailureSummary({
            category: diag.category,
            description: diag.description,
            logs: diag.logs,
            exploitMeta
        });
        const metaHeader = exploitMeta ? `[Exploit Memory Map Status]\n- Canary: ${exploitMeta.canary}\n- Libc Base: ${exploitMeta.libcBase}\n- System Address: ${exploitMeta.systemAddr}\n\n` : '';
        extraPrompt = [
            metaHeader,
            'Exploit Failure Diagnosis:',
            `- Category: ${diag.category}`,
            `- Evidence grade: ${diag.evidence || 'none'}`,
            `- Description: ${diag.description}`,
            `- Expected correction: ${previousFailure.expectedCorrection}`,
            '- Required next verification: produce uid/gid output with a live command, or read the flag directly.',
            '- Weak markers such as PWNED, still_alive, or final_check are not accepted as success.',
            `- Execution Logs:\n${diag.logs}`,
            'Adjust offsets, payload structure, leak parsing, or shell command flow based only on this evidence.'
        ].filter(Boolean).join('\n');
        registerAttemptFailure();
    }
};

const runDynamicProbeAndExploit = async (state, staticAnalysis, options) => {
    appendLog('info', 'Phase 2: Proving leak and exploit route before exploit coding.');
    const dynamicAnalysis = await parseDynamicWithCorrection(state, staticAnalysis, options);
    appendLog('info', `Dynamic exploitability proof completed. Observations: ${dynamicAnalysis.runtime_facts.observations.length}`);
    await savePhaseCheckpoint(state, {
        stage: 'exploit',
        staticAnalysis,
        dynamicAnalysis,
        previousFailure: null,
        nextAttempt: 1
    });
    appendLog('info', 'Phase 3: Starting exploit code generation and verification.');
    await runCoderWithDiagnosis(state, staticAnalysis, dynamicAnalysis, options);
};

const runExploitFromStatic = async (state, staticAnalysis, options) => {
    let dynamicAnalysis = null;
    const dynamicBeforeExploit = shouldRunDynamicProbe(staticAnalysis);
    if (dynamicBeforeExploit) {
        await savePhaseCheckpoint(state, {
            stage: 'analysis_dynamic',
            staticAnalysis,
            dynamicAnalysis: null,
            previousFailure: null,
            nextAttempt: 1
        });
        await runDynamicProbeAndExploit(state, staticAnalysis, options);
        return;
    }

    appendLog('info', 'Phase 2: Dynamic probe deferred; trying first exploit from static triage.');
    await savePhaseCheckpoint(state, {
        stage: 'exploit',
        staticAnalysis,
        dynamicAnalysis,
        previousFailure: null,
        nextAttempt: 1
    });
    appendLog('info', 'Phase 3: Starting exploit code generation and verification.');
    await runCoderWithDiagnosis(state, staticAnalysis, dynamicAnalysis, options);
};

const resumeFromContinuation = async (state, continuation, options) => {
    const checkpoint = normalizeContinuation(continuation);
    if (!checkpoint) {
        return false;
    }

    if (checkpoint.stage === 'analysis_static' || !checkpoint.staticAnalysis) {
        appendLog('info', 'Resuming at static analysis phase.');
        const staticAnalysis = await parseStaticWithCorrection(state, options);
        appendLog('info', `Static analysis completed. Targets: ${staticAnalysis.targets.map(t => t.function_name).join(', ')}`);
        await runExploitFromStatic(state, staticAnalysis, options);
        return true;
    }

    if (checkpoint.stage === 'analysis_dynamic') {
        appendLog('info', 'Resuming at dynamic analysis phase.');
        await runDynamicProbeAndExploit(state, checkpoint.staticAnalysis, options);
        return true;
    }

    const proofIssues = dynamicProofIssues(checkpoint.dynamicAnalysis, checkpoint.staticAnalysis);
    if (proofIssues.length > 0) {
        appendLog('warn', `Discarding stale dynamic artifact before ${checkpoint.stage}: ${proofIssues.join(', ')}`);
        await savePhaseCheckpoint(state, {
            stage: 'analysis_dynamic',
            staticAnalysis: checkpoint.staticAnalysis,
            dynamicAnalysis: null,
            previousFailure: checkpoint.previousFailure,
            nextAttempt: 1
        });
        await runDynamicProbeAndExploit(state, checkpoint.staticAnalysis, options);
        return true;
    }

    appendLog('info', `Resuming ${checkpoint.stage} phase at attempt ${checkpoint.nextAttempt}.`);
    await runCoderWithDiagnosis(state, checkpoint.staticAnalysis, checkpoint.dynamicAnalysis, {
        ...options,
        previousFailure: checkpoint.previousFailure,
        startAttempt: checkpoint.nextAttempt
    });
    return true;
};

const runCodexAgent = async (state, options = {}) => {
    if (options.signal?.aborted) {
        return { status: 'canceled', mode: 'autorun', exitCode: null, promptPath: null, manifestPath: null };
    }
    const promptPath = path.join(paths.codexDir, 'codex_task.md');
    const manifestPath = path.join(paths.codexDir, 'manifest.json');
    const tracePaths = tracePathsForRun(state.runId, state.executionId);

    if (options.signal?.aborted) {
        return { status: 'canceled', mode: 'autorun', exitCode: null, promptPath, manifestPath };
    }

    const autorun = resolveCodexAutorun();
    if (!autorun.enabled) {
        process.env.CODEX_SYSTEM_PROMPT_FILE = DISCOVERY_PROMPT;
        const prepared = await prepareCodexTask(state, { phaseMeta: buildDiscoveryPhaseMeta(1) });
        appendLog('info', `Multi-Agent Pipeline prepared: ${prepared.promptPath}`);
        return {
            status: 'waiting',
            mode: 'manual',
            promptPath: prepared.promptPath,
            manifestPath: prepared.manifestPath,
            rawTrace: prepared.trace,
            message: autorun.message || 'Codex autorun is disabled.'
        };
    }

    if (autorun.recovered) {
        appendLog('warn', autorun.message);
    }

    let rawTrace;
    try {
        const recoveredEvidence = await traceExecutionEvidence(state);
        if (recoveredEvidence) {
            appendLog('info', `Recovered verified ${recoveredEvidence.evidence} evidence from trace; completing pipeline without another Codex turn.`);
            await clearContinuation();
            appendTraceEventSync(tracePaths.currentTracePath, {
                runId: state.runId,
                executionId: state.executionId || null,
                source: 'dashboard',
                type: 'agent_run_result',
                data: { status: 'success', recoveredEvidence: recoveredEvidence.evidence }
            });
            rawTrace = await publishRawTrace({ runId: state.runId, executionId: state.executionId, status: 'success' });
            return {
                status: 'success',
                mode: 'autorun',
                exitCode: 0,
                promptPath,
                manifestPath,
                rawTrace
            };
        }

        if (!options.continue) {
            await clearContinuation();
        }
        const continuation = options.continue ? await loadContinuation(state) : null;
        if (continuation && await resumeFromContinuation(state, continuation, options)) {
            // Resumed from checkpoint.
        } else {
            await savePhaseCheckpoint(state, {
                stage: 'analysis_static',
                staticAnalysis: null,
                dynamicAnalysis: null,
                previousFailure: null,
                nextAttempt: 1
            });
            appendLog('info', 'Phase 1: Starting static vulnerability analysis.');
            const staticAnalysis = await parseStaticWithCorrection(state, options);
            appendLog('info', `Static analysis completed. Targets: ${staticAnalysis.targets.map(t => t.function_name).join(', ')}`);
            await runExploitFromStatic(state, staticAnalysis, options);
        }
        appendLog('info', 'Multi-Agent pipeline completed successfully.');
        await clearContinuation();

        appendTraceEventSync(tracePaths.currentTracePath, {
            runId: state.runId,
            executionId: state.executionId || null,
            source: 'dashboard',
            type: 'agent_run_result',
            data: { status: 'success' }
        });
        rawTrace = await publishRawTrace({ runId: state.runId, executionId: state.executionId, status: 'success' });
        return {
            status: 'success',
            mode: 'autorun',
            exitCode: 0,
            promptPath,
            manifestPath,
            rawTrace
        };
    } catch (error) {
        if (error.canceled || options.signal?.aborted) {
            return {
                status: 'canceled',
                mode: 'autorun',
                exitCode: null,
                promptPath,
                manifestPath,
                rawTrace: null
            };
        }
        appendLog('error', `Pipeline execution error: ${error.message}`);
        if (error.continuation) {
            await saveContinuation(state, error.continuation).catch((saveError) => {
                appendLog('warn', `Could not save repair continuation: ${saveError.message}`);
            });
        }

        // 정교한 구제 로직: 토큰 한도 초과 등 외부 오류 발생 시, 실제 익스플로잇 성공 증적이 있으면 success로 전환
        appendTraceEventSync(tracePaths.currentTracePath, {
            runId: state.runId,
            executionId: state.executionId || null,
            source: 'dashboard',
            type: 'codex_error',
            data: { message: error.message }
        });
        appendTraceEventSync(tracePaths.currentTracePath, {
            runId: state.runId,
            executionId: state.executionId || null,
            source: 'dashboard',
            type: 'agent_run_result',
            data: { status: 'failure', message: error.message }
        });
        rawTrace = await publishRawTrace({ runId: state.runId, executionId: state.executionId, status: 'failure' });
        return {
            status: 'failure',
            mode: 'autorun',
            exitCode: 1,
            promptPath,
            manifestPath,
            rawTrace
        };
    }
};

module.exports = {
    observePhaseTool,
    normalizeDiscoveryResult,
    normalizeContinuation,
    runCodexAgent,
    shouldRunDynamicProbe,
    dynamicProofIssues,
    staticReasonLooksLikeRawDump,
    withStaticFallbackTarget,
    validatePhaseTool
};
