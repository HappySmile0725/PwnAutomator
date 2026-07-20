const fs = require('fs');
const path = require('path');

const paths = require('./paths');

const STAGE_DEFINITIONS = [
    { key: 'challenge_upload', label: 'Challenge Upload' },
    { key: 'docker_build', label: 'Docker Build' },
    { key: 'container_start', label: 'Container Start' },
    { key: 'inspect_runtime', label: 'Inspect Runtime' },
    { key: 'mcp_setup', label: 'MCP Setup' },
    { key: 'codex_agent', label: 'Codex Agent' },
    { key: 'dataset_save', label: 'Dataset Save' }
];

const terminalStageStatuses = new Set(['success', 'failure', 'waiting', 'skipped', 'canceled']);

const nowIso = () => new Date().toISOString();

const cloneStageDefinitions = () => STAGE_DEFINITIONS.map((stage, index) => ({
    ...stage,
    index,
    status: 'pending',
    detail: '',
    startedAt: null,
    completedAt: null
}));

const buildExecutionId = (runId, counter) => {
    const base = String(runId || 'manual').trim() || 'manual';
    const attempt = Number(counter) > 0 ? Number(counter) : 1;
    return `${base}-exec${String(attempt).padStart(2, '0')}`;
};

const createEmptyState = () => ({
    version: 2,
    runId: null,
    executionId: null,
    executionCounter: 0,
    executionStartedAt: null,
    status: 'idle',
    currentStage: null,
    createdAt: null,
    updatedAt: null,
    stages: cloneStageDefinitions(),
    challenge: null,
    mcpRuntime: null,
    docker: null,
    runtime: null,
    codex: null,
    dataset: null,
    logs: []
});

const normalizeState = (state) => {
    const base = createEmptyState();
    const incomingStages = Array.isArray(state?.stages) ? state.stages : [];
    const stages = base.stages.map((stage) => {
        const existing = incomingStages.find((item) => item?.key === stage.key) || {};
        return {
            ...stage,
            status: existing.status || stage.status,
            detail: existing.detail || '',
            startedAt: existing.startedAt || null,
            completedAt: existing.completedAt || null
        };
    });

    return {
        ...base,
        ...(state && typeof state === 'object' && !Array.isArray(state) ? state : {}),
        stages,
        logs: Array.isArray(state?.logs) ? state.logs.slice(-500) : []
    };
};

const readState = () => {
    try {
        return normalizeState(JSON.parse(fs.readFileSync(paths.pipelineStatePath, 'utf8')));
    } catch (_) {
        return createEmptyState();
    }
};

const writeState = (state) => {
    const normalized = normalizeState({ ...state, updatedAt: nowIso() });
    fs.mkdirSync(path.dirname(paths.pipelineStatePath), { recursive: true });
    fs.writeFileSync(paths.pipelineStatePath, JSON.stringify(normalized, null, 2), 'utf8');
    return normalized;
};

const updateState = (mutator) => {
    const state = readState();
    const result = mutator(state) || state;
    return writeState(result);
};

const appendLogs = (entries) => updateState((state) => {
    const nextEntries = (Array.isArray(entries) ? entries : [entries])
        .filter(Boolean)
        .map((entry) => ({
            at: entry.at || nowIso(),
            level: entry.level || 'info',
            message: String(entry.message || ''),
            meta: entry.meta || null
        }));

    state.logs = [
        ...(Array.isArray(state.logs) ? state.logs : []),
        ...nextEntries
    ].slice(-500);
    return state;
});

const appendLog = (level, message, meta) => appendLogs({ level, message, meta });

const setRunStatus = (status, currentStage) => updateState((state) => {
    state.status = status;
    if (currentStage !== undefined) {
        state.currentStage = currentStage;
    }
    return state;
});

const setStageStatus = (key, status, detail) => updateState((state) => {
    const stage = state.stages.find((item) => item.key === key);
    if (!stage) {
        return state;
    }

    stage.status = status;
    stage.detail = detail || '';
    if (status === 'running' && !stage.startedAt) {
        stage.startedAt = nowIso();
    }
    if (terminalStageStatuses.has(status)) {
        stage.completedAt = nowIso();
    }
    state.currentStage = key;
    return state;
});

const beginPipelineExecution = () => updateState((state) => {
    const timestamp = nowIso();
    const previousChallengeStage = state.stages.find((item) => item.key === 'challenge_upload');
    const stages = cloneStageDefinitions();
    const executionCounter = Math.max(0, Number(state.executionCounter) || 0) + 1;

    stages[0] = {
        ...stages[0],
        status: previousChallengeStage?.status === 'success' ? 'success' : 'pending',
        detail: previousChallengeStage?.detail || '',
        startedAt: previousChallengeStage?.startedAt || null,
        completedAt: previousChallengeStage?.completedAt || null
    };

    state.version = 2;
    state.executionCounter = executionCounter;
    state.executionId = buildExecutionId(state.runId, executionCounter);
    state.executionStartedAt = timestamp;
    state.status = 'uploaded';
    state.currentStage = 'challenge_upload';
    state.stages = stages;
    state.mcpRuntime = null;
    state.docker = null;
    state.runtime = null;
    state.codex = null;
    state.dataset = null;
    state.logs = [];
    return state;
});

const startUploadedRun = (runData) => {
    const state = createEmptyState();
    const timestamp = nowIso();
    state.runId = runData.runId;
    state.status = 'uploaded';
    state.currentStage = 'challenge_upload';
    state.createdAt = timestamp;
    state.updatedAt = timestamp;
    state.challenge = runData.challenge;
    state.stages[0] = {
        ...state.stages[0],
        status: 'success',
        detail: runData.challenge?.dockerfilePath ? 'Challenge ready' : 'Uploaded without Dockerfile',
        startedAt: timestamp,
        completedAt: timestamp
    };
    return writeState(state);
};

const failCurrentStage = (error) => updateState((state) => {
    const key = state.currentStage;
    const stage = state.stages.find((item) => item.key === key);
    if (stage) {
        stage.status = 'failure';
        stage.detail = error?.message || String(error || 'Stage failed');
        stage.completedAt = nowIso();
    }
    state.status = 'failed';
    return state;
});

const formatLogLine = (entry) => {
    const time = entry?.at ? new Date(entry.at).toLocaleTimeString('en-US', { hour12: false }) : '--:--:--';
    const level = entry?.level && entry.level !== 'info' ? `${String(entry.level).toUpperCase()} ` : '';
    return `[${time}] ${level}${entry?.message || ''}`;
};

const getPipelineView = () => {
    const state = readState();
    const files = state.challenge?.trackingFiles || [];
    const output = (state.logs || []).map(formatLogLine);
    return {
        ...state,
        steps: state.stages,
        files,
        output
    };
};

module.exports = {
    appendLog,
    appendLogs,
    beginPipelineExecution,
    failCurrentStage,
    getPipelineView,
    readState,
    setRunStatus,
    setStageStatus,
    startUploadedRun,
    updateState
};
