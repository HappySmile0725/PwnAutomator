const path = require('path');
const fs = require('fs').promises;

const paths = require('./paths');
const dockerService = require('./docker.service');
const { runCodexAgent } = require('./codexAgent.service');
const { inspectRuntime } = require('./runtimeInspect.service');
const { saveDatasetPackage } = require('./dataset.service');
const { setupManagedMcpRuntime, shouldAutoStartMcp } = require('./mcpRuntime.service');
const { tracePathsForRun } = require('./trace.service');
const {
    appendLog,
    appendLogs,
    failCurrentStage,
    getPipelineView: getBasePipelineView,
    readState,
    setRunStatus,
    setStageStatus,
    updateState
} = require('./state.service');

let activePipeline = null;
let activeAbortController = null;

const patchState = (mutator) => updateState((state) => {
    mutator(state);
    return state;
});

const withPipeline = (payload) => ({ ...payload, pipeline: getPipelineView() });

const getPipelineView = () => {
    const pipeline = getBasePipelineView();
    const tracePaths = tracePathsForRun(pipeline.runId);
    return {
        ...pipeline,
        tracePaths
    };
};

const createBufferedLogger = () => {
    let buffer = [];

    const flush = () => {
        if (buffer.length === 0) {
            return;
        }
        const entries = buffer;
        buffer = [];
        appendLogs(entries);
    };

    return {
        log(level, message, meta) {
            buffer.push({ level, message, meta, at: new Date().toISOString() });
            if (buffer.length >= 20) {
                flush();
            }
        },
        flush
    };
};

const sanitizeDockerName = (value) => String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '-')
    .replace(/^-+|-+$/g, '');

const buildRunDockerNames = (runId) => {
    const safeRunId = sanitizeDockerName(runId || Date.now());
    return {
        imageTag: `pwnautomator-challenge:${safeRunId}`,
        containerName: `pwnautomator-${safeRunId}`
    };
};

const containerNameFromInfo = (info) => String(info?.Name || '').replace(/^\//, '');
const currentContainerRef = (state) => state.docker?.containerId || state.docker?.containerName;
const currentBinaryMarkerPath = () => path.join(paths.challengeMetaDir, 'current_binary');

const challengeUploadError = (state) => {
    if (!state.challenge?.contextDir) {
        return 'Upload a challenge before starting the pipeline.';
    }
    if (!state.challenge?.dockerfilePath) {
        return 'Dockerfile was not found in the uploaded challenge.';
    }
    return '';
};

const readCurrentBinaryMarker = async () => {
    try {
        const markerPath = currentBinaryMarkerPath();
        const raw = await fs.readFile(markerPath, 'utf8');
        const candidate = String(raw || '').trim();
        if (!candidate) {
            return '';
        }
        const resolved = path.resolve(candidate);
        await fs.access(resolved);
        return resolved;
    } catch (_) {
        return '';
    }
};

const resolveChallengeBinaryFocus = async (challenge) => {
    const markerBinary = await readCurrentBinaryMarker();
    const contextDir = challenge?.contextDir || paths.challengeDir;
    const dockerfilePath = challenge?.dockerfilePath || null;
    const trackingFiles = dockerService.resolveTrackingFiles(dockerfilePath, contextDir);
    const fallbackBinary = trackingFiles[0] ? path.resolve(contextDir, trackingFiles[0]) : '';
    const targetBinaryPath = markerBinary || fallbackBinary;

    if (targetBinaryPath) {
        await fs.mkdir(paths.challengeMetaDir, { recursive: true });
        await fs.writeFile(currentBinaryMarkerPath(), targetBinaryPath, 'utf8');
    }

    return { trackingFiles, targetBinaryPath };
};

const refreshChallengeFocus = async () => {
    const state = readState();
    const challenge = state.challenge || {};
    const { trackingFiles, targetBinaryPath } = await resolveChallengeBinaryFocus(challenge);

    patchState((current) => {
        current.challenge = {
            ...(current.challenge || {}),
            trackingFiles,
            mcpWorkspace: {
                ...(current.challenge?.mcpWorkspace || {}),
                runId: current.runId,
                challengeDir: paths.challengeDir,
                contextDir: current.challenge?.contextDir || paths.challengeDir,
                dockerfilePath: current.challenge?.dockerfilePath || null,
                trackingFiles,
                targetBinaryPath,
                updatedAt: new Date().toISOString()
            }
        };
    });

    if (targetBinaryPath) {
        appendLog('info', `MCP focus binary: ${targetBinaryPath}`);
    } else {
        appendLog('warn', 'No focus binary resolved for MCP tools.');
    }
};

const applyExistingContainer = async (state) => {
    const names = buildRunDockerNames(state.runId);
    const dockerState = state.docker || {};
    const info = await dockerService.findRunningChallengeContainer({
        runId: state.runId,
        containerId: dockerState.containerId,
        containerName: dockerState.containerName || names.containerName,
        imageTag: dockerState.imageTag || names.imageTag
    });

    if (!info) {
        return false;
    }

    const containerName = containerNameFromInfo(info) || dockerState.containerName || names.containerName;
    const imageTag = info.Config?.Image || dockerState.imageTag || names.imageTag;
    patchState((current) => {
        current.docker = {
            ...(current.docker || {}),
            imageTag,
            containerName,
            containerId: info.Id,
            contextDir: state.challenge.contextDir,
            dockerfilePath: state.challenge.dockerfilePath,
            reusedExisting: true,
            reusedAt: new Date().toISOString(),
            startedAt: info.State?.StartedAt || current.docker?.startedAt || null
        };
    });
    setStageStatus('docker_build', 'skipped', 'Existing running container detected');
    setStageStatus('container_start', 'success', 'Existing container reused');
    appendLog('info', `Using existing challenge container: ${containerName}`);
    return true;
};

const runDockerBuild = async (state) => {
    setStageStatus('docker_build', 'running', 'Building challenge Docker image');
    const names = buildRunDockerNames(state.runId);
    const logger = createBufferedLogger();
    appendLog('info', `Docker build started: ${names.imageTag}`);

    try {
        await dockerService.buildDockerImage({
            contextDir: state.challenge.contextDir,
            dockerfilePath: state.challenge.dockerfilePath,
            imageTag: names.imageTag,
            onLog: (line) => logger.log('info', `docker: ${line}`)
        });
    } finally {
        logger.flush();
    }

    patchState((current) => {
        current.docker = {
            ...(current.docker || {}),
            imageTag: names.imageTag,
            containerName: names.containerName,
            contextDir: state.challenge.contextDir,
            dockerfilePath: state.challenge.dockerfilePath,
            builtAt: new Date().toISOString()
        };
    });
    setStageStatus('docker_build', 'success', 'Docker image built');
    appendLog('info', 'Docker build completed.');
};

const runContainerStart = async () => {
    const state = readState();
    setStageStatus('container_start', 'running', 'Starting challenge container');
    const container = await dockerService.startContainer({
        imageTag: state.docker.imageTag,
        containerName: state.docker.containerName,
        runId: state.runId
    });

    patchState((current) => {
        current.docker = {
            ...(current.docker || {}),
            containerId: container.id,
            startedAt: new Date().toISOString()
        };
    });
    setStageStatus('container_start', 'success', 'Container started');
    appendLog('info', `Container started: ${state.docker.containerName}`);
};

const runRuntimeInspection = async () => {
    const state = readState();
    setStageStatus('inspect_runtime', 'running', 'Inspecting running container');
    const runtime = await inspectRuntime(currentContainerRef(state));
    patchState((current) => {
        current.runtime = runtime;
    });
    setStageStatus('inspect_runtime', 'success', 'Runtime inspected');

    const ports = runtime.network?.ports || [];
    if (ports.length > 0) {
        appendLog('info', `Runtime ports: ${ports.map((port) => `${port.hostIp || '*'}:${port.hostPort || '-'}->${port.containerPort}`).join(', ')}`);
    } else {
        appendLog('warn', 'No exposed runtime ports were detected.');
    }
};

const runMcpSetupStage = async () => {
    if (!shouldAutoStartMcp()) {
        setStageStatus('mcp_setup', 'skipped', 'MCP autostart disabled');
        appendLog('info', 'MCP autostart disabled. Skipping MCP setup.');
        return;
    }

    const state = readState();
    setStageStatus('mcp_setup', 'running', 'Starting MCP servers');
    const runtime = await setupManagedMcpRuntime({
        binaryPath: state.challenge?.mcpWorkspace?.targetBinaryPath || ''
    });

    patchState((current) => {
        current.mcpRuntime = {
            ...(current.mcpRuntime || {}),
            enabled: runtime.enabled,
            pid: runtime.pid,
            scriptPath: runtime.scriptPath,
            endpoints: runtime.endpoints,
            readyAt: new Date().toISOString()
        };
    });
    setStageStatus('mcp_setup', 'success', 'MCP servers ready');
    const endpointSummary = (runtime.endpoints || [])
        .map((endpoint) => `${endpoint.name}=${endpoint.host}:${endpoint.port}`)
        .join(', ');
    appendLog('info', `MCP runtime ready: ${endpointSummary}`);
};

const runCodexStage = async (signal) => {
    setStageStatus('codex_agent', 'running', 'Preparing Codex agent task');
    const result = await runCodexAgent(readState(), { signal });
    patchState((current) => {
        current.codex = result;
    });

    if (result.status === 'canceled') {
        setStageStatus('codex_agent', 'canceled', 'Codex agent canceled');
        setRunStatus('canceled', 'codex_agent');
        return false;
    }

    if (result.status === 'waiting') {
        setStageStatus('codex_agent', 'waiting', result.message);
        setRunStatus('waiting_for_codex', 'codex_agent');
        return false;
    }

    setStageStatus('codex_agent', 'success', 'Codex agent completed');
    return true;
};

const runDatasetSaveStage = async () => {
    setStageStatus('dataset_save', 'running', 'Saving dataset package');
    const result = await saveDatasetPackage(readState());
    patchState((current) => {
        current.dataset = result;
    });

    setStageStatus('dataset_save', 'success', 'Dataset package saved');
    setRunStatus('success', 'dataset_save');
    appendLog('info', `Dataset package saved: ${path.relative(paths.repoRoot, result.packagePath)}`);
    return result;
};

const executePipeline = async (signal) => {
    try {
        const initialState = readState();
        const uploadError = challengeUploadError(initialState);
        if (uploadError) {
            throw new Error(uploadError);
        }
        const runDockerNames = buildRunDockerNames(initialState.runId);
        const cleanedContainers = await dockerService.stopStaleChallengeContainers({
            keepRunId: initialState.runId,
            keepContainerName: runDockerNames.containerName
        });
        if (cleanedContainers.length > 0) {
            appendLog('info', `Stopped stale challenge containers: ${cleanedContainers.map((item) => item.name || item.id).join(', ')}`);
        }
        await refreshChallengeFocus();
        setRunStatus('running', 'mcp_setup');
        await runMcpSetupStage();
        setRunStatus('running', 'docker_build');

        const reusedContainer = await applyExistingContainer(initialState);
        if (!reusedContainer) {
            await runDockerBuild(initialState);
            await runContainerStart();
        }
        await runRuntimeInspection();

        const codexCompleted = await runCodexStage(signal);
        if (!codexCompleted) {
            return;
        }

        await runDatasetSaveStage();
    } catch (error) {
        if (signal?.aborted) {
            appendLog('warn', 'Pipeline canceled by user.');
            const stage = readState().currentStage || 'codex_agent';
            setStageStatus(stage, 'canceled', 'Canceled by user');
            setRunStatus('canceled', stage);
            return;
        }
        appendLog('error', error.message || 'Pipeline failed.');
        failCurrentStage(error);
    }
};

const startPipeline = async () => {
    if (activePipeline) {
        return withPipeline({ success: true, running: true });
    }

    const error = challengeUploadError(readState());
    if (error) {
        return withPipeline({ success: false, error });
    }

    activeAbortController = new AbortController();
    activePipeline = executePipeline(activeAbortController.signal).finally(() => {
        activePipeline = null;
        activeAbortController = null;
    });

    return withPipeline({ success: true, running: true });
};

const cancelActivePipeline = async () => {
    if (!activePipeline || !activeAbortController) {
        return withPipeline({ success: false, error: 'No running LLM to cancel.' });
    }

    const state = readState();
    if (state.currentStage !== 'codex_agent') {
        return withPipeline({ success: false, error: 'Codex agent is not running yet.' });
    }

    appendLog('warn', 'Cancel requested by user.');
    activeAbortController.abort();
    setStageStatus('codex_agent', 'canceled', 'Cancel requested');
    setRunStatus('canceled', 'codex_agent');
    return withPipeline({ success: true, canceled: true });
};

const saveCurrentDatasetPackage = async () => {
    if (activePipeline) {
        return withPipeline({ success: false, error: 'Pipeline is still running.' });
    }

    try {
        const result = await runDatasetSaveStage();
        return withPipeline({ success: true, dataset: result });
    } catch (error) {
        appendLog('error', error.message || 'Dataset package save failed.');
        failCurrentStage(error);
        return withPipeline({ success: false, error: error.message });
    }
};

const getPipelineStatus = async () => {
    const pipeline = getPipelineView();
    const containerRunning = await dockerService.isContainerRunning(currentContainerRef(pipeline));

    return {
        ...pipeline,
        status: containerRunning ? 'operational' : pipeline.status,
        pipelineStatus: pipeline.status,
        containerRunning
    };
};

module.exports = {
    cancelActivePipeline,
    getPipelineStatus,
    getPipelineView,
    saveCurrentDatasetPackage,
    startPipeline
};
