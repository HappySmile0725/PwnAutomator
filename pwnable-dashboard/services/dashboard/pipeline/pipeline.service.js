const path = require('path');

const paths = require('./paths');
const dockerService = require('./docker.service');
const { runCodexAgent } = require('./codexAgent.service');
const { inspectRuntime } = require('./runtimeInspect.service');
const { saveDatasetDraft } = require('./dataset.service');
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

const ensureUploadedChallenge = (state) => {
    if (!state.challenge?.contextDir) {
        throw new Error('Upload a challenge before starting the pipeline.');
    }
    if (!state.challenge?.dockerfilePath) {
        throw new Error('Dockerfile was not found in the uploaded challenge.');
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
    updateState((current) => {
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
        return current;
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

    updateState((current) => {
        current.docker = {
            ...(current.docker || {}),
            imageTag: names.imageTag,
            containerName: names.containerName,
            contextDir: state.challenge.contextDir,
            dockerfilePath: state.challenge.dockerfilePath,
            builtAt: new Date().toISOString()
        };
        return current;
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

    updateState((current) => {
        current.docker = {
            ...(current.docker || {}),
            containerId: container.id,
            startedAt: new Date().toISOString()
        };
        return current;
    });
    setStageStatus('container_start', 'success', 'Container started');
    appendLog('info', `Container started: ${state.docker.containerName}`);
};

const runRuntimeInspection = async () => {
    const state = readState();
    setStageStatus('inspect_runtime', 'running', 'Inspecting running container');
    const runtime = await inspectRuntime(state.docker.containerId || state.docker.containerName);
    updateState((current) => {
        current.runtime = runtime;
        return current;
    });
    setStageStatus('inspect_runtime', 'success', 'Runtime inspected');

    const ports = runtime.network?.ports || [];
    if (ports.length > 0) {
        appendLog('info', `Runtime ports: ${ports.map((port) => `${port.hostIp || '*'}:${port.hostPort || '-'}->${port.containerPort}`).join(', ')}`);
    } else {
        appendLog('warn', 'No exposed runtime ports were detected.');
    }
};

const runCodexStage = async (signal) => {
    setStageStatus('codex_agent', 'running', 'Preparing Codex agent task');
    const result = await runCodexAgent(readState(), { signal });
    updateState((current) => {
        current.codex = result;
        return current;
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
    setStageStatus('dataset_save', 'running', 'Saving dataset draft');
    const result = await saveDatasetDraft(readState());
    updateState((current) => {
        current.dataset = result;
        return current;
    });

    setStageStatus('dataset_save', 'waiting', 'Dataset draft saved; schema pending');
    setRunStatus('waiting_for_dataset_schema', 'dataset_save');
    appendLog('info', `Dataset package saved: ${path.relative(paths.repoRoot, result.packagePath || result.filePath)}`);
    return result;
};

const executePipeline = async (signal) => {
    try {
        const initialState = readState();
        ensureUploadedChallenge(initialState);
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
            setStageStatus(readState().currentStage || 'codex_agent', 'canceled', 'Canceled by user');
            setRunStatus('canceled', readState().currentStage || 'codex_agent');
            return;
        }
        appendLog('error', error.message || 'Pipeline failed.');
        failCurrentStage(error);
    }
};

const startPipeline = async () => {
    if (activePipeline) {
        return { success: true, running: true, pipeline: getPipelineView() };
    }

    try {
        ensureUploadedChallenge(readState());
    } catch (error) {
        return { success: false, error: error.message, pipeline: getPipelineView() };
    }

    activeAbortController = new AbortController();
    activePipeline = executePipeline(activeAbortController.signal).finally(() => {
        activePipeline = null;
        activeAbortController = null;
    });

    return { success: true, running: true, pipeline: getPipelineView() };
};

const cancelActivePipeline = async () => {
    if (!activePipeline || !activeAbortController) {
        return { success: false, error: 'No running LLM to cancel.', pipeline: getPipelineView() };
    }

    const state = readState();
    if (state.currentStage !== 'codex_agent') {
        return { success: false, error: 'Codex agent is not running yet.', pipeline: getPipelineView() };
    }

    appendLog('warn', 'Cancel requested by user.');
    activeAbortController.abort();
    setStageStatus('codex_agent', 'canceled', 'Cancel requested');
    setRunStatus('canceled', 'codex_agent');
    return { success: true, canceled: true, pipeline: getPipelineView() };
};

const saveCurrentDatasetDraft = async () => {
    if (activePipeline) {
        return { success: false, error: 'Pipeline is still running.', pipeline: getPipelineView() };
    }

    try {
        const result = await runDatasetSaveStage();
        return { success: true, dataset: result, pipeline: getPipelineView() };
    } catch (error) {
        appendLog('error', error.message || 'Dataset draft save failed.');
        failCurrentStage(error);
        return { success: false, error: error.message, pipeline: getPipelineView() };
    }
};

const getPipelineStatus = async () => {
    const pipeline = getPipelineView();
    const containerRef = pipeline.docker?.containerId || pipeline.docker?.containerName;
    const containerRunning = await dockerService.isContainerRunning(containerRef);

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
    saveCurrentDatasetDraft,
    startPipeline
};
