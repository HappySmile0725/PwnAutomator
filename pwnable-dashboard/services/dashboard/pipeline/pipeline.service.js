const path = require('path');
const fs = require('fs').promises;

const paths = require('./paths');
const dockerService = require('./docker.service');
const { runCodexAgent } = require('./codexAgent.service');
const { inspectRuntime } = require('./runtimeInspect.service');
const { datasetSaveError, saveDatasetPackage } = require('./dataset.service');
const { setupManagedMcpRuntime, shouldAutoStartMcp, stopManagedMcpRuntime } = require('./mcpRuntime.service');
const { tracePathsForRun } = require('./trace.service');
const {
    appendLog,
    appendLogs,
    beginPipelineExecution,
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

const logIncludes = (state, needle) => Array.isArray(state?.logs)
    && state.logs.some((entry) => String(entry?.message || '').includes(needle));

const traceSuccessPattern = /\b(?:uid|gid)=\d+|[A-Za-z0-9_]{2,16}\{[^}\r\n]{4,}\}/i;

const isDatasetSaveCandidate = (state) => (
    ['success', 'failure'].includes(state?.codex?.status)
    || (
        logIncludes(state, 'codex turn completed')
        && logIncludes(state, 'pwn_payload_write completed')
    )
) && !datasetSaveError(state);

const isContinueCandidate = (state) => Boolean(state?.challenge?.contextDir)
    && !activePipeline
    && ['failed', 'canceled', 'waiting_for_codex'].includes(state?.status)
    && state?.currentStage === 'codex_agent'
    && ['failure', 'canceled', 'waiting'].includes(state?.codex?.status);

const existsSince = async (filePath, since) => {
    if (!filePath) {
        return false;
    }
    try {
        const stat = await fs.stat(filePath);
        if (!since) {
            return true;
        }
        return stat.mtime.getTime() >= new Date(since).getTime() - 5000;
    } catch (_) {
        return false;
    }
};

const getPipelineView = () => {
    const pipeline = getBasePipelineView();
    const tracePaths = tracePathsForRun(pipeline.runId, pipeline.executionId);
    return {
        ...pipeline,
        tracePaths,
        canSaveDataset: isDatasetSaveCandidate(pipeline),
        canContinue: isContinueCandidate(pipeline)
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
const currentBinaryMarkerPath = () => path.join(paths.challengeMetaDir, 'current_binary');
const libcFileName = 'libc.so.6';
const containerLibcPath = '/usr/lib/x86_64-linux-gnu/libc.so.6';
const libcNamePattern = /^libc(?:[-_.A-Za-z0-9]*)?\.so(?:\.\d+)*$/i;

const readTraceContent = async (runId, executionId) => {
    if (!runId) {
        return '';
    }
    const tracePaths = tracePathsForRun(runId, executionId);
    const chunks = [];
    for (const filePath of [tracePaths.currentTracePath, tracePaths.rawDatasetPath]) {
        try {
            chunks.push(await fs.readFile(filePath, 'utf8'));
        } catch (_) {
            // Missing trace copies are normal before dataset save.
        }
    }
    return chunks.join('\n');
};

const traceEventHasVerifiedExploit = (event) => {
    if (event?.type === 'exploit_verification') {
        return event?.data?.success === true && ['command', 'flag'].includes(event?.data?.evidence);
    }
    const item = event?.data?.item;
    if (event?.source !== 'codex' || event?.type !== 'llm_json_event' || item?.type !== 'mcp_tool_call' || item?.status !== 'completed') {
        return false;
    }
    const result = JSON.stringify(item.result || {});
    if (item.tool === 'pwn_session_poll') {
        return traceSuccessPattern.test(result);
    }
    return item.tool === 'pwn_payload_execute' && /[A-Za-z0-9_]{2,16}\{[^}\r\n]{4,}\}/.test(result);
};

const traceHasVerifiedExploit = async (runId, executionId) => {
    const content = await readTraceContent(runId, executionId);
    return content.split(/\r?\n/).some((line) => {
        try {
            return traceEventHasVerifiedExploit(JSON.parse(line));
        } catch (_) {
            return false;
        }
    });
};

const hasRecentExploitArtifact = async (state) => {
    const codexStage = state.stages.find((stage) => stage.key === 'codex_agent');
    const startedAt = codexStage?.startedAt || state.createdAt;
    const candidates = [
        path.join(paths.solutionDir, 'exploit.py'),
        path.join(paths.challengeDir, 'hack.py')
    ];

    for (const candidate of candidates) {
        if (await existsSince(candidate, startedAt)) {
            return true;
        }
    }
    return false;
};

const recoverCompletedCodexResult = async ({ allowRunning = false } = {}) => {
    const state = readState();
    if (state.codex?.status === 'success') {
        return false;
    }
    const recoverableState = ['canceled', 'failed', 'waiting_for_codex'].includes(state.status)
        || (allowRunning && state.status === 'running' && state.currentStage === 'codex_agent');
    if (!recoverableState || !['codex_agent', 'dataset_save'].includes(state.currentStage)) {
        return false;
    }
    const [exploitArtifact, verifiedExploit] = await Promise.all([
        hasRecentExploitArtifact(state),
        traceHasVerifiedExploit(state.runId, state.executionId)
    ]);
    if (!verifiedExploit || !exploitArtifact) {
        return false;
    }

    const tracePaths = tracePathsForRun(state.runId, state.executionId);
    const recoveredAt = new Date().toISOString();
    patchState((current) => {
        current.codex = {
            status: 'success',
            mode: 'autorun',
            exitCode: 0,
            promptPath: path.join(paths.codexDir, 'codex_task.md'),
            manifestPath: path.join(paths.codexDir, 'manifest.json'),
            rawTrace: {
                enabled: true,
                runId: current.runId,
                executionId: current.executionId || null,
                status: 'success',
                recoveredFromFailedTurn: true,
                recoveredAt,
                ...tracePaths
            },
            recoveredFromFailedTurn: true,
            recoveredAt
        };
    });
    setStageStatus('codex_agent', 'success', 'Codex agent completed (recovered)');
    setRunStatus('waiting_for_dataset', 'dataset_save');
    appendLog('info', 'Recovered verified exploit from trace; dataset save is available.');
    return true;
};

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

const resolveChallengeBinaryFocus = async (challenge, { preferMarker = true } = {}) => {
    const markerBinary = preferMarker ? await readCurrentBinaryMarker() : '';
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

const refreshChallengeFocus = async (options = {}) => {
    const state = readState();
    const challenge = state.challenge || {};
    const { trackingFiles, targetBinaryPath } = await resolveChallengeBinaryFocus(challenge, options);

    patchState((current) => {
        current.challenge = {
            ...(current.challenge || {}),
            trackingFiles,
            mcpWorkspace: {
                ...(current.challenge?.mcpWorkspace || {}),
                runId: current.runId,
                executionId: current.executionId || null,
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

const findChallengeLibc = async (baseDir, outputPath) => {
    const queue = [baseDir].filter(Boolean);
    const skipDirs = new Set(['.git', '__MACOSX', 'node_modules', '.pwnautomator', 'solution']);
    const output = outputPath ? path.resolve(outputPath) : '';

    while (queue.length > 0) {
        const currentDir = queue.shift();
        let entries;
        try {
            entries = await fs.readdir(currentDir, { withFileTypes: true });
        } catch (_) {
            continue;
        }
        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory() && !skipDirs.has(entry.name)) {
                queue.push(fullPath);
            } else if (entry.isFile() && libcNamePattern.test(entry.name) && path.resolve(fullPath) !== output) {
                return fullPath;
            }
        }
    }
    return '';
};

const ensureChallengeLibc = async () => {
    const state = readState();
    const targetBinaryPath = state.challenge?.mcpWorkspace?.targetBinaryPath || '';
    if (!targetBinaryPath) {
        return '';
    }

    const targetPath = path.join(path.dirname(targetBinaryPath), libcFileName);
    try {
        await fs.access(targetPath);
        return targetPath;
    } catch (_) {}

    const provided = await findChallengeLibc(state.challenge?.contextDir || paths.challengeDir, targetPath);
    if (provided) {
        await fs.copyFile(provided, targetPath);
        appendLog('info', `Using challenge libc: ${path.relative(paths.repoRoot, targetPath)}`);
        return targetPath;
    }

    const copied = await dockerService.copyFirstExistingFromContainer(currentContainerRef(state), [containerLibcPath], targetPath);
    if (copied) {
        appendLog('info', `Copied container libc: ${copied.containerPath} -> ${path.relative(paths.repoRoot, targetPath)}`);
        return targetPath;
    }

    appendLog('warn', 'No libc.so.6 found in challenge files or container.');
    return '';
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
    await ensureChallengeLibc();
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
    const remote = remoteEndpointFromRuntime(state.runtime);
    setStageStatus('mcp_setup', 'running', 'Starting MCP servers');
    const runtime = await setupManagedMcpRuntime({
        binaryPath: state.challenge?.mcpWorkspace?.targetBinaryPath || '',
        remoteHost: remote.host,
        remotePort: remote.port
    });

    patchState((current) => {
        current.mcpRuntime = {
            ...(current.mcpRuntime || {}),
            enabled: runtime.enabled,
            pid: runtime.pid,
            scriptPath: runtime.scriptPath,
            stdoutPath: runtime.stdoutPath,
            stderrPath: runtime.stderrPath,
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

const runCodexStage = async (signal, options = {}) => {
    setStageStatus('codex_agent', 'running', 'Preparing Codex agent task');
    const result = await runCodexAgent(readState(), { signal, continue: options.continue === true });
    patchState((current) => {
        current.codex = result;
    });

    if (result.status === 'canceled') {
        setStageStatus('codex_agent', 'canceled', 'Codex agent canceled');
        setRunStatus('canceled', 'codex_agent');
        return result;
    }

    if (result.status === 'waiting') {
        setStageStatus('codex_agent', 'waiting', result.message);
        setRunStatus('waiting_for_codex', 'codex_agent');
        return result;
    }

    if (result.status === 'failure') {
        setStageStatus('codex_agent', 'failure', 'Codex agent failed');
        setRunStatus('failed', 'codex_agent');
        return result;
    }

    if (result.status !== 'success') {
        setStageStatus('codex_agent', 'failure', `Unexpected Codex status: ${result.status || 'unknown'}`);
        setRunStatus('failed', 'codex_agent');
        return result;
    }

    setStageStatus('codex_agent', 'success', 'Codex agent completed');
    return result;
};

const runDatasetSaveStage = async (options = {}) => {
    setStageStatus('dataset_save', 'running', 'Saving dataset package');
    const state = readState();
    const previousRunStatus = state.status;
    const result = await saveDatasetPackage(state);
    patchState((current) => {
        current.dataset = result;
    });

    setStageStatus('dataset_save', 'success', 'Dataset package saved');
    if (!options.preserveRunStatus && previousRunStatus !== 'failed') {
        setRunStatus('success', 'dataset_save');
    }
    appendLog('info', `Dataset package saved: ${path.relative(paths.repoRoot, result.packagePath)}`);
    return result;
};

const prepareContinuation = () => {
    patchState((state) => {
        state.status = 'uploaded';
        state.currentStage = 'codex_agent';
        state.codex = null;
        state.dataset = null;
        for (const stage of state.stages) {
            if (stage.key === 'codex_agent') {
                stage.status = 'pending';
                stage.detail = 'Ready to continue';
                stage.completedAt = null;
            }
            if (stage.key === 'dataset_save') {
                stage.status = 'pending';
                stage.detail = '';
                stage.startedAt = null;
                stage.completedAt = null;
            }
        }
    });
    appendLog('info', 'Continuing Codex run from the existing workspace and trace.');
};

const stopActivePipelineForNewUpload = async () => {
    if (!activePipeline) {
        return false;
    }

    appendLog('warn', 'Stopping active pipeline before new challenge upload.');
    activeAbortController?.abort();
    await stopManagedMcpRuntime();
    await activePipeline.catch(() => {});
    return true;
};

const resetRuntimeForFreshStart = async () => {
    await stopManagedMcpRuntime();
    await fs.rm(path.join(paths.challengeMetaDir, 'ghidra_project'), { recursive: true, force: true });
    const cleanedContainers = await dockerService.stopStaleChallengeContainers();
    patchState((state) => {
        state.docker = null;
        state.runtime = null;
        state.mcpRuntime = null;
    });
    if (cleanedContainers.length > 0) {
        appendLog('info', `Stopped challenge containers: ${cleanedContainers.map((item) => item.name || item.id).join(', ')}`);
    }
};

const executePipeline = async (signal, options = {}) => {
    try {
        const continuing = options.continue === true;
        const initialState = readState();
        const uploadError = challengeUploadError(initialState);
        if (uploadError) {
            throw new Error(uploadError);
        }
        if (!continuing) {
            await resetRuntimeForFreshStart();
        }
        await refreshChallengeFocus({ preferMarker: continuing });
        setRunStatus('running', 'docker_build');

        const buildState = readState();
        const reusedContainer = continuing ? await applyExistingContainer(buildState) : false;
        if (!reusedContainer) {
            await runDockerBuild(buildState);
            await runContainerStart();
        }
        await runRuntimeInspection();
        await ensureChallengeLibc();

        setRunStatus('running', 'mcp_setup');
        await runMcpSetupStage();

        const codexResult = await runCodexStage(signal, { continue: continuing });
        if (codexResult.status === 'canceled' || codexResult.status === 'waiting') {
            return;
        }

        if (codexResult.status === 'failure') {
            const recovered = await recoverCompletedCodexResult();
            if (isDatasetSaveCandidate(readState())) {
                await runDatasetSaveStage({ preserveRunStatus: !recovered });
                if (!recovered) {
                    setRunStatus('failed', 'dataset_save');
                }
            }
            return;
        }

        if (codexResult.status === 'success') {
            await runDatasetSaveStage();
        }
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

    beginPipelineExecution();
    activeAbortController = new AbortController();
    activePipeline = executePipeline(activeAbortController.signal).finally(() => {
        activePipeline = null;
        activeAbortController = null;
    });

    return withPipeline({ success: true, running: true });
};

const continuePipeline = async () => {
    if (activePipeline) {
        return withPipeline({ success: true, running: true });
    }

    const state = readState();
    const error = challengeUploadError(state);
    if (error) {
        return withPipeline({ success: false, error });
    }
    if (!isContinueCandidate(state)) {
        return withPipeline({ success: false, error: 'No resumable Codex run is available.' });
    }

    prepareContinuation();
    activeAbortController = new AbortController();
    activePipeline = executePipeline(activeAbortController.signal, { continue: true }).finally(() => {
        activePipeline = null;
        activeAbortController = null;
    });

    return withPipeline({ success: true, running: true, continued: true });
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
        const recovered = await recoverCompletedCodexResult({ allowRunning: true });
        if (!recovered) {
            return withPipeline({ success: false, error: 'Pipeline is still running.' });
        }
    }

    try {
        await recoverCompletedCodexResult();
        const blocked = datasetSaveError(readState());
        if (blocked) {
            return withPipeline({ success: false, error: blocked });
        }
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
    continuePipeline,
    getPipelineStatus,
    getPipelineView,
    saveCurrentDatasetPackage,
    traceHasVerifiedExploit,
    traceEventHasVerifiedExploit,
    stopActivePipelineForNewUpload,
    startPipeline
};
