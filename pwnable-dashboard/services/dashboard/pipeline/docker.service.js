const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const Docker = require('dockerode');

const dockerClient = new Docker();
const CHALLENGE_ROLE_LABEL = 'pwnautomator.role';
const CHALLENGE_RUN_LABEL = 'pwnautomator.runId';
const CHALLENGE_ROLE = 'challenge';
const ignoredDirs = new Set(['.git', '__MACOSX', 'node_modules', '.pwnautomator', 'solution']);
const ignoredFiles = new Set(['hack.py']);
const ignoredBinaryNames = new Set(['Dockerfile', 'flag', ...ignoredFiles]);
const ignoredBinaryNamePatterns = [
    /^libc(?:-[\d.]+)?\.so(?:\.\d+)*$/i,
    /^ld(?:-[\d.]+)?\.so(?:\.\d+)*$/i,
    /^ld-linux.*\.so(?:\.\d+)*$/i
];
const ignoredBinaryExtensions = new Set([
    '.json',
    '.md',
    '.txt',
    '.yml',
    '.yaml',
    '.toml',
    '.ini',
    '.log',
    '.zip'
]);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const isRemovalConflict = (error) => {
    const message = String(error?.message || '').toLowerCase();
    return error?.statusCode === 409 || message.includes('already in progress');
};

const findDockerContext = (baseDir) => {
    if (!baseDir || !fs.existsSync(baseDir)) {
        return null;
    }

    const queue = [baseDir];
    while (queue.length > 0) {
        const currentDir = queue.shift();
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        if (entries.some((entry) => entry.isFile() && entry.name === 'Dockerfile')) {
            return currentDir;
        }
        for (const entry of entries) {
            if (entry.isDirectory() && !ignoredDirs.has(entry.name)) {
                queue.push(path.join(currentDir, entry.name));
            }
        }
    }

    return null;
};

const collectContextFiles = (currentDir, baseDir, out) => {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
        if (ignoredDirs.has(entry.name)) {
            continue;
        }

        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
            collectContextFiles(fullPath, baseDir, out);
            continue;
        }
        if (entry.isFile()) {
            if (ignoredFiles.has(entry.name)) {
                continue;
            }
            out.push(path.relative(baseDir, fullPath).replace(/\\/g, '/'));
        }
    }
};

const getContextFiles = (contextDir) => {
    const files = [];
    collectContextFiles(contextDir, contextDir, files);
    return files;
};

const buildDockerImage = async ({ contextDir, dockerfilePath, imageTag, onLog }) => {
    const src = getContextFiles(contextDir);
    if (src.length === 0) {
        throw new Error('Build context is empty.');
    }

    const dockerfile = path.relative(contextDir, dockerfilePath).replace(/\\/g, '/');
    const tarStream = await dockerClient.buildImage({ context: contextDir, src }, { t: imageTag, dockerfile });

    return new Promise((resolve, reject) => {
        dockerClient.modem.followProgress(tarStream, (err, result) => {
            if (err) {
                reject(err);
                return;
            }

            const failed = (result || []).find((item) => item?.error || item?.errorDetail?.message);
            if (failed) {
                reject(new Error(failed.error || failed.errorDetail.message));
                return;
            }

            resolve(result || []);
        }, (event) => {
            const text = event?.stream || event?.status || event?.error || '';
            if (!text || typeof onLog !== 'function') {
                return;
            }
            const lines = String(text).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
            for (const line of lines) {
                onLog(line);
            }
        });
    });
};

const removeContainerByName = async (containerName) => {
    if (!containerName) {
        return;
    }

    for (let attempt = 1; attempt <= 10; attempt += 1) {
        try {
            const container = dockerClient.getContainer(containerName);
            const info = await container.inspect();
            if (info?.State?.Running) {
                await container.stop({ t: 5 });
            }
            await container.remove({ force: true });
            return;
        } catch (error) {
            if (error?.statusCode === 404) {
                return;
            }
            const transientConflict = isRemovalConflict(error);
            if (!transientConflict || attempt === 10) {
                throw error;
            }
            await sleep(200 * attempt);
        }
    }
};

const normalizeContainerName = (value) => String(value || '').replace(/^\//, '');
const isChallengeContainerName = (name) => normalizeContainerName(name).startsWith('pwnautomator-');
const isRunningState = (state) => String(state || '').toLowerCase() === 'running';
const listContainersSafe = (options) => dockerClient.listContainers(options).catch(() => []);

const inspectContainerSafe = async (containerIdOrName) => {
    if (!containerIdOrName) {
        return null;
    }

    try {
        return await inspectContainer(containerIdOrName);
    } catch (_) {
        return null;
    }
};

const isRunningInfo = (info) => Boolean(info?.State?.Running);

const containerMatchesChallenge = (info, { runId, containerName, imageTag } = {}) => {
    if (!isRunningInfo(info)) {
        return false;
    }

    const labels = info.Config?.Labels || {};
    const name = normalizeContainerName(info.Name);
    if (containerName && name === normalizeContainerName(containerName)) {
        return true;
    }
    if (runId && labels[CHALLENGE_RUN_LABEL] === runId && labels[CHALLENGE_ROLE_LABEL] === CHALLENGE_ROLE) {
        return true;
    }
    if (imageTag && info.Config?.Image === imageTag) {
        return true;
    }
    return false;
};

const stopStaleChallengeContainers = async ({ keepRunId, keepContainerName } = {}) => {
    const keepName = normalizeContainerName(keepContainerName);
    const containers = await listContainersSafe({ all: true });
    const stale = [];

    for (const container of containers) {
        const labels = container.Labels || {};
        const name = normalizeContainerName(container.Names?.[0] || '');
        const isChallenge = labels[CHALLENGE_ROLE_LABEL] === CHALLENGE_ROLE || isChallengeContainerName(name);
        if (!isChallenge) {
            continue;
        }

        const runId = labels[CHALLENGE_RUN_LABEL];
        if (keepRunId && runId && runId === keepRunId) {
            continue;
        }
        if (keepName && name === keepName) {
            continue;
        }

        stale.push({
            id: container.Id,
            name,
            runId: runId || '',
            wasRunning: isRunningState(container.State)
        });
    }

    for (const containerInfo of stale) {
        const ref = containerInfo.id || containerInfo.name;
        if (!ref) {
            continue;
        }

        for (let attempt = 1; attempt <= 10; attempt += 1) {
            try {
                const container = dockerClient.getContainer(ref);
                if (containerInfo.wasRunning) {
                    await container.stop({ t: 5 });
                }
                await container.remove({ force: true });
                break;
            } catch (error) {
                if (error?.statusCode === 404) {
                    break;
                }
                const transientConflict = isRemovalConflict(error);
                if (!transientConflict) {
                    throw error;
                }
                if (attempt === 10) {
                    break;
                }
                await sleep(200 * attempt);
            }
        }
    }

    return stale;
};

const findRunningChallengeContainer = async ({ runId, containerId, containerName, imageTag } = {}) => {
    for (const ref of [containerId, containerName].filter(Boolean)) {
        const info = await inspectContainerSafe(ref);
        if (containerMatchesChallenge(info, { runId, containerName, imageTag })) {
            return info;
        }
    }

    const containers = await listContainersSafe({ all: false });
    for (const container of containers) {
        const info = await inspectContainerSafe(container.Id);
        if (containerMatchesChallenge(info, { runId, containerName, imageTag })) {
            return info;
        }
    }

    return null;
};

const startContainer = async ({ imageTag, containerName, runId }) => {
    await removeContainerByName(containerName);
    const container = await dockerClient.createContainer({
        name: containerName,
        Image: imageTag,
        HostConfig: {
            PublishAllPorts: true
        },
        Labels: {
            [CHALLENGE_RUN_LABEL]: runId || '',
            [CHALLENGE_ROLE_LABEL]: CHALLENGE_ROLE
        }
    });
    await container.start();
    return container;
};

const copyFirstExistingFromContainer = async (containerIdOrName, containerPaths, hostPath) => {
    if (!containerIdOrName || !hostPath) {
        return null;
    }
    fs.mkdirSync(path.dirname(hostPath), { recursive: true });
    for (const containerPath of containerPaths.filter(Boolean)) {
        const result = spawnSync('docker', ['cp', '-L', `${containerIdOrName}:${containerPath}`, hostPath], {
            encoding: 'utf8'
        });
        if (result.status === 0) {
            return { containerPath, hostPath };
        }
    }
    return null;
};

const inspectContainer = async (containerIdOrName) => {
    const container = dockerClient.getContainer(containerIdOrName);
    return container.inspect();
};

const isContainerRunning = async (containerIdOrName) => {
    if (!containerIdOrName) {
        return false;
    }
    try {
        const info = await inspectContainer(containerIdOrName);
        return Boolean(info?.State?.Running);
    } catch (_) {
        return false;
    }
};

const tokenizeDockerInstruction = (line) => line.match(/"[^"]+"|'[^']+'|\S+/g) || [];

const stripDockerQuotes = (value) => String(value || '').replace(/^["']|["']$/g, '');

const normalizeDockerSource = (value) => String(value || '')
    .replace(/^["']|["']$/g, '')
    .replace(/\\/g, '/');

const isIgnoredBinaryName = (name) => {
    const base = String(name || '');
    return ignoredBinaryNames.has(base) || ignoredBinaryNamePatterns.some((pattern) => pattern.test(base));
};

const isIgnoredBinaryPath = (filePath) => isIgnoredBinaryName(path.basename(filePath));

const expandDockerVariables = (value, variables) => String(value || '').replace(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g, (match, braced, plain) => {
    const key = braced || plain;
    return Object.prototype.hasOwnProperty.call(variables, key) ? variables[key] : match;
});

const collectDockerVariables = (line, variables) => {
    const match = line.match(/^(env|arg)\s+(.+)$/i);
    if (!match) {
        return;
    }
    const tokens = tokenizeDockerInstruction(match[2]).map(stripDockerQuotes);
    if (tokens.length === 0) {
        return;
    }
    if (tokens[0].includes('=')) {
        for (const token of tokens) {
            const index = token.indexOf('=');
            if (index > 0) {
                variables[token.slice(0, index)] = expandDockerVariables(token.slice(index + 1), variables);
            }
        }
        return;
    }
    if (match[1].toLowerCase() === 'env' && tokens.length >= 2) {
        variables[tokens[0]] = expandDockerVariables(tokens.slice(1).join(' '), variables);
        return;
    }
    const index = tokens[0].indexOf('=');
    if (match[1].toLowerCase() === 'arg' && index > 0) {
        variables[tokens[0].slice(0, index)] = expandDockerVariables(tokens[0].slice(index + 1), variables);
    }
};

const parseJsonDockerArgs = (rawArgs) => {
    try {
        const parsed = JSON.parse(rawArgs);
        return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
        return [];
    }
};

const parseDockerfileSources = (dockerfilePath) => {
    if (!dockerfilePath || !fs.existsSync(dockerfilePath)) {
        return [];
    }

    const content = fs.readFileSync(dockerfilePath, 'utf8');
    const sources = [];
    const variables = {};

    for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) {
            continue;
        }

        collectDockerVariables(line, variables);

        const match = line.match(/^(copy|add)\s+(.+)$/i);
        if (!match) {
            continue;
        }

        const rawArgs = match[2].trim();
        const argsWithoutFlags = rawArgs.replace(/^(--\S+\s+)*/, '').trim();
        let args;
        if (argsWithoutFlags.startsWith('[')) {
            args = parseJsonDockerArgs(argsWithoutFlags);
        } else {
            args = tokenizeDockerInstruction(rawArgs).filter((token) => !token.startsWith('--'));
        }

        if (args.length < 2) {
            continue;
        }

        for (const source of args.slice(0, -1)) {
            const normalized = normalizeDockerSource(expandDockerVariables(source, variables));
            if (!normalized || normalized === '.' || normalized === './' || normalized.includes('*')) {
                continue;
            }
            sources.push(normalized);
        }
    }

    return sources;
};

const findLargestLikelyBinary = (baseDir) => {
    let best = null;
    if (!baseDir || !fs.existsSync(baseDir)) {
        return null;
    }

    const queue = [baseDir];
    while (queue.length > 0) {
        const currentDir = queue.shift();
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (!ignoredDirs.has(entry.name)) {
                    queue.push(path.join(currentDir, entry.name));
                }
                continue;
            }
            if (!entry.isFile() || isIgnoredBinaryName(entry.name)) {
                continue;
            }

            const ext = path.extname(entry.name).toLowerCase();
            if (ignoredBinaryExtensions.has(ext)) {
                continue;
            }

            const fullPath = path.join(currentDir, entry.name);
            const stat = fs.statSync(fullPath);
            if (!best || stat.size > best.size) {
                best = { path: fullPath, size: stat.size };
            }
        }
    }

    return best?.path || null;
};

const resolveTrackingFiles = (dockerfilePath, contextDir) => {
    const sources = parseDockerfileSources(dockerfilePath);
    const resolved = sources
        .map((source) => path.resolve(contextDir, source))
        .filter((sourcePath) => fs.existsSync(sourcePath) && fs.statSync(sourcePath).isFile())
        .filter((sourcePath) => !isIgnoredBinaryPath(sourcePath))
        .map((sourcePath) => path.relative(contextDir, sourcePath).replace(/\\/g, '/'));

    if (resolved.length > 0) {
        return [...new Set(resolved)];
    }

    const fallback = findLargestLikelyBinary(contextDir);
    return fallback ? [path.relative(contextDir, fallback).replace(/\\/g, '/')] : [];
};

module.exports = {
    buildDockerImage,
    copyFirstExistingFromContainer,
    findRunningChallengeContainer,
    findDockerContext,
    inspectContainer,
    isContainerRunning,
    resolveTrackingFiles,
    stopStaleChallengeContainers,
    startContainer
};
