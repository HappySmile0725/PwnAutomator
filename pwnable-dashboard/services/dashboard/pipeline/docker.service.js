const fs = require('fs');
const path = require('path');
const Docker = require('dockerode');

const dockerClient = new Docker();
const CHALLENGE_ROLE_LABEL = 'pwnautomator.role';
const CHALLENGE_RUN_LABEL = 'pwnautomator.runId';
const CHALLENGE_ROLE = 'challenge';
const ignoredDirs = new Set(['.git', '__MACOSX', 'node_modules', '.pwnautomator', 'solution']);
const ignoredFiles = new Set(['hack.py']);
const ignoredBinaryNames = new Set(['Dockerfile', 'flag', ...ignoredFiles]);
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

    try {
        const container = dockerClient.getContainer(containerName);
        const info = await container.inspect();
        if (info?.State?.Running) {
            await container.stop({ t: 5 });
        }
        await container.remove({ force: true });
    } catch (error) {
        if (error.statusCode !== 404) {
            throw error;
        }
    }
};

const normalizeContainerName = (value) => String(value || '').replace(/^\//, '');

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

const findRunningChallengeContainer = async ({ runId, containerId, containerName, imageTag } = {}) => {
    for (const ref of [containerId, containerName].filter(Boolean)) {
        const info = await inspectContainerSafe(ref);
        if (containerMatchesChallenge(info, { runId, containerName, imageTag })) {
            return info;
        }
    }

    const labelFilters = [`${CHALLENGE_ROLE_LABEL}=${CHALLENGE_ROLE}`];
    if (runId) {
        labelFilters.push(`${CHALLENGE_RUN_LABEL}=${runId}`);
    }

    const containers = await dockerClient.listContainers({
        all: false,
        filters: JSON.stringify({ label: labelFilters })
    }).catch(() => []);

    for (const container of containers) {
        const info = await inspectContainerSafe(container.Id);
        if (containerMatchesChallenge(info, { runId, containerName, imageTag })) {
            return info;
        }
    }

    if (imageTag) {
        const imageContainers = await dockerClient.listContainers({
            all: false,
            filters: JSON.stringify({ ancestor: [imageTag] })
        }).catch(() => []);

        for (const container of imageContainers) {
            const info = await inspectContainerSafe(container.Id);
            if (containerMatchesChallenge(info, { runId, containerName, imageTag })) {
                return info;
            }
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
    } catch (error) {
        return false;
    }
};

const tokenizeDockerInstruction = (line) => line.match(/"[^"]+"|'[^']+'|\S+/g) || [];

const normalizeDockerSource = (value) => String(value || '')
    .replace(/^["']|["']$/g, '')
    .replace(/\\/g, '/');

const parseJsonDockerArgs = (rawArgs) => {
    try {
        const parsed = JSON.parse(rawArgs);
        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        return [];
    }
};

const parseDockerfileSources = (dockerfilePath) => {
    if (!dockerfilePath || !fs.existsSync(dockerfilePath)) {
        return [];
    }

    const content = fs.readFileSync(dockerfilePath, 'utf8');
    const sources = [];

    for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) {
            continue;
        }

        const match = line.match(/^(copy|add)\s+(.+)$/i);
        if (!match) {
            continue;
        }

        const rawArgs = match[2].trim();
        let args;
        if (rawArgs.startsWith('[')) {
            args = parseJsonDockerArgs(rawArgs);
        } else {
            args = tokenizeDockerInstruction(rawArgs).filter((token) => !token.startsWith('--'));
        }

        if (args.length < 2) {
            continue;
        }

        for (const source of args.slice(0, -1)) {
            const normalized = normalizeDockerSource(source);
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
            if (!entry.isFile() || ignoredBinaryNames.has(entry.name)) {
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
        .filter((sourcePath) => path.basename(sourcePath).toLowerCase() !== 'flag')
        .map((sourcePath) => path.relative(contextDir, sourcePath).replace(/\\/g, '/'));

    if (resolved.length > 0) {
        return [...new Set(resolved)];
    }

    const fallback = findLargestLikelyBinary(contextDir);
    return fallback ? [path.relative(contextDir, fallback).replace(/\\/g, '/')] : [];
};

module.exports = {
    buildDockerImage,
    findRunningChallengeContainer,
    findDockerContext,
    inspectContainer,
    isContainerRunning,
    removeContainerByName,
    resolveTrackingFiles,
    startContainer
};
