const path = require('path');
const fs = require('fs');

const { buildDockerImage } = require('./dockers/buildDockerImage');
const { startContainer } = require('./dockers/startContainer');
const { applyDockerfileSetup } = require('./dockers/applyDockerSetup');
const { findDockerContext } = require('./dockers/findDockerContext');
const { setRunActive } = require('../ais/runtimeState');

const nowDir = path.join(__dirname, '..', '..', '..', 'data', 'storage', 'now');
const aiDataPath = path.join(__dirname, '..', '..', '..', 'data', 'ai.json');
const defaultOutput = ['Build Success', 'Container Ready', 'Running Qwen3-Coder30b'];

const readAiData = () => {
    try {
        return JSON.parse(fs.readFileSync(aiDataPath, 'utf8'));
    } catch (error) {
        return {};
    }
};

const writeAiData = (data) => {
    fs.writeFileSync(aiDataPath, JSON.stringify(data, null, 2));
};

const appendOutputLines = (output, lines) => {
    const next = Array.isArray(output) ? [...output] : [];
    for (const line of lines) {
        if (!next.includes(line)) {
            next.push(line);
        }
    }
    return next;
};

const updateAiOutput = (lines) => {
    const existing = readAiData();
    const output = appendOutputLines(existing.output, lines);
    const updated = { ...existing, output };
    writeAiData(updated);
    return updated;
};

const resetAiOutput = () => {
    const existing = readAiData();
    const updated = { ...existing, output: [] };
    writeAiData(updated);
    return updated;
};

const tokenizeDockerLine = (line) => {
    return line.match(/"[^"]+"|'[^']+'|\S+/g) || [];
};

const normalizeSourcePath = (value) => {
    if (!value) {
        return '';
    }
    return value.replace(/^["']|["']$/g, '').replace(/\\/g, '/');
};

const parseDockerfileSources = (dockerfilePath) => {
    const content = fs.readFileSync(dockerfilePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const sources = [];

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) {
            continue;
        }
        const tokens = tokenizeDockerLine(trimmed);
        if (tokens.length < 2) {
            continue;
        }
        const instruction = tokens[0].toLowerCase();
        if (instruction !== 'copy' && instruction !== 'add') {
            continue;
        }
        const args = tokens.slice(1).filter((token) => !token.startsWith('--'));
        if (args.length < 2) {
            continue;
        }
        const sourceTokens = args.slice(0, -1);
        for (const rawSource of sourceTokens) {
            const source = normalizeSourcePath(rawSource);
            if (!source || source === '.' || source === './' || source.includes('*')) {
                continue;
            }
            sources.push(source);
        }
    }

    return sources;
};

const findLargestBinary = (baseDir) => {
    let best = null;
    const skipExtensions = new Set(['.json', '.md', '.txt', '.yml', '.yaml', '.toml', '.ini', '.log', '.zip']);
    const skipNames = new Set(['Dockerfile', 'flag']);

    const queue = [baseDir];
    while (queue.length > 0) {
        const currentDir = queue.shift();
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                if (entry.name === '.git' || entry.name === '__MACOSX') {
                    continue;
                }
                queue.push(path.join(currentDir, entry.name));
                continue;
            }
            if (!entry.isFile()) {
                continue;
            }
            if (skipNames.has(entry.name)) {
                continue;
            }
            const ext = path.extname(entry.name).toLowerCase();
            if (skipExtensions.has(ext)) {
                continue;
            }
            const fullPath = path.join(currentDir, entry.name);
            const stat = fs.statSync(fullPath);
            if (!best || stat.size > best.size) {
                best = { path: fullPath, size: stat.size };
            }
        }
    }

    return best ? best.path : '';
};

const resolveTrackingFiles = (dockerfilePath, contextDir) => {
    const sources = parseDockerfileSources(dockerfilePath);
    const resolved = sources
        .map((source) => path.resolve(contextDir, source))
        .filter((sourcePath) => fs.existsSync(sourcePath) && fs.statSync(sourcePath).isFile())
        .filter((sourcePath) => path.basename(sourcePath).toLowerCase() !== 'flag')
        .map((sourcePath) => path.relative(contextDir, sourcePath).replace(/\\/g, '/'));

    if (resolved.length > 0) {
        return resolved;
    }

    const fallback = findLargestBinary(contextDir);
    if (!fallback) {
        return [];
    }
    return [path.relative(contextDir, fallback).replace(/\\/g, '/')];
};

const updateAiData = (files, output) => {
    const existing = readAiData();
    const existingOutput = Array.isArray(existing.output) ? existing.output : [];
    const mergedOutput = Array.isArray(output)
        ? output
        : [
            ...defaultOutput,
            ...existingOutput.filter((line) => !defaultOutput.includes(line))
        ];

    const updated = {
        ...existing,
        status: 'operational',
        files,
        output: mergedOutput
    };

    writeAiData(updated);
    return updated;
};

const buildProcess = async (challengeDir, imageTag = 'pwnautomator-challenge') => {
    const contextDir = challengeDir || findDockerContext(nowDir);

    if (!contextDir) {
        return { success: false, error: 'Dockerfile not found in now directory.' };
    }

    const dockerfilePath = path.join(contextDir, 'Dockerfile');

    if (!fs.existsSync(dockerfilePath)) {
        return { success: false, error: 'Dockerfile not found in challenge directory.' };
    }

    applyDockerfileSetup(dockerfilePath);

    setRunActive(false);
    resetAiOutput();
    const result = await buildDockerImage(contextDir, 'Dockerfile', imageTag);
    updateAiOutput(['Build Success']);
    const container = await startContainer(imageTag);
    setRunActive(true);
    const trackingFiles = resolveTrackingFiles(dockerfilePath, contextDir);
    const baseData = readAiData();
    const output = appendOutputLines(baseData.output, ['Container Ready', 'Running Qwen3-Coder30b']);
    const aiData = updateAiData(trackingFiles, output);

    return {
        success: true,
        result,
        containerId: container.id,
        ai: { files: aiData.files || [], output: aiData.output || [] },
        status: { status: aiData.status || 'nothing' }
    };
};

module.exports = { buildProcess };
