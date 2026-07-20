const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const paths = require('./paths');
const { appendLog, startUploadedRun } = require('./state.service');
const { findDockerContext, resolveTrackingFiles, stopStaleChallengeContainers } = require('./docker.service');
const { stopManagedMcpRuntime } = require('./mcpRuntime.service');

const activeWorkspaceDirs = [
    paths.uploadDir,
    paths.challengeDir,
    paths.solutionDir,
    paths.codexDir,
    paths.datasetDir,
    paths.traceDir
];
const DEFAULT_DOCKER_PORT = 31337;
const DEFAULT_DOCKER_USER = 'ctf';

const createRunId = () => {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
    return `${stamp}-${crypto.randomBytes(3).toString('hex')}`;
};

const exists = async (filePath) => Boolean(filePath) && fs.access(filePath).then(() => true).catch(() => false);

const normalizeUploadName = (name) => {
    const base = path.basename(String(name || 'challenge.bin').replace(/\\/g, '/'));
    return base.replace(/[^a-zA-Z0-9._-]/g, '_') || 'challenge.bin';
};

const resolveUploadFiles = (req) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return [];
    }

    return Object.values(req.files).flatMap((value) => Array.isArray(value) ? value : [value]).filter(Boolean);
};

const isInside = (baseDir, targetPath) => {
    const base = path.resolve(baseDir);
    const target = path.resolve(targetPath);
    return target === base || target.startsWith(`${base}${path.sep}`);
};

const resetCurrentWorkspace = async () => {
    if (!isInside(paths.storageDir, paths.nowDir)) {
        throw new Error('Invalid workspace path.');
    }
    if (!isInside(paths.mcpDir, paths.challengeDir) || path.resolve(paths.challengeDir) === path.resolve(paths.mcpDir)) {
        throw new Error('Challenge workspace must stay inside the MCP directory.');
    }
    for (const dir of activeWorkspaceDirs.filter((dir) => dir !== paths.challengeDir)) {
        if (!isInside(paths.nowDir, dir)) {
            throw new Error(`Invalid managed workspace path: ${dir}`);
        }
    }

    await Promise.all([paths.nowDir, paths.challengeDir].map((dir) => fs.rm(dir, { recursive: true, force: true })));
    await Promise.all(activeWorkspaceDirs.map((dir) => fs.mkdir(dir, { recursive: true })));
};

const assertInside = (baseDir, targetPath) => {
    if (!isInside(baseDir, targetPath)) {
        throw new Error(`Unsafe archive entry: ${targetPath}`);
    }
};

const chmodIfExecutable = async (targetPath, entry) => {
    const unixMode = (entry?.attr >>> 16) & 0o777;
    if ((unixMode & 0o111) === 0) {
        return;
    }
    try {
        await fs.chmod(targetPath, unixMode);
    } catch (_) {
        // Windows hosts may ignore POSIX modes.
    }
};

const extractZipSafely = async (zipPath, destDir) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();

    for (const entry of entries) {
        const entryName = String(entry.entryName || '').replace(/\\/g, '/');
        if (!entryName || entryName.startsWith('/') || entryName.includes('\0')) {
            throw new Error(`Unsafe archive entry: ${entry.entryName}`);
        }

        const targetPath = path.join(destDir, entryName);
        assertInside(destDir, targetPath);

        if (entry.isDirectory) {
            await fs.mkdir(targetPath, { recursive: true });
            continue;
        }

        await fs.mkdir(path.dirname(targetPath), { recursive: true });
        await fs.writeFile(targetPath, entry.getData());
        await chmodIfExecutable(targetPath, entry);
    }
};

const saveUploadedFile = async (file, targetDir) => {
    const safeName = normalizeUploadName(file.name);
    const targetPath = path.join(targetDir, safeName);
    assertInside(targetDir, targetPath);
    await file.mv(targetPath);
    return {
        originalName: file.name,
        savedName: safeName,
        path: targetPath,
        size: Number(file.size) || 0
    };
};

const importChallengeFiles = async (savedFiles) => {
    for (const file of savedFiles) {
        if (file.savedName.toLowerCase().endsWith('.zip')) {
            await extractZipSafely(file.path, paths.challengeDir);
            continue;
        }

        const targetPath = path.join(paths.challengeDir, file.savedName);
        assertInside(paths.challengeDir, targetPath);
        await fs.copyFile(file.path, targetPath);
    }
};

const writeMcpWorkspaceMetadata = async ({ runId, contextDir, dockerfilePath, trackingFiles }) => {
    const firstTrackingFile = Array.isArray(trackingFiles) ? trackingFiles[0] : '';
    const binaryPath = firstTrackingFile ? path.resolve(contextDir || paths.challengeDir, firstTrackingFile) : '';
    const payload = {
        version: 1,
        runId,
        challengeDir: paths.challengeDir,
        contextDir: contextDir || paths.challengeDir,
        dockerfilePath,
        targetBinaryPath: binaryPath,
        trackingFiles: trackingFiles || [],
        updatedAt: new Date().toISOString()
    };

    if (binaryPath) {
        await fs.mkdir(paths.challengeMetaDir, { recursive: true });
        await fs.writeFile(path.join(paths.challengeMetaDir, 'current_binary'), binaryPath, 'utf8');
    }

    return payload;
};

const relForDocker = (baseDir, filePath) => {
    const relativePath = path.isAbsolute(filePath) ? path.relative(baseDir, filePath) : filePath;
    return relativePath.split(path.sep).join('/');
};

const findFlagFile = async (dir) => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isFile() && entry.name === 'flag') {
            return fullPath;
        }
        if (entry.isDirectory()) {
            const found = await findFlagFile(fullPath);
            if (found) {
                return found;
            }
        }
    }
    return null;
};

const renderDefaultDockerfile = ({ binaryRel, flagRel }) => {
    const lines = [
        'FROM ubuntu:22.04',
        '',
        `ENV user=${DEFAULT_DOCKER_USER}`,
        `ENV port=${DEFAULT_DOCKER_PORT}`,
        '',
        'RUN apt-get update \\',
        ' && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y socat \\',
        ' && rm -rf /var/lib/apt/lists/*',
        '',
        'RUN chmod 1733 /tmp /var/tmp /dev/shm \\',
        ' && useradd -m -s /bin/sh $user',
        '',
        'WORKDIR /home/$user',
        `COPY --chown=root:${DEFAULT_DOCKER_USER} ${JSON.stringify([binaryRel, `/home/${DEFAULT_DOCKER_USER}/chall`])}`
    ];

    if (flagRel) {
        lines.push(`COPY --chown=root:${DEFAULT_DOCKER_USER} ${JSON.stringify([flagRel, `/home/${DEFAULT_DOCKER_USER}/flag`])}`);
    }

    lines.push(
        `RUN chmod 755 /home/$user/chall${flagRel ? ' && chmod 440 /home/$user/flag' : ''}`,
        '',
        'USER $user',
        'EXPOSE $port',
        'CMD socat -t 30 -T 30 TCP-LISTEN:$port,reuseaddr,fork EXEC:"/home/$user/chall",stderr'
    );
    return `${lines.join('\n')}\n`;
};

const resolveChallengeLayout = async () => {
    const contextDir = findDockerContext(paths.challengeDir) || paths.challengeDir;
    const dockerfilePath = path.join(contextDir, 'Dockerfile');
    const hasDockerfile = await exists(dockerfilePath);
    if (!hasDockerfile) {
        const trackingFiles = resolveTrackingFiles(null, contextDir);
        if (!trackingFiles[0]) {
            return { contextDir, dockerfilePath: null, trackingFiles, generatedDockerfile: false };
        }
        const flagPath = await findFlagFile(contextDir);
        await fs.writeFile(dockerfilePath, renderDefaultDockerfile({
            binaryRel: relForDocker(contextDir, trackingFiles[0]),
            flagRel: flagPath ? relForDocker(contextDir, flagPath) : null
        }), 'utf8');
        return { contextDir, dockerfilePath, trackingFiles, generatedDockerfile: true };
    }

    return {
        contextDir,
        dockerfilePath,
        trackingFiles: resolveTrackingFiles(dockerfilePath, contextDir),
        generatedDockerfile: false
    };
};

const publicUploadInfo = (file) => ({
    originalName: file.originalName,
    savedName: file.savedName,
    size: file.size
});

const handleChallengeUpload = async (req) => {
    const uploadFiles = resolveUploadFiles(req);
    if (uploadFiles.length === 0) {
        return { success: false, error: 'No challenge files were uploaded.' };
    }

    try {
        await stopManagedMcpRuntime();
        const stoppedContainers = await stopStaleChallengeContainers();
        await resetCurrentWorkspace();

        const savedFiles = await Promise.all(uploadFiles.map((file) => saveUploadedFile(file, paths.uploadDir)));
        await importChallengeFiles(savedFiles);

        const runId = createRunId();
        const { contextDir, dockerfilePath, trackingFiles, generatedDockerfile } = await resolveChallengeLayout();
        const mcpWorkspace = await writeMcpWorkspaceMetadata({
            runId,
            contextDir,
            dockerfilePath,
            trackingFiles
        });
        const state = startUploadedRun({
            runId,
            challenge: {
                uploadedAt: new Date().toISOString(),
                uploads: savedFiles.map(publicUploadInfo),
                rootDir: paths.challengeDir,
                contextDir,
                dockerfilePath,
                trackingFiles,
                mcpWorkspace
            }
        });

        appendLog('info', `Uploaded ${savedFiles.length} challenge file(s).`);
        if (stoppedContainers.length > 0) {
            appendLog('info', `Stopped previous challenge container(s): ${stoppedContainers.map((item) => item.name || item.id).join(', ')}`);
        }
        appendLog('info', `Unified challenge workspace: ${path.relative(paths.repoRoot, paths.challengeDir) || '.'}`);
        if (dockerfilePath) {
            appendLog('info', `Docker context: ${path.relative(paths.repoRoot, contextDir) || '.'}`);
            if (generatedDockerfile) {
                appendLog('info', `Generated default Ubuntu 22.04 Dockerfile: ${path.relative(paths.repoRoot, dockerfilePath)}`);
            }
        } else {
            appendLog('warn', 'Dockerfile was not found in the uploaded challenge.');
        }
        if (mcpWorkspace.targetBinaryPath) {
            appendLog('info', `MCP focus binary reset: ${mcpWorkspace.targetBinaryPath}`);
        } else {
            appendLog('warn', 'No MCP focus binary was resolved for the uploaded challenge.');
        }

        return { success: true, pipeline: state };
    } catch (error) {
        appendLog('error', error.message || 'Upload failed.');
        return { success: false, error: error.message || 'Internal server error during upload.' };
    }
};

module.exports = { handleChallengeUpload };
