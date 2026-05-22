const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const paths = require('./paths');
const { appendLog, startUploadedRun } = require('./state.service');
const { findDockerContext, resolveTrackingFiles } = require('./docker.service');

const createRunId = () => {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
    return `${stamp}-${crypto.randomBytes(3).toString('hex')}`;
};

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

const ensureWorkspaceRoot = async () => {
    const resolvedStorage = path.resolve(paths.storageDir);
    const resolvedNow = path.resolve(paths.nowDir);
    const resolvedMcp = path.resolve(paths.mcpDir);
    const resolvedChallenge = path.resolve(paths.challengeDir);

    if (!resolvedNow.startsWith(resolvedStorage)) {
        throw new Error('Invalid workspace path.');
    }
    if (!resolvedChallenge.startsWith(`${resolvedMcp}${path.sep}`)) {
        throw new Error('Challenge workspace must stay inside the MCP directory.');
    }

    await fs.rm(paths.nowDir, { recursive: true, force: true });
    await fs.rm(paths.challengeDir, { recursive: true, force: true });
    await fs.mkdir(paths.uploadDir, { recursive: true });
    await fs.mkdir(paths.challengeDir, { recursive: true });
    await fs.mkdir(paths.solutionDir, { recursive: true });
};

const assertInside = (baseDir, targetPath) => {
    const base = path.resolve(baseDir);
    const target = path.resolve(targetPath);
    if (target !== base && !target.startsWith(`${base}${path.sep}`)) {
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
    } catch (error) {
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

    await fs.mkdir(paths.challengeMetaDir, { recursive: true });
    await fs.writeFile(path.join(paths.challengeMetaDir, 'manifest.json'), JSON.stringify(payload, null, 2), 'utf8');
    if (binaryPath) {
        await fs.writeFile(path.join(paths.challengeMetaDir, 'current_binary'), binaryPath, 'utf8');
    }

    return payload;
};

const handleChallengeUpload = async (req) => {
    const uploadFiles = resolveUploadFiles(req);
    if (uploadFiles.length === 0) {
        return { success: false, error: 'No challenge files were uploaded.' };
    }

    try {
        await ensureWorkspaceRoot();

        const savedFiles = [];
        for (const file of uploadFiles) {
            savedFiles.push(await saveUploadedFile(file, paths.uploadDir));
        }

        await importChallengeFiles(savedFiles);

        const runId = createRunId();
        const contextDir = findDockerContext(paths.challengeDir) || paths.challengeDir;
        const dockerfilePath = contextDir ? path.join(contextDir, 'Dockerfile') : null;
        const hasDockerfile = dockerfilePath && await fs.access(dockerfilePath).then(() => true).catch(() => false);
        const trackingFiles = resolveTrackingFiles(hasDockerfile ? dockerfilePath : null, contextDir);
        const mcpWorkspace = await writeMcpWorkspaceMetadata({
            runId,
            contextDir,
            dockerfilePath: hasDockerfile ? dockerfilePath : null,
            trackingFiles
        });
        const state = startUploadedRun({
            runId,
            challenge: {
                uploadedAt: new Date().toISOString(),
                uploads: savedFiles.map((file) => ({
                    originalName: file.originalName,
                    savedName: file.savedName,
                    size: file.size
                })),
                rootDir: paths.challengeDir,
                contextDir,
                dockerfilePath: hasDockerfile ? dockerfilePath : null,
                trackingFiles,
                mcpWorkspace
            }
        });

        appendLog('info', `Uploaded ${savedFiles.length} challenge file(s).`);
        appendLog('info', `Unified challenge workspace: ${path.relative(paths.repoRoot, paths.challengeDir) || '.'}`);
        if (hasDockerfile) {
            appendLog('info', `Docker context: ${path.relative(paths.repoRoot, contextDir) || '.'}`);
        } else {
            appendLog('warn', 'Dockerfile was not found in the uploaded challenge.');
        }

        return { success: true, pipeline: state };
    } catch (error) {
        appendLog('error', error.message || 'Upload failed.');
        return { success: false, error: error.message || 'Internal server error during upload.' };
    }
};

module.exports = { handleChallengeUpload };
