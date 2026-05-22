const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');

const paths = require('./paths');
const { publishRawTrace, readTraceAsJson, tracePathsForRun } = require('./trace.service');

const exists = async (filePath) => fs.access(filePath).then(() => true).catch(() => false);

const addFileIfExists = async (zip, sourcePath, zipPath) => {
    if (await exists(sourcePath)) {
        zip.addLocalFile(sourcePath, path.dirname(zipPath), path.basename(zipPath));
        return true;
    }
    return false;
};

const addTextFile = (zip, zipPath, content) => {
    zip.addFile(zipPath, Buffer.from(String(content || ''), 'utf8'));
};

const addJsonFile = (zip, zipPath, payload) => {
    addTextFile(zip, zipPath, JSON.stringify(payload, null, 2));
};

const addOriginalUploads = async (zip, state) => {
    const uploads = Array.isArray(state.challenge?.uploads) ? state.challenge.uploads : [];
    const added = [];
    for (const upload of uploads) {
        const savedName = path.basename(upload.savedName || '');
        if (!savedName) {
            continue;
        }
        const sourcePath = path.join(paths.uploadDir, savedName);
        if (await addFileIfExists(zip, sourcePath, path.join('uploads', savedName))) {
            added.push(savedName);
        }
    }
    return added;
};

const addChallengeWorkspaceZip = async (zip) => {
    if (!await exists(paths.challengeDir)) {
        return false;
    }

    const challengeZip = new AdmZip();
    challengeZip.addLocalFolder(paths.challengeDir);
    zip.addFile('challenge_workspace.zip', challengeZip.toBuffer());
    return true;
};

const addExploitFiles = async (zip) => {
    const exploitPath = path.join(paths.solutionDir, 'exploit.py');
    const hackPath = path.join(paths.challengeDir, 'hack.py');
    const added = [];

    if (await addFileIfExists(zip, exploitPath, 'exploit/exploit.py')) {
        added.push(exploitPath);
    }
    if (await addFileIfExists(zip, hackPath, added.length === 0 ? 'exploit/exploit.py' : 'exploit/hack.py')) {
        added.push(hackPath);
    }

    return added;
};

const addRawTraceFiles = async (zip, rawTrace) => {
    const traceSource = rawTrace.rawDatasetPath && await exists(rawTrace.rawDatasetPath)
        ? rawTrace.rawDatasetPath
        : rawTrace.currentTracePath;
    const metaSource = rawTrace.rawMetadataPath && await exists(rawTrace.rawMetadataPath)
        ? rawTrace.rawMetadataPath
        : rawTrace.currentMetadataPath;
    const added = [];

    if (await addFileIfExists(zip, traceSource, 'raw/codex_raw_trace.jsonl')) {
        added.push(traceSource);
    }
    if (await addFileIfExists(zip, metaSource, 'raw/codex_raw_trace.meta.json')) {
        added.push(metaSource);
    }

    const events = await readTraceAsJson(traceSource);
    if (events.length > 0) {
        addJsonFile(zip, 'raw/codex_raw_trace.json', events);
        added.push('raw/codex_raw_trace.json');
    }

    return added;
};

const saveDatasetDraft = async (state) => {
    await fs.mkdir(paths.datasetDraftDir, { recursive: true });
    await fs.mkdir(paths.rootDatasetPackageDir, { recursive: true });
    const rawTrace = await publishRawTrace({
        runId: state.runId,
        status: state.codex?.status || state.status || 'draft'
    });

    const draft = {
        version: 1,
        schemaStatus: 'pending',
        savedAt: new Date().toISOString(),
        runId: state.runId,
        challenge: state.challenge,
        docker: state.docker,
        runtime: state.runtime,
        codex: state.codex,
        rawTrace,
        rawTraceFallback: tracePathsForRun(state.runId),
        note: 'Dataset schema is pending. Replace this draft writer after the final schema is defined.'
    };
    const filePath = path.join(paths.datasetDraftDir, 'dataset_draft.json');
    await fs.writeFile(filePath, JSON.stringify(draft, null, 2), 'utf8');

    const zip = new AdmZip();
    const uploadedFiles = await addOriginalUploads(zip, state);
    const challengeWorkspaceAdded = await addChallengeWorkspaceZip(zip);
    const exploitFiles = await addExploitFiles(zip);
    const rawTraceFiles = await addRawTraceFiles(zip, rawTrace);
    await addFileIfExists(zip, filePath, 'dataset_draft.json');
    await addFileIfExists(zip, path.join(paths.codexDir, 'manifest.json'), 'codex/manifest.json');
    await addFileIfExists(zip, path.join(paths.codexDir, 'codex_task.md'), 'codex/codex_task.md');

    const manifest = {
        version: 1,
        runId: state.runId,
        createdAt: new Date().toISOString(),
        uploadedFiles,
        challengeWorkspaceAdded,
        exploitFiles,
        rawTraceFiles,
        datasetDraftPath: filePath,
        rawTrace,
        note: 'This package intentionally keeps raw Codex-visible output and MCP responses for later fine-tuning preprocessing.'
    };
    addJsonFile(zip, 'package_manifest.json', manifest);

    const safeRunId = String(state.runId || 'manual').replace(/[^a-zA-Z0-9_.-]/g, '-');
    const packagePath = path.join(paths.rootDatasetPackageDir, `${safeRunId || 'manual'}.zip`);
    const currentPackagePath = path.join(paths.datasetDraftDir, 'dataset_package.zip');
    zip.writeZip(packagePath);
    if (packagePath !== currentPackagePath) {
        await fs.copyFile(packagePath, currentPackagePath);
    }

    const packageSize = await fs.stat(packagePath).then((stat) => stat.size).catch(() => 0);
    if (!fssync.existsSync(packagePath)) {
        throw new Error('Dataset package was not created.');
    }

    return {
        status: 'waiting_schema',
        filePath,
        packagePath,
        currentPackagePath,
        packageSize,
        rawTrace,
        included: {
            uploadedFiles,
            challengeWorkspaceAdded,
            exploitFiles,
            rawTraceFiles
        },
        message: 'Dataset draft saved. Final schema is pending.'
    };
};

module.exports = { saveDatasetDraft };
