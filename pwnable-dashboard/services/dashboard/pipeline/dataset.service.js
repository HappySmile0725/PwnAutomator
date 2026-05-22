const fs = require('fs').promises;
const path = require('path');
const AdmZip = require('adm-zip');

const paths = require('./paths');
const { publishRawTrace } = require('./trace.service');

const exists = async (filePath) => Boolean(filePath) && fs.access(filePath).then(() => true).catch(() => false);
const packageName = (number, problemName) => `DataSet${number}_${problemName}.zip`;

const sanitizeDatasetName = (value) => {
    const normalized = String(value || 'challenge')
        .replace(/\.[^.\\/]+$/g, '')
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .replace(/^_+|_+$/g, '');
    return normalized || 'challenge';
};

const resolveProblemName = (state) => {
    const targetBinary = state.challenge?.mcpWorkspace?.targetBinaryPath;
    const trackingFile = Array.isArray(state.challenge?.trackingFiles) ? state.challenge.trackingFiles[0] : '';
    const firstUpload = Array.isArray(state.challenge?.uploads) ? state.challenge.uploads[0] : null;
    const rawName = targetBinary || trackingFile || firstUpload?.originalName || firstUpload?.savedName || state.runId;
    return sanitizeDatasetName(path.basename(rawName || 'challenge'));
};

const nextDatasetNumber = async () => {
    await fs.mkdir(paths.rootDatasetPackageDir, { recursive: true });
    const entries = await fs.readdir(paths.rootDatasetPackageDir).catch(() => []);
    const numbers = entries
        .map((name) => name.match(/^DataSet(\d+)_.*\.zip$/i))
        .filter(Boolean)
        .map((match) => Number(match[1]))
        .filter(Number.isFinite);
    return numbers.length > 0 ? Math.max(...numbers) + 1 : 1;
};

const resolveDatasetPackagePath = async (state) => {
    const number = await nextDatasetNumber();
    const problemName = resolveProblemName(state);
    const name = packageName(number, problemName);
    return {
        datasetNumber: number,
        problemName,
        packageName: name,
        packagePath: path.join(paths.rootDatasetPackageDir, name)
    };
};

const addLocalFile = async (zip, sourcePath, zipPath) => {
    if (await exists(sourcePath)) {
        zip.addLocalFile(sourcePath, path.dirname(zipPath), path.basename(zipPath));
        return sourcePath;
    }
    return null;
};

const firstExisting = async (...filePaths) => {
    for (const filePath of filePaths.filter(Boolean)) {
        if (await exists(filePath)) {
            return filePath;
        }
    }
    return null;
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
        if (await addLocalFile(zip, sourcePath, path.join('uploads', savedName))) {
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
    const candidates = [
        path.join(paths.solutionDir, 'exploit.py'),
        path.join(paths.challengeDir, 'hack.py')
    ];
    const added = [];

    for (const sourcePath of candidates) {
        const targetName = added.length === 0 ? 'exploit.py' : path.basename(sourcePath);
        const addedPath = await addLocalFile(zip, sourcePath, path.join('exploit', targetName));
        if (addedPath) {
            added.push(addedPath);
        }
    }

    return added;
};

const addCodexFiles = async (zip) => {
    const files = [
        { source: path.join(paths.codexDir, 'manifest.json'), target: 'codex/manifest.json' },
        { source: path.join(paths.codexDir, 'codex_task.md'), target: 'codex/codex_task.md' }
    ];
    const added = [];

    for (const file of files) {
        const addedPath = await addLocalFile(zip, file.source, file.target);
        if (addedPath) {
            added.push(file.target);
        }
    }

    return added;
};

const addRawTraceFiles = async (zip, rawTrace) => {
    const traceSource = await firstExisting(rawTrace.rawDatasetPath, rawTrace.currentTracePath);
    const added = [];

    if (await addLocalFile(zip, traceSource, 'raw/codex_raw_trace.jsonl')) {
        added.push(traceSource);
    }

    return added;
};

const saveDatasetPackage = async (state) => {
    await Promise.all([
        fs.mkdir(paths.datasetDir, { recursive: true }),
        fs.mkdir(paths.rootDatasetPackageDir, { recursive: true })
    ]);

    const rawTrace = await publishRawTrace({
        runId: state.runId,
        status: state.codex?.status || state.status || 'saved'
    });

    const zip = new AdmZip();
    const uploadedFiles = await addOriginalUploads(zip, state);
    const challengeWorkspaceAdded = await addChallengeWorkspaceZip(zip);
    const exploitFiles = await addExploitFiles(zip);
    const rawTraceFiles = await addRawTraceFiles(zip, rawTrace);
    const codexFiles = await addCodexFiles(zip);

    const datasetPackage = await resolveDatasetPackagePath(state);
    const packagePath = datasetPackage.packagePath;
    const currentPackagePath = path.join(paths.datasetDir, 'dataset_package.zip');

    zip.writeZip(packagePath);
    if (packagePath !== currentPackagePath) {
        await fs.copyFile(packagePath, currentPackagePath);
    }

    const packageSize = (await fs.stat(packagePath)).size;

    return {
        status: 'saved',
        packagePath,
        packageName: datasetPackage.packageName,
        datasetNumber: datasetPackage.datasetNumber,
        problemName: datasetPackage.problemName,
        currentPackagePath,
        packageSize,
        rawTrace,
        included: {
            uploadedFiles,
            challengeWorkspaceAdded,
            exploitFiles,
            rawTraceFiles,
            codexFiles
        },
        message: 'Dataset package saved.'
    };
};

module.exports = { saveDatasetPackage };
