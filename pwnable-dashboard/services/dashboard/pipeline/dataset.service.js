const fs = require('fs').promises;
const nodeFs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const AdmZip = require('adm-zip');

const paths = require('./paths');
const { inspectContainer } = require('./docker.service');
const { publishRawTrace } = require('./trace.service');

const exists = async (filePath) => Boolean(filePath) && fs.access(filePath).then(() => true).catch(() => false);
const packageName = (number, problemName) => `Dataset${number}_${problemName}.zip`;
const allowFailureDatasets = () => /^(1|true|yes)$/i.test(String(process.env.PWN_AUTOMATOR_DATASET_ALLOW_FAILURES || ''));
const strictQualityDatasets = () => !/^(0|false|no)$/i.test(String(process.env.PWN_AUTOMATOR_DATASET_STRICT_QUALITY || '1'));

const TRAINING_EXPORTS = [
    ['qwen3_coder_next_static_analysis_sft.jsonl', 'train/qwen3_coder_next_static_analysis_sft.jsonl'],
    ['qwen3_coder_next_dynamic_analysis_sft.jsonl', 'train/qwen3_coder_next_dynamic_analysis_sft.jsonl'],
    ['qwen3_coder_next_exploit_sft.jsonl', 'train/qwen3_coder_next_exploit_sft.jsonl'],
    ['qwen3_coder_next_repair_sft.jsonl', 'train/qwen3_coder_next_repair_sft.jsonl']
];

const METADATA_EXPORTS = [
    ['summary.json', 'metadata/summary.json'],
    ['quality_report.json', 'metadata/quality_report.json'],
    ['dataset_card.json', 'metadata/dataset_card.json'],
    ['adapter_routing.json', 'metadata/adapter_routing.json'],
    ['trace_replay_manifest.json', 'metadata/replay_manifest.trace.json'],
    ['tool_schema_catalog.json', 'metadata/tool_schema_catalog.json']
];

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
    const uploads = Array.isArray(state.challenge?.uploads) ? state.challenge.uploads : [];
    const namedUpload = uploads.find((file) => /\.zip$/i.test(file?.originalName || file?.savedName || '')) || uploads[0] || null;
    const rawName = namedUpload?.originalName || namedUpload?.savedName || targetBinary || trackingFile || state.runId;
    return sanitizeDatasetName(path.basename(rawName || 'challenge'));
};

const nextDatasetNumber = async () => {
    await fs.mkdir(paths.rootDatasetPackageDir, { recursive: true });
    const entries = await fs.readdir(paths.rootDatasetPackageDir).catch(() => []);
    const numbers = entries
        .map((name) => name.match(/^Dataset(\d+)(?:_.*)?\.zip$/i))
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

const sha256File = async (filePath) => new Promise((resolve) => {
    if (!filePath || !nodeFs.existsSync(filePath) || !nodeFs.statSync(filePath).isFile()) {
        resolve('');
        return;
    }
    const hash = crypto.createHash('sha256');
    const stream = nodeFs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', () => resolve(''));
    stream.on('end', () => resolve(hash.digest('hex')));
});

const sha256Text = (value) => crypto.createHash('sha256').update(String(value || '')).digest('hex');

const displayPath = (filePath) => {
    if (!filePath) {
        return '';
    }
    const relative = path.relative(paths.repoRoot, filePath);
    return relative && !relative.startsWith('..') && !path.isAbsolute(relative)
        ? relative.replace(/\\/g, '/')
        : path.basename(filePath);
};

const fileRecord = async (filePath, role) => {
    if (!(await exists(filePath))) {
        return null;
    }
    const stat = await fs.stat(filePath).catch(() => null);
    if (!stat?.isFile()) {
        return null;
    }
    return {
        role,
        path: displayPath(filePath),
        size: stat.size,
        sha256: await sha256File(filePath)
    };
};

const challengeFiles = async (state) => {
    const contextDir = state.challenge?.contextDir || paths.challengeDir;
    const targetBinary = state.challenge?.mcpWorkspace?.targetBinaryPath || '';
    const tracking = Array.isArray(state.challenge?.trackingFiles) ? state.challenge.trackingFiles : [];
    const candidates = [
        { role: 'target_binary', path: targetBinary },
        ...tracking.map((item) => ({ role: 'tracking_file', path: path.isAbsolute(item) ? item : path.join(contextDir, item) }))
    ];
    const seen = new Set();
    const records = [];
    for (const candidate of candidates) {
        const resolved = candidate.path ? path.resolve(candidate.path) : '';
        if (!resolved || seen.has(resolved)) {
            continue;
        }
        seen.add(resolved);
        const record = await fileRecord(resolved, candidate.role);
        if (record) {
            records.push(record);
        }
    }
    return records;
};

const readJsonSafe = async (filePath) => {
    try {
        return JSON.parse(await fs.readFile(filePath, 'utf8'));
    } catch (_) {
        return null;
    }
};

const promptFileRecords = async () => {
    const files = [
        'guidline_docs/codex-system-prompt.md',
        'guidline_docs/system-prompt-discovery.md',
        'config/training-policy.json'
    ];
    return (await Promise.all(files.map((file) => fileRecord(path.join(paths.repoRoot, file), file)))).filter(Boolean);
};

const inspectContainerSafe = async (state) => {
    const ref = state.docker?.containerId || state.docker?.containerName;
    if (!ref) {
        return null;
    }
    try {
        return await inspectContainer(ref);
    } catch (_) {
        return null;
    }
};

const buildRuntimeReplayManifest = async ({ state, rawTrace, datasetPackage, qualityReport }) => {
    const container = await inspectContainerSafe(state);
    const codexManifest = await readJsonSafe(path.join(paths.codexDir, 'manifest.json'));
    const policy = await fs.readFile(path.join(paths.repoRoot, 'config', 'training-policy.json'), 'utf8').catch(() => '');
    return {
        schema: 'pwnautomator.replay_manifest.v1',
        runId: state.runId || null,
        executionId: state.executionId || null,
        dataset: {
            packageName: datasetPackage.packageName,
            datasetNumber: datasetPackage.datasetNumber,
            problemName: datasetPackage.problemName,
            qualityGate: qualityReport?.qualityGate || null
        },
        challenge: {
            contextDir: displayPath(state.challenge?.contextDir || paths.challengeDir),
            files: await challengeFiles(state)
        },
        docker: {
            imageTag: state.docker?.imageTag || container?.Config?.Image || '',
            imageId: container?.Image || '',
            containerName: state.docker?.containerName || String(container?.Name || '').replace(/^\//, ''),
            containerId: state.docker?.containerId || container?.Id || '',
            command: container?.Config?.Cmd || [],
            entrypoint: container?.Config?.Entrypoint || [],
            workingDir: container?.Config?.WorkingDir || '',
            ports: state.runtime?.network?.ports || []
        },
        mcp: {
            runtime: state.mcpRuntime || null,
            servers: codexManifest?.mcpServers || []
        },
        promptsAndPolicy: {
            policySha256: sha256Text(policy),
            files: await promptFileRecords()
        },
        verifier: {
            acceptedEvidence: ['flag', 'command'],
            commandIdentityRequired: true,
            weakMarkersRejected: true,
            rawTraceStatus: rawTrace?.status || ''
        },
        trace: {
            rawDatasetPath: displayPath(rawTrace?.rawDatasetPath),
            currentTracePath: displayPath(rawTrace?.currentTracePath),
            eventCount: rawTrace?.eventCount || null
        }
    };
};

const addJson = (zip, zipPath, value) => {
    zip.addFile(zipPath, Buffer.from(JSON.stringify(value, null, 2), 'utf8'));
    return zipPath;
};

const addTrainingManifest = (zip, state, files, qualityReport) => {
    const taskFiles = {
        staticAnalysis: files.training.filter((file) => file.includes('_static_analysis_sft.')),
        dynamicAnalysis: files.training.filter((file) => file.includes('_dynamic_analysis_sft.')),
        exploit: files.training.filter((file) => file.includes('_exploit_sft.')),
        repair: files.training.filter((file) => file.includes('_repair_sft.'))
    };
    const manifest = {
        schema: 'pwnautomator.training_manifest.v3',
        runId: state.runId || null,
        executionId: state.executionId || null,
        problemName: resolveProblemName(state),
        targetModel: {
            checkpoint: 'Qwen/Qwen3-Coder-Next',
            contextLength: 262144,
            thinkingMode: false,
            chatTemplate: 'Use the tokenizer bundled with the checkpoint.'
        },
        recommendedTrainingFiles: taskFiles,
        taskTrainingFiles: taskFiles,
        allTrainingFiles: files.training,
        metadataFiles: files.metadata,
        excludedByDesign: [
            'raw traces',
            'combined SFT exports',
            'legacy flattened exports',
            'tool_failures',
            'challenge workspace',
            'uploaded originals',
            'dashboard pipeline logs',
            'Codex prompt/runtime artifacts'
        ],
        qualityGate: qualityReport?.qualityGate || null,
        dedupePolicy: {
            warning: 'Train each specialist adapter from its matching task file. Do not concatenate task files into one adapter dataset.'
        },
        routingMetadata: 'metadata/adapter_routing.json',
        replayMetadata: 'metadata/replay_manifest.json',
        toolSchemaCatalog: 'metadata/tool_schema_catalog.json',
        notes: [
            'Pass each row messages and tools to tokenizer.apply_chat_template; do not manually serialize Qwen tool XML.',
            'Mask loss to assistant messages only; train assistant tool_calls but never train tool observations as model output.',
            'Qwen3-Coder-Next is non-thinking; do not add think tags or enable thinking mode.',
            'Train separate LoRA adapters for staticAnalysis, dynamicAnalysis, exploit, and repair. DynamicAnalysis must prove leak/no-leak-needed and control/direct-read exploitability before exploit rows are used.',
            'metadata/*.json documents quality and provenance only.',
            'This package intentionally excludes noisy diagnostics and raw traces.'
        ]
    };
    zip.addFile('metadata/training_manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
    return 'metadata/training_manifest.json';
};

const addGeneratedDatasetOutputs = async (zip, outputDir, runId, qualityReport, state) => {
    const added = [];
    const files = { training: [], metadata: [] };

    const addGenerated = async (suffix, target, group) => {
        const sourcePath = path.join(outputDir, `${runId}_${suffix}`);
        const addedPath = await addLocalFile(zip, sourcePath, target);
        if (addedPath) {
            added.push(target);
            files[group].push(target);
        }
    };

    for (const [suffix, target] of TRAINING_EXPORTS) {
        await addGenerated(suffix, target, 'training');
    }
    for (const [suffix, target] of METADATA_EXPORTS) {
        await addGenerated(suffix, target, 'metadata');
    }

    const requiredTraining = [
        'train/qwen3_coder_next_static_analysis_sft.jsonl',
        'train/qwen3_coder_next_dynamic_analysis_sft.jsonl',
        'train/qwen3_coder_next_exploit_sft.jsonl',
        'train/qwen3_coder_next_repair_sft.jsonl'
    ];
    const missing = requiredTraining.filter((file) => !files.training.includes(file));
    if (missing.length > 0) {
        throw new Error(`Dataset package missing required training files: ${missing.join(', ')}`);
    }

    const manifestPath = addTrainingManifest(zip, state, files, qualityReport);
    added.push(manifestPath);
    files.metadata.push(manifestPath);

    return { added, files };
};

const pythonCandidates = () => {
    const configured = process.env.PWN_AUTOMATOR_PYTHON || process.env.PYTHON;
    return [configured, 'python3', 'python'].filter((value, index, values) => value && values.indexOf(value) === index);
};

const extractDatasetFiles = (traceSource, outputDir) => {
    for (const command of pythonCandidates()) {
        const result = spawnSync(command, ['scripts/extract_dataset.py', traceSource, outputDir], {
            cwd: paths.repoRoot,
            encoding: 'utf8'
        });
        if (!result.error && result.status === 0) {
            return { success: true, command };
        }
        if (result.error?.code === 'ENOENT') {
            continue;
        }
        return {
            success: false,
            command,
            error: result.stderr || result.stdout || result.error?.message || `exit ${result.status}`
        };
    }
    return { success: false, command: null, error: 'No Python interpreter found.' };
};

const replaceDirectory = async (sourceDir, targetDir) => {
    await fs.rm(targetDir, { recursive: true, force: true });
    await fs.rename(sourceDir, targetDir);
};

const readGeneratedQualityReport = async (outputDir) => {
    const entries = await fs.readdir(outputDir).catch(() => []);
    const qualityFile = entries.find((name) => name.endsWith('_quality_report.json'));
    if (!qualityFile) {
        return null;
    }
    const content = await fs.readFile(path.join(outputDir, qualityFile), 'utf8');
    return JSON.parse(content);
};

const datasetQualityError = (qualityReport) => {
    if (!strictQualityDatasets()) {
        return '';
    }
    const gate = qualityReport?.qualityGate || {};
    if (gate.passed) {
        return '';
    }
    const blockers = Array.isArray(gate.blockers) ? gate.blockers.join(', ') : 'unknown_quality_gate_failure';
    return `Dataset quality gate failed: ${blockers}`;
};

const datasetSaveError = (state) => {
    if (!['success', 'failure'].includes(state?.codex?.status)) {
        return 'Dataset package can only be saved after a completed Codex run.';
    }
    if (state?.codex?.status !== 'success' && !allowFailureDatasets()) {
        return 'Dataset package save is restricted to successful Codex runs. Set PWN_AUTOMATOR_DATASET_ALLOW_FAILURES=true to override.';
    }
    return '';
};

const assertCanSaveDataset = (state) => {
    const error = datasetSaveError(state);
    if (error) {
        throw new Error(error);
    }
};

const saveDatasetPackage = async (state) => {
    assertCanSaveDataset(state);

    await Promise.all([
        fs.mkdir(paths.datasetDir, { recursive: true }),
        fs.mkdir(paths.rootDatasetPackageDir, { recursive: true })
    ]);

    const rawTrace = await publishRawTrace({
        runId: state.runId,
        executionId: state.executionId,
        status: state.codex?.status || state.status || 'saved'
    });

    const datasetPackage = await resolveDatasetPackagePath(state);
    const packagePath = datasetPackage.packagePath;
    const currentPackagePath = path.join(paths.datasetDir, 'dataset_package.zip');

    const outputDir = path.join(paths.codexDir, 'dataset_extracted');
    const tempOutputDir = path.join(paths.codexDir, `dataset_extracted.tmp-${Date.now()}`);
    const traceSource = await firstExisting(rawTrace.rawDatasetPath, rawTrace.currentTracePath);
    let extraction = { success: false, command: null, error: 'No trace source available.' };
    let qualityReport = null;
    if (traceSource) {
        await fs.rm(tempOutputDir, { recursive: true, force: true });
        await fs.mkdir(tempOutputDir, { recursive: true });
        extraction = extractDatasetFiles(traceSource, tempOutputDir);
        if (extraction.success) {
            qualityReport = await readGeneratedQualityReport(tempOutputDir);
            const qualityError = datasetQualityError(qualityReport);
            if (qualityError) {
                await fs.rm(tempOutputDir, { recursive: true, force: true });
                throw new Error(qualityError);
            }
            await replaceDirectory(tempOutputDir, outputDir);
        } else {
            await fs.rm(tempOutputDir, { recursive: true, force: true });
        }
    }

    const zip = new AdmZip();
    const exported = extraction.success
        ? await addGeneratedDatasetOutputs(zip, outputDir, state.runId, qualityReport, state)
        : { added: [], files: { training: [], metadata: [] } };
    const runtimeManifestPath = addJson(zip, 'metadata/replay_manifest.json', await buildRuntimeReplayManifest({
        state,
        rawTrace,
        datasetPackage,
        qualityReport
    }));
    exported.added.push(runtimeManifestPath);
    exported.files.metadata.push(runtimeManifestPath);

    zip.writeZip(packagePath);
    if (packagePath !== currentPackagePath) {
        await fs.copyFile(packagePath, currentPackagePath).catch(() => {});
    }

    const stat = await fs.stat(packagePath).catch(() => null);
    const packageSize = stat ? stat.size : 0;

    return {
        status: 'saved',
        packagePath,
        packageName: datasetPackage.packageName,
        datasetNumber: datasetPackage.datasetNumber,
        problemName: datasetPackage.problemName,
        currentPackagePath,
        packageSize,
        rawTrace,
        executionId: state.executionId || null,
        extraction,
        qualityReport,
        included: {
            trainingFiles: exported.files.training,
            metadataFiles: exported.files.metadata,
            exportedFiles: exported.added
        },
        message: 'Dataset package saved.'
    };
};

module.exports = { datasetSaveError, saveDatasetPackage };
