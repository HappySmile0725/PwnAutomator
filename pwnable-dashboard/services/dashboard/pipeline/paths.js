const path = require('path');

const appRoot = path.resolve(__dirname, '..', '..', '..');
const repoRoot = path.resolve(appRoot, '..');
const dataDir = path.join(appRoot, 'data');
const storageDir = path.join(dataDir, 'storage');
const nowDir = path.join(storageDir, 'now');
const mcpDir = path.join(repoRoot, 'mcps');

const resolveRepoPath = (value, fallback) => {
    const target = value || fallback;
    return path.isAbsolute(target) ? path.resolve(target) : path.resolve(repoRoot, target);
};

const challengeDir = resolveRepoPath(process.env.PWN_AUTOMATOR_CHALLENGE_DIR, path.join('mcps', 'test'));

module.exports = {
    appRoot,
    repoRoot,
    mcpDir,
    dataDir,
    storageDir,
    nowDir,
    uploadDir: path.join(nowDir, 'upload'),
    challengeDir,
    challengeMetaDir: path.join(challengeDir, '.pwnautomator'),
    codexDir: path.join(nowDir, 'codex'),
    solutionDir: path.join(nowDir, 'solution'),
    datasetDir: path.join(nowDir, 'dataset'),
    traceDir: path.join(nowDir, 'trace'),
    historyDir: path.join(storageDir, 'history'),
    rootDatasetsDir: path.join(repoRoot, 'datasets'),
    rootRawDatasetDir: path.join(repoRoot, 'datasets', 'raw'),
    rootDatasetPackageDir: path.join(repoRoot, 'datasets', 'packages'),
    pipelineStatePath: path.join(dataDir, 'pipeline.json')
};
