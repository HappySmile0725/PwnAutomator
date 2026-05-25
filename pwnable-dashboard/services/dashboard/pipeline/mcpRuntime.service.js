const fs = require('fs');
const fsp = require('fs').promises;
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const paths = require('./paths');

const DEFAULT_RUNTIME_SCRIPT = path.join('mcps', 'run_ghidra_server.sh');
const DEFAULT_READY_TIMEOUT_MS = 180000;
const DEFAULT_POLL_INTERVAL_MS = 500;
const DEFAULT_STOP_TIMEOUT_MS = 5000;

const runtimeStatePath = path.join(paths.challengeMetaDir, 'mcp_runtime.json');
const runtimeStdoutPath = path.join(paths.challengeMetaDir, 'mcp_runtime.out.log');
const runtimeStderrPath = path.join(paths.challengeMetaDir, 'mcp_runtime.err.log');

const parseBool = (value, fallback = true) => {
    if (value === undefined) {
        return fallback;
    }
    return !['0', 'false', 'no', 'off'].includes(String(value).trim().toLowerCase());
};

const parsePort = (value, fallback) => {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const localHost = (host) => {
    const value = String(host || '').trim();
    if (!value || value === '0.0.0.0' || value === '::') {
        return '127.0.0.1';
    }
    return value;
};

const shouldAutoStartMcp = () => parseBool(process.env.PWN_AUTOMATOR_MCP_AUTOSTART, true);

const resolveRepoPath = (value, fallback) => {
    const target = String(value || fallback || '').trim();
    if (!target) {
        return '';
    }
    return path.isAbsolute(target) ? path.resolve(target) : path.resolve(paths.repoRoot, target);
};

const runtimeScriptPath = () => resolveRepoPath(process.env.PWN_AUTOMATOR_MCP_SERVER_SCRIPT, DEFAULT_RUNTIME_SCRIPT);

const readyTimeoutMs = () => parsePort(process.env.PWN_AUTOMATOR_MCP_READY_TIMEOUT_MS, DEFAULT_READY_TIMEOUT_MS);

const configuredEndpoints = () => ([
    {
        name: 'ghidra-mcp',
        host: localHost(process.env.GHIDRA_HOST || '127.0.0.1'),
        port: parsePort(process.env.GHIDRA_PORT, 9999)
    },
    {
        name: 'pwntools-mcp',
        host: localHost(process.env.GHIDRA_MCP_PWN_HOST || '127.0.0.1'),
        port: parsePort(process.env.GHIDRA_MCP_PWN_PORT, 19191)
    },
    {
        name: 'pwno-mcp',
        host: localHost(process.env.PWNO_MCP_HOST || '127.0.0.1'),
        port: parsePort(process.env.PWNO_MCP_PORT, 5500)
    }
]);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const isProcessAlive = (pid) => {
    if (!Number.isInteger(pid) || pid <= 0) {
        return false;
    }
    try {
        process.kill(pid, 0);
        return true;
    } catch (_) {
        return false;
    }
};

const safeKill = (pid, signal) => {
    try {
        process.kill(pid, signal);
        return true;
    } catch (_) {
        return false;
    }
};

const readRuntimeState = async () => {
    try {
        const raw = await fsp.readFile(runtimeStatePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object') {
            return null;
        }
        return parsed;
    } catch (_) {
        return null;
    }
};

const writeRuntimeState = async (payload) => {
    await fsp.mkdir(path.dirname(runtimeStatePath), { recursive: true });
    await fsp.writeFile(runtimeStatePath, JSON.stringify(payload, null, 2), 'utf8');
};

const clearRuntimeState = async () => {
    await fsp.rm(runtimeStatePath, { force: true });
};

const terminateProcess = async (pid, timeoutMs = DEFAULT_STOP_TIMEOUT_MS) => {
    if (!isProcessAlive(pid)) {
        return;
    }

    if (process.platform === 'win32') {
        await new Promise((resolve) => {
            const killer = spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { windowsHide: true });
            killer.on('close', () => resolve());
            killer.on('error', () => resolve());
        });
        return;
    }

    if (!safeKill(-pid, 'SIGTERM')) {
        safeKill(pid, 'SIGTERM');
    }

    const deadline = Date.now() + timeoutMs;
    while (isProcessAlive(pid) && Date.now() < deadline) {
        await sleep(100);
    }

    if (!isProcessAlive(pid)) {
        return;
    }

    if (!safeKill(-pid, 'SIGKILL')) {
        safeKill(pid, 'SIGKILL');
    }
};

const stopManagedMcpRuntime = async () => {
    const state = await readRuntimeState();
    const pid = Number(state?.pid);
    if (Number.isInteger(pid) && pid > 0) {
        await terminateProcess(pid);
    }
    await clearRuntimeState();
};

const canConnect = (host, port, timeoutMs = 800) => new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (ok) => {
        if (settled) {
            return;
        }
        settled = true;
        socket.destroy();
        resolve(ok);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
});

const waitForEndpoints = async (endpoints, timeoutMs) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const checks = await Promise.all(endpoints.map(async (endpoint) => ({
            endpoint,
            ok: await canConnect(endpoint.host, endpoint.port)
        })));
        if (checks.every((item) => item.ok)) {
            return;
        }
        await sleep(DEFAULT_POLL_INTERVAL_MS);
    }

    const pending = [];
    for (const endpoint of endpoints) {
        const ok = await canConnect(endpoint.host, endpoint.port);
        if (!ok) {
            pending.push(`${endpoint.name}(${endpoint.host}:${endpoint.port})`);
        }
    }
    throw new Error(`MCP runtime readiness timeout: ${pending.join(', ') || 'unknown'}`);
};

const startManagedMcpRuntime = async ({ binaryPath } = {}) => {
    const scriptPath = runtimeScriptPath();
    await fsp.access(scriptPath);
    await fsp.mkdir(paths.challengeMetaDir, { recursive: true });

    const stdoutFd = fs.openSync(runtimeStdoutPath, 'a');
    const stderrFd = fs.openSync(runtimeStderrPath, 'a');
    try {
        const args = [scriptPath];
        const targetBinaryPath = String(binaryPath || '').trim();
        if (targetBinaryPath) {
            args.push(targetBinaryPath);
        }

        const child = spawn('bash', args, {
            cwd: paths.repoRoot,
            env: {
                ...process.env,
                PWN_AUTOMATOR_CHALLENGE_DIR: paths.challengeDir,
                PWN_AUTOMATOR_BINARY_PATH: targetBinaryPath
            },
            detached: process.platform !== 'win32',
            windowsHide: process.platform === 'win32',
            stdio: ['ignore', stdoutFd, stderrFd]
        });

        if (!child.pid) {
            throw new Error('Failed to spawn MCP runtime process.');
        }

        child.unref();
        await writeRuntimeState({
            pid: child.pid,
            scriptPath,
            startedAt: new Date().toISOString(),
            binaryPath: targetBinaryPath,
            challengeDir: paths.challengeDir
        });

        return { pid: child.pid, scriptPath };
    } finally {
        fs.closeSync(stdoutFd);
        fs.closeSync(stderrFd);
    }
};

const setupManagedMcpRuntime = async ({ binaryPath } = {}) => {
    if (!shouldAutoStartMcp()) {
        return { enabled: false, reason: 'disabled' };
    }

    await stopManagedMcpRuntime();
    const started = await startManagedMcpRuntime({ binaryPath });
    const endpoints = configuredEndpoints();
    try {
        await waitForEndpoints(endpoints, readyTimeoutMs());
    } catch (error) {
        await stopManagedMcpRuntime();
        throw error;
    }

    return {
        enabled: true,
        pid: started.pid,
        scriptPath: started.scriptPath,
        endpoints
    };
};

module.exports = {
    setupManagedMcpRuntime,
    shouldAutoStartMcp,
    stopManagedMcpRuntime
};
