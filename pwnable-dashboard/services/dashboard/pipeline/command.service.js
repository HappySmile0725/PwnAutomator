const { spawn } = require('child_process');

const parseCommandLine = (value) => {
    if (!value) {
        return [];
    }

    return String(value)
        .match(/"[^"]+"|'[^']+'|\S+/g)
        ?.map((token) => token.replace(/^["']|["']$/g, '')) || [];
};

const applyTemplate = (value, variables) => Object.entries(variables || {}).reduce((result, [key, replacement]) => {
    return result.split(`{${key}}`).join(replacement == null ? '' : String(replacement));
}, String(value || ''));

const safeProcessKill = (pid, signal) => {
    try {
        process.kill(pid, signal);
        return true;
    } catch (_) {
        return false;
    }
};

const safeChildKill = (child, signal) => {
    try {
        child.kill(signal);
        return true;
    } catch (_) {
        return false;
    }
};

const terminateChild = (child, killTimeoutMs = 3000) => {
    if (!child?.pid || child.killed) {
        return;
    }

    if (process.platform === 'win32') {
        safeChildKill(child, 'SIGTERM');
        spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true });
        return;
    }

    if (!safeProcessKill(-child.pid, 'SIGTERM') && !safeChildKill(child, 'SIGTERM')) {
        return;
    }

    setTimeout(() => {
        if (child.killed) {
            return;
        }
        if (!safeProcessKill(-child.pid, 'SIGKILL')) {
            safeChildKill(child, 'SIGKILL');
        }
    }, killTimeoutMs).unref();
};

const runCommand = ({
    command,
    args,
    cwd,
    env,
    stdin,
    onLine,
    onData,
    signal,
    killTimeoutMs,
    terminateAfterLine,
    terminateAfterLineMs
}) => new Promise((resolve, reject) => {
    const spawnOptions = {
        cwd,
        env: { ...process.env, ...(env || {}) },
        detached: process.platform !== 'win32'
    };
    if (process.platform === 'win32') {
        spawnOptions.windowsHide = true;
    }

    let aborted = false;
    let terminatedAfterLine = false;
    let terminateTimer = null;
    const lineBuffers = { stdout: '', stderr: '' };
    const child = spawn(command, args || [], spawnOptions);

    child.stdout?.setEncoding?.('utf8');
    child.stderr?.setEncoding?.('utf8');

    const abort = () => {
        aborted = true;
        terminateChild(child, killTimeoutMs);
    };

    if (signal) {
        if (signal.aborted) {
            abort();
        } else {
            signal.addEventListener('abort', abort, { once: true });
        }
    }

    const scheduleTerminateAfterLine = (delayValue) => {
        if (terminateTimer || !child?.pid) {
            return;
        }
        const delay = Number.isFinite(Number(delayValue)) ? Number(delayValue) : 3000;
        terminateTimer = setTimeout(() => {
            terminatedAfterLine = true;
            terminateChild(child, killTimeoutMs);
        }, Math.max(0, delay));
        terminateTimer.unref?.();
    };

    const emitLine = (level, line) => {
        const trimmed = String(line || '').trim();
        if (!trimmed) {
            return;
        }
        if (typeof onLine === 'function') {
            onLine(level, trimmed);
        }
        if (typeof terminateAfterLine === 'function' && terminateAfterLine(level, trimmed)) {
            const delay = typeof terminateAfterLineMs === 'function'
                ? terminateAfterLineMs(level, trimmed)
                : terminateAfterLineMs;
            scheduleTerminateAfterLine(delay);
        }
    };

    const handleData = (level) => (chunk) => {
        const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');

        if (typeof onData === 'function') {
            onData(level, text);
        }

        if (typeof onLine !== 'function' && typeof terminateAfterLine !== 'function') {
            return;
        }

        lineBuffers[level] += text;
        const lines = lineBuffers[level].split(/\r?\n/);
        lineBuffers[level] = lines.pop() || '';
        for (const line of lines) {
            emitLine(level, line);
        }
    };

    child.stdout.on('data', handleData('stdout'));
    child.stderr.on('data', handleData('stderr'));
    child.stdin.on('error', () => {});
    child.on('error', reject);
    child.on('close', (code) => {
        if (signal) {
            signal.removeEventListener('abort', abort);
        }
        emitLine('stdout', lineBuffers.stdout);
        emitLine('stderr', lineBuffers.stderr);
        if (terminateTimer) {
            clearTimeout(terminateTimer);
        }
        resolve({ code, canceled: aborted, terminatedAfterLine });
    });

    if (stdin) {
        child.stdin.write(stdin);
    }
    child.stdin.end();
});

module.exports = {
    applyTemplate,
    parseCommandLine,
    runCommand
};
