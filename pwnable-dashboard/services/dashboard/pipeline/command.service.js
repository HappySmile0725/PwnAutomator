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

const terminateChild = (child, killTimeoutMs = 3000) => {
    if (!child?.pid || child.killed) {
        return;
    }

    if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true });
        return;
    }

    try {
        process.kill(-child.pid, 'SIGTERM');
    } catch (_) {
        try {
            child.kill('SIGTERM');
        } catch (_) {
            return;
        }
    }

    setTimeout(() => {
        if (child.killed) {
            return;
        }
        try {
            process.kill(-child.pid, 'SIGKILL');
        } catch (_) {
            try {
                child.kill('SIGKILL');
            } catch (_) {}
        }
    }, killTimeoutMs).unref();
};

const runCommand = ({ command, args, cwd, env, stdin, onLine, onData, signal, killTimeoutMs }) => new Promise((resolve, reject) => {
    const spawnOptions = {
        cwd,
        env: { ...process.env, ...(env || {}) },
        detached: process.platform !== 'win32'
    };
    if (process.platform === 'win32') {
        spawnOptions.windowsHide = true;
    }

    let aborted = false;
    const child = spawn(command, args || [], spawnOptions);

    let stdout = '';
    let stderr = '';

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

    const handleData = (level) => (chunk) => {
        const text = chunk.toString();
        if (level === 'stderr') {
            stderr += text;
        } else {
            stdout += text;
        }

        if (typeof onData === 'function') {
            onData(level, text);
        }

        if (typeof onLine === 'function') {
            const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
            for (const line of lines) {
                onLine(level, line);
            }
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
        resolve({ code, stdout, stderr, canceled: aborted });
    });

    if (stdin) {
        child.stdin.write(stdin);
    }
    child.stdin.end();
});

module.exports = {
    applyTemplate,
    parseCommandLine,
    runCommand,
    terminateChild
};
