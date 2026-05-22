const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');

const paths = require('./paths');

const TRACE_SCHEMA = 'pwnautomator.raw_trace.v1';

let localSeq = 0;

const enabled = (value, fallback = true) => {
    if (value === undefined) {
        return fallback;
    }
    return !['0', 'false', 'no', 'off'].includes(String(value).trim().toLowerCase());
};

const isTraceEnabled = () => enabled(process.env.PWN_AUTOMATOR_TRACE_ENABLED, true);

const sanitizeRunId = (value) => String(value || 'manual')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '-')
    .replace(/^-+|-+$/g, '') || 'manual';

const tracePathsForRun = (runId) => {
    const safeRunId = sanitizeRunId(runId);
    return {
        currentTracePath: path.join(paths.traceDir, 'codex_raw_trace.jsonl'),
        rawDatasetPath: path.join(paths.rootRawDatasetDir, `${safeRunId}.jsonl`)
    };
};

const appendTraceEventSync = (filePath, event) => {
    if (!isTraceEnabled() || !filePath) {
        return;
    }

    try {
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        const payload = {
            schema: TRACE_SCHEMA,
            at: new Date().toISOString(),
            pid: process.pid,
            seq: ++localSeq,
            ...event
        };
        fs.appendFileSync(filePath, `${JSON.stringify(payload)}\n`, 'utf8');
    } catch (_) {
        // Tracing must never break the solver pipeline.
    }
};

const resetTrace = async ({ runId, metadata }) => {
    const tracePaths = tracePathsForRun(runId);
    if (!isTraceEnabled()) {
        return { enabled: false, ...tracePaths };
    }

    await fsp.mkdir(paths.traceDir, { recursive: true });
    await fsp.writeFile(tracePaths.currentTracePath, '', 'utf8');
    const meta = {
        schema: TRACE_SCHEMA,
        runId,
        createdAt: new Date().toISOString(),
        currentTracePath: tracePaths.currentTracePath,
        rawDatasetPath: tracePaths.rawDatasetPath,
        note: 'Raw trace contains Codex-visible output and MCP calls/responses. Hidden model reasoning is not available unless Codex emits it.',
        ...metadata
    };
    appendTraceEventSync(tracePaths.currentTracePath, {
        runId,
        source: 'dashboard',
        type: 'trace_start',
        data: meta
    });
    return { enabled: true, ...tracePaths };
};

const countLines = async (filePath) => {
    try {
        const content = await fsp.readFile(filePath, 'utf8');
        if (!content) {
            return 0;
        }
        return content.endsWith('\n') ? content.split('\n').length - 1 : content.split('\n').length;
    } catch (_) {
        return 0;
    }
};

const publishRawTrace = async ({ runId, status, extra } = {}) => {
    const tracePaths = tracePathsForRun(runId);
    if (!isTraceEnabled()) {
        return { enabled: false, ...tracePaths };
    }

    try {
        await fsp.mkdir(paths.rootRawDatasetDir, { recursive: true });
        await fsp.copyFile(tracePaths.currentTracePath, tracePaths.rawDatasetPath);
        const eventCount = await countLines(tracePaths.currentTracePath);
        return {
            enabled: true,
            schema: TRACE_SCHEMA,
            runId,
            status: status || 'published',
            publishedAt: new Date().toISOString(),
            eventCount,
            ...tracePaths,
            ...(extra || {})
        };
    } catch (error) {
        return { enabled: false, error: error.message, ...tracePaths };
    }
};

module.exports = {
    TRACE_SCHEMA,
    appendTraceEventSync,
    isTraceEnabled,
    publishRawTrace,
    resetTrace,
    tracePathsForRun
};
