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
        currentMetadataPath: path.join(paths.traceDir, 'codex_raw_trace.meta.json'),
        rawDatasetPath: path.join(paths.rootRawDatasetDir, `${safeRunId}.jsonl`),
        rawMetadataPath: path.join(paths.rootRawDatasetDir, `${safeRunId}.meta.json`)
    };
};

const parseJsonLine = (line) => {
    try {
        return JSON.parse(line);
    } catch (_) {
        return null;
    }
};

const stringifyCompact = (value) => {
    try {
        return JSON.stringify(value);
    } catch (_) {
        return String(value);
    }
};

const truncateText = (value, maxChars) => {
    const text = typeof value === 'string' ? value : stringifyCompact(value);
    if (!Number.isFinite(maxChars) || maxChars <= 0 || text.length <= maxChars) {
        return text;
    }
    return `${text.slice(0, maxChars)}... [truncated ${text.length - maxChars} chars]`;
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
    await fsp.writeFile(tracePaths.currentMetadataPath, JSON.stringify(meta, null, 2), 'utf8');
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

const readJsonlSync = (filePath) => {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return content
            .split(/\r?\n/)
            .filter(Boolean)
            .map(parseJsonLine)
            .filter(Boolean);
    } catch (_) {
        return [];
    }
};

const readTailJsonlSync = (filePath, maxBytes = Number(process.env.PWN_AUTOMATOR_TRACE_TAIL_BYTES) || 2 * 1024 * 1024) => {
    try {
        const stat = fs.statSync(filePath);
        const start = Math.max(0, stat.size - maxBytes);
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(stat.size - start);
        fs.readSync(fd, buffer, 0, buffer.length, start);
        fs.closeSync(fd);

        let content = buffer.toString('utf8');
        if (start > 0) {
            const firstNewline = content.indexOf('\n');
            content = firstNewline >= 0 ? content.slice(firstNewline + 1) : '';
        }

        return content
            .split(/\r?\n/)
            .filter(Boolean)
            .map(parseJsonLine)
            .filter(Boolean);
    } catch (_) {
        return [];
    }
};

const readJsonl = async (filePath) => {
    try {
        const content = await fsp.readFile(filePath, 'utf8');
        return content
            .split(/\r?\n/)
            .filter(Boolean)
            .map(parseJsonLine)
            .filter(Boolean);
    } catch (_) {
        return [];
    }
};

const buildMcpResponses = (events, { limit = 30, maxResponseChars = 12000 } = {}) => {
    const calls = new Map();
    const responses = [];

    for (const event of events) {
        if (event.type === 'mcp_tool_call') {
            calls.set(String(event.requestId), event);
        }
        if (event.type === 'mcp_tool_response') {
            responses.push(event);
        }
    }

    return responses.slice(-limit).map((event) => {
        const call = calls.get(String(event.requestId));
        return {
            at: event.at,
            requestId: event.requestId,
            tool: event.tool,
            arguments: call?.arguments || null,
            durationMs: event.durationMs,
            isError: Boolean(event.isError),
            response: event.response || null,
            responsePreview: truncateText(event.response || null, maxResponseChars)
        };
    });
};

const readRecentMcpResponsesSync = (runId, options = {}) => {
    const tracePaths = tracePathsForRun(runId);
    let events = readTailJsonlSync(tracePaths.currentTracePath);
    if (events.length === 0) {
        events = readTailJsonlSync(tracePaths.rawDatasetPath);
    }
    return buildMcpResponses(events, options);
};

const readTraceAsJson = async (filePath) => readJsonl(filePath);

const publishRawTrace = async ({ runId, status, extra } = {}) => {
    const tracePaths = tracePathsForRun(runId);
    if (!isTraceEnabled()) {
        return { enabled: false, ...tracePaths };
    }

    try {
        await fsp.mkdir(paths.rootRawDatasetDir, { recursive: true });
        await fsp.copyFile(tracePaths.currentTracePath, tracePaths.rawDatasetPath);
        const eventCount = await countLines(tracePaths.currentTracePath);
        const meta = {
            schema: TRACE_SCHEMA,
            runId,
            status: status || 'published',
            publishedAt: new Date().toISOString(),
            eventCount,
            currentTracePath: tracePaths.currentTracePath,
            rawDatasetPath: tracePaths.rawDatasetPath,
            ...(extra || {})
        };
        await fsp.writeFile(tracePaths.rawMetadataPath, JSON.stringify(meta, null, 2), 'utf8');
        return { enabled: true, eventCount, ...tracePaths };
    } catch (error) {
        return { enabled: false, error: error.message, ...tracePaths };
    }
};

module.exports = {
    TRACE_SCHEMA,
    appendTraceEventSync,
    isTraceEnabled,
    publishRawTrace,
    readRecentMcpResponsesSync,
    readTraceAsJson,
    resetTrace,
    tracePathsForRun
};
