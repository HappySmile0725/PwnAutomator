const assert = require('node:assert/strict');
const test = require('node:test');

const {
    traceEventHasVerifiedExploit,
    traceHasVerifiedExploit
} = require('../pwnable-dashboard/services/dashboard/pipeline/pipeline.service');

test('does not recover from uid text embedded in payload source', () => {
    assert.equal(traceEventHasVerifiedExploit({
        source: 'codex',
        type: 'llm_json_event',
        data: {
            item: {
                type: 'mcp_tool_call',
                tool: 'pwn_payload_write',
                status: 'completed',
                result: { structuredContent: { payload_content: 'p.sendline(b"id") # uid=1000' } }
            }
        }
    }), false);
});

test('recovers only from verifier success or a completed session poll', () => {
    assert.equal(traceEventHasVerifiedExploit({
        type: 'exploit_verification',
        data: { success: true, evidence: 'command' }
    }), true);
    assert.equal(traceEventHasVerifiedExploit({
        source: 'codex',
        type: 'llm_json_event',
        data: {
            item: {
                type: 'mcp_tool_call',
                tool: 'pwn_session_poll',
                status: 'completed',
                result: { structuredContent: { stdout: 'uid=1000(pwn) gid=1000(pwn)\n' } }
            }
        }
    }), true);
});

test('verified trace scan awaits async trace content', async () => {
    assert.equal(await traceHasVerifiedExploit('', ''), false);
});
