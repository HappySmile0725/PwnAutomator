const assert = require('node:assert/strict');
const test = require('node:test');

const { runCommand } = require('../pwnable-dashboard/services/dashboard/pipeline/command.service');

test('terminates a command immediately after verified output', async () => {
    const started = Date.now();
    const result = await runCommand({
        command: process.execPath,
        args: ['-e', 'console.log("VERIFIED"); setInterval(() => {}, 1000)'],
        terminateAfterLine: (_, line) => line === 'VERIFIED',
        terminateAfterLineMs: () => 0,
    });

    assert.equal(result.terminatedAfterLine, true);
    assert(Date.now() - started < 3000);
});
