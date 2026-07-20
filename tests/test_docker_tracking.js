const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveTrackingFiles } = require('../pwnable-dashboard/services/dashboard/pipeline/docker.service');

const withTempChallenge = (fn) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pwnauto-docker-track-'));
    try {
        fs.mkdirSync(path.join(dir, 'deploy'), { recursive: true });
        fs.writeFileSync(path.join(dir, 'deploy', 'chall'), 'x');
        fs.writeFileSync(path.join(dir, 'deploy', 'flag'), 'flag');
        fs.writeFileSync(path.join(dir, 'deploy', 'libc.so.6'), 'libc'.repeat(1024));
        return fn(dir);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
};

test('Dockerfile ENV variables are expanded when resolving challenge binary', () => {
    withTempChallenge((dir) => {
        const dockerfile = path.join(dir, 'Dockerfile');
        fs.writeFileSync(dockerfile, [
            'FROM ubuntu:22.04',
            'ENV user chall',
            'ADD ./deploy/flag /home/$user/flag',
            'ADD ./deploy/$user /home/$user/$user',
            'ADD ./deploy/libc.so.6 /home/$user/libc.so.6'
        ].join('\n'));

        assert.deepEqual(resolveTrackingFiles(dockerfile, dir), ['deploy/chall']);
    });
});

test('fallback tracking ignores libc support files', () => {
    withTempChallenge((dir) => {
        assert.deepEqual(resolveTrackingFiles(null, dir), ['deploy/chall']);
    });
});
