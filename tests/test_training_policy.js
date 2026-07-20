const assert = require('node:assert/strict');
const test = require('node:test');

const {
    extractManagedPayloadBody,
    payloadPolicyIssues
} = require('../pwnable-dashboard/services/dashboard/pipeline/trainingPolicy.service');

const managedPayload = (body) => [
    'from pwn import *',
    "p = process('./prob')",
    "e = ELF('./prob', checksec=False)",
    '',
    body,
    '',
    'p.interactive()',
    ''
].join('\n');

const managedRemotePayload = (body) => [
    'from pwn import *',
    'import os',
    "p = remote(os.environ['PWN_AUTOMATOR_REMOTE_HOST'], int(os.environ['PWN_AUTOMATOR_REMOTE_PORT']))",
    "e = ELF('./prob', checksec=False)",
    "libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else e.libc",
    '',
    body,
    '',
    'p.interactive()',
    ''
].join('\n');

test('managed MCP wrapper is excluded from payload policy checks', () => {
    const source = managedPayload('p.sendline(b"id")');
    assert.equal(extractManagedPayloadBody(source), 'p.sendline(b"id")');
    assert.deepEqual(payloadPolicyIssues(source), []);
});

test('managed remote MCP wrapper is excluded from payload policy checks', () => {
    const source = managedRemotePayload('p.sendline(b"id")');
    assert.equal(extractManagedPayloadBody(source), 'p.sendline(b"id")');
    assert.deepEqual(payloadPolicyIssues(source), []);
});

test('wrapper management emitted inside the payload body is rejected', () => {
    const issues = payloadPolicyIssues(managedPayload("q = process('./other')"));
    assert(issues.some((issue) => issue.includes('process')));
});

test('remote wrapper management emitted inside the payload body is rejected', () => {
    const issues = payloadPolicyIssues(managedRemotePayload("q = remote('127.0.0.1', 31337)"));
    assert(issues.some((issue) => issue.includes('remote')));
});

test('forbidden runtime introspection remains rejected', () => {
    const issues = payloadPolicyIssues(managedPayload("open(f'/proc/{p.pid}/maps').read()"));
    assert(issues.some((issue) => issue.includes('/proc')));
});
