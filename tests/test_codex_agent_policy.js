const assert = require('node:assert/strict');
const test = require('node:test');

const {
    definesUncalledExploitEntrypoint,
    payloadPolicyIssues,
    policy
} = require('../pwnable-dashboard/services/dashboard/pipeline/trainingPolicy.service');
const {
    normalizeContinuation,
    normalizeDiscoveryResult,
    dynamicProofIssues,
    observePhaseTool,
    shouldRunDynamicProbe,
    staticReasonLooksLikeRawDump,
    withStaticFallbackTarget
} = require('../pwnable-dashboard/services/dashboard/pipeline/codexAgent.service');

const usage = () => ({ calls: 0, payloadWrites: 0, payloadExecutes: 0, hexReads: 0, pending: new Set(), seen: new Set() });
const phase = (name, contract) => ({ phase: name, contract });

test('static analysis rejects runtime execution tools', () => {
    const result = observePhaseTool(
        phase('analysis_static', policy.contracts.analysisStatic),
        { type: 'mcp_tool_call', id: 'static-1', tool: 'pwncli', status: 'in_progress', arguments: {} },
        usage()
    );

    assert.equal(result, 'tool_not_allowed:pwncli');
});

test('static analysis permits ghidra memory reads without artificial byte limits', () => {
    const state = usage();
    const meta = phase('analysis_static', policy.contracts.analysisStatic);
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'static-2', tool: 'mem_hex', status: 'in_progress', arguments: { addr: '0x401000', size: 256 } },
        state
    ), '');
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'static-3', tool: 'mem_hex', status: 'in_progress', arguments: { addr: '0x401000', size: 257 } },
        state
    ), '');
});

test('static analysis permits ghidra raw calls but rejects empty searches', () => {
    assert.equal(observePhaseTool(
        phase('analysis_static', policy.contracts.analysisStatic),
        { type: 'mcp_tool_call', id: 'generic-1', tool: 'ghidra_call', status: 'in_progress', arguments: { cmd: 'help', args: {} } },
        usage()
    ), '');
    assert.equal(observePhaseTool(
        phase('analysis_static', policy.contracts.analysisStatic),
        { type: 'mcp_tool_call', id: 'search-1', tool: 'search_str', status: 'in_progress', arguments: { pattern: '' } },
        usage()
    ), 'empty_search_pattern:search_str');
    assert.equal(observePhaseTool(
        phase('analysis_static', policy.contracts.analysisStatic),
        { type: 'mcp_tool_call', id: 'search-2', tool: 'ghidra_call', status: 'in_progress', arguments: { cmd: 'search.str', args: { pattern: '' } } },
        usage()
    ), 'empty_search_pattern:search.str');
});

test('static analysis exposes full ghidra static tooling but not payload tools', () => {
    const meta = phase('analysis_static', policy.contracts.analysisStatic);
    for (const tool of [
        'help',
        'meta',
        'func_list',
        'func_by_name',
        'func_by_addr',
        'mem_hex',
        'mem_dec',
        'mem_str',
        'mem_asm',
        'disassemble_function',
        'decompile_by_name',
        'decompile_by_addr',
        'search_func',
        'search_str',
        'search_bytes',
        'search_xrefs_to',
        'search_xrefs_from'
    ]) {
        assert(policy.contracts.analysisStatic.allowedTools.includes(tool), `${tool} should be allowed`);
    }
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'payload-1', tool: 'pwn_payload_write', status: 'in_progress', arguments: {} },
        usage()
    ), 'tool_not_allowed:pwn_payload_write');
});

test('static analysis permits concrete address decompile only with a valid address', () => {
    const meta = phase('analysis_static', policy.contracts.analysisStatic);
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'addr-1', tool: 'decompile_by_addr', status: 'in_progress', arguments: { addr: '0x401209' } },
        usage()
    ), '');
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'addr-2', tool: 'func_by_addr', status: 'in_progress', arguments: {} },
        usage()
    ), 'missing_address:func_by_addr');
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'addr-3', tool: 'decompile_by_addr', status: 'in_progress', arguments: { addr: 'main' } },
        usage()
    ), 'invalid_address:decompile_by_addr');
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'addr-4', tool: 'disassemble_function', status: 'in_progress', arguments: { start_address: '0x401209' } },
        usage()
    ), '');
    assert.equal(observePhaseTool(
        meta,
        { type: 'mcp_tool_call', id: 'addr-5', tool: 'search_xrefs_to', status: 'in_progress', arguments: { addr: 'not_addr' } },
        usage()
    ), 'invalid_address:search_xrefs_to');
});

test('static analysis permits repeated ghidra hex reads', () => {
    const state = usage();
    const meta = phase('analysis_static', policy.contracts.analysisStatic);
    assert.equal(observePhaseTool(meta, {
        type: 'mcp_tool_call', id: 'hex-0', tool: 'mem_hex', status: 'in_progress', arguments: { addr: '0x401000', size: 16 }
    }, state), '');
    assert.equal(observePhaseTool(meta, {
        type: 'mcp_tool_call', id: 'hex-1', tool: 'mem_hex', status: 'in_progress', arguments: { addr: '0x401100', size: 16 }
    }, state), '');
});

test('static reason allows address evidence but rejects raw hex dumps', () => {
    const evidence = 'entry passes 0x1012f0 as main; code zeros 0x1012f0 and calls 0x1012e0 with edi=0x20 before 0x1012fe.';
    const dump = Array.from({ length: 40 }, (_, index) => (index % 256).toString(16).padStart(2, '0')).join(' ');

    assert.equal(staticReasonLooksLikeRawDump(evidence), false);
    assert.equal(staticReasonLooksLikeRawDump(dump), true);
});

test('exploit phase permits repeated payload writes without artificial budget limits', () => {
    const state = usage();
    const meta = phase('exploit', policy.contracts.exploit);
    assert.equal(observePhaseTool(meta, {
        type: 'mcp_tool_call', id: 'write-1', tool: 'pwn_payload_write', status: 'in_progress', arguments: {}
    }, state), '');
    assert.equal(observePhaseTool(meta, {
        type: 'mcp_tool_call', id: 'write-2', tool: 'pwn_payload_write', status: 'in_progress', arguments: {}
    }, state), '');
});

test('payload policy rejects hardcoded workspace paths and uncalled exploit entrypoints', () => {
    assert.equal(definesUncalledExploitEntrypoint('def exploit(p):\n    p.sendline(b"1")\n'), true);
    assert.equal(definesUncalledExploitEntrypoint('def exploit(p):\n    p.sendline(b"1")\n\nexploit(p)\n'), false);
    assert(payloadPolicyIssues('elf = ELF("/workspace/nullnull")').some((issue) => issue.includes('/workspace')));
    assert(payloadPolicyIssues('def exploit(p):\n    p.sendline(b"1")\n').some((issue) => issue.includes('not called')));
});

test('fast dynamic probe is deferred unless runtime facts are required', () => {
    const originalMode = process.env.PWN_AUTOMATOR_DYNAMIC_MODE;
    process.env.PWN_AUTOMATOR_DYNAMIC_MODE = 'defer';
    try {
        assert.equal(shouldRunDynamicProbe({
            protections: { Canary: false, NX: true },
            targets: [{ function_name: 'main', reason: 'stack buffer overflow with no stack canary' }],
            exploit_requirements: { needs_dynamic_probe: false, likely_strategy: 'ret2win' }
        }), false);
        assert.equal(shouldRunDynamicProbe({
            protections: { Canary: false, NX: true },
            targets: [{ function_name: 'main', reason: 'format string leaks libc before overwrite' }],
            exploit_requirements: { needs_dynamic_probe: false, likely_strategy: 'ret2libc' }
        }), true);
        assert.equal(shouldRunDynamicProbe({
            protections: { Canary: true, NX: true },
            targets: [{ function_name: 'main', reason: 'stack overflow requires canary handling' }],
            exploit_requirements: { needs_dynamic_probe: false, likely_strategy: 'leak then overwrite' }
        }), true);
    } finally {
        if (originalMode === undefined) {
            delete process.env.PWN_AUTOMATOR_DYNAMIC_MODE;
        } else {
            process.env.PWN_AUTOMATOR_DYNAMIC_MODE = originalMode;
        }
    }
});

test('empty static targets become low-confidence dynamic probe candidates', () => {
    const parsed = {
        protections: { Canary: false, NX: true },
        targets: [],
        exploit_requirements: {
            needs_dynamic_probe: false,
            needed_facts: [],
            likely_strategy: 'No exploit strategy can be selected because __libc_start_main points to probable main.',
            confidence: 'low'
        }
    };
    const result = withStaticFallbackTarget(normalizeDiscoveryResult(parsed), parsed);
    assert.equal(result.targets.length, 1);
    assert.equal(result.targets[0].function_name, 'main');
    assert.equal(result.exploit_requirements.needs_dynamic_probe, true);
    assert.equal(result.exploit_requirements.confidence, 'low');
});

test('continuation checkpoints resume from the saved phase', () => {
    assert.equal(normalizeContinuation({ stage: 'analysis_dynamic', staticAnalysis: { targets: [] } }).stage, 'analysis_dynamic');
    assert.equal(normalizeContinuation({ staticAnalysis: { targets: [] }, nextAttempt: 4 }).stage, 'repair');
    assert.equal(normalizeContinuation({ staticAnalysis: { targets: [] }, nextAttempt: 0 }).nextAttempt, 1);
    assert.equal(normalizeContinuation(null), null);
});

test('dynamic validation accepts useful fine-grained observation kinds', () => {
    const staticAnalysis = {
        targets: [{ function_name: 'FUN_004012ca', reason: 'selected interpreter target' }]
    };
    const dynamicAnalysis = {
        runtime_facts: {
            observations: [
                { target: 'FUN_004012ca', kind: 'control_flow', fact: 'Debugger confirmed the normal runtime path reaches the interpreter.' },
                { target: 'FUN_004012ca', kind: 'write_primitive', evidence: 'Debugger confirmed a controlled byte write relative to the stack frame.' },
                { target: 'FUN_004012ca', kind: 'control_hijack', evidence: 'Debugger confirmed saved RIP control reaches the selected ROP gadget.' },
                { target: 'FUN_004012ca', kind: 'libc_leak', evidence: 'Debugger confirmed puts(read@got) leaks a resolved libc read pointer.' }
            ],
            primitives: [
                { type: 'saved_rip_control', status: 'confirmed', details: 'Saved RIP is controlled while preserving the canary.' },
                { type: 'resolved_got_leak', status: 'confirmed', details: 'read@got leaks libc read after resolution.' }
            ],
            blockers: [],
            exploitability: {
                status: 'confirmed',
                leak: { status: 'confirmed', method: 'puts(read@got)', evidence: 'GDB confirmed read@got contains libc read.' },
                control: { status: 'confirmed', method: 'stack byte-write ROP', evidence: 'GDB confirmed return into gadget.' },
                exploit_plan: ['leak libc', 'ret2libc system']
            }
        }
    };

    assert.deepEqual(dynamicProofIssues(dynamicAnalysis, staticAnalysis), []);
});
