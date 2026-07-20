import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / 'scripts' / 'extract_dataset.py'


def load_extractor():
    spec = importlib.util.spec_from_file_location('extract_dataset', SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_trace(path, events):
    with open(path, 'w', encoding='utf-8') as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + '\n')


def read_json(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def read_jsonl(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return [json.loads(line) for line in handle if line.strip()]


def prompt_text(phase='exploit', attempt=1):
    return '\n'.join([
        '# System Instructions',
        'You are a professional pwnable solver.',
        '',
        '# User Task',
        'Solve the pwnable challenge.',
        '',
        '# Runtime Context',
        '- Challenge directory: /challenge',
        '- Target binary: /challenge/prob',
        '',
        '# Phase Context',
        f'- Phase: {phase}',
        f'- Attempt: {attempt}',
    ])


def phase_meta(phase='exploit', attempt=1, previous_failure=None):
    agent_head = {
        'analysis_static': 'analysis.static',
        'analysis_dynamic': 'analysis.dynamic',
        'analysis_dynamic_poc': 'analysis.dynamic_poc',
        'repair': 'exploit.repair',
    }.get(phase, 'exploit.coder')
    meta = {
        'phase': phase,
        'attempt': attempt,
        'goal': 'obtain_shell' if phase in ('exploit', 'repair') else 'analyze',
        'objective': 'write verified exploit' if phase in ('exploit', 'repair') else 'collect validated analysis facts',
        'requiresShell': phase in ('exploit', 'repair'),
        'discoveryTargetCount': 1,
        'contract': {
            'agentHead': agent_head,
            'role': 'Exploit Coder Agent',
            'supervisionTarget': 'write exploit from verified target',
            'successCriteria': ['uid/gid command output or direct flag evidence is confirmed'],
            'requiredEvidence': ['payload write', 'command execution'],
        },
    }
    if previous_failure:
        meta['previousFailure'] = previous_failure
    return meta


def payload_source(offset=72):
    lines = [
        'from pwn import *',
        'context.log_level = "error"',
        f'payload = b"A" * {offset}',
        'payload += p64(0x40101a)',
        'payload += p64(0x401050)',
        'p.sendlineafter(b"> ", payload)',
        'p.sendline(b"id")',
        'print(p.recvuntil(b"gid=", timeout=2))',
    ]
    lines.extend(f'padding_{index} = {index}' for index in range(40))
    return '\n'.join(lines)


def event(run_id, execution_id, source, event_type, **extra):
    payload = {
        'runId': run_id,
        'executionId': execution_id,
        'source': source,
        'type': event_type,
    }
    payload.update(extra)
    return payload


def codex_item(run_id, execution_id, item):
    return event(run_id, execution_id, 'codex', 'llm_json_event', data={'item': item})


def phase_events(run_id, execution_id, phase, attempt, execute_result, phase_status, payload, previous_failure=None, include_run_result=False, run_status=None, include_final=True, include_session_poll=True):
    meta = phase_meta(phase, attempt, previous_failure)
    events = [
        event(
            run_id,
            execution_id,
            'dashboard',
            'codex_prompt',
            phase=phase,
            phaseAttempt=attempt,
            phaseGoal='obtain_shell',
            phaseObjective='write verified exploit',
            phaseAgentHead=meta['contract']['agentHead'],
            phaseRequiresShell=True,
            text=prompt_text(phase, attempt),
            data={'phaseMeta': meta, 'promptMetadata': {'systemPromptFile': 'guidline_docs/codex-system-prompt.md'}},
        ),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': 'I will write the exploit and verify command execution with id output.',
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_write',
            'status': 'in_progress',
            'arguments': {'payload_content': payload},
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_write',
            'status': 'completed',
            'result': {'structuredContent': {'status': 'ok', 'path': '/challenge/hack.py'}},
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_execute',
            'status': 'completed',
            'result': {'structuredContent': execute_result},
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'phase_validation',
            phase=phase,
            phaseAttempt=attempt,
            phaseAgentHead=meta['contract']['agentHead'],
            phaseRequiresShell=True,
            data={'status': phase_status, 'phaseMeta': meta, 'verification': 'wrapper_execution'},
        ),
    ]
    if include_session_poll:
        events.insert(-1, codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_session_poll',
            'status': 'completed',
            'result': {'structuredContent': execute_result},
        }))
    if include_final:
        events.insert(-1, codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': 'Evidence Summary: the vulnerability and payload path were validated through MCP execution, and command execution evidence was checked before completion.',
        }))
    if include_run_result:
        events.append(event(run_id, execution_id, 'dashboard', 'agent_run_result', data={'status': run_status or phase_status}))
    return events


def exploit_trace(run_id, execution_id, execute_result, run_status):
    return phase_events(
        run_id,
        execution_id,
        'exploit',
        1,
        execute_result,
        run_status,
        payload_source(),
        include_run_result=True,
        run_status=run_status,
    )


def dashboard_verified_trace(run_id, execution_id):
    meta = phase_meta('exploit', 1)
    payload = payload_source()
    return [
        event(
            run_id,
            execution_id,
            'dashboard',
            'codex_prompt',
            phase='exploit',
            phaseAttempt=1,
            phaseGoal='obtain_shell',
            phaseObjective='write verified exploit',
            phaseAgentHead=meta['contract']['agentHead'],
            phaseRequiresShell=True,
            text=prompt_text('exploit', 1),
            data={'phaseMeta': meta, 'promptMetadata': {'systemPromptFile': 'guidline_docs/codex-system-prompt.md'}},
        ),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': 'Evidence Summary: stack overwrite, offset 72, ret2win payload, dashboard verification will confirm id output.',
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_write',
            'status': 'in_progress',
            'arguments': {'payload_content': payload},
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_write',
            'status': 'completed',
            'result': {'structuredContent': {'status': 'ok', 'path': '/challenge/hack.py'}},
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'exploit_verification',
            phase='exploit',
            phaseAttempt=1,
            phaseAgentHead=meta['contract']['agentHead'],
            phaseRequiresShell=True,
            data={
                'phaseMeta': meta,
                'success': True,
                'evidence': 'command',
                'logs': 'STDOUT:\nuid=1000(pwn) gid=1000(pwn)\nSTDERR:\n',
            },
        ),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': 'Evidence Summary: dashboard execution independently verified the payload and confirmed command execution from the resulting shell session.',
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'phase_validation',
            phase='exploit',
            phaseAttempt=1,
            phaseAgentHead=meta['contract']['agentHead'],
            phaseRequiresShell=True,
            data={'status': 'success', 'phaseMeta': meta, 'verification': 'wrapper_execution'},
        ),
        event(run_id, execution_id, 'dashboard', 'agent_run_result', data={'status': 'success'}),
    ]


def analysis_trace(run_id, execution_id):
    meta = phase_meta('analysis_static', 1)
    meta['goal'] = 'identify_static_vulnerability_targets'
    meta['requiresShell'] = False
    meta['contract']['agentHead'] = 'analysis.static'
    return [
        event(
            run_id,
            execution_id,
            'dashboard',
            'codex_prompt',
            phase='analysis_static',
            phaseAttempt=1,
            phaseAgentHead='analysis.static',
            phaseRequiresShell=False,
            text=prompt_text('analysis_static', 1),
            data={'phaseMeta': meta},
        ),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': 'I will inspect binary metadata first and select only the strongest input-connected vulnerability candidate.',
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'meta',
            'status': 'in_progress',
            'arguments': {'binary_path': '/challenge/prob'},
        }),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'meta',
            'status': 'completed',
            'result': {'structuredContent': {'name': 'prob', 'checksec': {'NX': True, 'PIE': False}}},
        }),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': '{"protections":{"NX":true,"PIE":false},"targets":[{"function_name":"main","reason":"User-controlled input reaches an unchecked stack buffer write, making main the direct exploit entry point."}]}',
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'phase_validation',
            phase='analysis_static',
            phaseAttempt=1,
            phaseAgentHead='analysis.static',
            phaseRequiresShell=False,
            data={'status': 'success', 'phaseMeta': meta, 'validation': 'static_schema_and_content'},
        ),
    ]


def dynamic_trace(run_id, execution_id):
    meta = phase_meta('analysis_dynamic', 1)
    meta['staticAnalysis'] = {
        'protections': {'NX': True, 'PIE': False},
        'targets': [{'function_name': 'main', 'reason': 'User-controlled input reaches an unchecked stack buffer write.'}],
    }
    return [
        event(
            run_id,
            execution_id,
            'dashboard',
            'codex_prompt',
            phase='analysis_dynamic',
            phaseAttempt=1,
            phaseAgentHead='analysis.dynamic',
            phaseRequiresShell=False,
            text=prompt_text('analysis_dynamic', 1),
            data={'phaseMeta': meta},
        ),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwno',
            'tool': 'get_context',
            'status': 'completed',
            'arguments': {},
            'result': {'structuredContent': {'registers': {'rip': '0x401050'}}},
        }),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': '{"runtime_facts":{"observations":[{"target":"main","kind":"control","evidence":"Debugger context after the checked input reaches the vulnerable return path."}],"primitives":[{"name":"return-address-control","confidence":"confirmed","evidence":"RIP reaches the saved return path after the input."}],"blockers":[]}}',
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'phase_validation',
            phase='analysis_dynamic',
            phaseAttempt=1,
            phaseAgentHead='analysis.dynamic',
            phaseRequiresShell=False,
            data={'status': 'success', 'phaseMeta': meta, 'validation': 'dynamic_schema_and_content'},
        ),
    ]


def dynamic_poc_trace(run_id, execution_id):
    meta = phase_meta('analysis_dynamic_poc', 1)
    meta['staticAnalysis'] = {
        'protections': {'NX': True, 'PIE': False},
        'targets': [{'function_name': 'main', 'reason': 'User-controlled input reaches an unchecked stack buffer write.'}],
    }
    return [
        event(
            run_id,
            execution_id,
            'dashboard',
            'codex_prompt',
            phase='analysis_dynamic_poc',
            phaseAttempt=1,
            phaseAgentHead='analysis.dynamic_poc',
            phaseRequiresShell=False,
            text=prompt_text('analysis_dynamic', 1),
            data={'phaseMeta': meta},
        ),
        codex_item(run_id, execution_id, {
            'type': 'mcp_tool_call',
            'server': 'pwno',
            'tool': 'get_context',
            'status': 'completed',
            'arguments': {},
            'result': {'structuredContent': {'registers': {'rip': '0x401080', 'rsp': '0x7fffffffe000'}}},
        }),
        codex_item(run_id, execution_id, {
            'type': 'agent_message',
            'text': '{"runtime_facts":{"observations":[{"target":"main","kind":"control","evidence":"Debugger confirmed the exact crashing return path and the usable saved return overwrite route for the selected input handler."}],"primitives":[{"name":"saved-return-overwrite","confidence":"confirmed","evidence":"The debugger-observed stack layout confirms command execution can be reached without an additional leak."}],"blockers":[]}}',
        }),
        event(
            run_id,
            execution_id,
            'dashboard',
            'phase_validation',
            phase='analysis_dynamic_poc',
            phaseAttempt=1,
            phaseAgentHead='analysis.dynamic_poc',
            phaseRequiresShell=False,
            data={'status': 'success', 'phaseMeta': meta, 'validation': 'poc_grounded_dynamic_schema_and_content'},
        ),
    ]


def repair_trace(run_id, execution_id):
    previous_failure = {
        'category': 'Memory Corruption (SIGSEGV)',
        'issue': 'bad_offset',
        'description': 'Initial exploit crashed before command execution.',
    }
    return [
        *phase_events(
            run_id,
            execution_id,
            'exploit',
            1,
            {'status': 'error', 'stderr': 'Segmentation fault SIGSEGV\n'},
            'failure',
            payload_source(72),
        ),
        *phase_events(
            run_id,
            execution_id,
            'repair',
            2,
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
            payload_source(80),
            previous_failure=previous_failure,
            include_run_result=True,
            run_status='success',
        ),
    ]


class ExtractDatasetRegressionTest(unittest.TestCase):
    def setUp(self):
        self.extractor = load_extractor()

    def run_trace(self, run_id, events):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            trace_path = tmp_path / 'trace.jsonl'
            output_dir = tmp_path / 'out'
            write_trace(trace_path, events)
            self.extractor.process_trace(str(trace_path), str(output_dir))
            return {
                'summary': read_json(output_dir / f'{run_id}_summary.json'),
                'quality': read_json(output_dir / f'{run_id}_quality_report.json'),
                'sft': read_jsonl(output_dir / f'{run_id}_sft_train.jsonl'),
                'train': read_jsonl(output_dir / f'{run_id}_train.jsonl'),
                'gold': read_jsonl(output_dir / f'{run_id}_gold_train.jsonl'),
                'exploit_code': read_jsonl(output_dir / f'{run_id}_exploit_code_train.jsonl'),
                'repair': read_jsonl(output_dir / f'{run_id}_repair_train.jsonl'),
                'tool_failures': read_jsonl(output_dir / f'{run_id}_tool_failures.jsonl'),
                'qwen_sft': read_jsonl(output_dir / f'{run_id}_qwen3_coder_next_sft.jsonl'),
                'qwen_static': read_jsonl(output_dir / f'{run_id}_qwen3_coder_next_static_analysis_sft.jsonl'),
                'qwen_dynamic': read_jsonl(output_dir / f'{run_id}_qwen3_coder_next_dynamic_analysis_sft.jsonl'),
                'qwen_exploit': read_jsonl(output_dir / f'{run_id}_qwen3_coder_next_exploit_sft.jsonl'),
                'qwen_repair': read_jsonl(output_dir / f'{run_id}_qwen3_coder_next_repair_sft.jsonl'),
                'adapter_routing': read_json(output_dir / f'{run_id}_adapter_routing.json'),
                'trace_replay': read_json(output_dir / f'{run_id}_trace_replay_manifest.json'),
                'tool_catalog': read_json(output_dir / f'{run_id}_tool_schema_catalog.json'),
                'card': read_json(output_dir / f'{run_id}_dataset_card.json'),
            }

    def test_strong_success_generates_gold_and_exploit_code(self):
        run_id = '20260703010101-abcdef'
        result = self.run_trace(run_id, exploit_trace(
            run_id,
            'exec-strong',
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
        ))

        self.assertEqual(result['summary']['runStatus'], 'success')
        self.assertEqual(result['quality']['goldStrongSuccessCount'], 1)
        self.assertGreaterEqual(len(result['gold']), 1)
        self.assertGreaterEqual(len(result['exploit_code']), 1)
        self.assertGreaterEqual(len(result['train']), 1)
        self.assertGreaterEqual(len(result['sft']), 1)
        self.assertEqual(result['train'][0]['agent_head'], 'exploit.coder')
        self.assertEqual(result['train'][0]['metadata']['action_outcome']['outcome'], 'verified_success')
        self.assertEqual(result['card']['policyVersion'], 4)
        self.assertEqual(result['quality']['sftTrainStepCount'], len(result['sft']))
        self.assertEqual(len(result['qwen_exploit']), 1)
        self.assertEqual(result['qwen_exploit'][0]['model_family'], 'Qwen3-Coder-Next')
        self.assertEqual(result['qwen_exploit'][0]['head_type'], 'exploit.coder')
        self.assertEqual(result['qwen_exploit'][0]['task_role'], 'exploit_generation_and_verification')
        self.assertEqual(result['qwen_exploit'][0]['metadata']['adapter_name'], 'qwen3-coder-next-exploit-coder-lora')
        self.assertTrue(any(message.get('tool_calls') for message in result['qwen_exploit'][0]['messages']))
        self.assertTrue(any(message.get('role') == 'tool' for message in result['qwen_exploit'][0]['messages']))
        self.assertEqual(result['qwen_exploit'][0]['messages'][-1]['role'], 'assistant')
        self.assertNotIn('<think>', json.dumps(result['qwen_exploit'][0]['messages']).lower())
        self.assertEqual(result['qwen_exploit'][0]['training']['loss_on_roles'], ['assistant'])
        self.assertTrue(result['qwen_exploit'][0]['training']['train_tool_calls'])
        self.assertFalse(result['qwen_exploit'][0]['training']['train_tool_results'])
        self.assertIn('exploit', result['adapter_routing']['routing'])
        self.assertGreaterEqual(result['tool_catalog']['toolCount'], 1)
        self.assertEqual(result['trace_replay']['policyVersion'], 4)

    def test_dashboard_verification_promotes_payload_to_gold_without_extra_mcp_execute(self):
        run_id = '20260703011111-abc123'
        result = self.run_trace(run_id, dashboard_verified_trace(run_id, 'exec-dashboard-verify'))

        self.assertEqual(result['summary']['runStatus'], 'success')
        self.assertEqual(result['quality']['goldStrongSuccessCount'], 1)
        self.assertIn('no_qwen_verified_static_analysis_episode', result['quality']['qualityGate']['blockers'])
        self.assertGreaterEqual(len(result['gold']), 1)
        self.assertGreaterEqual(len(result['exploit_code']), 1)
        self.assertEqual(result['gold'][0]['metadata']['action_outcome']['outcome'], 'verified_success')
        self.assertEqual(len(result['qwen_exploit']), 1)

    def test_qwen_native_full_pipeline_passes_quality_gate(self):
        run_id = '20260703012121-c0ffee'
        execution_id = 'exec-qwen-native'
        result = self.run_trace(run_id, [
            *analysis_trace(run_id, execution_id),
            *dynamic_trace(run_id, execution_id),
            *exploit_trace(
                run_id,
                execution_id,
                {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
                'success',
            ),
        ])

        self.assertTrue(result['quality']['qualityGate']['passed'])
        self.assertEqual(len(result['qwen_static']), 1)
        self.assertEqual(len(result['qwen_dynamic']), 1)
        self.assertEqual(len(result['qwen_exploit']), 1)
        self.assertEqual(len(result['qwen_sft']), 3)

    def test_fast_path_static_and_exploit_requires_dynamic_proof(self):
        run_id = '20260703013131-fa57ed'
        execution_id = 'exec-fast-path'
        result = self.run_trace(run_id, [
            *analysis_trace(run_id, execution_id),
            *exploit_trace(
                run_id,
                execution_id,
                {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
                'success',
            ),
        ])

        self.assertFalse(result['quality']['qualityGate']['passed'])
        self.assertEqual(len(result['qwen_static']), 1)
        self.assertEqual(len(result['qwen_dynamic']), 0)
        self.assertEqual(len(result['qwen_exploit']), 1)
        self.assertIn('no_qwen_verified_dynamic_analysis_episode', result['quality']['qualityGate']['blockers'])

    def test_poc_dynamic_verification_distills_clean_dynamic_sft_only(self):
        run_id = '20260703013535-pocdyn'
        execution_id = 'exec-poc-dynamic'
        result = self.run_trace(run_id, [
            *analysis_trace(run_id, execution_id),
            *dynamic_trace(run_id, execution_id),
            *dynamic_poc_trace(run_id, execution_id),
        ])

        self.assertEqual(len(result['qwen_static']), 1)
        self.assertEqual(len(result['qwen_dynamic']), 1)
        self.assertEqual(len(result['qwen_sft']), 2)
        self.assertEqual(result['qwen_dynamic'][0]['metadata']['phase'], 'analysis_dynamic')
        self.assertEqual(result['qwen_dynamic'][0]['metadata']['distilled_from_phase'], 'analysis_dynamic_poc')
        self.assertEqual(result['qwen_dynamic'][0]['head_type'], 'analysis.dynamic')
        self.assertNotIn('analysis_dynamic_poc', result['adapter_routing']['routing'])
        self.assertEqual(result['quality']['qwenDistilledDynamicFromPocCount'], 1)

    def test_qwen_static_export_rejects_empty_targets(self):
        run_id = '20260703014141-empty'
        events = analysis_trace(run_id, 'exec-empty-static')
        for event in events:
            item = event.get('data', {}).get('item', {})
            if item.get('type') == 'agent_message' and item.get('text', '').startswith('{'):
                item['text'] = '{"protections":{"NX":true},"targets":[],"exploit_requirements":{"needs_dynamic_probe":true,"needed_facts":["find input path"],"likely_strategy":"dynamic triage","confidence":"low"}}'
        result = self.run_trace(run_id, events)

        self.assertEqual(len(result['qwen_static']), 0)
        self.assertEqual(result['quality']['qwenRejectedEpisodes']['empty_static_targets'], 1)

    def test_weak_marker_is_not_promoted_to_primary_or_gold(self):
        run_id = '20260703020202-fedcba'
        result = self.run_trace(run_id, exploit_trace(
            run_id,
            'exec-weak',
            {'status': 'ok', 'stdout': 'PWNED final_check\n'},
            'failure',
        ))

        self.assertEqual(result['summary']['runStatus'], 'failure')
        self.assertEqual(result['quality']['goldStrongSuccessCount'], 0)
        self.assertEqual(len(result['gold']), 0)
        self.assertEqual(len(result['exploit_code']), 0)
        self.assertEqual(len(result['train']), 0)
        self.assertEqual(len(result['qwen_sft']), 0)
        self.assertGreaterEqual(len(result['tool_failures']), 1)
        self.assertTrue(result['tool_failures'][0]['metadata']['weak_success_marker'])
        self.assertEqual(result['tool_failures'][0]['metadata']['action_outcome']['outcome'], 'weak_unverified_marker')

    def test_qwen_export_redacts_runtime_flag(self):
        run_id = '20260703023232-f1a6ed'
        result = self.run_trace(run_id, exploit_trace(
            run_id,
            'exec-flag-redaction',
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\nflag{runtime_secret}\n'},
            'success',
        ))

        serialized = json.dumps(result['qwen_exploit'], ensure_ascii=False)
        self.assertIn('<FLAG>', serialized)
        self.assertIn('<IDENTITY>', serialized)
        self.assertNotIn('flag{runtime_secret}', serialized)
        self.assertEqual(result['quality']['qwenRawFlagLeakCount'], 0)

    def test_qwen_export_rejects_hardcoded_flag_payload(self):
        run_id = '20260703024242-badf1a'
        payload = payload_source() + '\nexpected = b"flag{hardcoded_value}"'
        result = self.run_trace(run_id, phase_events(
            run_id,
            'exec-hardcoded-flag',
            'exploit',
            1,
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
            payload,
            include_run_result=True,
            run_status='success',
        ))

        self.assertEqual(len(result['qwen_exploit']), 0)
        self.assertEqual(result['quality']['qwenRejectedEpisodes']['unsafe_or_hardcoded_payload'], 1)

    def test_qwen_export_rejects_non_english_assistant_text(self):
        run_id = '20260703024747-english'
        events = exploit_trace(
            run_id,
            'exec-non-english',
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
        )
        for event in events:
            item = event.get('data', {}).get('item', {})
            if item.get('type') == 'agent_message':
                item['text'] = '\ubd84\uc11d \uc644\ub8cc: \uc250 \uc2e4\ud589\uc774 \uac80\uc99d\ub418\uc5c8\uc2b5\ub2c8\ub2e4.'
                break

        result = self.run_trace(run_id, events)

        self.assertEqual(len(result['qwen_exploit']), 0)
        self.assertEqual(result['quality']['qwenRejectedEpisodes']['english_language_violation'], 1)

    def test_qwen_export_adds_verifier_terminal_summary_after_early_stop(self):
        run_id = '20260703025252-ver1fy'
        result = self.run_trace(run_id, phase_events(
            run_id,
            'exec-early-stop',
            'exploit',
            1,
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
            payload_source(),
            include_run_result=True,
            run_status='success',
            include_final=False,
        ))

        episode = result['qwen_exploit'][0]
        self.assertEqual(episode['metadata']['terminal_summary_source'], 'verifier')
        self.assertIn('MCP verifier confirmed', episode['messages'][-1]['content'])
        self.assertIn('Vulnerability:', episode['messages'][-1]['content'])
        self.assertIn('Payload strategy:', episode['messages'][-1]['content'])

    def test_static_episode_with_runtime_tool_is_rejected(self):
        run_id = '20260703030000-static'
        events = analysis_trace(run_id, 'exec-static-policy')
        events.insert(-1, codex_item(run_id, 'exec-static-policy', {
            'type': 'mcp_tool_call',
            'server': 'pwno',
            'tool': 'pwncli',
            'status': 'completed',
            'arguments': {'file': 'print(1)'},
            'result': {'structuredContent': {'status': 'ok'}},
        }))
        result = self.run_trace(run_id, events)

        self.assertEqual(result['qwen_static'], [])
        self.assertEqual(result['quality']['qwenRejectedEpisodes']['tool_not_allowed:pwncli'], 1)

    def test_exploit_episode_with_multiple_payloads_is_accepted(self):
        run_id = '20260703030101-budget'
        events = exploit_trace(
            run_id,
            'exec-budget',
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
        )
        events.insert(-2, codex_item(run_id, 'exec-budget', {
            'type': 'mcp_tool_call',
            'server': 'pwnautomator',
            'tool': 'pwn_payload_write',
            'status': 'completed',
            'arguments': {'payload_content': payload_source(80)},
            'result': {'structuredContent': {'status': 'ok'}},
        }))
        result = self.run_trace(run_id, events)

        self.assertGreaterEqual(len(result['qwen_exploit']), 1)
        self.assertNotIn('tool_budget_exceeded:maxPayloadWrites', result['quality']['qwenRejectedEpisodes'])

    def test_payload_execute_identity_without_session_poll_is_not_success(self):
        run_id = '20260703030304-session'
        result = self.run_trace(run_id, phase_events(
            run_id,
            'exec-no-session',
            'exploit',
            1,
            {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
            'success',
            payload_source(),
            include_run_result=True,
            run_status='success',
            include_session_poll=False,
        ))

        self.assertEqual(len(result['gold']), 0)
        self.assertEqual(len(result['qwen_exploit']), 0)

    def test_repair_payload_change_gets_before_after_label(self):
        run_id = '20260703030303-a1b2c3'
        result = self.run_trace(run_id, repair_trace(run_id, 'exec-repair'))

        self.assertEqual(result['summary']['runStatus'], 'success')
        self.assertEqual(result['quality']['repairTransitionCount'], 1)
        self.assertEqual(result['quality']['repairPayloadChangedCount'], 1)
        self.assertEqual(result['quality']['repairTransitionLabels']['changed_and_verified'], 1)

        repair_rows = [row for row in result['exploit_code'] if row['phase'] == 'repair']
        self.assertGreaterEqual(len(repair_rows), 1)
        self.assertGreaterEqual(len(result['repair']), 1)
        transition = repair_rows[0]['metadata']['repair_transition']
        self.assertEqual(transition['label'], 'changed_and_verified')
        self.assertTrue(transition['payload_changed'])
        self.assertNotEqual(transition['before_payload_sha256'], transition['after_payload_sha256'])
        self.assertEqual(transition['previous_failure']['issue'], 'bad_offset')
        self.assertIn('before_payload', transition['change_summary'])
        self.assertEqual(result['quality']['repairRowsWithBeforeAfter'], 1)
        self.assertEqual(len(result['qwen_exploit']), 1)
        self.assertEqual(len(result['qwen_repair']), 1)
        self.assertEqual(result['qwen_exploit'][0]['head_type'], 'exploit.coder')
        self.assertEqual(result['qwen_exploit'][0]['metadata']['distilled_from_phase'], 'repair')
        self.assertEqual(result['qwen_repair'][0]['head_type'], 'exploit.repair')
        self.assertEqual(result['qwen_repair'][0]['metadata']['distilled_from_phase'], 'repair')
        self.assertEqual(result['qwen_repair'][0]['metadata']['repair_transition']['label'], 'changed_and_verified')
        self.assertGreaterEqual(result['qwen_exploit'][0]['metadata']['tool_call_count'], 3)
        self.assertEqual(result['quality']['qwenDistilledExploitCount'], 1)
        self.assertEqual(result['quality']['qwenDistilledRepairCount'], 1)
        self.assertEqual(result['adapter_routing']['routing']['exploit']['sample_count'], 1)

    def test_hinted_repair_distills_deployable_clean_exploit(self):
        run_id = '20260703030303-hinted'
        execution_id = 'exec-hinted-repair'
        events = repair_trace(run_id, execution_id)
        for event_item in events:
            if event_item.get('type') == 'codex_prompt' and event_item.get('phase') == 'repair':
                meta = event_item['data']['phaseMeta']
                meta['hint'] = {'source': 'poc_grounded_analysis', 'level': 1, 'notes': ['verified dynamic facts only']}
                meta['staticAnalysis'] = {'targets': [{'function_name': 'main', 'reason': 'Unchecked stack input controls the return path.'}]}
                meta['dynamicAnalysis'] = {'runtime_facts': {'observations': [{'target': 'main', 'evidence': 'Debugger-confirmed saved return overwrite reaches command execution.'}]}}

        result = self.run_trace(run_id, events)

        self.assertEqual(len(result['qwen_exploit']), 1)
        self.assertEqual(len(result['qwen_repair']), 0)
        self.assertEqual(result['qwen_exploit'][0]['metadata']['hint_source'], '')
        self.assertEqual(result['qwen_exploit'][0]['metadata']['distilled_from_hint_source'], 'poc_grounded_analysis')
        self.assertEqual(result['quality']['qwenExploitSftCount'], 1)
        self.assertEqual(result['quality']['qwenRepairHintedExcludedCount'], 1)

    def test_phases_after_verified_exploit_are_excluded(self):
        run_id = '20260703040404-deadbe'
        events = [
            *phase_events(
                run_id,
                'exec-extra-repair',
                'exploit',
                1,
                {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
                'success',
                payload_source(72),
            ),
            *phase_events(
                run_id,
                'exec-extra-repair',
                'repair',
                2,
                {'status': 'ok', 'stdout': 'uid=1000(pwn) gid=1000(pwn)\n'},
                'success',
                payload_source(80),
                include_run_result=True,
                run_status='success',
            ),
        ]
        result = self.run_trace(run_id, events)

        self.assertGreater(result['quality']['postSuccessEventsDropped'], 0)
        self.assertEqual(len(result['repair']), 0)
        self.assertTrue(all(row['phase'] != 'repair' for row in result['sft']))
        self.assertEqual(result['gold'][0]['phase'], 'exploit')

    def test_policy_regexes_cover_success_and_wrapper_variants(self):
        self.assertTrue(self.extractor.matches_any_regex('uid=1000(pwn)', self.extractor.STRONG_SUCCESS_PATTERNS))
        self.assertTrue(self.extractor.matches_any_regex('PWNED final_check', self.extractor.WEAK_SUCCESS_PATTERNS))
        self.assertTrue(self.extractor.payload_uses_wrapper_boilerplate('p = process ("./prob")'))
        self.assertTrue(self.extractor.payload_uses_disallowed_runtime_introspection("open(f'/proc/{p.pid}/maps').read()"))
        self.assertTrue(self.extractor.payload_uses_disallowed_runtime_introspection("libs = p.libs()"))

    def test_static_ghidra_policy_allows_full_static_tooling(self):
        usage = {'calls': 1, 'payload_writes': 0, 'payload_executes': 0, 'hex_reads': 1}
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'mem_hex', {'addr': '0x401000', 'size': 256}, usage),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'mem_hex', {'addr': '0x401000', 'size': 257}, usage),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'mem_hex', {'addr': '0x401010', 'size': 16}, {'calls': 2, 'payload_writes': 0, 'payload_executes': 0, 'hex_reads': 2}),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'ghidra_call', {'cmd': 'help', 'args': {}}, usage),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'search_str', {'pattern': ''}, usage),
            'empty_search_pattern:search_str'
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'ghidra_call', {'cmd': 'search.str', 'args': {'pattern': ''}}, usage),
            'empty_search_pattern:search.str'
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'decompile_by_addr', {'addr': '0x401209'}, usage),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'func_by_addr', {}, usage),
            'missing_address:func_by_addr'
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'decompile_by_addr', {'addr': 'main'}, usage),
            'invalid_address:decompile_by_addr'
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'disassemble_function', {'start_address': '0x401209'}, usage),
            ''
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'search_xrefs_to', {'addr': 'not_addr'}, usage),
            'invalid_address:search_xrefs_to'
        )
        self.assertEqual(
            self.extractor.tool_policy_issue('analysis_static', 'pwn_payload_write', {}, usage),
            'tool_not_allowed:pwn_payload_write'
        )


if __name__ == '__main__':
    unittest.main()
