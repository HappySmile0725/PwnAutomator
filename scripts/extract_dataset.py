import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from difflib import unified_diff
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "config" / "training-policy.json"
POLICY = json.loads(POLICY_PATH.read_text(encoding="utf-8")) if POLICY_PATH.exists() else {}

RUNTIME = POLICY.get("runtimeValidation", {})
PAYLOAD = POLICY.get("payloadValidation", {})
CURATION = POLICY.get("datasetCuration", {})
CONTRACTS = POLICY.get("contracts", {})
PHASE_CONTRACTS = {
    "analysis_static": CONTRACTS.get("analysisStatic") or CONTRACTS.get("discovery") or {},
    "analysis_dynamic": CONTRACTS.get("analysisDynamic") or {},
    "analysis_dynamic_poc": CONTRACTS.get("analysisDynamicPoc") or CONTRACTS.get("analysisDynamic") or {},
    "exploit": CONTRACTS.get("exploit") or {},
    "repair": CONTRACTS.get("repair") or {},
}
LEGACY_PHASES = {"discovery": "analysis_static", "analysis": "analysis_static"}
PHASE_HEADS = {
    "analysis_static": "analysis.static",
    "analysis_dynamic": "analysis.dynamic",
    "analysis_dynamic_poc": "analysis.dynamic_poc",
    "exploit": "exploit.coder",
    "repair": "exploit.repair",
}
PHASE_TASK_ROLES = {
    "analysis_static": "static_vulnerability_analysis",
    "analysis_dynamic": "runtime_exploitability_validation",
    "analysis_dynamic_poc": "poc_grounded_runtime_verification",
    "exploit": "exploit_generation_and_verification",
    "repair": "exploit_repair_and_reverification",
}
PHASE_TRAINING_FILES = {
    "analysis_static": "train/qwen3_coder_next_static_analysis_sft.jsonl",
    "analysis_dynamic": "train/qwen3_coder_next_dynamic_analysis_sft.jsonl",
    "exploit": "train/qwen3_coder_next_exploit_sft.jsonl",
    "repair": "train/qwen3_coder_next_repair_sft.jsonl",
}
PHASE_ADAPTERS = {
    "analysis_static": "qwen3-coder-next-analysis-static-lora",
    "analysis_dynamic": "qwen3-coder-next-analysis-dynamic-lora",
    "exploit": "qwen3-coder-next-exploit-coder-lora",
    "repair": "qwen3-coder-next-exploit-repair-lora",
}


def regexes(patterns):
    return [re.compile(pattern, re.I | re.M) for pattern in patterns or []]


STRONG_SUCCESS_PATTERNS = regexes(RUNTIME.get("strongSuccessRegex"))
FLAG_PATTERNS = regexes([RUNTIME.get("flagRegex")])
WEAK_SUCCESS_PATTERNS = regexes(RUNTIME.get("weakSuccessRegex"))
UNSTABLE_PATTERNS = regexes(RUNTIME.get("unstableRegex"))
DISALLOWED_PAYLOAD_PATTERNS = regexes(PAYLOAD.get("disallowedRegex"))
WRAPPER_BOILERPLATE_PATTERNS = regexes(
    PAYLOAD.get("wrapperBoilerplateRegex") or PAYLOAD.get("wrapperBoilerplatePatterns")
)


def matches_any_regex(value, patterns):
    text = str(value or "")
    return any(pattern.search(text) for pattern in patterns)


def payload_uses_disallowed_runtime_introspection(source):
    text = str(source or "")
    return any(str(item or "") in text for item in PAYLOAD.get("disallowedPatterns", [])) or matches_any_regex(
        text, DISALLOWED_PAYLOAD_PATTERNS
    )


def payload_uses_wrapper_boilerplate(source):
    text = str(source or "")
    sleep_limit = int(PAYLOAD.get("maxTimeSleepCalls", 1) or 1)
    return (
        any(str(item or "") in text for item in PAYLOAD.get("wrapperBoilerplatePatterns", []))
        or matches_any_regex(text, WRAPPER_BOILERPLATE_PATTERNS)
        or len(re.findall(r"\btime\.sleep\s*\(", text)) > sleep_limit
        or payload_defines_uncalled_exploit_entrypoint(text)
    )


def payload_defines_uncalled_exploit_entrypoint(source):
    text = str(source or "")
    if not re.search(r"(?m)^\s*def\s+exploit\s*\(", text):
        return False
    without_definition = re.sub(r"(?m)^\s*def\s+exploit\s*\([^\n]*\):\s*$", "", text)
    return re.search(r"(?m)^\s*exploit\s*\(", without_definition) is None


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def sha256_text(value):
    return hashlib.sha256(str(value or "").encode("utf-8", errors="ignore")).hexdigest()


def short_text(value, limit=500):
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "\n...<truncated>"


def payload_change_summary(before, after, limit=1600):
    if not before or not after:
        return ""
    diff = "\n".join(unified_diff(
        str(before).splitlines(),
        str(after).splitlines(),
        fromfile="before_payload",
        tofile="after_payload",
        lineterm="",
        n=2,
    ))
    return short_text(diff, limit)


def load_events(trace_path):
    with open(trace_path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def nested_get(value, *keys):
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def parse_json_text(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def codex_item(event):
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    if isinstance(data.get("item"), dict):
        return data["item"]
    parsed = parse_json_text(event.get("text", ""))
    if isinstance(parsed, dict) and isinstance(parsed.get("item"), dict):
        return parsed["item"]
    return {}


def structured_result(item):
    result = item.get("result")
    if not isinstance(result, dict):
        return {}
    for key in ("structuredContent", "structured_content"):
        if isinstance(result.get(key), dict):
            return result[key]
    content = result.get("content")
    if isinstance(content, list):
        for part in content:
            text = part.get("text") if isinstance(part, dict) else ""
            parsed = parse_json_text(text)
            if isinstance(parsed, dict):
                return parsed
    return result


def phase_from(event, default="unknown"):
    phase = event.get("phase") or nested_get(event, "data", "phaseMeta", "phase") or default
    return LEGACY_PHASES.get(phase, phase)


def agent_head(event, phase):
    explicit = event.get("phaseAgentHead") or nested_get(event, "data", "phaseMeta", "contract", "agentHead")
    if explicit:
        return explicit
    if phase == "analysis_static":
        return "analysis.static"
    if phase == "analysis_dynamic":
        return "analysis.dynamic"
    if phase == "repair":
        return "exploit.repair"
    if phase == "exploit":
        return "exploit.coder"
    return "unknown"


def phase_contract(phase):
    return PHASE_CONTRACTS.get(phase, {})


def phase_artifact_schema(phase):
    return str(phase_contract(phase).get("artifactSchema") or "")


def phase_head_type(phase):
    return str(phase_contract(phase).get("agentHead") or PHASE_HEADS.get(phase) or "unknown")


def phase_task_role(phase):
    return PHASE_TASK_ROLES.get(phase, "unknown")


def phase_adapter_name(phase):
    return PHASE_ADAPTERS.get(phase, "unknown")


def phase_training_file(phase):
    return PHASE_TRAINING_FILES.get(phase, "")


def ghidra_command(arguments):
    return str(arguments.get("cmd") or "").strip() if isinstance(arguments, dict) else ""


def is_hex_address(value):
    return bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", str(value or "").strip()))


def tool_argument_issue(tool, arguments):
    args = arguments if isinstance(arguments, dict) else {}
    if tool in ("search_str", "search_func", "search_bytes") and not str(args.get("pattern") or "").strip():
        return f"empty_search_pattern:{tool}"
    if tool in ("func_by_addr", "decompile_by_addr", "mem_hex", "mem_dec", "mem_str", "mem_asm", "search_xrefs_to", "search_xrefs_from"):
        if not str(args.get("addr") or "").strip():
            return f"missing_address:{tool}"
        if not is_hex_address(args.get("addr")):
            return f"invalid_address:{tool}"
    if tool == "disassemble_function":
        if not str(args.get("start_address") or "").strip():
            return "missing_address:disassemble_function"
        if not is_hex_address(args.get("start_address")):
            return "invalid_address:disassemble_function"
    if tool == "ghidra_call":
        command = ghidra_command(args)
        nested = args.get("args") if isinstance(args.get("args"), dict) else args
        if command in ("search.str", "search.func", "search.bytes") and not str(nested.get("pattern") or "").strip():
            return f"empty_search_pattern:{command}"
    return ""


def hex_read_size(tool, arguments):
    if not isinstance(arguments, dict):
        return 0
    def size(value):
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return 0
        return parsed if parsed > 0 else 0
    if tool == "mem_hex":
        return size(arguments.get("size", 8) or 8)
    if tool == "ghidra_call" and ghidra_command(arguments) == "mem.hex":
        nested = arguments.get("args") if isinstance(arguments.get("args"), dict) else arguments
        return size(nested.get("size", 8) or 8)
    return 0


def tool_policy_issue(phase, tool, arguments, usage):
    contract = phase_contract(phase)
    if not contract:
        return "unknown_phase_contract"
    if tool not in contract.get("allowedTools", []):
        return f"tool_not_allowed:{tool}"
    argument_issue = tool_argument_issue(tool, arguments)
    if argument_issue:
        return argument_issue
    if tool == "ghidra_call" and ghidra_command(arguments) not in contract.get("allowedGhidraCommands", []):
        return f"ghidra_command_not_allowed:{ghidra_command(arguments) or 'missing'}"

    return ""


def action_outcome(logs, status=None):
    text = str(logs or "")
    weak = matches_any_regex(text, WEAK_SUCCESS_PATTERNS)
    unstable = matches_any_regex(text, UNSTABLE_PATTERNS)
    strong = matches_any_regex(text, STRONG_SUCCESS_PATTERNS) and not unstable
    if strong or status is True or str(status).lower() == "success":
        return {
            "outcome": "verified_success",
            "strong_success": True,
            "weak_success_marker": weak,
            "unstable_success": False,
        }
    if weak:
        return {
            "outcome": "weak_unverified_marker",
            "strong_success": False,
            "weak_success_marker": True,
            "unstable_success": unstable,
        }
    return {
        "outcome": "failure",
        "strong_success": False,
        "weak_success_marker": False,
        "unstable_success": unstable,
    }


def runtime_outcome(tool, logs, status=None):
    outcome = action_outcome(logs, status)
    if tool == "pwn_payload_execute" and outcome["strong_success"] and not matches_any_regex(logs, FLAG_PATTERNS):
        return {
            "outcome": "failure",
            "strong_success": False,
            "weak_success_marker": outcome["weak_success_marker"],
            "unstable_success": outcome["unstable_success"],
        }
    return outcome


def output_text_from_result(result):
    if not isinstance(result, dict):
        return str(result or "")
    chunks = []
    for key in ("stdout", "stderr", "logs", "output", "message", "error"):
        if result.get(key):
            chunks.append(str(result[key]))
    responses = result.get("responses")
    if isinstance(responses, list):
        chunks.extend(str(item.get("payload") or item) for item in responses)
    return "\n".join(chunks)


def trim_post_success_phases(events):
    current_phase = "unknown"
    current_attempt = 1
    success_key = None
    for index, event in enumerate(events):
        if event.get("type") in ("codex_prompt", "phase_start"):
            current_phase = phase_from(event, current_phase)
            current_attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
        phase = phase_from(event, current_phase)
        attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
        key = (phase, attempt)
        if success_key and event.get("type") in ("codex_prompt", "phase_start") and key != success_key:
            return events[:index], len(events) - index

        item = codex_item(event)
        tool = item.get("tool")
        is_runtime_result = item.get("type") == "mcp_tool_call" and tool in ("pwn_payload_execute", "pwn_session_poll")
        is_dashboard_verify = event.get("type") == "exploit_verification"
        if not is_runtime_result and not is_dashboard_verify:
            continue
        result = event.get("data", {}) if is_dashboard_verify else structured_result(item)
        logs = output_text_from_result(result)
        status = nested_get(event, "data", "success") if is_dashboard_verify else None
        if runtime_outcome(tool, logs, status)["strong_success"]:
            success_key = key
    return events, 0


def compact_prompt(text):
    text = str(text or "")
    if "# User Task" in text:
        text = "# User Task" + text.split("# User Task", 1)[1]
    text = re.sub(r"# MCP Servers\n.*?\n\n# Constraints", "# MCP Servers\n[MCP servers omitted]\n\n# Constraints", text, flags=re.S)
    return text.strip()


def redact_value(value):
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    for pattern in FLAG_PATTERNS:
        text = pattern.sub("<FLAG>", text)
    text = re.sub(r"\b(uid|gid)=\d+\([^)]+\)", lambda match: match.group(0).split("(", 1)[0] + "(<IDENTITY>)", text)
    text = re.sub(r"(?:[A-Za-z]:[\\/]|/mnt/|/home/|/Users/)[^\s'\"`]+", "<HOST_PATH>", text)
    text = re.sub(r"\b\d{14}-[0-9a-f]{6}\b", "<RUN_ID>", text, flags=re.I)
    return text


def prompt_messages(text):
    raw = str(text or "")
    system = "You are a professional pwnable solver. Use evidence, write minimal exploits, and verify shell or flag output."
    if raw.startswith("# System Instructions") and "# User Task" in raw:
        system = raw.split("# System Instructions", 1)[1].split("# User Task", 1)[0].strip()
    return system, compact_prompt(raw)


def clean_assistant_text(value):
    text = re.sub(r"<think>.*?</think>\s*", "", str(value or ""), flags=re.S | re.I)
    return redact_value(text).strip()


def compact_tool_result(value, limit):
    text = json.dumps(redact_value(value), ensure_ascii=False, separators=(",", ":"))
    if len(text) <= limit:
        return text
    head = int(limit * 0.6)
    tail = limit - head
    return text[:head] + "\n<TRUNCATED_TOOL_RESULT>\n" + text[-tail:]


def has_text_corruption(value):
    text = str(value or "")
    return "\ufffd" in text or any(marker in text for marker in ("ì›", "í•", "ë¬", "?먮"))


def has_hangul(value):
    return any("\uac00" <= char <= "\ud7a3" for char in str(value or ""))


def schema_for_value(value):
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, list):
        return {"type": "array", "items": schema_for_value(value[0]) if value else {}}
    if isinstance(value, dict):
        return {
            "type": "object",
            "properties": {key: schema_for_value(item) for key, item in value.items()},
            "additionalProperties": True,
        }
    return {"type": "string"}


def collect_tool_catalog(events):
    catalog = {}
    observed = defaultdict(list)
    for event in events:
        if event.get("type") == "mcp_tools_list":
            for tool in nested_get(event, "data", "tools") or []:
                if isinstance(tool, dict) and tool.get("name"):
                    catalog[tool["name"]] = {
                        "type": "function",
                        "function": {
                            "name": tool["name"],
                            "description": tool.get("description") or f"MCP tool {tool['name']}",
                            "parameters": tool.get("inputSchema") or {"type": "object", "properties": {}},
                        },
                    }
        item = codex_item(event)
        if item.get("type") == "mcp_tool_call" and item.get("tool"):
            observed[item["tool"]].append(item.get("arguments") if isinstance(item.get("arguments"), dict) else {})

    for name, calls in observed.items():
        if name in catalog:
            continue
        properties = {}
        required = set(calls[0]) if calls else set()
        for arguments in calls:
            required &= set(arguments)
            for key, value in arguments.items():
                properties.setdefault(key, schema_for_value(value))
        catalog[name] = {
            "type": "function",
            "function": {
                "name": name,
                "description": f"PwnAutomator MCP tool {name}",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": sorted(required),
                    "additionalProperties": True,
                },
            },
        }
    return catalog


def group_phase_events(events):
    groups = {}
    current_phase = "unknown"
    current_attempt = 1
    for event in events:
        if event.get("type") == "codex_prompt":
            current_phase = phase_from(event, current_phase)
            current_attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
        phase = phase_from(event, current_phase)
        attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
        if phase == "unknown":
            continue
        group = groups.setdefault((phase, attempt), {"phase": phase, "attempt": attempt, "prompt": "", "phase_meta": {}, "events": []})
        if event.get("type") == "codex_prompt":
            group["prompt"] = event.get("text", "")
            group["phase_meta"] = nested_get(event, "data", "phaseMeta") or {}
        group["events"].append(event)
    return list(groups.values())


def phase_evidence(group):
    validation_success = False
    best = None
    for event in group["events"]:
        if event.get("type") == "phase_validation" and str(nested_get(event, "data", "status")).lower() == "success":
            validation_success = True
        item = codex_item(event)
        if item.get("type") == "mcp_tool_call" and item.get("tool") in ("pwn_payload_execute", "pwn_session_poll"):
            logs = output_text_from_result(structured_result(item))
            outcome = runtime_outcome(item.get("tool"), logs)
            if outcome["strong_success"]:
                best = "flag" if matches_any_regex(logs, FLAG_PATTERNS) else "command"
        if event.get("type") == "exploit_verification" and nested_get(event, "data", "success") is True:
            best = nested_get(event, "data", "evidence") or best or "command"
    if group["phase"] in ("analysis_static", "analysis_dynamic", "analysis_dynamic_poc"):
        return "schema" if validation_success else None
    return best


def verifier_terminal_summary(evidence, group, payload):
    verified = "hidden flag output" if evidence == "flag" else "live command execution"
    meta = group.get("phase_meta") or {}
    static = meta.get("staticAnalysis") or {}
    targets = static.get("targets") or meta.get("selectedTargets") or []
    target = targets[0] if isinstance(targets, list) and targets else {}
    dynamic = meta.get("dynamicAnalysis") or {}
    observations = dynamic.get("observations") or nested_get(dynamic, "runtime_facts", "observations") or []
    observation = observations[0] if isinstance(observations, list) and observations else {}
    lines = [
        "Evidence Summary:",
        f"- Vulnerability: {target.get('reason') or 'validated target evidence recorded in the phase artifact.'}",
        f"- Dynamic fact: {observation.get('evidence') or 'runtime facts were consumed before payload construction.'}",
        f"- Payload strategy: pwn_payload_write produced the verified candidate ({sha256_text(payload)[:12]}).",
        f"- MCP verifier confirmed {verified}.",
        "- The shell objective has been achieved; no further tool calls are required.",
    ]
    return "\n".join(lines)


def qwen_episode(group, catalog, run_id, execution_id):
    evidence = phase_evidence(group)
    if not evidence or not group["prompt"]:
        return None, "unverified_phase"

    system, user = prompt_messages(group["prompt"])
    if has_text_corruption(system) or has_text_corruption(user):
        return None, "text_encoding_corruption"

    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    pending_text = []
    pending_calls = {}
    used_tools = set()
    payload = ""
    tool_calls = 0
    failed_calls = 0
    usage = {"calls": 0, "payload_writes": 0, "payload_executes": 0, "hex_reads": 0}
    head = agent_head({"phaseAgentHead": nested_get(group, "phase_meta", "contract", "agentHead")}, group["phase"])
    if CURATION.get("requireAgentHead", False) and head == "unknown":
        return None, "missing_agent_head"
    expected_head = phase_contract(group["phase"]).get("agentHead")
    if expected_head and head != expected_head:
        return None, "agent_head_mismatch"
    head_type = phase_head_type(group["phase"])
    task_role = phase_task_role(group["phase"])
    adapter_name = phase_adapter_name(group["phase"])

    for event in group["events"]:
        item = codex_item(event)
        if item.get("type") == "agent_message" and item.get("text"):
            text = clean_assistant_text(item["text"])
            if has_text_corruption(text):
                return None, "text_encoding_corruption"
            if CURATION.get("requireEnglishAssistant", False) and has_hangul(text):
                return None, "english_language_violation"
            if text:
                pending_text.append(text)
            continue
        if item.get("type") != "mcp_tool_call" or not item.get("tool"):
            continue

        call_key = item.get("id") or (item.get("server"), item.get("tool"))
        if item.get("status") == "in_progress":
            pending_calls[call_key] = item
            continue
        if item.get("status") != "completed":
            continue

        started = pending_calls.pop(call_key, {})
        arguments = item.get("arguments") or started.get("arguments") or {}
        if not isinstance(arguments, dict):
            return None, "non_object_tool_arguments"
        if item["tool"] == "pwn_payload_write" and arguments.get("payload_content"):
            payload = str(arguments["payload_content"])
            if (
                payload_uses_disallowed_runtime_introspection(payload)
                or payload_uses_wrapper_boilerplate(payload)
                or matches_any_regex(payload, FLAG_PATTERNS)
            ):
                return None, "unsafe_or_hardcoded_payload"

        usage["calls"] += 1
        if item["tool"] == "pwn_payload_write":
            usage["payload_writes"] += 1
        if item["tool"] == "pwn_payload_execute":
            usage["payload_executes"] += 1
        if hex_read_size(item["tool"], arguments):
            usage["hex_reads"] += 1
        policy_issue = tool_policy_issue(group["phase"], item["tool"], arguments, usage)
        if policy_issue:
            return None, policy_issue

        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        structured = structured_result(item)
        status = str(structured.get("status") or structured.get("success") or "").lower()
        if item.get("error") or status in ("error", "failure", "failed", "false"):
            failed_calls += 1

        call_id = str(item.get("id") or f"call_{tool_calls + 1}")
        messages.append({
            "role": "assistant",
            "content": "\n\n".join(pending_text),
            "tool_calls": [{
                "id": call_id,
                "type": "function",
                "function": {"name": item["tool"], "arguments": redact_value(arguments)},
            }],
        })
        limit = int(CURATION.get("qwenMaxToolResultChars", 12000) or 12000)
        result_text = compact_tool_result(structured or result, limit)
        messages.append({"role": "tool", "tool_call_id": call_id, "name": item["tool"], "content": result_text})
        pending_text = []
        used_tools.add(item["tool"])
        tool_calls += 1

    final_text = "\n\n".join(pending_text).strip()
    terminal_summary_source = "agent" if final_text else ""
    if not final_text and evidence in ("command", "flag"):
        final_text = verifier_terminal_summary(evidence, group, payload)
        terminal_summary_source = "verifier"
    if final_text:
        messages.append({"role": "assistant", "content": final_text})

    limits = {
        "min_calls": int(CURATION.get("qwenMinToolCalls", 1) or 1),
        "max_failed": int(CURATION.get("qwenMaxFailedToolCalls", 8) or 8),
        "max_chars": int(CURATION.get("qwenMaxEpisodeChars", 600000) or 600000),
        "min_final": int(CURATION.get("qwenMinFinalAssistantChars", 80) or 80),
    }
    if tool_calls < limits["min_calls"]:
        return None, "tool_call_count_out_of_range"
    if failed_calls > limits["max_failed"]:
        return None, "too_many_failed_tool_calls"
    if not messages or messages[-1].get("role") != "assistant" or len(messages[-1].get("content", "")) < limits["min_final"]:
        return None, "missing_final_assistant_summary"
    if group["phase"] in ("exploit", "repair") and "Evidence Summary" not in messages[-1]["content"]:
        return None, "missing_evidence_summary"
    if group["phase"] in ("analysis_static", "analysis_dynamic", "analysis_dynamic_poc") and CURATION.get("requireStructuredArtifacts", False):
        artifact = parse_json_text(messages[-1].get("content", ""))
        if not isinstance(artifact, dict):
            return None, "missing_structured_artifact"
        required_key = "targets" if group["phase"] == "analysis_static" else "runtime_facts"
        if required_key not in artifact:
            return None, "invalid_structured_artifact"
        if group["phase"] == "analysis_static" and not artifact.get("targets"):
            return None, "empty_static_targets"
        if group["phase"] in ("analysis_dynamic", "analysis_dynamic_poc"):
            observations = nested_get(artifact, "runtime_facts", "observations")
            selected = {
                str(target.get("function_name") or "")
                for target in nested_get(group, "phase_meta", "staticAnalysis", "targets") or []
                if isinstance(target, dict)
            }
            if not isinstance(observations, list) or not observations:
                return None, "missing_dynamic_observations"
            if selected and any(str(item.get("target") or "") not in selected for item in observations if isinstance(item, dict)):
                return None, "dynamic_observation_unknown_target"
    if len(json.dumps(messages, ensure_ascii=False)) > limits["max_chars"]:
        return None, "episode_too_large"

    tools = [catalog[name] for name in sorted(used_tools) if name in catalog]
    if len(tools) != len(used_tools):
        return None, "missing_tool_schema"
    sample_id = sha256_text(f"{run_id}:{execution_id}:{group['phase']}:{group['attempt']}:{json.dumps(messages, ensure_ascii=False)}")[:24]
    return {
        "schema": "pwnautomator.qwen3_coder_next.sft.v1",
        "sample_id": sample_id,
        "model_family": "Qwen3-Coder-Next",
        "head_type": head_type,
        "task_role": task_role,
        "adapter_name": adapter_name,
        "messages": messages,
        "tools": tools,
        "training": {
            "loss_on_roles": ["assistant"],
            "train_tool_calls": True,
            "train_tool_results": False,
            "head_type": head_type,
            "adapter_name": adapter_name,
        },
        "metadata": {
            "run_id": run_id,
            "execution_id": execution_id,
            "phase": group["phase"],
            "attempt": group["attempt"],
            "agent_head": head,
            "head_type": head_type,
            "task_role": task_role,
            "adapter_name": adapter_name,
            "training_file": phase_training_file(group["phase"]),
            "artifact_schema": phase_artifact_schema(group["phase"]),
            "verified": True,
            "evidence_grade": evidence,
            "tool_call_count": tool_calls,
            "failed_tool_call_count": failed_calls,
            "payload_write_count": usage["payload_writes"],
            "payload_execute_count": usage["payload_executes"],
            "payload_sha256": sha256_text(payload) if payload else "",
            "terminal_summary_source": terminal_summary_source,
            "thinking_mode": False,
            "chat_template": "tokenizer.apply_chat_template(messages, tools=tools)",
            "hint_source": nested_get(group, "phase_meta", "hint", "source") or "",
            "hint_level": int(nested_get(group, "phase_meta", "hint", "level") or 0),
        },
    }, None


def episode_tool_pairs(episode):
    messages = episode.get("messages") or []
    pairs = []
    for index, message in enumerate(messages[:-1]):
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        tool_message = messages[index + 1] if index + 1 < len(messages) else {}
        if message.get("role") != "assistant" or not calls or tool_message.get("role") != "tool":
            continue
        call = calls[0]
        function = call.get("function") if isinstance(call, dict) else {}
        if not isinstance(function, dict) or not function.get("name"):
            continue
        content = tool_message.get("content") or ""
        pairs.append({
            "index": index,
            "call_id": call.get("id") or f"distilled_{len(pairs) + 1}",
            "name": function["name"],
            "arguments": function.get("arguments") if isinstance(function.get("arguments"), dict) else {},
            "result": parse_json_text(content) or {},
            "tool_content": content,
        })
    return pairs


def pair_session_id(pair):
    return str(pair.get("arguments", {}).get("session_id") or pair.get("result", {}).get("session_id") or "")


def pair_has_command_evidence(pair):
    text = pair.get("tool_content") or ""
    return "uid=" in text or "gid=" in text or "<IDENTITY>" in text or matches_any_regex(text, FLAG_PATTERNS)


def clone_tool_message(pair, call_id):
    return {"role": "tool", "tool_call_id": call_id, "name": pair["name"], "content": pair["tool_content"]}


def tool_call_message(call_id, tool, arguments, content):
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": tool, "arguments": redact_value(arguments)},
        }],
    }


def verified_tool_chain(episode):
    pairs = episode_tool_pairs(episode)
    poll = next((pair for pair in reversed(pairs) if pair["name"] == "pwn_session_poll" and pair_has_command_evidence(pair)), None)
    if not poll:
        return None, "missing_verified_poll"
    session_id = pair_session_id(poll)
    send = next((pair for pair in reversed(pairs[:pairs.index(poll)]) if pair["name"] == "pwn_session_send" and pair_session_id(pair) == session_id), None)
    execute = next((pair for pair in reversed(pairs[:pairs.index(poll)]) if pair["name"] == "pwn_payload_execute" and pair_session_id(pair) == session_id), None)
    if not execute:
        return None, "missing_verified_execute"
    write = next((pair for pair in reversed(pairs[:pairs.index(execute)]) if pair["name"] == "pwn_payload_write"), None)
    payload = str((write or {}).get("arguments", {}).get("payload_content") or "")
    if not payload:
        return None, "missing_verified_payload"
    if payload_uses_disallowed_runtime_introspection(payload) or payload_uses_wrapper_boilerplate(payload) or matches_any_regex(payload, FLAG_PATTERNS):
        return None, "unsafe_or_hardcoded_payload"
    return {"write": write, "execute": execute, "send": send, "poll": poll, "payload": payload}, None


def json_prompt_section(title, value):
    if not value:
        return ""
    return "\n".join([f"## {title}", "```json", json.dumps(value, ensure_ascii=False, indent=2), "```"])


def clean_exploit_prompt_from_group(group):
    meta = group.get("phase_meta") or {}
    static = meta.get("staticAnalysis")
    dynamic = meta.get("dynamicAnalysis")
    if not static and not dynamic:
        return ""
    sections = [
        "# User Task",
        "Solve the pwnable challenge from the validated analysis artifacts. Write the minimal exploit and verify shell or flag output.",
        "",
        "# Phase Context",
        "- Phase: exploit",
        "- Attempt: 1",
        "- Objective: Convert validated findings into a working exploit that obtains shell or flag access.",
        "- Goal: obtain_shell",
        "- Requires shell: yes",
        "",
        json_prompt_section("Static Analysis Artifact", static),
        "",
        json_prompt_section("Dynamic Analysis Artifact", dynamic),
    ]
    return "\n".join(section for section in sections if section).strip()


def distill_exploit_from_repair(repair_episode, exploit_group, catalog, run_id, execution_id, repair_group=None):
    chain, reason = verified_tool_chain(repair_episode)
    if not chain:
        return None, reason
    payload = chain["payload"]
    source_hint = repair_episode.get("metadata", {}).get("hint_source", "")
    clean_prompt = clean_exploit_prompt_from_group(repair_group or {}) if source_hint else ""
    prompt = clean_prompt or (exploit_group.get("prompt") if exploit_group else "")
    system, user = prompt_messages(prompt)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    selected = [
        (chain["write"], "distilled_write", "I will use the validated primitive directly, write the final payload, and avoid repeating failed probes."),
        (chain["execute"], "distilled_execute", "The payload is written. I will execute it once and keep the live session returned by the wrapper."),
    ]
    if chain["send"]:
        selected.append((chain["send"], "distilled_send", "The payload returned a live session. I will send `id` for command verification."))
    selected.append((chain["poll"], "distilled_poll", "I will poll the session and require uid/gid command evidence before declaring success."))
    for pair, call_id, content in selected:
        messages.append(tool_call_message(call_id, pair["name"], pair["arguments"], content))
        messages.append(clone_tool_message(pair, call_id))

    evidence = repair_episode.get("metadata", {}).get("evidence_grade") or "command"
    final_text = verifier_terminal_summary(evidence, exploit_group or {"phase_meta": {}}, payload)
    messages.append({"role": "assistant", "content": final_text})

    used_tools = {pair["name"] for pair, _, _ in selected}
    tools = [catalog[name] for name in sorted(used_tools) if name in catalog]
    if len(tools) != len(used_tools):
        return None, "missing_tool_schema"
    sample_id = sha256_text(f"{run_id}:{execution_id}:exploit:distilled:{repair_episode['sample_id']}:{json.dumps(messages, ensure_ascii=False)}")[:24]
    return {
        "schema": "pwnautomator.qwen3_coder_next.sft.v1",
        "sample_id": sample_id,
        "model_family": "Qwen3-Coder-Next",
        "head_type": phase_head_type("exploit"),
        "task_role": phase_task_role("exploit"),
        "adapter_name": phase_adapter_name("exploit"),
        "messages": messages,
        "tools": tools,
        "training": {
            "loss_on_roles": ["assistant"],
            "train_tool_calls": True,
            "train_tool_results": False,
            "head_type": phase_head_type("exploit"),
            "adapter_name": phase_adapter_name("exploit"),
        },
        "metadata": {
            "run_id": run_id,
            "execution_id": execution_id,
            "phase": "exploit",
            "attempt": 1,
            "agent_head": phase_head_type("exploit"),
            "head_type": phase_head_type("exploit"),
            "task_role": phase_task_role("exploit"),
            "adapter_name": phase_adapter_name("exploit"),
            "training_file": phase_training_file("exploit"),
            "artifact_schema": phase_artifact_schema("exploit"),
            "verified": True,
            "evidence_grade": evidence,
            "tool_call_count": len(selected),
            "failed_tool_call_count": 0,
            "payload_write_count": 1,
            "payload_execute_count": 1,
            "payload_sha256": sha256_text(payload),
            "terminal_summary_source": "distilled_verified_repair",
            "thinking_mode": False,
            "chat_template": "tokenizer.apply_chat_template(messages, tools=tools)",
            "distilled_from_phase": "repair",
            "distilled_from_hint_source": source_hint,
            "source_sample_id": repair_episode["sample_id"],
            "hint_source": "",
            "hint_level": 0,
        },
    }, None


def distill_repair_from_repair(repair_episode, repair_group, catalog, run_id, execution_id):
    chain, reason = verified_tool_chain(repair_episode)
    if not chain:
        return None, reason
    payload = chain["payload"]
    system, user = prompt_messages(repair_group.get("prompt") or "")
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    selected = [
        (chain["write"], "distilled_repair_write", "I will replace the failed candidate with the verified corrected payload."),
        (chain["execute"], "distilled_repair_execute", "The corrected payload is written. I will execute it and preserve the live session for verification."),
    ]
    if chain["send"]:
        selected.append((chain["send"], "distilled_repair_send", "The corrected payload produced a live session. I will send `id` to verify command execution."))
    selected.append((chain["poll"], "distilled_repair_poll", "I will poll for uid/gid output and only then mark the repair successful."))
    for pair, call_id, content in selected:
        messages.append(tool_call_message(call_id, pair["name"], pair["arguments"], content))
        messages.append(clone_tool_message(pair, call_id))

    previous_failure = nested_get(repair_group, "phase_meta", "previousFailure") or {}
    summary = verifier_terminal_summary(repair_episode.get("metadata", {}).get("evidence_grade") or "command", repair_group, payload)
    messages.append({"role": "assistant", "content": "\n".join([
        "Repair Transition Label:",
        "- Label: changed_and_verified",
        "- Payload changed: true",
        f"- After payload sha256: {sha256_text(payload)}",
        f"- Previous failure: {json.dumps(previous_failure, ensure_ascii=False)}",
        "",
        summary,
    ])})

    used_tools = {pair["name"] for pair, _, _ in selected}
    tools = [catalog[name] for name in sorted(used_tools) if name in catalog]
    if len(tools) != len(used_tools):
        return None, "missing_tool_schema"
    sample_id = sha256_text(f"{run_id}:{execution_id}:repair:distilled:{repair_episode['sample_id']}:{json.dumps(messages, ensure_ascii=False)}")[:24]
    return {
        "schema": "pwnautomator.qwen3_coder_next.sft.v1",
        "sample_id": sample_id,
        "model_family": "Qwen3-Coder-Next",
        "head_type": phase_head_type("repair"),
        "task_role": phase_task_role("repair"),
        "adapter_name": phase_adapter_name("repair"),
        "messages": messages,
        "tools": tools,
        "training": {
            "loss_on_roles": ["assistant"],
            "train_tool_calls": True,
            "train_tool_results": False,
            "head_type": phase_head_type("repair"),
            "adapter_name": phase_adapter_name("repair"),
        },
        "metadata": {
            "run_id": run_id,
            "execution_id": execution_id,
            "phase": "repair",
            "attempt": repair_episode["metadata"].get("attempt") or 1,
            "agent_head": phase_head_type("repair"),
            "head_type": phase_head_type("repair"),
            "task_role": phase_task_role("repair"),
            "adapter_name": phase_adapter_name("repair"),
            "training_file": phase_training_file("repair"),
            "artifact_schema": phase_artifact_schema("repair"),
            "verified": True,
            "evidence_grade": repair_episode["metadata"].get("evidence_grade") or "command",
            "tool_call_count": len(selected),
            "failed_tool_call_count": 0,
            "payload_write_count": 1,
            "payload_execute_count": 1,
            "payload_sha256": sha256_text(payload),
            "terminal_summary_source": "distilled_verified_repair",
            "thinking_mode": False,
            "chat_template": "tokenizer.apply_chat_template(messages, tools=tools)",
            "distilled_from_phase": "repair",
            "source_sample_id": repair_episode["sample_id"],
            "hint_source": repair_episode["metadata"].get("hint_source", ""),
            "hint_level": repair_episode["metadata"].get("hint_level", 0),
            "repair_transition": {
                "label": "changed_and_verified",
                "payload_changed": True,
                "after_payload_sha256": sha256_text(payload),
                "previous_failure": previous_failure,
            },
        },
    }, None


POC_REFERENCE_PATTERN = re.compile(r"\b(reference (exploit|poc)|the poc|provided (exploit|poc|reference))\b", re.I)


def distill_dynamic_from_poc_verification(poc_episode, dynamic_group, run_id, execution_id):
    if not dynamic_group or not dynamic_group.get("prompt"):
        return None, "missing_blind_dynamic_prompt"
    tail = poc_episode["messages"][2:]
    if POC_REFERENCE_PATTERN.search("\n".join(m.get("content") or "" for m in tail if m.get("role") == "assistant")):
        return None, "poc_reference_leak"
    system, user = prompt_messages(dynamic_group["prompt"])
    if has_text_corruption(system) or has_text_corruption(user):
        return None, "text_encoding_corruption"

    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}] + tail
    metadata = dict(poc_episode["metadata"])
    metadata.update({
        "phase": "analysis_dynamic",
        "attempt": int(dynamic_group.get("attempt") or 1),
        "agent_head": phase_head_type("analysis_dynamic"),
        "head_type": phase_head_type("analysis_dynamic"),
        "task_role": phase_task_role("analysis_dynamic"),
        "adapter_name": phase_adapter_name("analysis_dynamic"),
        "training_file": phase_training_file("analysis_dynamic"),
        "artifact_schema": phase_artifact_schema("analysis_dynamic"),
        "terminal_summary_source": "distilled_verified_poc",
        "distilled_from_phase": "analysis_dynamic_poc",
        "source_sample_id": poc_episode["sample_id"],
    })
    sample_id = sha256_text(f"{run_id}:{execution_id}:analysis_dynamic:distilled:{poc_episode['sample_id']}:{json.dumps(messages, ensure_ascii=False)}")[:24]
    return {
        "schema": "pwnautomator.qwen3_coder_next.sft.v1",
        "sample_id": sample_id,
        "model_family": "Qwen3-Coder-Next",
        "head_type": phase_head_type("analysis_dynamic"),
        "task_role": phase_task_role("analysis_dynamic"),
        "adapter_name": phase_adapter_name("analysis_dynamic"),
        "messages": messages,
        "tools": poc_episode["tools"],
        "training": {
            "loss_on_roles": ["assistant"],
            "train_tool_calls": True,
            "train_tool_results": False,
            "head_type": phase_head_type("analysis_dynamic"),
            "adapter_name": phase_adapter_name("analysis_dynamic"),
        },
        "metadata": metadata,
    }, None


def qwen_datasets(events, run_id, execution_id):
    catalog = collect_tool_catalog(events)
    groups = group_phase_events(events)
    episodes = []
    rejected = Counter()
    for group in groups:
        episode, reason = qwen_episode(group, catalog, run_id, execution_id)
        if episode:
            episodes.append(episode)
        else:
            rejected[reason] += 1
    source_repair_episodes = [episode for episode in episodes if episode["metadata"]["phase"] == "repair"]
    repair_groups = {
        int(group.get("attempt") or 1): group
        for group in groups
        if group["phase"] == "repair" and group.get("prompt")
    }
    if source_repair_episodes:
        distilled = []
        for episode in episodes:
            if episode["metadata"]["phase"] != "repair":
                distilled.append(episode)
                continue
            repair_group = repair_groups.get(int(episode["metadata"].get("attempt") or 1), {})
            distilled_repair, reason = distill_repair_from_repair(episode, repair_group, catalog, run_id, execution_id)
            if distilled_repair:
                distilled.append(distilled_repair)
            else:
                rejected[f"distill_repair:{reason}"] += 1
                distilled.append(episode)
        episodes = distilled
    if not any(episode["metadata"]["phase"] == "exploit" for episode in episodes):
        exploit_group = next((group for group in groups if group["phase"] == "exploit" and group.get("prompt")), {})
        for repair_episode in source_repair_episodes:
            repair_group = repair_groups.get(int(repair_episode["metadata"].get("attempt") or 1), {})
            distilled, reason = distill_exploit_from_repair(
                repair_episode,
                exploit_group,
                catalog,
                run_id,
                execution_id,
                repair_group,
            )
            if distilled:
                episodes.append(distilled)
                break
            rejected[f"distill_exploit:{reason}"] += 1
    poc_episodes = [episode for episode in episodes if episode["metadata"]["phase"] == "analysis_dynamic_poc"]
    if poc_episodes:
        # A PoC rescue firing at all proves the blind analysis_dynamic episode
        # was insufficient, so only the clean distilled analysis_dynamic sample
        # may survive. The PoC-grounded raw episode is verification material,
        # not deployable SFT.
        dynamic_group = next((group for group in groups if group["phase"] == "analysis_dynamic" and group.get("prompt")), {})
        distilled_dynamic, reason = distill_dynamic_from_poc_verification(poc_episodes[0], dynamic_group, run_id, execution_id)
        episodes = [
            episode
            for episode in episodes
            if episode["metadata"]["phase"] not in ("analysis_dynamic", "analysis_dynamic_poc")
        ]
        if distilled_dynamic:
            episodes.append(distilled_dynamic)
        else:
            rejected[f"distill_dynamic:{reason}"] += 1
            rejected["analysis_dynamic_poc_excluded"] += len(poc_episodes)
    else:
        episodes = [episode for episode in episodes if episode["metadata"]["phase"] != "analysis_dynamic_poc"]
    order = {phase: index for index, phase in enumerate(CURATION.get("phaseExportOrder", []))}
    episodes.sort(key=lambda item: (order.get(item["metadata"]["phase"], 99), item["metadata"]["attempt"]))
    return episodes, rejected, catalog


def build_messages(prompt, assistant):
    return [
        {"role": "system", "content": "You are a professional pwnable solver. Use evidence, write minimal exploits, and verify shell or flag output."},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": assistant.strip()},
    ]


def row_quality(row):
    score = 0
    content = row.get("messages", [{}, {}, {"content": ""}])[-1].get("content", "")
    meta = row.get("metadata", {})
    outcome = meta.get("action_outcome", {})
    if outcome.get("strong_success"):
        score += 5
    if row.get("payload_sha256"):
        score += 2
    if len(content) >= 300:
        score += 2
    if "Evidence Summary" in content or "Verification" in content or "uid=" in content or "gid=" in content:
        score += 2
    if meta.get("payload_policy", {}).get("disallowed"):
        score -= 6
    if meta.get("payload_policy", {}).get("wrapper_boilerplate"):
        score -= 3
    if outcome.get("weak_success_marker") and not outcome.get("strong_success"):
        score -= 4
    return max(score, 0)


def summarize_rows(rows):
    return [row for row in rows if row.get("quality_score", 0) >= int(CURATION.get("primaryMinQualityScore", 7) or 7)]


def extract_records(events):
    prompts = {}
    current_prompt = ""
    current_phase = "unknown"
    current_attempt = 1
    current_previous_failure = None
    last_payload = {}
    payload_history = []
    last_failure = None
    records = []
    tool_failures = []
    top_tools = Counter()

    for event_index, event in enumerate(events):
        if event.get("type") == "codex_prompt":
            current_phase = phase_from(event, current_phase)
            current_attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
            current_previous_failure = nested_get(event, "data", "phaseMeta", "previousFailure")
        phase = phase_from(event, current_phase)
        attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
        key = (phase, attempt)

        if event.get("type") == "codex_prompt":
            current_prompt = compact_prompt(event.get("text", ""))
            prompts[key] = current_prompt
            continue

        item = codex_item(event)
        tool = item.get("tool")
        if tool:
            top_tools[tool] += 1

        if item.get("type") == "mcp_tool_call" and tool == "pwn_payload_write":
            payload = nested_get(item, "arguments", "payload_content")
            if payload:
                payload_text = str(payload)
                last_payload[key] = payload_text
                payload_history.append({
                    "key": key,
                    "phase": phase,
                    "attempt": attempt,
                    "payload": payload_text,
                })
            continue

        result = structured_result(item)
        is_payload_execute = item.get("type") == "mcp_tool_call" and tool == "pwn_payload_execute"
        is_session_poll = item.get("type") == "mcp_tool_call" and tool == "pwn_session_poll"
        is_dashboard_verify = event.get("type") == "exploit_verification"
        if not is_payload_execute and not is_session_poll and not is_dashboard_verify:
            continue

        logs = output_text_from_result(event.get("data", {})) if is_dashboard_verify else output_text_from_result(result)
        status = nested_get(event, "data", "success") if is_dashboard_verify else None
        outcome = action_outcome(logs, status) if is_dashboard_verify else runtime_outcome(tool, logs)
        tool_status = str(result.get("status") or result.get("success") or "").lower()
        if is_payload_execute and not outcome["strong_success"] and not item.get("error") and tool_status in ("ok", "success", "true"):
            continue
        payload = last_payload.get(key, "")
        payload_meta = {
            "disallowed": payload_uses_disallowed_runtime_introspection(payload),
            "wrapper_boilerplate": payload_uses_wrapper_boilerplate(payload),
        }
        head = agent_head(event, phase)
        previous_failure = nested_get(event, "data", "phaseMeta", "previousFailure") or current_previous_failure
        repair_transition = None
        if phase == "repair":
            before_payload = last_failure.get("payload", "") if last_failure else ""
            if not before_payload:
                for previous in reversed(payload_history):
                    if previous["key"] != key and previous.get("payload"):
                        before_payload = previous["payload"]
                        break
            repair_transition = {
                "label": "changed_and_verified" if before_payload and before_payload != payload and outcome["strong_success"] else "unchanged_or_unverified",
                "payload_changed": bool(before_payload and before_payload != payload),
                "before_payload_sha256": sha256_text(before_payload) if before_payload else "",
                "after_payload_sha256": sha256_text(payload),
                "previous_failure": previous_failure or (last_failure or {}).get("summary") or {},
                "before_payload_excerpt": short_text(before_payload),
                "after_payload_excerpt": short_text(payload),
                "change_summary": payload_change_summary(before_payload, payload),
            }

        assistant = "\n".join(
            part
            for part in [
                "\n".join([
                    "Repair Transition Label:",
                    f"- Label: {repair_transition['label']}",
                    f"- Payload changed: {str(repair_transition['payload_changed']).lower()}",
                    f"- Before payload sha256: {repair_transition['before_payload_sha256']}",
                    f"- After payload sha256: {repair_transition['after_payload_sha256']}",
                    f"- Previous failure: {json.dumps(repair_transition['previous_failure'], ensure_ascii=False)}",
                ]) if repair_transition else "",
                "Evidence Summary:",
                "Payload was written with pwn_payload_write.",
                f"Observed execution output:\n{logs[:3000]}",
                "Final exploit payload:\n```python\n" + payload.strip() + "\n```" if payload else "",
            ]
            if part
        )
        row = {
            "schema": "pwnautomator.train.v1",
            "run_id": event.get("runId"),
            "execution_id": event.get("executionId"),
            "phase": phase,
            "attempt": attempt,
            "agent_head": head,
            "messages": build_messages(prompts.get(key) or current_prompt, assistant),
            "payload_sha256": sha256_text(payload) if payload else "",
            "metadata": {
                "tool": "exploit_verification" if is_dashboard_verify else tool,
                "event_index": event_index,
                "payload_policy": payload_meta,
                "action_outcome": outcome,
                "weak_success_marker": outcome["weak_success_marker"],
                "repair_transition": repair_transition,
            },
        }
        row["quality_score"] = row_quality(row)

        if payload_meta["disallowed"] or payload_meta["wrapper_boilerplate"] or not outcome["strong_success"]:
            tool_failures.append(row)
        if outcome["strong_success"] and not payload_meta["disallowed"]:
            records.append(row)
        else:
            last_failure = {
                "payload": payload,
                "summary": {
                    "issue": "weak_or_failed_execution" if outcome["weak_success_marker"] else "execution_failed",
                    "description": logs[:500],
                },
            }

    return records, tool_failures, top_tools


def collect_agent_messages(events):
    rows = []
    prompt = ""
    current_phase = "unknown"
    current_attempt = 1
    for event in events:
        if event.get("type") == "codex_prompt":
            current_phase = phase_from(event, current_phase)
            current_attempt = int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt)
            prompt = compact_prompt(event.get("text", ""))
            continue
        phase = phase_from(event, current_phase)
        item = codex_item(event)
        if item.get("type") == "agent_message" and item.get("text"):
            rows.append({
                "schema": "pwnautomator.train.v1",
                "run_id": event.get("runId"),
                "execution_id": event.get("executionId"),
                "phase": phase,
                "attempt": int(event.get("phaseAttempt") or nested_get(event, "data", "phaseMeta", "attempt") or current_attempt),
                "agent_head": agent_head(event, phase),
                "messages": build_messages(prompt, item["text"]),
                "metadata": {"action_outcome": {"outcome": "analysis_step"}},
                "quality_score": 3,
            })
    return rows


def row_signature(row):
    if row.get("payload_sha256"):
        return f"payload:{row['payload_sha256']}"
    content = row.get("messages", [{}, {}, {"content": ""}])[-1].get("content", "")
    return f"{row.get('phase', 'unknown')}:{sha256_text(content)}"


def row_rank(row):
    content = row.get("messages", [{}, {}, {"content": ""}])[-1].get("content", "")
    outcome = row.get("metadata", {}).get("action_outcome", {})
    repair = row.get("metadata", {}).get("repair_transition") or {}
    return (
        1 if matches_any_regex(content, FLAG_PATTERNS) else 0,
        1 if repair.get("label") == "changed_and_verified" else 0,
        1 if outcome.get("strong_success") else 0,
        int(row.get("quality_score", 0) or 0),
        int(row.get("metadata", {}).get("event_index", 0) or 0),
    )


def dedupe_rows(rows):
    selected = {}
    for row in rows:
        signature = row_signature(row)
        if signature not in selected or row_rank(row) > row_rank(selected[signature]):
            selected[signature] = row
    return sorted(selected.values(), key=lambda row: (
        row.get("phase") not in ("analysis_static", "analysis_dynamic", "analysis_dynamic_poc"),
        row.get("phase") or "",
        row.get("attempt") or 0,
        row.get("metadata", {}).get("event_index", 0) or 0,
    ))


def trace_start_data(events):
    for event in events:
        if event.get("type") == "trace_start" and isinstance(event.get("data"), dict):
            return event["data"]
    return {}


def event_type_counts(events):
    return dict(Counter(event.get("type") or "unknown" for event in events))


def tool_catalog_manifest(catalog):
    tools = [catalog[name] for name in sorted(catalog)]
    return {
        "schema": "pwnautomator.tool_schema_catalog.v1",
        "toolCount": len(tools),
        "toolSchemaHash": sha256_text(json.dumps(tools, sort_keys=True, ensure_ascii=False)),
        "tools": tools,
    }


def adapter_routing_manifest(phase_rows_by_phase, hinted_excluded_by_phase=None):
    hinted_excluded_by_phase = hinted_excluded_by_phase or {}
    phases = {}
    for phase in PHASE_TRAINING_FILES:
        phase_rows = phase_rows_by_phase.get(phase, [])
        phases[phase] = {
            "head_type": phase_head_type(phase),
            "task_role": phase_task_role(phase),
            "adapter_name": phase_adapter_name(phase),
            "training_file": phase_training_file(phase),
            "sample_count": len(phase_rows),
            "tool_call_count": sum(int(row["metadata"].get("tool_call_count", 0) or 0) for row in phase_rows),
            "dynamic_optional": phase == "analysis_dynamic" and not CurationBool("packageRequiresDynamicAnalysis"),
            "hinted_episodes_excluded": len(hinted_excluded_by_phase.get(phase, [])),
        }
    return {
        "schema": "pwnautomator.adapter_routing.v1",
        "model_family": POLICY.get("targetModel", {}).get("family", "Qwen3-Coder-Next"),
        "routing": phases,
        "merge_policy": {
            "train_as_specialist_adapters": True,
            "do_not_mix_phase_files_before_adapter_training": True,
            "exploit_and_repair_exclude_hinted_episodes_by_default": True,
            "analysis_dynamic_poc_raw_never_trains": True,
            "analysis_dynamic_poc_may_only_distill_clean_analysis_dynamic": True,
        },
    }


def trace_replay_manifest(events, run_id, execution_id, qwen_sft, catalog):
    start = trace_start_data(events)
    prompt_metadata = start.get("promptMetadata") if isinstance(start.get("promptMetadata"), dict) else {}
    mcp_servers = start.get("mcpServers") if isinstance(start.get("mcpServers"), list) else []
    return {
        "schema": "pwnautomator.trace_replay_manifest.v1",
        "runId": run_id,
        "executionId": execution_id,
        "policyVersion": POLICY.get("version", 1),
        "policySha256": sha256_text(json.dumps(POLICY, sort_keys=True, ensure_ascii=False)),
        "targetModel": POLICY.get("targetModel", {}),
        "trace": {
            "sourceSchema": start.get("schema") or "pwnautomator.raw_trace.v1",
            "eventCount": len(events),
            "eventTypeCounts": event_type_counts(events),
            "postSuccessTrimmed": True,
        },
        "prompts": {
            "systemPromptFile": prompt_metadata.get("systemPromptFile") or "",
            "promptTemplateVersion": prompt_metadata.get("templateVersion") or "",
        },
        "mcpServers": mcp_servers,
        "toolSchemaHash": tool_catalog_manifest(catalog)["toolSchemaHash"],
        "trainingOutputs": {
            "qwenSftSamples": len(qwen_sft),
        },
        "replayNotes": [
            "Use metadata/replay_manifest.json for runtime file hashes and Docker/container details.",
            "Use this trace manifest to confirm prompt, MCP, event, and policy provenance.",
            "Raw traces are intentionally excluded from the training package.",
        ],
    }


def process_trace(trace_path, output_dir):
    events = load_events(trace_path)
    if not events:
        raise SystemExit(1)

    events, post_success_events_dropped = trim_post_success_phases(events)

    os.makedirs(output_dir, exist_ok=True)
    run_id = events[0].get("runId") or "unknown"
    execution_id = events[0].get("executionId") or nested_get(events[0], "data", "executionId")
    records, tool_failures, top_tools = extract_records(events)
    analysis_rows = collect_agent_messages(events)
    qwen_sft, qwen_rejected, tool_catalog = qwen_datasets(events, run_id, execution_id)
    qwen_static = [row for row in qwen_sft if row["metadata"]["phase"] == "analysis_static"]
    qwen_dynamic = [row for row in qwen_sft if row["metadata"]["phase"] == "analysis_dynamic"]
    # exploit/repair adapters run on every real deployment against challenges
    # that have no reference PoC, so their canonical training file must stay
    # cold (hint_source == ""). Anything a hint touched -- self-derived or
    # PoC-grounded -- is routed to a separate *_hinted_sft.jsonl instead of
    # being silently mixed into the corpus that teaches blind solving.
    qwen_exploit_all = [row for row in qwen_sft if row["metadata"]["phase"] == "exploit"]
    qwen_repair_all = [row for row in qwen_sft if row["metadata"]["phase"] == "repair"]
    qwen_exploit = [row for row in qwen_exploit_all if not row["metadata"].get("hint_source")]
    qwen_exploit_hinted = [row for row in qwen_exploit_all if row["metadata"].get("hint_source")]
    qwen_repair = [row for row in qwen_repair_all if not row["metadata"].get("hint_source")]
    qwen_repair_hinted = [row for row in qwen_repair_all if row["metadata"].get("hint_source")]
    qwen_deploy_sft = qwen_static + qwen_dynamic + qwen_exploit + qwen_repair
    qwen_flag_leaks = sum(matches_any_regex(json.dumps(row, ensure_ascii=False), FLAG_PATTERNS) for row in qwen_deploy_sft)
    qwen_duplicate_samples = len(qwen_deploy_sft) - len({row["sample_id"] for row in qwen_deploy_sft})

    full_rows = analysis_rows + records + tool_failures
    curated = records + [row for row in analysis_rows if row["quality_score"] >= 3]
    primary = summarize_rows(records)
    analysis_phases = ("analysis_static", "analysis_dynamic")
    sft_train = dedupe_rows([row for row in curated if row["phase"] in analysis_phases] + primary)
    gold_candidates = [row for row in records if row["metadata"]["action_outcome"]["strong_success"]]
    gold = sorted(
        gold_candidates,
        key=lambda row: (
            matches_any_regex(row["messages"][-1]["content"], FLAG_PATTERNS),
            row.get("metadata", {}).get("event_index", 0),
        ),
        reverse=True,
    )[: int(CURATION.get("goldSuccessLimit", 1) or 1)]
    exploit_code = [
        row
        for row in records
        if row["phase"] in ("exploit", "repair")
        and row.get("payload_sha256")
        and not row["metadata"]["payload_policy"]["wrapper_boilerplate"]
    ][: int(CURATION.get("exploitCodeLimit", 2) or 2)]

    run_status = "success" if gold else "failure"
    repair_rows = [row for row in exploit_code if row["phase"] == "repair" and row["metadata"].get("repair_transition")]
    blockers = []
    if CurationBool("packageRequiresGold") and not gold:
        blockers.append("no_gold_success")
    if CurationBool("goldRequiresExploitCode") and gold and not exploit_code:
        blockers.append("gold_without_exploit_code")
    if not primary:
        blockers.append("no_primary_steps")
    if CurationBool("packageRequiresQwenNative") and not qwen_deploy_sft:
        blockers.append("no_qwen_native_sft")
    if CurationBool("packageRequiresQwenNative") and not qwen_static:
        blockers.append("no_qwen_verified_static_analysis_episode")
    if CurationBool("packageRequiresQwenNative") and CurationBool("packageRequiresDynamicAnalysis") and not qwen_dynamic:
        blockers.append("no_qwen_verified_dynamic_analysis_episode")
    if CurationBool("packageRequiresQwenNative") and not qwen_exploit and not qwen_repair:
        blockers.append("no_qwen_verified_exploit_episode")
    if CurationBool("requireHeadType") and any(not row["metadata"].get("head_type") for row in qwen_deploy_sft):
        blockers.append("qwen_sample_missing_head_type")
    if qwen_flag_leaks:
        blockers.append("qwen_export_contains_raw_flag")
    if qwen_duplicate_samples:
        blockers.append("duplicate_qwen_samples")

    quality = {
        "fullStepCount": len(full_rows),
        "curatedStepCount": len(curated),
        "primaryStepCount": len(primary),
        "sftTrainStepCount": len(sft_train),
        "qualityProfile": CURATION.get("qualityProfile", "default"),
        "primaryMinQualityScore": int(CURATION.get("primaryMinQualityScore", 7) or 7),
        "exploitCodeStepCount": len(exploit_code),
        "exploitTraceStepCount": len(records),
        "toolFailureStepCount": len(tool_failures),
        "goldStepCount": len(gold),
        "goldStrongSuccessCount": len(gold),
        "repairTransitionCount": len(repair_rows),
        "repairPayloadChangedCount": sum(1 for row in repair_rows if row["metadata"]["repair_transition"]["payload_changed"]),
        "repairTransitionLabels": dict(Counter(row["metadata"]["repair_transition"]["label"] for row in repair_rows)),
        "repairRowsWithBeforeAfter": sum(1 for row in repair_rows if row["metadata"]["repair_transition"].get("before_payload_sha256") and row["metadata"]["repair_transition"].get("after_payload_sha256")),
        "goldRowsWithoutStrongSuccess": sum(1 for row in gold if not row["metadata"]["action_outcome"]["strong_success"]),
        "toolFailureRowsWithSuccess": sum(1 for row in tool_failures if row["metadata"]["action_outcome"]["strong_success"]),
        "primaryRowsWithFailures": sum(1 for row in primary if row["metadata"]["action_outcome"]["outcome"] != "verified_success"),
        "primaryRowsWithEmptyResults": 0,
        "primaryRowsWithDisallowedPayloads": sum(1 for row in primary if row["metadata"]["payload_policy"]["disallowed"]),
        "primaryRowsWithMixedOutcomes": 0,
        "primaryRowsWithToolProbes": 0,
        "primaryRowsWithHexOnlyDumps": 0,
        "primaryRowsWithSummaryOnly": 0,
        "primaryRowsWithWeakSuccessMarkers": sum(1 for row in primary if row["metadata"]["action_outcome"]["weak_success_marker"]),
        "droppedStepCount": max(len(full_rows) - len(curated), 0),
        "duplicateSftRowsDropped": max(len([row for row in curated if row["phase"] in analysis_phases] + primary) - len(sft_train), 0),
        "postSuccessEventsDropped": post_success_events_dropped,
        "qwenNativeSftCount": len(qwen_deploy_sft),
        "qwenTotalVerifiedEpisodeCount": len(qwen_sft),
        "qwenStaticAnalysisSftCount": len(qwen_static),
        "qwenDynamicAnalysisSftCount": len(qwen_dynamic),
        "qwenDistilledDynamicFromPocCount": sum(row["metadata"].get("distilled_from_phase") == "analysis_dynamic_poc" for row in qwen_dynamic),
        "qwenExploitSftCount": len(qwen_exploit),
        "qwenRepairSftCount": len(qwen_repair),
        "qwenDistilledExploitCount": sum(row["metadata"].get("distilled_from_phase") == "repair" for row in qwen_exploit),
        "qwenDistilledRepairCount": sum(row["metadata"].get("distilled_from_phase") == "repair" for row in qwen_repair),
        "qwenPocGroundedEpisodesExcludedFromDeploySft": sum(row["metadata"].get("hint_source") == "poc_grounded_analysis" for row in qwen_sft),
        "qwenSelfHintedEpisodes": sum(row["metadata"].get("hint_source") == "self_failure_compression" for row in qwen_sft),
        "qwenExploitHintedExcludedCount": len(qwen_exploit_hinted),
        "qwenRepairHintedExcludedCount": len(qwen_repair_hinted),
        "qwenNativeToolCallCount": sum(row["metadata"]["tool_call_count"] for row in qwen_deploy_sft),
        "qwenRejectedEpisodes": dict(qwen_rejected),
        "qwenRawFlagLeakCount": qwen_flag_leaks,
        "qwenDuplicateSampleCount": qwen_duplicate_samples,
        "qwenNonThinkingViolations": sum("<think>" in json.dumps(row["messages"], ensure_ascii=False).lower() for row in qwen_deploy_sft),
        "qwenSamplesMissingHeadType": sum(not row["metadata"].get("head_type") for row in qwen_deploy_sft),
        "qwenSamplesMissingTaskRole": sum(not row["metadata"].get("task_role") for row in qwen_deploy_sft),
        "qwenSamplesMissingAdapterName": sum(not row["metadata"].get("adapter_name") for row in qwen_deploy_sft),
        "qwenMalformedToolPairs": sum(
            1
            for row in qwen_deploy_sft
            for index, message in enumerate(row["messages"])
            if message.get("tool_calls") and (index + 1 >= len(row["messages"]) or row["messages"][index + 1].get("role") != "tool")
        ),
        "qwenEpisodesWithoutAgentHead": sum(not row["metadata"].get("agent_head") for row in qwen_deploy_sft),
        "qwenVerifierTerminalSummaries": sum(row["metadata"].get("terminal_summary_source") == "verifier" for row in qwen_deploy_sft),
        "phaseBreakdown": phase_breakdown(full_rows, curated, primary),
        "avgCuratedAssistantChars": average_len(curated),
        "avgCuratedQualityScore": average_score(curated),
        "avgPrimaryAssistantChars": average_len(primary),
        "avgPrimaryQualityScore": average_score(primary),
        "lowSignalBlocksDropped": max(len(analysis_rows) - len([row for row in analysis_rows if row["quality_score"] >= 3]), 0),
        "toolFailureBlocksSeen": len(tool_failures),
        "emptyAnalysisBlocksSeen": 0,
        "disallowedPayloadBlocksSeen": sum(1 for row in full_rows if row.get("metadata", {}).get("payload_policy", {}).get("disallowed")),
        "strongSuccessBlocksSeen": len(gold_candidates),
        "weakSuccessMarkerBlocksSeen": sum(1 for row in full_rows if row.get("metadata", {}).get("action_outcome", {}).get("weak_success_marker")),
        "unstableSuccessBlocksSeen": sum(1 for row in full_rows if row.get("metadata", {}).get("action_outcome", {}).get("unstable_success")),
        "mixedOutcomeBlocksSeen": 0,
        "toolProbeBlocksSeen": 0,
        "hexOnlyDumpBlocksSeen": 0,
        "summaryOnlyBlocksSeen": 0,
        "wrapperBoilerplatePayloadBlocksSeen": sum(1 for row in full_rows if row.get("metadata", {}).get("payload_policy", {}).get("wrapper_boilerplate")),
        "fullPayloadCodeBlocks": len(exploit_code),
        "goldRowsWithUnstableSuccess": sum(1 for row in gold if row["metadata"]["action_outcome"].get("unstable_success")),
        "exploitCodeRowsWithWrapperBoilerplate": sum(1 for row in exploit_code if row["metadata"]["payload_policy"]["wrapper_boilerplate"]),
        "topTools": top_tools.most_common(20),
        "qualityGate": {"passed": not blockers, "blockers": blockers},
    }
    summary = {
        "runId": run_id,
        "runStatus": run_status,
        "fullStepCount": len(full_rows),
        "curatedStepCount": len(curated),
        "primaryStepCount": len(primary),
        "sftTrainStepCount": len(sft_train),
        "goldStepCount": len(gold),
        "exploitCodeStepCount": len(exploit_code),
        "qwenNativeSftCount": len(qwen_deploy_sft),
        "qwenTotalVerifiedEpisodeCount": len(qwen_sft),
        "qwenStaticAnalysisSftCount": len(qwen_static),
        "qwenDynamicAnalysisSftCount": len(qwen_dynamic),
        "qwenDistilledDynamicFromPocCount": sum(row["metadata"].get("distilled_from_phase") == "analysis_dynamic_poc" for row in qwen_dynamic),
        "qwenExploitSftCount": len(qwen_exploit),
        "qwenRepairSftCount": len(qwen_repair),
        "qwenDistilledExploitCount": sum(row["metadata"].get("distilled_from_phase") == "repair" for row in qwen_exploit),
        "qwenDistilledRepairCount": sum(row["metadata"].get("distilled_from_phase") == "repair" for row in qwen_repair),
    }
    adapter_routing = adapter_routing_manifest(
        {
            "analysis_static": qwen_static,
            "analysis_dynamic": qwen_dynamic,
            "exploit": qwen_exploit,
            "repair": qwen_repair,
        },
        {"exploit": qwen_exploit_hinted, "repair": qwen_repair_hinted},
    )
    trace_manifest = trace_replay_manifest(events, run_id, execution_id, qwen_deploy_sft, tool_catalog)
    tool_manifest = tool_catalog_manifest(tool_catalog)
    card = {
        "schema": "pwnautomator.dataset_card.v1",
        "runId": run_id,
        "policyVersion": POLICY.get("version", 1),
        "targetModel": POLICY.get("targetModel", {}),
        "qualityProfile": CURATION.get("qualityProfile", "default"),
        "qualityGate": quality["qualityGate"],
        "adapterRouting": adapter_routing["routing"],
    }

    # Only files that are actually consumed downstream are written: the
    # dashboard's TRAINING_EXPORTS/METADATA_EXPORTS package these into the
    # shipped dataset zip, and tests/test_extract_dataset_regression.py reads
    # the rest back as its verification surface. Every other legacy export
    # (full_train, curated_train, analysis_train, exploit_train/_full/_trace,
    # repair_full_train, *_sharegpt.json, initial/retry/failures/episodes.json)
    # was dead weight -- nothing ever read them back -- so they are no longer
    # generated.
    prefix = Path(output_dir) / run_id
    write_json(f"{prefix}_summary.json", summary)
    write_json(f"{prefix}_quality_report.json", quality)
    write_json(f"{prefix}_dataset_card.json", card)
    write_json(f"{prefix}_adapter_routing.json", adapter_routing)
    write_json(f"{prefix}_trace_replay_manifest.json", trace_manifest)
    write_json(f"{prefix}_tool_schema_catalog.json", tool_manifest)
    write_jsonl(f"{prefix}_sft_train.jsonl", sft_train)
    write_jsonl(f"{prefix}_train.jsonl", primary)
    write_jsonl(f"{prefix}_gold_train.jsonl", gold)
    write_jsonl(f"{prefix}_exploit_code_train.jsonl", exploit_code)
    write_jsonl(f"{prefix}_repair_train.jsonl", [row for row in primary if row["phase"] == "repair"])
    write_jsonl(f"{prefix}_tool_failures.jsonl", tool_failures)
    write_jsonl(f"{prefix}_qwen3_coder_next_sft.jsonl", qwen_deploy_sft)
    write_jsonl(f"{prefix}_qwen3_coder_next_static_analysis_sft.jsonl", qwen_static)
    write_jsonl(f"{prefix}_qwen3_coder_next_dynamic_analysis_sft.jsonl", qwen_dynamic)
    write_jsonl(f"{prefix}_qwen3_coder_next_exploit_sft.jsonl", qwen_exploit)
    write_jsonl(f"{prefix}_qwen3_coder_next_repair_sft.jsonl", qwen_repair)
    # Not packaged by dataset.service.js on purpose -- these are hint-assisted
    # exploit/repair episodes kept available for a deliberate future ablation,
    # never mixed into the adapters that must solve without a reference PoC.
    write_jsonl(f"{prefix}_qwen3_coder_next_exploit_hinted_sft.jsonl", qwen_exploit_hinted)
    write_jsonl(f"{prefix}_qwen3_coder_next_repair_hinted_sft.jsonl", qwen_repair_hinted)


def CurationBool(key):
    return bool(CURATION.get(key, False))


def average_len(rows):
    if not rows:
        return 0
    return round(sum(len(row["messages"][-1]["content"]) for row in rows) / len(rows), 2)


def average_score(rows):
    if not rows:
        return 0
    return round(sum(row.get("quality_score", 0) for row in rows) / len(rows), 2)


def phase_breakdown(full_rows, curated, primary):
    def count(rows):
        counter = Counter(row.get("phase") or "unknown" for row in rows)
        return dict(counter)

    return {"full": count(full_rows), "curated": count(curated), "primary": count(primary)}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit("usage: extract_dataset.py TRACE_JSONL OUTPUT_DIR")
    process_trace(sys.argv[1], sys.argv[2])
