import sys
import os
import json
import re

# Precompile compiler wrapper junk pattern and register check pattern for optimization
JUNK_SYMBOLS = {"@plt", "_init", "_fini", "register_tm", "frame_dummy", "do_global"}
REG_PATTERN = re.compile(r"\b(rax|rbx|rcx)\b", re.IGNORECASE)

def filter_mcp_output(tool, output_str):
    """Prunes unnecessary outputs from Ghidra and GDB to minimize tokens"""
    if not output_str:
        return output_str

    # Strip ANSI escape/color sequences
    output_str = re.sub(r'(?:\x1b|\\u001b)\[[0-9;]*[a-zA-Z]', '', output_str)
    
    # Prune interactive timeouts and duplicate empty lines
    output_str = re.sub(r"(\$\s*){5,}", "$\n[interactive prompt timeout/truncated]\n", output_str)
    output_str = re.sub(r"\n{4,}", "\n\n", output_str)

    if tool != "execute":
        return output_str
        
    try:
        data = json.loads(output_str)
    except ValueError:
        return output_str

    if not data.get("success", True):
        return output_str
        
    cmd = str(data.get("command", ""))
    
    # 1. Clean functions list
    if "info functions" in cmd:
        payload = data.get("responses", [])
        data["responses"] = [
            resp for resp in payload 
            if not any(junk in (resp.get("payload") or "") for junk in JUNK_SYMBOLS)
        ]
        return json.dumps(data)
        
    # 2. Clean GDB crash verbose dump
    if "disassemble" not in cmd:
        payload = data.get("responses", [])
        data["responses"] = [
            resp for resp in payload 
            if not REG_PATTERN.search(resp.get("payload") or "")
        ]
        return json.dumps(data)
        
    # 3. Clean GDB disassemble duplicate standard instructions & padding
    if "disassemble" in cmd:
        payload = data.get("responses", [])
        for resp in payload:
            text = resp.get("payload") or ""
            text = re.sub(r"(nop\s+DWORD PTR\s+\[rax\+0x0\]\n?){3,}", "[nop * multiple]\n", text)
            text = re.sub(r"(nop\s+WORD PTR\s+\[rax\+rax\*1\+0x0\]\n?){3,}", "[nop * multiple]\n", text)
            text = re.sub(r"(endbr64\n?){2,}", "[endbr64]\n", text)
            text = re.sub(r"(0x00000000\s+){4,}", "[0x00 * multiple] ", text)
            text = re.sub(r"(0x00\s+){8,}", "[0x00 * multiple] ", text)
            resp["payload"] = text
        return json.dumps(data)

    # 4. Clean Ghidra decompilation standard junk and omit internal function bodies
    if "decompile" in cmd or tool in ["get_decompiled_code", "decompile_by_name", "decompile_by_addr"]:
        payload = data.get("responses", [])
        junk_funcs = {"_init", "_fini", "register_tm_clones", "frame_dummy", "_start", "__libc_csu_init", "__libc_csu_fini", "__stack_chk_fail", "__libc_start_main"}
        for resp in payload:
            text = resp.get("payload") or ""
            # Omit internal helper/compiler function bodies
            func_match = re.search(r"\b([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{", text)
            if func_match and (func_match.group(1) in junk_funcs or func_match.group(1).startswith("__")):
                resp["payload"] = f"// [Internal Compiler Function ({func_match.group(1)}) - Body Omitted]\n"
                continue
            # Prune undefined scalar and array declarations
            text = re.sub(r"\bundefined\d*\s+\w+(\s*\[\d+\])?(\s*=\s*[^;]+)?;\n?", "", text)
            # Prune redundant decompiled pointer and scalar casts
            text = re.sub(r"\((undefined\d*|uint|ulong|long|char)\s*\*+\)", "", text)
            # Simplify compiler-generated stack guard checks
            text = re.sub(r"if\s+\(local_audit_guard\s+==\s+[^)]+\)\s+\{[^}]+\}\s+else\s+\{[^}]+\}", "[stack guard validation check]", text)
            resp["payload"] = text
        return json.dumps(data)
        
    return output_str

def extract_python_code(text):
    match = re.search(r"```python\s*(.*?)\s*```", text, re.DOTALL)
    return match.group(1) if match else None

def replace_python_code(text, new_code):
    return re.sub(r"```python\s*(.*?)\s*```", f"```python\n{new_code}\n```", text, flags=re.DOTALL)

def make_code_snippet_diff(old_code, new_code):
    old_lines = [l.strip() for l in old_code.strip().split('\n') if l.strip()]
    new_lines = new_code.strip().split('\n')
    diff_lines = []
    for line in new_lines:
        if line.strip() and line.strip() not in old_lines:
            diff_lines.append(line)
            
    if len(diff_lines) < len(new_lines) * 0.4 and len(diff_lines) > 0:
        return "# [Modified Snippet / Applied Fix]\n" + "\n".join(diff_lines)
    return new_code

def extract_tool_signatures(gpt_value):
    sigs = []
    for line in gpt_value.split('\n'):
        if '"mcp_tool_call"' in line or '"tool"' in line:
            match = re.search(r'"tool"\s*:\s*"([^"]+)"', line)
            args = re.search(r'"arguments"\s*:\s*({[^}]+})', line)
            if match:
                sigs.append((match.group(1), args.group(1) if args else ''))
    return sigs

def compress_trace(events, role_filter=None):
    compressed_conversations = []
    current_role = "discovery"
    last_python_code = None
    prompt_count = 0
    
    for ev in events:
        ev_type = ev.get("type")
        source = ev.get("source")
        data = ev.get("data", {})
        text = ev.get("text", "")

        # Role transition detection
        if ev_type == "codex_prompt":
            if "Discovery Targets" in text or "system-prompt-coder" in text:
                current_role = "coder"
            else:
                current_role = "discovery"

        # Apply role filter if specified
        if role_filter and current_role != role_filter:
            continue

        if ev_type == "mcp_tool_call" and ev.get("tool") in ["list_processes", "list_python_packages"]:
            continue

        if ev_type == "llm_output_chunk" and source == "codex":
            if compressed_conversations and compressed_conversations[-1]["from"] == "gpt":
                compressed_conversations[-1]["value"] += text
            else:
                compressed_conversations.append({"from": "gpt", "value": text})
                
        elif ev_type == "codex_prompt":
            clean_prompt = text
            if "System Instructions" in text:
                parts = text.split("# User Task")
                clean_prompt = "# User Task" + parts[-1] if len(parts) > 1 else text
            
            if prompt_count > 0:
                clean_prompt = re.sub(
                    r"# MCP Servers\n(.*?)\n\n# Constraints", 
                    "# MCP Servers\n[MCP Servers Specification Omitted]\n\n# Constraints", 
                    clean_prompt, 
                    flags=re.DOTALL
                )
            prompt_count += 1
            
            # Sanitize embedded MCP outputs inside the prompt if any
            mcp_blocks = re.findall(r"({.*?})", clean_prompt)
            for block in mcp_blocks:
                try:
                    parsed = json.loads(block)
                    if "command" in parsed or "success" in parsed:
                        sanitized = filter_mcp_output("execute", block)
                        clean_prompt = clean_prompt.replace(block, sanitized)
                except ValueError:
                    continue

            clean_prompt = re.sub(r"0x[0-9a-fA-F]+(\s+0x[0-9a-fA-F]+)+", "[hex dump compressed]", clean_prompt)
            if compressed_conversations and compressed_conversations[-1]["from"] == "human":
                compressed_conversations[-1]["value"] += "\n" + clean_prompt
            else:
                compressed_conversations.append({"from": "human", "value": clean_prompt})

    # Prune redundant sequential tool call loops
    pruned = []
    for turn in compressed_conversations:
        if turn["from"] == "gpt" and len(pruned) >= 2:
            prev_gpt = pruned[-2]
            if prev_gpt["from"] == "gpt":
                curr_sigs = extract_tool_signatures(turn["value"])
                prev_sigs = extract_tool_signatures(prev_gpt["value"])
                if curr_sigs and prev_sigs and curr_sigs == prev_sigs:
                    pruned.pop()  # Remove previous human
                    pruned.pop()  # Remove previous gpt
        pruned.append(turn)

    # Post-process GPT turns for Snippet-based Patch
    for turn in pruned:
        if turn["from"] == "gpt":
            code = extract_python_code(turn["value"])
            if code:
                if last_python_code:
                    diff_code = make_code_snippet_diff(last_python_code, code)
                    if diff_code != code:
                        turn["value"] = replace_python_code(turn["value"], diff_code)
                last_python_code = code
                
    return pruned

def convert_to_sharegpt(events, output_json, role_filter=None):
    conversations = compress_trace(events, role_filter)
    if not conversations:
        return
        
    system_prompt = "You are a professional pwnable solver. Follow: 1. Entry Point 2. Surrounding Logic 3. Vuln Identification 4. Leak Design 5. Exploit to Shell."
    if role_filter == "discovery":
        system_prompt = "You are a professional pwnable solver specializing in vulnerability discovery."
    elif role_filter == "coder":
        system_prompt = "You are a professional pwnable solver specializing in writing exploits and debugging payload issues."
        
    sharegpt_record = {
        "system": system_prompt,
        "conversations": conversations
    }
    with open(output_json, "w", encoding="utf-8") as out:
        json.dump([sharegpt_record], out, indent=2, ensure_ascii=False)

def process_trace(trace_path, output_dir):
    if not os.path.exists(trace_path):
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)
    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f]

    run_id = events[0].get("runId", "unknown")
    
    # Generate schema dataset logs
    initial_steps = []
    retry_steps = []
    failures = []
    current_phase = "initial"

    for ev in events:
        ev_type = ev.get("type")
        source = ev.get("source")
        data = ev.get("data", {})

        if ev_type == "codex_prompt":
            if "Exploit Failure Diagnosis" in ev.get("text", ""):
                current_phase = "retry"

        if source == "codex" and ev_type == "llm_output_chunk":
            chunk_text = ev.get("text", "")
            step_record = {
                "phase": current_phase,
                "text": chunk_text,
                "timestamp": ev.get("at")
            }
            if current_phase == "initial":
                initial_steps.append(step_record)
            else:
                retry_steps.append(step_record)

        if "Exploit Failure Diagnosis" in str(data):
            failures.append({
                "runId": run_id,
                "diagnosis": data
            })

    # Save processed standard datasets
    with open(os.path.join(output_dir, f"{run_id}_initial.json"), "w", encoding="utf-8") as out:
        json.dump({"runId": run_id, "steps": initial_steps}, out, indent=2)

    if retry_steps:
        with open(os.path.join(output_dir, f"{run_id}_retry.json"), "w", encoding="utf-8") as out:
            json.dump({"runId": run_id, "steps": retry_steps}, out, indent=2)

    if failures:
        with open(os.path.join(output_dir, f"{run_id}_failures.json"), "w", encoding="utf-8") as out:
            json.dump({"runId": run_id, "failures": failures}, out, indent=2)

    # Automatically build optimized ShareGPT conversational files
    convert_to_sharegpt(events, os.path.join(output_dir, f"{run_id}_sharegpt.json"))
    convert_to_sharegpt(events, os.path.join(output_dir, f"{run_id}_discovery_sharegpt.json"), role_filter="discovery")
    convert_to_sharegpt(events, os.path.join(output_dir, f"{run_id}_coder_sharegpt.json"), role_filter="coder")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)
    process_trace(sys.argv[1], sys.argv[2])
