
# 1. 서버 최초 실행
``` bash
./ghidra_12.0.2_PUBLIC/support/analyzeHeadless challenge test \
    -process [문제파일] \
    -scriptPath ./ghidra_tools/server \
    -postScript ghidra_server.py
```

## 학습 데이터 형식
``` json
{
  "task_id": "pwn_001",
  "binary_meta": {
    "arch": "x86_64",
    "base": "0x100000",
    "protections": {
      "NX": true,
      "PIE": false,
      "Canary": false
    }
  },
  "steps": [
    {
      "action": "meta",
      "tool": "meta",
      "output": {
        "arch": "x86:LE:64",
        "base": "0x100000"
      }
    },
    {
      "action": "enumerate_functions",
      "tool": "func.list",
      "output": [
        {"addr": "0x101149", "name": "main"},
        {"addr": "0x101180", "name": "vuln_func"}
      ]
    },
    {
      "action": "inspect_entry",
      "tool": "decompile.name",
      "input": {"name": "main"},
      "output": {
        "code": "void main(){char buf[64];gets(buf);}"
      }
    },
    {
      "analysis": {
        "reason": "gets() has no bounds check",
        "stack_object": "buf[64]",
        "control_flow": "RET overwritten",
        "vuln_type": "stack buffer overflow"
      }
    },
    {
      "exploit_plan": {
        "offset_reason": "64 bytes buffer + 8 bytes saved RBP",
        "technique": "ROP",
        "constraints": ["NX enabled", "PIE disabled"]
      }
    }
  ]
}

```