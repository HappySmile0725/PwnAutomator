# CTF Exploit AI - 모델 설계 문서

## 목표

Qwen3 Coder 30B를 LoRA로 fine-tuning하여 CTF 바이너리 exploit을 자동화.
두 모델로 분업하며, 각각 별도 LoRA 어댑터로 학습.

---

## 모델 구성

### Model A — 분석 + Payload 생성 + 재시도

| 항목 | 내용 |
|------|------|
| 역할 | ① 바이너리 분석 → exploit 설계 → payload 생성<br>② Model B 진단 수신 → 재분석 or payload 재작성 |
| 입력 (initial) | raw binary path |
| 입력 (retry) | 이전 분석 결과 + Model B의 진단(diagnosis) |
| 출력 | `payload_code` |

**두 가지 동작 모드:**
- `initial`: 처음 바이너리를 받아 처음부터 분석하고 payload 생성
- `retry`: Model B의 진단을 받아 **재분석이 필요한지 판단**, 필요하면 일부 재분석 후 payload 재작성

> Model A가 retry 시 무엇을 할지는 Model A 스스로 결정.
> 진단이 단순 offset 오류면 payload만 재작성,
> 진단이 분석 자체의 오류를 지적하면 해당 부분 재분석.

---

### Model B — Payload 실행 실패 진단 (진단만, 수정 없음)

| 항목 | 내용 |
|------|------|
| 역할 | 실패한 payload + 실행 결과 → 동적 분석 → **원인 진단 후 Model A에 전달** |
| 입력 | Model A 분석 요약(context) + `failed_payload` + `execution_result` |
| 출력 | `diagnosis` (category + description + what_to_check) |
| tool 종류 | `debug_context`, `debug_regs`, `debug_bt`, `debug_cmd`(진단용), `debug_mem` |

**Model B가 하지 않는 것:**
- payload 수정
- exploit 재설계
- 새 분석 단계 수행

**Model B가 하는 것:**
- 실행 결과(signal, crash addr, 레지스터)를 보고 어디서 왜 실패했는지 GDB로 추적
- 원인을 진단하여 구조화된 `diagnosis` 객체 생성
- 이를 Model A에 넘김 → Model A가 어떻게 할지 결정

---

## 추론 파이프라인

```
Binary
  └─► Model A [initial]
        분석 → exploit 설계 → payload_code
                      │
              payload 실행
                      │
           ┌──────────┴──────────┐
         성공                  실패
           │                     │
          끝           Model B [diagnosis]
                         GDB 동적 분석
                         원인 진단만 수행
                                 │
                           diagnosis
                         (category + description
                          + what_to_check)
                                 │
                       Model A [retry]
                         진단 수신
                         재분석 여부 스스로 판단
                         payload 재작성
                                 │
                            payload 실행
                                 │
                          (성공 or 재실패 반복)
```

---

## Schema 정의

### Schema A-initial (Model A 초기 실행 학습 데이터)

현재 JSON 파일 구조 그대로 사용.

```json
{
  "meta": { "title", "binary", "arch", "ubuntu", "result" },
  "protections": { "RELRO", "Canary", "NX", "PIE", "SHSTK", "IBT", "note" },
  "analysis_steps": [
    {
      "step": int,
      "phase": string,
      "tool": string,
      "args": {},
      "output": {},
      "reasoning": "왜 이 tool을 썼고 결과에서 무엇을 파악했는지"
    }
  ],
  "vulnerabilities": [ { "id", "name", "location", "root_cause", "impact", ... } ],
  "exploit": { "strategy", "phases": [ { "phase", "name", "description", ... } ] },
  "payload_code": "완성된 pwntools 스크립트",
  "libc_offsets": {},
  "stack_offsets": {},
  "verification": { "tool", "output", "result" },
  "key_insights": []
}
```

---

### Schema A-retry (Model A 재시도 학습 데이터)

> 파일명 규칙: `{바이너리명}_retry.json`
> Schema A-initial과 별도 파일로 관리.

```json
{
  "meta": {
    "mode": "retry",
    "binary": "바이너리 경로",
    "related_schema_a": "초기 분석 JSON 파일명",
    "related_schema_b": "진단 JSON 파일명",
    "ubuntu": "버전"
  },
  "previous_payload": "실패한 payload 코드",
  "diagnosis": {
    "category": "root_cause_category 중 하나",
    "description": "Model B가 진단한 원인 설명",
    "what_to_check": "Model A가 확인해야 할 것 (재분석 범위 힌트)"
  },
  "model_a_decision": "rewrite_payload | re_analyze",
  "re_analysis_steps": [
    {
      "step": int,
      "phase": string,
      "tool": string,
      "args": {},
      "output": {},
      "reasoning": "진단을 받아 무엇을 재확인했는지"
    }
  ],
  "payload_code": "수정된 payload 코드",
  "verification": { "tool", "output", "result" }
}
```

**`model_a_decision` 값 기준:**
- `rewrite_payload`: 진단이 단순 수치 오류 (offset, byte 순서 등) → 재분석 없이 payload만 수정
- `re_analyze`: 진단이 분석 자체의 오류를 지적 (잘못된 취약점 파악, 스택 레이아웃 오해 등) → `re_analysis_steps` 수행 후 payload 재작성

---

### Schema B (Model B 학습 데이터)

> 파일명 규칙: `{바이너리명}_failures.json`

```json
{
  "meta": {
    "binary": "바이너리 경로",
    "related_schema_a": "초기 분석 JSON 파일명",
    "ubuntu": "버전"
  },
  "binary_context": {
    "protections": {},
    "stack_layout": {
      "buffer_to_canary": "N bytes",
      "buffer_to_saved_rip": "N bytes",
      "key_oob_offsets": {}
    },
    "libc_offsets": {},
    "exploit_goal": "system('/bin/sh') via ROP 등"
  },
  "failed_payload": {
    "code": "실패한 payload 코드",
    "intent": "이 payload가 의도한 것"
  },
  "execution_result": {
    "signal": "SIGSEGV | SIGABRT | null",
    "crash_address": "0x...",
    "stdout": "",
    "stderr": "*** stack smashing detected *** 등"
  },
  "debug_trajectory": [
    {
      "tool": "debug_context | debug_regs | debug_bt | debug_cmd | debug_mem",
      "args": {},
      "output": {},
      "reasoning": "왜 이 도구를 썼고 뭘 알게 됐는지"
    }
  ],
  "diagnosis": {
    "category": "root_cause_category 중 하나",
    "description": "구체적 원인 설명 (Model A에 전달되는 내용)",
    "what_to_check": "Model A가 재확인해야 할 부분 (재분석 범위 힌트)"
  }
}
```

**`diagnosis`는 진단 결과만 담음. 수정된 payload나 exploit 재설계 없음.**

---

## 파일 간 연결 관계

```
{binary}_initial.json     ← Schema A-initial  (Model A 학습)
    │
    ├── {binary}_failures.json  ← Schema B  (Model B 학습)
    │       diagnosis →
    └── {binary}_retry.json     ← Schema A-retry  (Model A retry 학습)
```

세 파일의 `meta.related_*` 필드로 서로 참조.

---

## 실패 기록 가이드라인

### 기록해야 하는 실패
- payload를 실제로 실행했을 때 프로세스가 crash나 비정상 종료된 경우
  - SIGSEGV, SIGABRT (stack smashing detected), 잘못된 출력, 셸 미획득

### 기록하지 않는 실패
- MCP tool 호출 자체의 오류 (네트워크, 타임아웃, GDB 연결 실패 등)
- 분석 중 잘못된 추측을 수정하는 과정 (Model A initial 내부)
- GDB 세션 재시작, breakpoint 재설정 등 환경 세팅 문제

### 데이터 생성 순서

새 바이너리를 풀 때:
```
1. Model A initial → {binary}_initial.json 작성
2. payload 첫 실행
3. 실패 시:
   a. GDB로 원인 추적 → debug_trajectory 기록
   b. diagnosis 작성 → {binary}_failures.json 저장 (Schema B)
   c. diagnosis 기반으로 payload 재작성
   d. → {binary}_retry.json 저장 (Schema A-retry)
4. 성공 시 종료
```

---

## 데이터 충분성 기준 (참고)

LoRA fine-tuning 기준 최소 권장량:

| 모델 / 모드 | 최소 권장 샘플 수 | 현재 |
|-------------|----------------|------|
| Model A (initial) | 50~100개 | 2개 |
| Model A (retry) | 30~50개 | 0개 |
| Model B | 30~50개 실패-진단 쌍 | 0개 |

데이터 다양성도 중요: 같은 기법(BOF+ROP)만 반복하지 말고
format string, heap exploit, ret2plt, FSOP 등 다양한 취약점 유형 포함 필요.
