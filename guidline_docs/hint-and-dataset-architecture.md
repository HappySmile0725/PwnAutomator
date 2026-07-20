# Hint And Dataset Architecture

## Goal

The pipeline may use a reference PoC only as a collection-time verifier after an unguided exploit/repair window fails. The PoC path must never become deployable SFT by itself.

## Flow

```text
static -> dynamic blind -> exploit/repair cold
                           |
                           | failure or window exhaustion
                           v
                     analysis_dynamic_poc
                           |
                           v
              clean analysis_dynamic distillation
```

## Training Rule

- `analysis_dynamic_poc` is non-deployable verification material.
- Raw PoC-grounded episodes are excluded from `train/*.jsonl`.
- If PoC verification succeeds, it may replace the weak blind `analysis_dynamic` episode with a clean `analysis_dynamic` SFT sample.
- The distilled dynamic sample must use the original blind dynamic prompt and only debugger-confirmed facts. It must not mention the reference PoC or copy payload code, comments, or offsets that were not independently verified.
- Hinted exploit/repair episodes stay excluded from deployable SFT by default.

## Packaged SFT Files

```text
train/qwen3_coder_next_static_analysis_sft.jsonl
train/qwen3_coder_next_dynamic_analysis_sft.jsonl
train/qwen3_coder_next_exploit_sft.jsonl
train/qwen3_coder_next_repair_sft.jsonl
```

`qwen3_coder_next_dynamic_poc_sft.jsonl` is intentionally not generated or packaged.

## Adapter Routing

Deployable adapters:

- `analysis.static`
- `analysis.dynamic`
- `exploit.coder`
- `exploit.repair`

Non-deployable collection-time source:

- `analysis.dynamic_poc`, only for clean `analysis.dynamic` distillation.
