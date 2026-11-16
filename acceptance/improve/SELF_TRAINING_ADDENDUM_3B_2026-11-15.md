# Addendum 3b: an exemplar leak closed, and a safe exemplar for each category's round — 2026-11-15 23:20 AEDT

Written before Qwen3.8-27B has generated any self-training trace, and before any model has been scored on the J3 held-out
sets (either version). Nothing in amendment 3 or addendum 3a is relaxed: the validator, the item rules, the training recipe,
the bars and the held-out tests stay as they were, except for the one excluded file below.

## 1. A few-shot exemplar's source file was in the J3 held-out test
- The quick bank's three few-shot exemplars are templated from Juliet `_02` files (scripts/imp_build_exemplars.py). They were
  written when pools J/J2 used only `_01`. J3 (amendment 2) later took flow variants `_02`–`_22` and `_31`–`_45`, so the
  command-injection exemplar's file, `CWE78_OS_Command_Injection__char_console_system_02.c`, was in the J3 held-out set (both
  functions) and its safe function was in the matched set.
- Test-time scorers (imp_selective, imp_eval_cot) show no exemplars. Trace generation does: every training trace was written
  with that file's vulnerable function worked through in the prompt. The leak is indirect, but it is a leak.
- Fix: a pair whose Juliet source file supplies a few-shot exemplar (any results/imp_fewshot_exemplars*.json) is excluded from
  every held-out test, and from every self-training pool.
  - J3 held-out (2b): 841 → 840 pairs, 1,680 functions. sha256 3f6996f6076a34a6d59bbdf8029295aafff93a6c2d9c438b9e967697802ab1cc
    (was 0844a504…).
  - J3 matched (2c), rebuilt by the unchanged 2c procedure: 576 functions. Command injection 128/128 (length-only 0.503 chars,
    0.503 tokens), path traversal CWE-23 91/91 (0.503) and CWE-36 69/69 (0.522), format string dropped as before.
    sha256 18f62ac977f8115e5315b4056bb00367c777a1a396d98d01f95ae3c89a718af1 (was b8db3f0c…). 38 command-injection functions
    differ from the 2c draw because removing one pair shifts the random stream; CWE-23 and CWE-36 are identical. No model has
    been scored on either version.
  - Self-training pools: 0 pairs dropped (no exemplar file was in any pool); pool items unchanged.
- New fail-first control, scripts/ci_exemplar_leak.py (a box check in every run): every set in ci_plan.SET_FILES against every
  exemplar, by source file and by whitespace-normalised code. The fixed sets pass. The pre-3b J3 sets are caught (exit 1,
  naming the three cases), and the self-test catches same-file and same-code mutants.

## 2. Each category's round shows a SAFE exemplar of that category
- Evidence, from the 14B-written quick bank on the command-injection pool: 38 traces of safe functions. 12 say VULNERABLE (a
  wrong verdict, which filtering removes). 7 say SAFE with the cmd_injection oracle, and every one carries a payload witness.
  Validator errors on safe traces include "SAFE but sink has no sufficient guard" (12) and "cmd_injection witness must contain
  the literal token CANARY" (9). The quick set has two VULNERABLE exemplars and one SAFE memory exemplar, and no SAFE
  injection example of the valid form: witness null, and the constant source marked as the sufficient guard.
- Rule: a round of category C uses the three quick exemplars plus the exemplars that scripts/imp_build_st_exemplars.py lists
  for C. Each is templated from Juliet ground truth (no model, no commercial model, no CASTLE case) and must pass the current
  validator with verdict_final = label, or the builder fails. Categories with no extra exemplars use the quick file. Extra
  exemplars for later categories are defined, and their source files checked against every held-out test, in an addendum
  written before that category's round.
- Command injection: E4 SAFE, the good half of E2's own `_02` file (already excluded above). Both sinks are `SYSTEM(data)`, and
  data is the fixed prefix plus the literal `"*.*"` (the guard, marked sufficient); witness null. File
  results/imp_fewshot_exemplars_st_cmd_injection.json, 4 exemplars (2 VULNERABLE, 2 SAFE), sha256
  921fecce0f8355704e24b0ffbeeb6407bcf1d8520a7c1de2714ab172297968f5. The three quick exemplars still pass the current
  validator.
- The validator does not move. Applied to E4, both 14B failure modes are rejected: a payload witness without CANARY ("witness
  must contain the literal token CANARY"), and an unguarded sink ("SAFE but sink s1 has no sufficient guard").
- The bank rows record `fewshot` (4 for this round), so a round can be shown to have used its file.

## What is reported either way
For command injection, round 1: traces, kept vulnerable and safe functions, and whether the ≥ 20 per class floor (3a) is met.
If it is not met, the round is reported as "insufficient correct traces" and the programme moves to path traversal; the
exemplar change is not repeated with a different exemplar to rescue the round.

## Note, 23:49 AEDT: generation memory (compute only; no trace had been written)
Round 1 of command injection started at 23:23 with the gpu-util 0.65 that addendum 3a set for a 27B model. On Spark unified
memory that reserves ~78 GB; with ~94 GB available at launch (the 72B download runs at night) only ~10 GB was left, and
Spark stopped answering ssh within minutes (ping answered: memory thrash, no OOM kill). No trace was written. Self-training
generation now uses gpu-util 0.55 (~66 GB: the 52 GB bf16 weights + KV) and starts only with 25 GB more than that free. The
staged CI CoT evaluation gets the same rule (27B: 0.64 -> 0.55; models <= 14B unchanged at 0.45; the free-memory margin rises
from 5 to 25 GB). Sampling, k, the few-shot file, the schema and every filter are unchanged.

## Note, 01:49 AEDT: the second freeze and its cause (compute only; still no trace written)
Round 1 restarted at 01:37 at gpu-util 0.55 with ~60 GB free, and Spark froze again at ~01:44. Both freezes happened right
after the weights finished loading. The first log ends with vLLM starting to profile the vision encoder "with 1 image items
of the maximum feature size". Qwen3.8-27B is a vision-language checkpoint, and that profiling pass is the likely trigger.
imp_trace_bank.py and imp_eval_cot.py now run vision-language checkpoints text-only (limit_mm_per_prompt image=0, video=0),
which skips the vision encoder. Our prompts contain no images, so prompts, sampling and outputs are unchanged; text-only
models such as Qwen2.5 get no change at all.
