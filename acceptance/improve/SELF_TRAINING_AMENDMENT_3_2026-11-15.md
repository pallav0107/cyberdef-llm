# Amendment 3: Qwen3.8-27B teaches itself, one monitor category at a time — 2026-11-15

Owner decision ("let Qwen3.8-27B teach Qwen3.8-27B and become better; improve category by category of monitor").
Written before Qwen3.8-27B has generated any trace and before its zero-shot baseline has finished.

## Model and recipe
- `Qwen/Qwen3.8-27B` (Apache-2.0), local weights on Spark. Never Qwen Cloud (its Customer Agreement, Models Supplemental
  2(d)(v), forbids training competing products on outputs). Thinking mode off for every prompt (`enable_thinking=False`,
  enforced by `cyberdef.chat_defaults`; a fail-first control checks it).
- Teacher = student = Qwen3.8-27B: rejection-sampling self-training (the model writes SC-CoT traces, filters keep only
  correct ones, the model trains on them). No hints: the model is never shown the answer while writing a trace.
- Training: the CI recipe, 4-bit QLoRA on Spark, LoRA r=16, alpha=32, target modules `q_proj k_proj v_proj o_proj
  gate_proj up_proj down_proj` (identical by name to the Qwen2.5 recipe). On Qwen3.8 that adapts its 16 full-attention
  layers and all 64 MLPs; the 48 linear-attention layers' projections are not adapted. Epochs 2, lr 1e-4, seed 0,
  max-chars 4000, pair batches as arm 2.
- Generation: schema v2.3 guided JSON, 3-shot, k = 4 samples per function, temperature as the trace bank, plus the
  length-edit C pass.

## Categories, in this order
command injection, path traversal, SQL injection, format string, memory (asan), integer, leak (lsan), resource, race (tsan).
Order rule: injection classes first because that is where batch 1 showed signal (CASTLE CWE-78 base 0.67 -> twin 0.92,
n = 7, and the gain ran against the length direction).

## One round of one category
1. The CURRENT model (round 1: base Qwen3.8; round 2: the round-1 adapter) writes traces for that category's training
   functions: Juliet J/J2/J3 functions of its CWEs, Q for SQL injection (training split only), and pool A (real-world
   VulSpot pairs) functions whose true CWE is in the category.
2. Keep a trace only if: verdict correct (V), validator passes (P), CWE named correctly (K), monitor correct (O); for
   categories with an execution oracle (asan/ubsan, lsan, the behaviour monitors for injection), the vulnerable-function
   traces must also pass X_strict (the witness fires on the bad program, not on empty input, not on the fixed program).
3. Train an adapter on the kept traces, and a verdict-only twin on identical rows.
4. Test both, plus the base model, on that category's held-out tests (below).
At most 2 rounds per category. A category stops after round 1 if round 1 does not beat the base model on its primary test.

## Held-out tests per category (built before any training of that category; never used for training)
- Command injection, path traversal: `j3_heldout_matched_cases.json` (amendment 2c, per-CWE length-matched; CWE-78 128/128,
  CWE-23 91/91, CWE-36 69/69). PRIMARY.
- SQL injection: the 133 verified Q pairs are split now, `random.Random(0)`, 2/3 training (89 pairs), 1/3 held-out
  (44 pairs), stratified by nothing else; the held-out third is never trained on in this programme.
- Format string, memory, integer, leak, resource, race: a "J4" held-out set built like J3 (Juliet single-file flow
  variants not in any training pool, labels verified by the sanitizer or behaviour oracle, per-CWE length-matched as in
  2c). A category without a length-matchable held-out test is reported, but no claim is made for it.
- Transfer (SECONDARY, reported for every adapter): CASTLE per bug family; PrimeVul and VulSpot length-matched overall.

## Bar (per category)
An adapter improves a category only if, on that category's PRIMARY held-out test, it beats BOTH the base Qwen3.8 zero-shot
and its own twin by more than 2 SE (paired bootstrap), with length-only shown beside it. Transfer is claimed only from the
secondary sets under the same rule. Every category is reported, including nulls; no category is dropped from the report.

## Unchanged
The audit before any claim (recompute from per_case, experiment-auditor), never publish without the owner, and the earlier
amendments' rules for batches 1 and 2.
