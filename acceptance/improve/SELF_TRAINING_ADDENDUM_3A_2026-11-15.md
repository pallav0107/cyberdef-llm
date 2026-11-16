# Addendum 3a: how a self-training round turns traces into items, and what each round is tested on — 2026-11-15

Written before Qwen3.8-27B has generated any trace. Fills in details amendment 3 left open. Nothing in amendment 3's bar
or held-out tests is relaxed.

## Items (scripts/imp_st_items.py)
- Pool: `results/st_pool_<category>.json` (scripts/imp_st_pool.py): vulnerable functions whose true CWE is in the category,
  each with its fixed partner, from pool A, J, J2, J3 (training 500) and the SQLi training split. Pool sizes at writing
  (pairs): command injection 126, path traversal 270, SQL injection 92, format string 177, memory 643, integer 121, leak 65,
  resource 47, race 17. The builder refuses any function that appears in a held-out test.
- A vulnerable trace is kept only if V, P, K and O hold, and X_strict holds wherever the execution check applies (X_strict is
  None where no oracle covers the function, e.g. real-world pool A; there V+P+K+O decides). A safe trace is kept only if V
  and P hold. The validator is the pre-registered one, unchanged.
- One trace per function: the first kept sample in sample order, an execution-confirmed one preferred for vulnerable
  functions. Classes are balanced by drawing the larger class down to the smaller one with `random.Random(0)`.
- A round with fewer than 20 items per class is NOT trained. It is reported as "insufficient correct traces" for that
  category and round, and the programme moves to the next category. (Dry run on 14B-written traces for command injection:
  10 vulnerable functions kept, all execution-confirmed, 0 safe: safe traces failed the validator, mostly "a
  command-injection witness must contain the literal token CANARY". The validator is not changed.)

## Generation and training
- Generation: `imp_trace_bank.py --pools ST:<category> --model Qwen/Qwen3.8-27B --gen g38r<round> --k 4`, round 2 with
  `--adapter` = the round-1 CoT adapter; schema v2.3 guided JSON, the quick bank's few-shot exemplars, max-model-len 12288,
  gpu-util 0.65 (a 27B model needs it; 0.40 was set for the 14B). Then the execution check (imp_bank_strictx.py) on a copy.
- Training: the CI recipe without `--pair-batches` (filtering does not keep pairs together): epochs 2, lr 1e-4, max-chars
  4000, seed 0, val-per-class 5. The twin trains on the identical rows, verdict only. Both on Spark.

## What each round is tested on
- Every adapter (CoT and twin) and the base model: the category's primary held-out test, CASTLE, and the 300-case
  length-matched PrimeVul sample.
- The full PrimeVul and VulSpot length-matched sets: for adapters that pass their category bar, and for the final adapter
  of each category. (Compute: a 27B CoT evaluation of all transfer sets takes hours per adapter. Every adapter's primary,
  CASTLE and 300-case results are reported, nulls included.)

## Held-out status at writing
- J3 matched (command injection 128/128, path traversal 91/91 and 69/69) and the SQLi held-out (44 pairs) are ready.
- J4 (memory, integer, leak): 451 pairs execution-verified, but after per-CWE length matching only CWE-121 (24/24) remains;
  integer bugs rarely fire on empty input, and leaks were never detected because the inherited sanitizer pattern lacks
  "ERROR: LeakSanitizer". Before the memory, integer or leak rounds, J4 is fixed and re-matched under a further addendum;
  until then those categories have no primary test and no claim is made for them.
