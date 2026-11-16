# Amendment: add the Juliet injection slice (J2) to the quick v2.3 trace bank — 2026-11-15

Owner-approved ("amend it, run"). Written before any J2 trace of the v2.3 bank exists and before any CoT arm has been
evaluated. The 1.5B, 1-epoch smoke runs of 15 Nov (tags `smoke_*`) are plumbing tests only: they are excluded from
every analysis.

## Why
- The pre-registered quick subset contains PrimeVul-derived pairs (pool A) and Juliet memory bugs (J), and no Juliet
  injection functions (J2).
- The v2.3 quick bank (4,575 traces, all schema v2.3) yields 33 traces that pass the whole chain
  (verdict, validator, CWE class, monitor). Arm 2's items are 223 SAFE / 27 VULNERABLE; arms 5 and 7 are empty.
- In the v2.3 pilot, J2 traces did pass the chain: command injection named the CWE class in 85% of traces, and 9 of
  14 command-injection witnesses were confirmed by execution (X_strict).

## Change
1. Generate a J2 slice with the SAME generator and decoding as the quick bank: Qwen2.5-14B-Instruct (`g14`),
   schema v2.3 guided JSON, 3-shot exemplars, k = 2 samples per function, plus the length-edit C pass. All 102 J2
   functions (51 vulnerable/fixed pairs). Output `results/imp_bankq_g14_j2.jsonl`.
2. When P35's monitor-confirmed synthetic SQLi items exist (`results/imp_train_sqli_items.json`), add a Q slice the same
   way (`results/imp_bankq_g14_q.jsonl`). The build marker records which slices went in.
3. Merge, X_strict, and item building are unchanged (`imp_bank_merge.py quick`, `imp_bank_strictx.py quick`,
   `imp_build_cot_items.py` with IMP_BANK=quick).

## Unchanged
Every arm and its recipe (P60/P61), the verdict-only twins on identical rows, the test sets and scorers
(selective for twins; SC-CoT generation for CoT arms; PrimeVul length-matched, VulSpot holdout and no-linux
length-matched, CASTLE, plus localisation for CoT arms and VulSpot pairs for arm 6), the 0.60 bar, the >2 SE rule over
length-only, SAST and the required baseline, and the audit before any claim.

## Note added 2026-11-15 17:50 AEDT, before any result of either build
An arm and its twin must come from one build. The first batch (arm 2, arm 2 twin, arm 6, arm 6 twin, on
Qwen2.5-7B (box) and Qwen2.5-14B (Spark)) is built from the quick subset + J2 only. The Q items are verified on the
box now (`imp_build_sqli.py`: spec-v2 sqli oracle, deduplicated against CASTLE) but are placed on Spark only after
that batch finishes. The build that then adds Q is stamped with its own slice list, and every arm is re-run with its
twin on it. Results are reported per build; arms are never compared with a twin from another build.

## Known limitation
J2 and Q are synthetic. Adding them changes the training mix, not the test sets: the tests stay real-world
length-matched sets plus CASTLE, so whether CoT learned from synthetic injection code transfers is exactly what they
measure. CASTLE is a separate benchmark from Juliet.
