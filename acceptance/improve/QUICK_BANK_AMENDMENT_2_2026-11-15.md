# Amendment 2: the batch-2 quick bank adds Juliet flow variants (J3) and synthetic SQLi (Q) — 2026-11-15

Owner request ("improve the dataset for the things this training is missing"). Written before the J3 pairs are
verified, before any J3 or Q trace exists, and before any CoT arm of batch 1 has been evaluated.

## What batch 1 lacks (measured on the J2 build, 17:57)
- J2 uses only Juliet flow variant `_01` (the simplest control flow): 102 candidates, 51 verified pairs. The model never
  sees the bug behind an if/loop/goto/switch, or passed through copies, helper functions, pointers or globals.
- 25 traces are confirmed by execution (X_strict); arm 7's pre-registered gate needs >= 200.
- Synthetic SQLi (Q) has 133 verified pairs on the box that are not in the bank yet.
- Integer, leak, race and resource categories have 0-1 usable traces. That is a teacher weakness (the 14B names the CWE
  in 6-19% of traces there), which more Juliet data does not fix; a stronger teacher is a separate, later amendment.

## Batch-2 bank (generator, decoding, k and the C pass unchanged: Qwen2.5-14B `g14`, schema v2.3, 3-shot, k = 2)
1. Quick subset + J2 (as batch 1).
2. **J3**: `scripts/imp_build_juliet3.py`, the J2 recipe unchanged (same CWEs 78 / 134 / 23 / 36; console, environment or
   file sources; no socket or Windows variants; a pair is kept only if the reference payload fires on the bad version and
   not on benign input, empty input, or the good version) over the single-file flow variants `_02`-`_22` and `_31`-`_45`
   (2,754 candidate files). **Cap: 500 verified pairs**, drawn with `random.Random(0)`, stratified by (CWE, flow variant),
   proportional allocation by largest remainder. The full verified set is kept as `imp_train_juliet3_items_all.json`.
3. **Q**: the 133 verified synthetic SQLi pairs (`imp_build_sqli.py`; spec-v2 sqli oracle; deduplicated against CASTLE).

## Batch order
- Batch 1 is cut to arm 2 and its twin on the J2 build. Arm 6 is not run on the J2 build; it runs in batch 2.
- Batch 2: arms 2 and 6 with their twins on the batch-2 build, on both machines. Arm 7 (execution-grounded) and its twin
  are trained only if the pre-registered arm-7 gate (>= 200 X_strict traces) passes on the batch-2 build.
- Results are reported per build. An arm is never compared with a twin from another build.

## Unchanged
Arm recipes (P60/P61), twins on identical rows, test sets and scorers, the 0.60 bar, the > 2 SE rule over length-only,
SAST and the required baseline, and the audit before any claim.

## Known limitation
J3 and Q are synthetic, so batch 2's training mix is more synthetic than batch 1's. The test sets do not change: whether
CoT learned on synthetic injection code transfers to real-world length-matched code and to CASTLE is what they measure.
