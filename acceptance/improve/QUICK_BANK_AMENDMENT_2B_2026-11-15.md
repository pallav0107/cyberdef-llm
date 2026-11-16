# Amendment 2b: a held-out per-class test set from J3 — 2026-11-15

Owner-approved. Written before the held-out file is built and before any batch-2 result exists.

## Why
CASTLE has only 6-9 programs per CWE, so a class-level effect cannot be confirmed there: one CWE's AUROC has a standard
error of roughly 0.15-0.2. On batch 1, the 7B twin moved from 0.67 (untrained base) to 0.92 on CASTLE command injection
(CWE-78, n = 7), and arm #1 scored 0.77-0.88 on integer overflow and leaks where the base sits near chance. Those are hints,
not findings. A held-out test with ~100x the programs per class can tell whether CoT training teaches a bug class at all.

## The set
`results/j3_heldout_cases.json`: every verified J3 pair (`imp_train_juliet3_items_all.json`, 1,341 pairs) that was NOT
drawn into the 500 training pairs (`imp_train_juliet3_items.json`): 841 pairs, both the vulnerable and the fixed text of
each (1,682 functions). Same CWEs (78, 134, 23, 36), same verification. No function in it appears in any training pool.

## How it is used
- Added to the pre-registered test sets for every batch-2 arm and twin, scored with the same scorer as the other sets.
- Reported overall and per CWE, with Hanley-McNeil SE, and always as IN-DISTRIBUTION (same benchmark family and CWEs as
  J3 training, different flow variants). It is never reported as transfer; CASTLE and the real-world length-matched sets
  remain the transfer tests.
- Its length-only AUROC is reported next to every result (the pairs are a function and its fix, so length is close but
  not matched by construction).

## Unchanged
Everything else in amendments 1 and 2: arms, recipes, twins, the other test sets and scorers, the 0.60 bar and the > 2 SE
rule over the required baselines, and the audit before any claim.
