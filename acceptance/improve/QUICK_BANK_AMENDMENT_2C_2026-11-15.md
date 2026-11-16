# Amendment 2c: a per-CWE length-matched version of the J3 held-out test — 2026-11-15

Written before any result on the J3 held-out sets exists (no model has been scored on them).

## Why
The first per-class table on `j3_heldout_cases.json` (amendment 2b) showed that length alone separates its classes:
format string (CWE-134) 0.989, path traversal (CWE-23) 0.592, command injection (CWE-78) 0.561, CWE-36 0.536. In Juliet the
safe text keeps both good functions (goodG2B, goodB2G) while the vulnerable text has one bad function, so lengths differ
systematically per CWE. A per-class result on the unmatched set could be a length shortcut.

## The set
`results/j3_heldout_matched_cases.json`, built by `scripts/imp_build_j3_matched.py` from `j3_heldout_cases.json`: within
each CWE, 10 code-length quantile bins; in each bin an equal number of vulnerable and safe functions drawn with
`random.Random(0)`. A CWE is kept only if its matched subset has length-only AUROC in [0.45, 0.55] (characters and tokens)
and at least 20 functions per class. Result: CWE-78 128/128 (length-only 0.500), CWE-23 91/91 (0.503), CWE-36 69/69
(0.522); CWE-134 is dropped (only 21/21 matchable, length-only 0.435). 576 functions.

## How it is used
- The matched set is the PRIMARY per-class test for batch 2; the unmatched held-out set (2b) stays, as secondary, always
  shown next to its per-class length-only AUROC.
- Both are reported as in-distribution, never as transfer.
- Training data note (not changed here): the Juliet pools carry strong per-CWE length differences in both directions (e.g.
  J2 command injection 0.94, J2/J3 format string 0.02-0.09). Whole arms are balanced (arm 2 items 0.53), but a model could
  learn a CWE-conditional length rule. The matched test is what detects that.

## Unchanged
Everything else in amendments 1, 2 and 2b.
