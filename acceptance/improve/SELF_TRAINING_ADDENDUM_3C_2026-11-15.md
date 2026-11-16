# Addendum 3c: path traversal exemplars, written before its round — 2026-11-15 23:52 AEDT

Written before Qwen3.8-27B has written any path-traversal trace, and before any model has been scored on the J3 held-out sets.
Follows the rule in addendum 3b §2. Nothing else changes.

## Exemplars
- The quick set has no path-traversal exemplar, vulnerable or safe. The round adds both, templated from Juliet ground truth
  (no model, no commercial model, no CASTLE case) by scripts/imp_build_st_exemplars.py:
  - E5 VULNERABLE: a stdin line is appended to BASEPATH and opened (FOPEN). The only check bounds the length (shown as an
    insufficient guard). Witness `../../CANARY/x` on stdin: the form the execution oracle confirms (an open with `..`
    components and the token).
  - E6 SAFE: the good half of the same file. The path is BASEPATH plus the literal `"file.txt"` (the guard, marked
    sufficient); witness null.
- Source file: `CWE23_Relative_Path_Traversal__char_console_fopen_02.cpp`. This is a J3 TRAINING file, in no held-out test: no
  single-file Juliet path-traversal source is outside both the pools and the tests, except one CWE-36 file. The pool builder
  drops it from training: path traversal goes from 270 to 269 pairs. Other flow variants of the same file family are in the
  J3 held-out test, exactly as other variants are in J3 training: that is J3's design (an in-distribution, per-class test by
  flow variant), and an exemplar from a training file adds no exposure that training on that file does not.
- CWE: J3's CWE-23 and CWE-36 functions are recorded in imp_true_cwe.json as CWE-22, the allowed parent. The schema rejects 23
  and 36 ("vuln_class cwe 23 not in the allowed list"), so both exemplars use CWE-22, and K/O can be met.
- File results/imp_fewshot_exemplars_st_path_traversal.json, 5 exemplars (3 quick + E5 + E6), sha256
  b6519af3e498e607bbc22880371e3c5637b72b0bfb8c63fecb7fa1023b3551c0, pinned in the data manifest.
  ci_exemplar_leak.py passes against every test set.
- The validator does not move. A VULNERABLE witness without CANARY, a SAFE trace with a payload witness, and CWE-23 are each
  rejected on these exemplars.

## Reported either way
Path traversal round 1: traces, the funnel per class, kept functions, and whether the ≥ 20 per class floor is met. Primary
test: J3 matched, CWE-23 (91/91) and CWE-36 (69/69) reported separately, each next to its length-only AUROC.
