# Addendum 3d: SQL injection exemplars, written before its round — 2026-11-16 00:37 AEDT

Written before Qwen3.8-27B has written any SQL-injection trace, and before any model has been scored on the SQLi held-out set
in a self-training round. Follows the rule in addendum 3b §2. Nothing else changes.

## Exemplars
- The quick set has no SQL-injection exemplar. The round adds one VULNERABLE and one SAFE exemplar, templated by
  scripts/imp_build_st_exemplars.py from the ground truth of one SQLi TRAINING pair, `s17k1`
  (results/imp_train_sqli_train_items.json; not in the 44-pair held-out set). Its labels are oracle-verified: both halves
  compile with sqlite3; the vulnerable half fires the sqli oracle on a reference payload and not on benign input; the safe
  half fires on none.
  - E7 VULNERABLE: the stdin line is pasted between quotes into the query with snprintf and run by sqlite3_exec. The newline
    strip is shown as an insufficient guard. Witness `x' OR CANARY=CANARY --` on stdin, the oracle's reference form.
  - E8 SAFE: the fixed half. The query text is a constant with a `?` placeholder, and the title is bound with
    sqlite3_bind_text (the guard, marked sufficient). Witness null.
- The pool builder drops the pair from training: SQL injection goes from 92 to 91 pairs. The exemplar key is `sqli:s17k1:`,
  with a trailing colon so it cannot match another pair id such as s17k10.
- File results/imp_fewshot_exemplars_st_sqli.json, 5 exemplars (3 quick + E7 + E8), sha256
  c30bd6a0f009fa860aab54e396cd27eb557bb408af3d8cd69081eec9dd285a4f, pinned in the data manifest.
  ci_exemplar_leak.py passes against every test set (SQLi held-out: 88 cases, 0 shared).
- The validator does not move. A VULNERABLE witness without CANARY, a SAFE trace whose bind is marked insufficient, and a
  SAFE trace with a payload witness are each rejected on these exemplars. The command-injection and path-traversal
  exemplar files are byte-identical after this change.

## Reported either way
SQL injection round 1: traces, the funnel per class, kept functions, and whether the >= 20 per class floor is met. Primary
test: the SQLi held-out set (44 pairs). Its length-only AUROC is 0.67, so every result on it is reported next to that number
and judged against it as well as the 2 SE bar.
