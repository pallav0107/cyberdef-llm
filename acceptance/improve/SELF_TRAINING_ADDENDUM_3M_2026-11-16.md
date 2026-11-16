# Addendum 3m: a perfect label leak in J4s, J3s and two pools; sets rebuilt, format-string round 1 voided — 2026-11-16 15:21 AEDT

(Header time corrected before commit: a draft said 16:20, a guess; the file was written at 15:21:30 box time.)

Written before any model has been scored on the rebuilt sets, and before format-string round 1 has built items, trained,
or been scored. Found by an independent experiment-auditor pass (its finding B0) and verified from the files.

## The leak
- Every VULNERABLE text in J4s and J3s ends in leftover main() code (`return 0;` ... `#endif`). Every SAFE text ends in `}`.
  - The last line alone predicts the label with AUROC 1.000 on J4s (2,122 functions) and on J3s (112).
  - The line `return 0;` scores 0.979 on J4s and 1.000 on J3s; `#endif` scores 0.972 on J4s.
  - The structural controls of 3i (length, function count, static count) could not see it.
- It also reaches two training pools built with `--structure` (3j/3l): st_pool_format_string 0.971 (sha 8e82e5f5…) and
  st_pool_memory 0.860 (sha 2adf7794…). The earlier CoT arm-2 items carry a weaker form: imp_cotq_2_items and their twin
  items, 0.755.
- Cause: removing the `#ifdef INCLUDEMAIN … #endif` block stopped at an inner `#endif`. one_good() rebuilds each SAFE text
  from its function bodies, so the leftover survived in VULNERABLE texts only.
- Not affected (scan of every cases, pool and items file): CASTLE, PrimeVul (all builds), VulSpot, J3/J4 matched,
  Q held-out, and the cmd-injection, path, SQLi, integer, leak, race and resource pools. On those, the best last-line
  string scores <= 0.61, and the residue is the known length/truncation pattern of the raw sets.

## Consequences (recorded before any rebuilt-set score exists)
1. J4s and J3s as built under 3i are NOT fair tests. Every score on them is void as evidence. Seen before this addendum:
   Qwen2.5-14B base 0.705 (J4s) / 0.6553 (J3s); 14B twin seed 0 0.6914 / 0.8645. The result files are kept and renamed
   *.before_3m.json, and are never cited as results.
2. TWIN_REPLICATION: its confirmatory family {J4s, J3s} was leaky. Re-run on the rebuilt sets with the same arms and the
   same bar. Disclosed: the leaky-set numbers above were seen. The leak is a defect of the sets, not a choice made
   after seeing an outcome. Seeds s2 and s3 were cancelled before they ran. Seed s1 finishes on the leaky sets, and its
   result is void.
3. Format-string round 1 is VOID: a data defect found before items, training or any score. It is re-run as "format string
   round 1 (rebuilt pool)" from a pool rebuilt under this addendum, under exactly the rules of 3l. Its traces from the
   leaky pool are never used.
4. Memory round 1 (pool 0.860) was never trained. Its recorded outcome ("insufficient correct traces") stands, and its
   traces are never used.
5. Any model trained on items with the leak (CoT arm 2, imp_cotq_2) may have learned the cue. The rebuilt tests no longer
   reward it. This is stated as a caveat next to those models' results.

## The fix (stricter; nothing relaxed)
- scripts/imp_build_structure_matched.py:
  - one_bad() rebuilds every VULNERABLE text exactly as one_good() rebuilds SAFE ones: the prefix plus every function,
    joined. Non-function leftovers are dropped from both labels.
  - The builder REFUSES any set in which the last line, or any preprocessor or `return 0;` line, predicts the label above
    0.6 in either direction (artefact_cue). Fail-first: the old sets give 1.000 (last line) and 0.979 / 1.000 (artefact
    line), so they are refused.
  - `--out-dir` builds to a staging directory.
- scripts/imp_st_pool.py `--structure` uses one_bad() for the vulnerable text. Pairs it cannot parse are dropped and
  counted.
- A CI control (ci_data_hygiene) gains the same artefact-cue check on every test set and pool, and fails above 0.6. It is
  deployed with the rebuilt sets.

## Rebuilt sets (same builder, same inputs, same matching bands as 3i)
- J3s: 122 functions (61 per class, CWE-134). sha256 d0eefc70b52bad84c3a21e51a462cc2f87d2f5eeb6d895d86e441e1a165198ce.
  Length-only 0.510, function-count 0.505, static 0.523, last line 0.500, artefact line 0.549.
- J4s: 2,166 functions. sha256 81669e115854d7fd0a7d32fbf0db123c0cc0b38c6535dd9472568cd06f67fbb2.
  - CWE-121/122/124/126/127/415/416 (memory), 190/191 (integer) and 401 (leak). Last line 0.500, artefact line 0.507.
  - CWE-369 is no longer kept: its static-count baseline is 0.554, outside the 3i band [0.45, 0.55]. That is the
    unchanged rule applied to the rebuilt texts.
- Remaining single-line cues, declared and reported with every result (cue baselines, 3k M3):
  - J4s: `else` 0.630; "Benign, fixed string" 0.625; `data = dataBuffer - 8;` 0.606.
  - J3s: `printf(data);` 0.631. That line is the bug itself.
- The rebuilt sets replace the old ones under the same file names. Every arm in every comparison is (re-)scored on them.
