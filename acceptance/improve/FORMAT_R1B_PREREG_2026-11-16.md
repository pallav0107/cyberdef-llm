# Pre-registration: format string round 1b (rebuilt pool, addendum 3m) — 2026-11-16 16:31 AEDT

Written and committed before round 1b generates any trace, and before any model has been scored on the rebuilt J3s.

## Why 1b
Format string round 1 (addendum 3l) is VOID: its pool carried the one-label artefact tail of addendum 3m (last line
AUROC 0.971). Round 1b repeats it on the rebuilt pool, under exactly the rules of 3l. Nothing from round 1 is trained or
used. Seen before this note, as a diagnostic on the leaky pool only (hope document, 16:22):
- verdicts right 92% (vulnerable) / 91% (safe);
- 299 execution-confirmed witnesses;
- 89 items per class.
No rule below was changed after seeing it.

## Pool (scripts/imp_st_pool.py format_string --structure --cap 250, as 3l, with 3m's one_bad)
- results/st_pool_format_string.json, sha256 92b12c5f2210c6e1f3c489fc8def63470a7968f9d0a1266eeb10071d93d914d7.
- 104 pairs: 98 Juliet (juliet2 15, juliet3 83) + 6 real-world. 71 dropped by the structure rule, 1 exemplar-file pair
  dropped, 1 normalised held-out collision dropped.
- Cues, all 208 texts (Juliet only in brackets): length 0.706 (0.732); function count 0.532 (0.536); static 0.500;
  last line 0.500; artefact line 0.500.
- Length still separates labels, because the vulnerable function carries the input-reading code (3l caveat). The
  rebuilt J3s is length-matched (0.510), so this cue cannot earn test credit. It is reported with every result.

## Rules (unchanged from 3a/3j/3k/3l)
- Qwen3.8-27B base. imp_st_round.sh format_string 1b. k=4, --skip-c, exemplars results/imp_fewshot_exemplars_st_format_string.json
  (3f), gpu-util 0.55 with the memory guard.
- Items: vulnerable V∧P∧K∧O plus X_strict where it applies; safe V∧P. Within-source balancing (3k). Floor of 20 per
  class, else "insufficient correct traces", with no rescue.

## Bar (3l, on the rebuilt sets)
- Primary: J3s as rebuilt under 3m (122 functions, CWE-134, sha256 d0eefc70…). The CoT adapter st_format_string_r1b
  must beat the Qwen3.8 CoT base AND the twin st_format_string_r1b_twin by more than 2 x the combined SE.
  - The SE is the paired stratified bootstrap (10,000 resamples, seed 0) plus the 3k decode-noise term.
  - CoT-scored models are decoded K=3 times in shuffled order (ci_step.sh, deployed in 36d4f34).
  - The adapter must also beat the length, function-count and static-count baselines by more than 2 SE.
  - Computed by scripts/imp_verdict.py round. Its acceptance check fails first.
- Reported alongside: Hanley-McNeil SE; balanced accuracy; the cue baselines (`printf(data);` line 0.631; the "%s"
  count); the cross cells (3k M1) where they can be run.
- Secondary: CASTLE and PrimeVul-300.
- No win is claimed without a recompute from per_case and an experiment-auditor pass. J3s has 112-122 functions
  (SE ~0.05): a null is weak evidence, and that will be said.

## Note, 2026-11-16 19:03 AEDT: test-set bundle narrowed to the format-string sets, before any round 1b score
The first dispatch (16 Nov 18:04, runs 43821211903 / 43821223400 / 43821234530 / 43821246008) used the bundle
"amendment 3i round sets", which puts J4s first. With 3 CoT decodes, J4s (2,166 memory/integer/leak functions) would
have cost ~10 h per CoT-scored model before J3s was reached. J4s is not part of this round's bar: the bar is J3s, with
CASTLE and PrimeVul-300 secondary.
All four runs were cancelled at 19:00, during the adapter's training. No test step had started and no score exists.
- The orphaned training container was stopped, and the partial checkpoint was moved to out/before_restart_r1b. The
  adapter retrains from scratch.
- The runs are re-dispatched with the new bundle "format string round sets (J3s, CASTLE, PrimeVul 300)".
- Nothing else changes: same items (sha 0f2b80b2… / 31499936…), same tags, same recipe, same scorer, same bar.
