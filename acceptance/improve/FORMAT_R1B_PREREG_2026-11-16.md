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

## Note, 2026-11-16 19:17 AEDT: a conditional larger primary test (J3s ∪ J5f) and a cluster bootstrap. Written before any round 1b score
Revised after an independent experiment-auditor review (verdict: commit with changes, all applied here).

Why: J3s has 122 functions, so only a gain of roughly 0.10-0.14 AUROC can pass. The owner asked for larger fair test
sets (16 Nov). Every verified single-file, input-driven Juliet CWE-134 case is already used. J5f therefore comes from
the MULTI-FILE CWE-134 cases.

### 1. Freeze deadline (what makes the timing verifiable)
J5f enters the primary test only if BOTH of these are pushed to origin/main before the first round-1b per_case file
exists for any set: the commit with scripts/imp_build_juliet5f.py and its output, AND the commit recording the J5f
matched set's sha256. The evidence is GitHub's push time against the round-1b test step's start time (run logs) and the
result files' mtimes. If the deadline is missed, the primary is J3s alone. No model, the 14B models included, is scored
on any J5f pair before the deadline.

### 2. J5f validity (one reading only)
J5f is valid iff ALL of these hold:
- acceptance/improve/check_j5f.py, as committed with this note (sha256 562e4f8b8377b494…), prints ALL PASS. This includes >= 300 verified pairs.
- imp_build_structure_matched.build() builds it without refusing.
- The checks in section 4 pass.
- At least 100 functions remain.
Any rebuild, bug fix or rule change after the deadline means the primary is J3s alone.

### 3. J5f construction (fixed now)
- Pairs: scripts/imp_build_juliet5f.py.
  - Input: multi-file Juliet CWE-134 cases with console / environment / file input (no socket, no w32), .c and .cpp.
  - Verification: the J3 rule. The payload fires the bad program; benign input, empty input and the good program with
    the payload do not.
  - Text: the parts joined in letter order, then imp_clean.clean_code (3g).
  - Exclusions: texts over 4,000 chars are dropped (never truncated); texts with label text are dropped; stems used
    anywhere else are dropped.
- Additional exclusion: stems matching `_2[12]$`, the static-flag flow variants that build() drops for J3s/J4s by file
  name.
- Prototype pruning, applied to BOTH labels before normalise(): a prototype line in the text that declares an fn_N
  never defined in that text is removed. one_good() keeps only the chosen variant, so without this, SAFE texts alone
  would carry declared-but-undefined prototypes.
- Set: imp_build_structure_matched.build(pairs, "j5f", "results/j5f_heldout_matched_cases.json", note), with:
  - one_good() / one_bad() (3m);
  - per-CWE length-decile matching with random.Random(0);
  - the [0.45, 0.55] bands on length, function count and static count;
  - the 3m artefact refusal.
  The prototype pruning is an optional post-processing hook in build(); the default is None, so J3s/J4s are unchanged.

### 4. Cue checks, run on J5f AND on U = J3s ∪ J5f without re-matching (any failure means J3s alone)
- Length, function count and static count: AUROC (either direction) in [0.45, 0.55].
- Every one of these at or below 0.60: the last line; any preprocessor or `return 0;` line; the number of
  declared-but-undefined prototypes; the number of calls to an fn_N that is neither declared nor defined before the
  call; and the number of parts.

### 5. Primary test and bar (U if J5f is valid and frozen in time; else J3s alone)
- AUROC on U counts only vulnerable-safe pairs from the SAME set:
  sum over sets of n1*n0*AUROC_set, divided by the sum of n1*n0.
  The paired bootstrap is stratified by set x label, and the baselines are computed the same way. A model that only
  scores the two sets on different scales gains nothing.
- The bar (unchanged) must pass under BOTH resampling schemes:
  - the case-level paired bootstrap;
  - a CLUSTER bootstrap, cluster = Juliet source x sink x char type, shared across J3s and J5f (10,000 resamples,
    seed 0).
  Each uses the 3k decode-noise term with K=3 shuffled decodes. There are only ~15-36 clusters: the cluster SE is the
  honest one for templated Juliet code. The cluster requirement also applies to the J3s-alone fallback. That is
  stricter than the original registration and never looser.
- The adapter must beat the CoT base AND the twin by more than 2 x the combined SE, and beat the length, function-count
  and static-count baselines by more than 2 SE, all on the primary set.
- J3s is ALSO judged under its original bar (case bootstrap), and that verdict is reported. A win is claimed only if
  the primary passes under both schemes.
- Components are reported, never as separate passes: J3s alone and J5f alone.

### 6. Scoring parity
J5f is scored in later test-only runs after a CI change. That change touches only the set key, the bundle and K=3 for
j5f; its diff is recorded. The runs use the SAME adapter and twin checkpoints (sha256 from the round-1b provenance), the
same base model revision and the same scorer files (sha256 equal to the J3s runs). Any mismatch means J5f is reported
descriptively and the primary is J3s alone.

### 7. Disclosed state at the time of this note
- No round 1b model exists. The adapter is retraining; its first dispatch was cancelled during training, before any
  test.
- Neither Qwen3.8 base nor any format-string adapter has been scored on J3s, old or rebuilt.
- One Qwen3.8 adapter WAS scored on a set that shares source pairs with J3s: command injection round 1 on J3m (the old
  J3 matched set, which includes CWE-134 pairs). That score was reported with the command-injection null.
- The 14B base and twin seeds are being scored on the rebuilt J3s for the twin replication. Their J3s scores have not
  been read; only key coverage was checked.
- J5f does not exist yet. Its builder (Kimi) started at 19:05.
