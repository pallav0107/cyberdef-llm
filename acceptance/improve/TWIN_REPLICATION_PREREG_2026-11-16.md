# Pre-registration: does the 14B verdict-only twin beat its untrained base? A confirmatory test — 2026-11-16 00:52 AEDT

Written after one exploratory observation and before any confirmatory data exists. Commit this file to git before the
confirmatory runs start; the experiment-auditor flagged that acceptance/ files are untracked and their mtimes can be changed.

## What was seen (exploratory; it is NOT evidence for this test)
On CASTLE (n=198), the batch-1 14B twin (adapter out/imp_cot2t_j2_14b, seed 0) scored 0.694 against 0.656 for the untrained
Qwen2.5-14B-Instruct. That is +0.038, paired bootstrap SE 0.018 (2.1 SE, uncorrected p ~ 0.03). It is NULL under the plan's
pre-registered unpaired Hanley-McNeil SE (Δ/SE = 0.70). The base was run on CASTLE only, after the twin's results were
visible. There is no gain at 7B. The auditor's verdict was PLAUSIBLE / exploratory. CASTLE is therefore EXCLUDED from the
confirmatory family below: it is where the effect was found.

## Hypothesis
H1: the 14B verdict-only twin recipe (CoT arm 2's rows, verdict only, J2 build) scores a higher AUROC than the untrained
Qwen2.5-14B-Instruct on held-out code it has not seen.

## Confirmatory sets (chosen now; no model has been scored on either)
1. J3 matched (results/j3_heldout_matched_cases.json, 576 functions, sha256 18f62ac9…; addendum 2c as rebuilt in 3b).
2. J4b matched (results/j4_heldout_matched_cases.json as rebuilt under addendum 3e: memory, integer and leak; written
   before this test runs; its sha256 is recorded in 3e).

Both sets are scored with the same scorer (imp_selective), commit, machine and precision for every arm.

## Arms
- Base: untrained Qwen2.5-14B-Instruct.
- Twin seed 0: out/imp_cot2t_j2_14b (already trained; never scored on either set).
- Twin seeds 1, 2, 3: the identical recipe and rows, `--seed 1/2/3`, trained on the box. These need Spark back up: the
  Dataset step verifies the CoT build against Spark.

## Bar (all must hold)
- Per set, the seed-0 twin minus base > 2 × the paired stratified bootstrap SE (10,000 resamples, seed 0). The unpaired
  Hanley-McNeil Δ/SE is reported next to it.
- Holm correction over the family {J3 matched, J4b matched}: the larger p must be < 0.05 and the smaller < 0.025, with
  one-sided p from the paired bootstrap.
- Seeds 1-3: the mean Δ over seeds 0-3 is > 0 on both sets, and no seed has Δ < −2 SE.
- On each set the twin also beats that set's length-only AUROC (both directions) by > 2 SE.
If any part fails, H1 is not supported. That is reported as a null, with every number.

## Also run, descriptive only (not part of the bar)
- The untrained 14B on PrimeVul, VulSpot holdout and VulSpot no-linux (pre-registered sets), so twin vs base can be read on
  every set the twin was scored on.
- A repeat of the untrained 14B on CASTLE, to measure run-to-run evaluation noise (the auditor: determinism unmeasured).

## Note, 01:14: confirmatory set hashes (before any confirmatory run)
Addendum 3g cleaned Juliet label text out of J3 and J4b. J3 matched is now 780 functions, sha256 46afd0127b161a16…; J4b
matched is 772 functions, sha256 a977fb0b16810083…. These cleaned sets are the confirmatory sets. No arm has been scored on
any version.

## Note, 06:52: confirmatory sets changed to J4s and J3s (addendum 3i), before any model was scored on them
J3 matched and J4b matched carry a structural shortcut: function count alone scores 0.975 / 0.956. They cannot test H1.
The confirmatory family is now {J4s (2,122 functions), J3s (112 functions)}, with the same bar and Holm over the two. Disclosed:
the J3-matched AUROC of seed 0 (0.949, against 0.672 for the untrained base) was seen before this note; that jump is how the
shortcut was found. No model has been scored on J4s or J3s.

## Note, 2026-11-16 15:34 AEDT: confirmatory sets rebuilt under addendum 3m, before any model was scored on the rebuilt sets
The 3i versions of J4s and J3s carried a perfect label leak: the last line of every VULNERABLE text was leftover main()
code (AUROC 1.000). They cannot test H1. The confirmatory family is now {J4s, J3s} as rebuilt under addendum 3m:
- J4s: 2,166 functions, sha256 81669e11…;
- J3s: 122 functions, sha256 d0eefc70….
The arms, scorer, bar and Holm correction are unchanged. The verdict is computed by scripts/imp_verdict.py twinrep,
whose acceptance check proved it fails first. The seed bar needs all of seeds 0-3.

Disclosed: on the leaky 3i versions the following were seen before this note: base 0.705 (J4s) / 0.6553 (J3s), and
seed-0 twin 0.6914 / 0.8645. Seed 1 also ran on them; it is void and is not used. Seeds 2 and 3 were cancelled before
they ran. Every arm (base, seeds 0-3) is re-scored on the rebuilt sets from one commit.
Caveat: the twin's training rows (CoT arm 2, J2 build) may carry a weaker form of the same cue. The rebuilt tests no
longer reward it.
