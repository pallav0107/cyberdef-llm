# Pre-registration: supervised verdict-only fine-tune on real-world fix pairs (VSP-SFT round 1) — 2026-11-17 08:04 AEDT

Written and committed before any training for this round, and before ANY model has been scored on VSP-T.
- Owner decision (17 Nov): the supervised fine-tune is the next attempt. It follows the ceiling rule of 88808c1: the
  base was above 0.90 on Juliet, so the target moves to real-world code.
- An experiment-auditor reviewed the draft (COMMIT WITH CHANGES). Every change is applied below: rule 5b, the
  length-balanced within-pair veto, Holm with a fixed family size, full pinning, extra training seeds, bow_lr, label
  confidence, recency.

## Hypothesis
H: a 4-bit QLoRA verdict-only fine-tune of Qwen/Qwen3.8-27B on VulSpot before/after fix pairs (VSP-SFT) scores a
higher AUROC than the untrained Qwen3.8-27B on VSP-T, i.e. on fix pairs from projects it never saw. Both are scored by
the same verdict log-probability scorer (imp_selective), so there is no scorer confound.

## Data (pinned by full sha256)
- Source: data/vulspot/cpp/full/data.parquet
  f10454790c04da5e25fc11e71bc788c8ade01cd2d2a43f49e2957e6a75e9c6ed (VulSpot covered_through 2026-10-12, version.json);
  splits/project_holdout.json e44770fb669c270f0e4b7c7aa6d36a2a6dc7311e451000ef64151e9c4affb88e (clone-group project
  holdout, seed 13).
- Primary test VSP-T: results/vsp_t_cases.json 543c4346ed41dd8d254f6c82346a4a592cc9e62fa7a26da5dd038bb18f2f5185
  (commit 3680322).
  - 388 pairs from test_paired_high, 159 projects, at most 10 per project. Gate: check_vsp.py ALL PASS.
  - Length strata: the fixed side is longer in 324 pairs, the vulnerable side in 45; 19 are equal.
- Training VSP-SFT: results/vsp_sft_items.json 1b105c86f688b9ee6033fb3b19d51ab39d4c2cc29709ebdb0863824df07f714e.
  - 1,283 pairs from 365 projects (40 from linux), built by scripts/imp_build_vsp_train.py.
  - Sources: VulSpot TRAIN-split pairs (vulnerable row + fixed_func_idx row, both in train).
  - Comments stripped from both sides (the VSP-T stripper). V != S. Both sides < 4,000 chars, never truncated.
  - Excluded: VSP-T projects, VSP-T normalised hashes, and (rule 5b) forks or vendored copies of VSP-T projects
    (rizin, rz-libdemangle, radare2-mcp, libgd, openbsd, mysql-server, civetweb, turbovnc: 40 pairs dropped) and any
    pair with a side at token-set Jaccard >= 0.5 to a VSP-T function (8 dropped).
  - At most 40 pairs per project.
  - Label confidence (VulSpot): high 807 / medium 423 / low 53 pairs (63% / 33% / 4%). These are VulSpot labels, not
    our verification.
  - The fixed side is longer in 86.0% of training pairs.
  - Gate: acceptance/improve/check_vsp_items.py ALL PASS. It was written independently and proven to fail first. It
    re-derives labels and texts from the parquet (2,566/2,566 match), checks train split only, test overlap, NEAR_DUP
    and FORK_PROJECT (both added after the audit and proven to fire on the pre-5b set), bands, the cap and the floor.

## Runs (spark.yml, one commit)
- Adapters: tags vsp_sft_r1 (seed 0), vsp_sft_r1_s1 (--seed 1) and vsp_sft_r1_s2 (--seed 2), train + test.
  Data "VSP fix pairs, verdict-only (VSP-SFT, real-world)", CI recipe (4-bit QLoRA, 2 epochs, lr 1e-4,
  --val-per-class 5).
- Base: untrained Qwen/Qwen3.8-27B, test only.
- All use the selective scorer and the bundle "VSP-T real-world fix pairs (VSP-T, CASTLE, PrimeVul 300)".
- bow_lr: scripts/imp_bow_lr.py (TF-IDF 1-2-gram logistic regression, C=1, fit on VSP-SFT ONLY; check_bowlr.py). It
  scores VSP-T as a reference.

## Multiplicity (fixed family)
- The family is every self-training or fine-tuning attempt in this campaign: command injection r1 (scored, null),
  format string 1b (FAIL), and at most 4 more. This is the first of those 4, so m = 6.
- Bar 1 must hold at one-sided p < 0.05/6 = 0.0083, i.e. delta > 2.394 x SE (`--z 2.394`). Under Holm, a pass at
  alpha/6 stands whatever later attempts show. After 4 more attempts without a pass, the campaign stops (88808c1).

## Bar (ALL must hold). scripts/imp_verdict.py round (two arms, seed-0 adapter vs base), with
## --z 2.394 --cluster-bootstrap --cluster-by project --pair-veto --baselines length,lines,if_count,static_count
1. Adapter AUROC minus base AUROC on VSP-T > 2.394 x SE, under BOTH the case-level paired stratified bootstrap and
   the PROJECT-cluster bootstrap (10,000 resamples each, seed 0).
2. Length-balanced within-pair veto: the share of pairs where V scores above its own S (ties 0.5), averaged equally
   over the S-longer pairs (324) and the V-longer pairs (45), equal-length pairs excluded. Adapter minus base must be
   > 0. Length alone scores exactly 0.5.
3. The adapter beats each baseline (length, lines, if count, static count) by > 2.394 x SE under both bootstraps.
4. Training-seed replication: the seed-1 and seed-2 adapters each show a pooled delta > 0 and a within-pair veto
   delta > 0 against the same base.
- Inputs are per_case p_vuln at full precision (6f051c8). Headline numbers are never used.

## What a pass may claim (fixed now)
- Unless the within-pair delta's project-cluster 95% interval (pair_veto.ci95_cluster) excludes 0, a pass reads
  "pooled gain on unseen projects; the within-pair direction is not contradicted". It never says "detects the fix".
- Any wording beyond "beats the untrained base" requires adapter - bow_lr > 2 x SE (reported via --cross bow_lr).
- Win claims need a recompute from per_case and an experiment-auditor pass. The wording follows the auditor.

## Power (simulated on VSP-T's real project structure, synthetic scores, before any model was scored)
Case SE ~0.018-0.020 and project-cluster SE ~0.016-0.020, at base AUROC ~0.6. At 2.394 x SE the minimum detectable
gain is about 0.045-0.048 AUROC. A null rules out gains above about 0.05.

## Reported with the verdict (descriptive, never in the bar)
- Within-project AUROC (pair-weighted). Per-CWE and per-project tables.
- Sensitivity: the verdict recomputed without the VSP-T projects that have forks or vendored code in training before
  rule 5b (radare2, php-src, src, server, mongoose, cJSON, tigervnc).
- Recency: the delta on the 73 VSP-T pairs committed in 2025-2026 (possible pre-training contamination is lower
  there).
- Label confidence: the delta by VulSpot label_confidence.
- Output-format and training-loss diagnostics. CASTLE and PrimeVul-300 deltas (transfer). Hanley-McNeil SE. bow_lr.

## Disclosed state at the time of this note
- No model has been scored on VSP-T; no result file exists.
- Known numbers on other sets: Qwen3.8 selective base CASTLE 0.738 / PrimeVul-300 0.609 / J3s 0.875.
- The older VulSpot pair set (imp_vs_pairs_eval_cases) is defective and never cited.
- The training set was rebuilt once BEFORE any score, after the audit found fork and vendored-copy leakage (sha256
  78c9c44e… -> 1b105c86…).

## If the verdict is FAIL (next step fixed now; one variable per attempt; attempt 4 of 6 next)
- Training changed outputs but not ranking: diff-grounded self-training (architect candidate 1).
- Underpowered (wide intervals): more test pairs from test_high under the same rules, registered first.
- No training effect at all: the recipe (epochs, lr), registered first.

## Code (pinned)
Tooling 717a236 + 20e9072 (builders, gates, verdict with --pair-veto/--z/--within-cluster/--baselines, bow_lr); CI wiring 9f3e0de (data option, VSP-T bundle, manifest-pinned dataset branch). Every gate named above passes at these commits.

## Note, 2026-11-17 23:00 AEDT: round PAUSED at the owner's request (Spark needed for another job)
- Base (43956367153) and seed-0 adapter (43956384102) runs completed successfully. Their result files are saved on the box in results/vsp_r1/. The seed-0 VSP-T score has NOT been read.
- Seed 1 (43956401861) was cancelled during training; its orphaned container was stopped by ID and its partial checkpoint moved to out/before_restart_vsp. Seed 2 (43956419160) was cancelled before starting.
- Restart: re-dispatch seeds 1 and 2 with the identical recipe and bundle at a commit whose CI scripts equal 9f3e0de. Nothing in this pre-registration changes. The verdict is computed only when seeds 1 and 2 have finished.
