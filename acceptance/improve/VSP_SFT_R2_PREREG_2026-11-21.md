# Pre-registration: pair-contrastive, length-balanced fine-tune on real-world fix pairs (VSP-SFT round 2, attempt 4 of 6) — 2026-11-21 01:01 AEDT

Written and committed before any pilot or final training for this round. No model trained under this recipe has been
scored on any set. The round-1 pre-registration (VSP_SFT_R1_PREREG_2026-11-17.md) is a pinned contract and is not
edited; this note supersedes only its "If the verdict is FAIL" next-step line, as disclosed below.

## Hypothesis
H: a 4-bit QLoRA fine-tune of Qwen/Qwen3.8-27B trained on VulSpot fix pairs with pair-batched updates (each optimiser
micro-batch is one vulnerable function and its own fix), an added pairwise margin term, and a shuffled sampler that
gives equal weight to pairs where the fixed side is longer (stratum A) and pairs where the vulnerable side is longer
(stratum B), raises the length-balanced within-pair rate on VSP-T AND the pooled AUROC above the untrained base, with
the same verdict log-probability scorer (imp_selective). Under equal stratum weight a length-only rule earns zero net
gradient, mirroring bar 2.

## Why this recipe (from round 1; adaptive, disclosed)
- Round 1 (3 seeds, experiment-auditor VALID): pooled AUROC 0.570 -> 0.630 / 0.652 / 0.639 (bars 1, 3 pass); length-
  balanced within-pair veto 0.662 -> 0.612 / 0.657 / 0.611 (bars 2, 4 fail). Auditor mechanism: the gain removed
  function-level noise (pair-mean spread 0.081 -> 0.012-0.020) while the within-pair margin shrank; the adapters learned
  a relative length cue (fixed side longer in 86.0% of training pairs; within-pair score-vs-length Spearman -0.24 vs base
  -0.03). The verdict training loss stayed at the coin-flip floor.
- Architect diagnosis (code-level): round 1 trained batch 1, shuffled, accumulation 8, so the two sides of a pair almost
  never shared an update and the common-mode gradient swamped the differential one. --pair-batches is the lever;
  --pair-loss rescales differential vs common-mode. The existing pair mode used a SequentialSampler over items sorted by
  project (same order every epoch and seed), so a shuffled pair sampler is required. --adv-length (absolute ln chars)
  does not target the relative within-pair cue and is not used.
- This design used round-1 VSP-T analysis (strata counts and the auditor mechanism). That is adaptive and is disclosed as a limitation (see Multiplicity).

## Protocol deviations from round 1 (disclosed)
1. Next step. Round 1 fixed "diff-grounded self-training (architect candidate 1)" as attempt 4. The round-1 outcome
   (pooled gain with no within-pair gain) is closest to branch 1, "training changed outputs but not ranking", whose
   fixed next step was candidate 1; this note departs from it. Candidate 1 is not
   run because (a) it is judged in CoT scorer cells while the bar is the verdict log-prob scorer, (b) its V2 acceptance
   selects pairs the base already gets right, (c) its own designer estimated ~15% pass for 36-48 Spark hours. This
   recipe is the pair-level training signal under the fixed per-function scorer: within a pair only the changed lines
   differ.
2. One variable per attempt is broken: batching/objective, shuffling, stratum balance and (K2 only) data change
   together. The confirmatory result cannot attribute an effect to one component. Pilot results are descriptive.
3. K2 data: 300 extra linux pairs exceed round 1's 40-pairs-per-project cap (linux 340 pairs in the K2 final); extras
   are restricted to VulSpot label_confidence "high" and stratum B.
4. Known trainer quirk, disclosed not fixed: build_examples reads `rank` as a boolean while items carry a running index,
   so the one pair whose V item has rank 0 gets no pair term. Seeds now also vary pair order.
5. The round-1 seed-0 verdict was read before seeds 1-2 finished (labelled prelim; not material; disclosed in the
   round-1 record).
6. Balanced sampling replays the minority stratum and skips part of the majority one each epoch (recomputed with
   imp_pairs.epoch_order): K1 final, each B pair about 4.31x per epoch and 57% of A pairs seen per epoch; K1 pilot
   4.68x / 56%; K2 final each B pair about 1.74x, 70% of A pairs seen per epoch (strata A 1,104 / B 445 / E 34); K2 pilot 1.54x / 74% (strata A 835 / B 400 / E 28). In round 1 every pair was seen once per epoch. Total
   pair-steps per epoch equal the number of pairs, as in round 1.
7. Data-hygiene control: scripts/ci_data_hygiene.py checks the new dev set (key vspdev) for overlap only against the
   pilot item files it is used with (SCOPED_POOLS), because dev is carved from VulSpot training projects and by
   construction shares code with legacy training pools that no pilot uses. Every other set is checked exactly as before;
   the scoped check fails hard if the pilot files are missing. Reviewed: a scoping, not a weakening.
8. CI guards added for this round: a pilot data option cannot be combined with any VSP-T test set; pilot adapter tags
   must start with vsp_pilot and a vsp_pilot tag is refused with any VSP-T test set (closing the "test only" path);
   K finals are refused on the dev set.
9. Round-1 seeds 1 and 2 CI runs show "failure" only at the artifact-upload step (network errors from Spark to GitHub);
   the same can happen in this round. Results are then copied from Spark and accepted only if the provenance file's
   result_sha256 matches the file used.

10. Vendored-copy leak found by the auditor and fixed before any training: K2 extra linux pair 205630
   (acpi_ps_complete_final_op, Linux's vendored ACPICA) was the VSP-T acpica function AcpiPsCompleteFinalOp with
   identifiers converted camelCase to snake_case (raw token Jaccard 0.45, below the 0.5 filter; 0.97 after identifier
   normalisation). The builder and check_vsp_dev.py now also refuse identifier-normalised Jaccard >= 0.5 to VSP-T and
   dev (check NORM_NEAR_DUP, proven to fail on the old files) and exclude Linux's vendored ACPICA core functions as a
   rule-5b vendored copy of a VSP-T project (check VENDORED_ACPICA). The K2 files were rebuilt and re-pinned below.
   The new rules removed 3 pairs from the eligible pool (128080, 205630, 223076: all vendored ACPICA; the
   normalised-Jaccard rule alone removes only 205630), 1,436 -> 1,433, and the 300 extras were resampled with the same
   seed. Old K2 hashes 6083f720… (pilot) and 5ace0a42… (final) are superseded and were never trained on. After the
   rebuild no pair in any file reaches normalised Jaccard 0.5 to VSP-T or dev (max 0.491, a round-1 side; round 1
   itself has 0 vendored-ACPICA pairs).
11. check_vsp_dev.py tolerates the FLOOR code (minimum pairs/projects) for the pilot item files, which are smaller by
   construction, and PROJECT_CAP for linux only (<= 340 pairs) in the K2 files.
12. The K2 extras are linux-only, stratum-B-only and label_confidence-high, so K2 data is not drawn from round 1's
   distribution. bow_lr was fitted on round-1 items only; if K2 wins, a bow_lr refit on the K2 final items is reported
   descriptively.
13. Pilots train on fewer pairs than finals (K1 963 vs 1,283; K2 1,263 vs 1,583) with different replay (item 6);
   the K1-vs-K2 ranking on dev could differ from the finals' ranking on VSP-T.
14. The commit contains only attempt-4 files. Unrelated working-tree changes (src/cyberdef/benchdata.py
   train_items_lenmatch, scripts/train_devign.py flags, an untracked .box_gpu.lock) are not part of it and are not used
   by any run in this note.

## Data (pinned by sha256)
- Round-1 training items: results/vsp_sft_items.json 1b105c86f688b9ee6033fb3b19d51ab39d4c2cc29709ebdb0863824df07f714e
  (unchanged; 1,283 pairs, strata A 1,104 / B 145 / E 34).
- Dev split (pilot only; never VSP-T): results/vsp_dev_cases.json 2a7d7e39b79fde58df835f78cccab47783f35b42da2865a59447d70f7c362279. Rule: round-1 projects except linux,
  ordered by sha256("vspdev-v1|" + project); projects with >= 1 stratum-B pair taken in order until dev holds >= 45
  B pairs, then the first ceil(10%) of the remaining non-linux projects. Result: 64 projects, 316 pairs (632 cases); strata A 265 / B 45 / E 6 (the architect's simulation said ~57 projects / 300 pairs; the literal rule as encoded in check_vsp_dev.py gives 64 / 316, and the checker is the spec).
- Pilot K1 items: results/vsp_pilot_k1_items.json b8443ee55feb61288c74948ab9091740a496f40a7df0ab68909734bdc89a8189 (round-1 minus dev projects minus pairs with token-set
  Jaccard >= 0.5 to any dev function). 963 pairs.
- Pilot K2 items: results/vsp_pilot_k2_items.json 4bfb3d09c105c742c96c82ccefd26f7e3e5496709a62439f6c8f180c1aa6bcd2 (1,263 pairs; K1 pilot + 300 extras).
- K2 final items: results/vsp_sft_k2_items.json 87b0516dc10ad259be2ed74370f92c5ad9a3ab1d553cecbbdf9f648d1bff23a5 (1,583 pairs; all round-1 items + the same 300 extras;
  linux 340 pairs).
- Extras: linux VulSpot TRAIN-split pairs passing every round-1 filter, stratum B after comment stripping,
  label_confidence high, not in round 1, raw AND identifier-normalised token Jaccard < 0.5 to dev and to VSP-T, not a
  vendored ACPICA core function, sorted numerically by pair id, random.Random(0).sample(300) (eligible pool 1,433
  pairs). Extras' `rank` continues after round 1's maximum so the pair
  term applies to them.
- Builder scripts/imp_build_vsp_dev.py; gates acceptance/improve/check_vsp_dev.py (+ selftest, 6 mutants caught) and
  check_pairbal.py (balanced passes; shuffle refused with BALANCE), written independently and proven to fail first.
- Primary test VSP-T unchanged: results/vsp_t_cases.json 543c4346ed41dd8d254f6c82346a4a592cc9e62fa7a26da5dd038bb18f2f5185.
- Base result file unchanged: results/vsp_r1/ci_ev_qwen3.8-27b_vspt.json (sha256 96cd996c9a7a0d64772f8c5f40b3677ee2e3797dc3329f254b4f4a9275a27bd6); bow_lr reference results/ci_ev_bowlr_vspt.json d5a6f09f02b869c17bd9b188e4cafe2e045d87cade72f6e81eb11df335888018.

## Recipe (all configs; every run on Spark via .github/workflows/spark.yml at the commit that adds this note (code identical to f75cda3))
Qwen/Qwen3.8-27B, 4-bit QLoRA r16 alpha 32, --epochs 2 --lr 1e-4 (unchanged), --val-per-class 5, --pair-batches
--pair-loss 1 --pair-sampler balanced (the CI data options' flag string). Scorer imp_selective (unchanged).
- K1: round-1 data. K2: round-1 data + 300 linux extras.
- K3 (only if neither K1 nor K2 is eligible): the pilot data option of whichever of K1/K2 had the higher dev
  pair_veto.delta, with TRAIN_FLAGS exactly `--pair-loss 4` (ci_step.sh appends TRAIN_FLAGS after the data flags, so
  this overrides --pair-loss 1).
- Pinned tags: base on dev = test only, blank tag (the untrained base); pilots vsp_pilot_k1, vsp_pilot_k2,
  vsp_pilot_k3 (pilot seed 0, no --seed flag); finals vsp_sft_r2 (seed 0), vsp_sft_r2_s1 (TRAIN_FLAGS `--seed 1`),
  vsp_sft_r2_s2 (TRAIN_FLAGS `--seed 2`).
- A failed or cancelled run is re-dispatched unchanged (same data option, test set, flags, tag; a fresh tag suffix
  _rN only if ci_step.sh refuses an existing adapter directory, disclosed). A run whose only failing step is the
  artifact upload is not re-run (deviation 9).

## Dev pilot protocol (one cycle; fixed now)
1. Base scored on dev (test only, test set "VSP dev split (pilot only; never VSP-T)").
2. Pilots K1 and K2 trained on the pilot item files and tested on dev only. The CI planner refuses a pilot data option
   or a vsp_pilot tag with any VSP-T test set.
3. Eligibility screens applied to each pilot's _imp_train_log.json BEFORE any dev score is read: (a) sampler check:
   pair_sampler.mode == balanced and every epochs_iterated entry has |A - B| <= 1 and E equal to the file's E count;
   (b) stop rule: last200.pair (mean pair loss over the last 200 pair terms) < 0.679 (ln 2 = 0.693). A config failing
   either screen is ineligible (a sampler failure is a defect: re-dispatched unchanged once after a fix, disclosed).
   A config that fails step 3 is still scored on dev and reported. K3's data is chosen by dev pair_veto.delta between
   K1 and K2 whatever their step-3 status; if neither was scored, K3 uses K1's data.
4. Dev verdicts with the unchanged command: scripts/imp_verdict.py round --cases results/vsp_dev_cases.json
   --adapter <pilot result> --base <base dev result> --z 2.394 --cluster-bootstrap --cluster-by project --pair-veto
   --baselines length,lines,if_count,static_count.
5. Step 3 is applied by hand from each _imp_train_log.json and recorded in the decision record. Only configs that pass
   it are given to scripts/imp_dev_gate.py, whose code is the rest of the rule: eligible iff pair_veto.delta > 0 and
   comparisons.base.delta > 0 on dev; the winner is the eligible config with the highest pair_veto.delta, K1 winning if
   within 0.02 of the best. If none is eligible, run K3 (steps 3-5); if K3 is not eligible either: NO-GO.
6. NO-GO: no adapter or final trained under this note is ever scored on VSP-T. The owner decides only whether a new
   pre-registration is written. Any further dev cycle needs its own committed note, numbered (cycle n), and every
   eventual claim reports the total number of dev cycles and configs screened. Owner decision: a dev-only NO-GO does
   not consume attempt 4, because no VSP-T test occurs.
7. The gate runs as written whatever the base dev values; base dev pooled AUROC and within-pair veto are reported.
   The dev gate is a sign screen, not evidence: with 45 stratum-B dev pairs and one seed its veto delta has an SE of
   roughly 0.03-0.04 (auditor estimate).
8. Finals: the winner's final items and flags are fixed (K1 final = results/vsp_sft_items.json, K2 final =
   results/vsp_sft_k2_items.json); seeds 0, 1, 2 train on them and are tested on the VSP-T bundle "VSP-T real-world fix
   pairs (VSP-T, CASTLE, PrimeVul 300)". Finals are scored on VSP-T once dispatched, whatever their training
   diagnostics; only the sampler check (step 3a, applied to each final's train log before its VSP-T score is read) and
   the 4-bit training mode can stop one, and a stopped final is re-dispatched unchanged once after a fix, disclosed.

## Base determinism (pre-stated)
The bar uses the pinned round-1 base file. The base is also re-scored on VSP-T at the commit that adds this note (code identical to f75cda3) on Spark (test only,
blank tag) before any final is read. If max |p_vuln difference| over the 776 per_case rows is <= 1e-4, nothing
changes. If it is larger, the verdict is computed against BOTH base files and every bar must pass against both; the
drift is reported.

## Multiplicity
Holm with fixed m = 6, as in round 1 (for a single test the threshold is alpha/6, z = 2.394). The family is every
self-training or fine-tuning attempt in this campaign: command injection r1, format string 1b, VSP-SFT r1, and this
attempt (4 of 6). Choosing among configs on disjoint dev data adds no VSP-T multiplicity. The recipe was informed by
round-1 VSP-T outputs (strata counts, the length-cue mechanism); this is disclosed, and no per-pair VSP-T score was
used to tune it. After attempt 6 without a pass the campaign stops (88808c1).

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

The round-1 bar and claim text above is copied character for character from VSP_SFT_R1_PREREG_2026-11-17.md and
applies unchanged to this round's seed-0 / seed-1 / seed-2 finals (vsp_sft_r2, _s1, _s2) against the base. As run in
round 1, the verdict command also carries --cross bow_lr=results/ci_ev_bowlr_vspt.json for the bow_lr wording rule.

## Added claim rules for this round (restrictions only)
- A pass is attributed to the recipe as a whole. No component (pair batching, margin term, balanced sampler, linux
  extras) is named as the cause. K1-vs-K2 dev differences are descriptive.
- Every claim reports the number of dev cycles (this note: one) and configs screened.

## Reported descriptively (never in the bar)
Base and pilot dev verdicts for every config; within-pair score-vs-length Spearman (round 1: -0.24); pair-mean spread
and mean within-pair difference; training pair-loss curves; fork-project sensitivity, 2025-26 recency, label
confidence, CASTLE and PrimeVul-300 transfer, bow_lr (and a refit on the K2 final items if K2 wins), as in round 1;
the base-determinism comparison.

## Code (pinned)
the commit that adds this note (code identical to f75cda3): src/cyberdef/imp_pairs.py, scripts/imp_train.py (--pair-sampler), scripts/imp_build_vsp_dev.py,
scripts/imp_dev_gate.py, scripts/ci_plan.py and spark.yml/gpu.yml options, scripts/ci_data_manifest.py,
scripts/ci_data_hygiene.py (vspdev scoping), data/DATA_MANIFEST.json entries, the four data files, and the checkers
acceptance/improve/check_pairbal.py, check_vsp_dev.py, check_vsp_dev_selftest.py. Untouched since e1dca15:
imp_verdict.py, imp_selective.py, selective_eval.py, evaluate.py, imp_adv.py, check_vsp_items.py, vsp_t_cases.json,
vsp_sft_items.json. Reviews: architect design; independent reviewer SHIP (tooling); experiment-auditor COMMIT WITH
CHANGES, all changes applied.

## Disclosed state at the time of this note
- No attempt-4 model exists; no pilot has run; dev has not been scored by any model.
- Round 1 is closed FAIL (verdict files results/vsp_r1/verdict_seed{0,1,2}_vs_base_prelim.json; seed-2 provenance
  stamped by run 44612165737, result_sha256 15d8696a…, verdict identical on the stamped file; results committed
  c76a8f7).
- Pass estimate (architect, judgment): ~20% (12-28%).

## Addendum 1 (2026-11-21 02:53 AEDT): line-ending defect, re-dispatch
The first dispatch at b166e20 (runs 44754966547 base-on-dev, 44754981792 pilot K1, 44754996445 pilot K2) stopped
before any model ran: Spark's job library (scripts/gpu_job_lib.sh, crlf_check) refuses any src/cyberdef/*.py
containing CR, and five attempt-4 files had been committed with CRLF line endings. No adapter was trained, no dev or
VSP-T score was produced (K1 left only a provenance stub; K2 was cancelled while queued).
Fix: CR removed from src/cyberdef/imp_pairs.py, scripts/imp_build_vsp_dev.py, acceptance/improve/check_pairbal.py,
check_vsp_dev.py, check_vsp_dev_selftest.py. Nothing else changed: `git diff --ignore-cr-at-eol` against b166e20 is
empty, and the Python AST of every changed file is identical before and after (CPython normalises source line endings,
so behaviour is unchanged). Data files, manifest, flags, tags, bars and protocol are unchanged. The pinned code for this
note is now this commit; the three runs are re-dispatched unchanged per "A failed or cancelled run is re-dispatched
unchanged". Dev cycles: still one; no score of any kind had been read.
