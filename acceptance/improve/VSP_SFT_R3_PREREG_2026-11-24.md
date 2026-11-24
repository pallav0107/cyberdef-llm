# Pre-registration: K4b finals on real-world fix pairs (VSP-SFT round 3, attempt 5 of 6) — 2026-11-25 01:10 AEDT

Written and committed before any K4b final is trained. No K4b final exists. VSP-T has not been scored by any model
trained under the K4 recipes. The round-1 and round-2 pre-registrations are pinned contracts; nothing in them is
edited. This note fixes the attempt-5 finals, bars and claim rules. Reviewed before commit by the experiment-auditor
(COMMIT WITH CHANGES); all of its changes are applied.

## Hypothesis
H: a 4-bit QLoRA fine-tune of Qwen/Qwen3.8-27B under the K4b recipe scores a higher pooled AUROC than the untrained
Qwen3.8-27B on VSP-T (fix pairs from 159 projects it never saw), and a higher length-balanced within-pair veto. Both
are scored by the same verdict log-probability scorer (imp_selective).

The K4b recipe is:
- pair-batched updates with the pairwise margin term;
- the domain-balanced, low-replay sampler (balanced_by_domain);
- linux A/B extras;
- the two-line target VERDICT then SITE (the line the fix changed).

## How the configuration was chosen (cycle 2, dev2 only)
- The design is CURRENT_PLAN.md cycle 2 plus Amendment 1. Amendment 1 states that it "SUPERSEDES ... the gate
  threshold". The governing rule is therefore the code of scripts/imp_dev_gate2.py, committed at c2572d0
  (21 Nov 21:23 AEDT) before any K4 pilot was trained:
  - veto >= 0.035;
  - B wins >= base - 2;
  - K4a wins when it is within 0.02 of the best;
  - screens are read from the train log.

  That code has not changed since. Under the superseded plan text (veto >= 0.03, B wins >= base - 1) the decision is
  the same: both configs are eligible and K4b wins.
- Dev2 is results/vsp_dev2_cases.json (sha256 9511373d…; 505 pairs, 106 projects, A 368 / B 122 / E 15). It is
  project-disjoint from VSP-T, from cycle-1 dev and from every pilot training file.
- Every K4 run used commit e80a9a3 (clean).

### Runs, in order (all Spark)
1. **23 Nov 07:18Z, first dispatch.** No model ran in any of these four runs, and no score existed:

   | run | what it was | how it ended |
   |---|---|---|
   | 45130112214 | test only | Plan failed ("ci_plan.py on spark is not the version in commit e80a9a3") |
   | 45130129303 | probe, K2 test only | Plan failed, then cancelled |
   | 45130145856 | base on dev2, test only | step 5 Test failed in zero seconds: "test set results/vsp_dev2_cases.json is missing on spark"; the step that recomputes AUROC from per_case was skipped; upload cancelled |
   | 45130163287 | K4b pilot | Dataset step failed; cancelled |

2. **Linux probe (descriptive set, never a gate set).** Base 45182772418 and the K2 pilot 45182795945, recorded in
   results/vsp_r2/K4_PROBE_READING.md (3973939).
3. **Base on dev2:** 45183188994.
4. **K4b pilot:** 45185319205. Its headline dev2 AUROC was visible in its CI Grade step from 24 Nov 13:21 AEDT.
5. **K4a pilot:** 45206161499.
   - Training completed and the train-log screens pass.
   - Its Test step failed at 24 Nov 22:10 AEDT. The model loaded with weights offloaded under low Spark memory, and
     PEFT `_update_offload` raised a KeyError. No score existed.
   - **Deviation:** the re-dispatch 45382370423 (24 Nov 22:14:36 AEDT) was test only, not train + test. It used the
     same tag, so the same completed adapter (out/imp_vsp_pilot_k4a) was scored.
   - It was dispatched before any dev2 verdict file was written (K4b verdict 22:16, K4a 23:29).
   - Re-testing K4a could only work against K4b, because K4a wins ties within 0.02.
6. **Uploads.** 45185319205 and the base run failed only at artifact upload (deviation 9). 45382370423 completed
   successfully. Result files were copied from Spark; each provenance result_sha256 matched the file used, and each
   cases_file_sha256 equals dev2.

### Screens and verdicts
- Screens, from the train logs (all pass):
  - K4a: last200.pair 0.492.
  - K4b: last200.pair 0.463; pair terms 1628 = pair-steps 1628.
- Verdicts: imp_verdict round, the unchanged command with --cases results/vsp_dev2_cases.json. The experiment-auditor
  recomputed these from per_case without imp_verdict code.

  | config | dev2 AUROC (base 0.5365) | base delta | pair_veto (base 0.5741) | veto delta | B wins (base 64) | eligible |
  |---|---|---|---|---|---|---|
  | K4a | 0.5880 | +0.0515 | 0.6354 | +0.0613 | 70 | yes |
  | K4b | 0.6074 | +0.0710 | 0.6598 | +0.0857 (cluster 95% CI +0.025..+0.146) | 67.5 | yes |

- The gate (results/vsp_r2/dev2_gate.json; reproduced JSON-identically by the auditor) returned **GO, winner K4b**.
  K4a was eligible but 0.0244 below K4b, outside the 0.02 tie margin.
- K4b's dev2 numbers are a selection result, inflated by choosing the best of two. They are never quoted as a test
  result.
- Dev cycles: 2. Configs screened: 4 (K1, K2 in cycle 1; K4a, K4b in cycle 2).

### Dev2 mechanism and the pre-stated predictions (descriptive)
Recomputed from the dev2 per_case files. "Changed lines" means difflib non-equal lines.

| | base | K4a | K4b |
|---|---|---|---|
| within-pair Spearman(dp, dlen) | -0.09 | -0.17 | -0.28 |
| veto, A (S-longer) | 0.624 | 0.697 | 0.766 |
| veto, B (V-longer) | 0.525 | 0.574 | 0.553 |
| 1-2-changed-line bucket (n=208) | 0.613 | 0.683 | 0.714 |

- K4b's prediction held: 1-2-line bucket >= base + 0.05 and B >= base B.
- K4a's prediction was not met on the Spearman (-0.166 against >= -0.15), but it was not refuted.
- The plan's stop rule (pooled up, B below base, Spearman <= -0.2) did not trigger, because B is above base for both.
- K4b's veto gain comes mostly from S-longer pairs, and its relative length cue is stronger than K4a's.

## Adaptivity (disclosed)
- The K4 recipes, every K4 data file, the dev2 split and the gate code were committed at c2572d0
  (2026-11-21 21:23 AEDT). No attempt-4 VSP-T score existed then; the first was seed 0, 2026-11-22 02:24.
- The design used cycle-1 dev analysis. It builds on the round-2 recipe, which used round-1 VSP-T findings.
- Decisions taken after the attempt-4 VSP-T result: to spend attempt 5 at all (with the owner's 0.70 target), and the
  probe reading (UNDEFINED; both pilots run).
- No per-pair VSP-T score was used for design or selection. Selection used dev2 only.

## Finals (fixed now)
### Data
- File: results/vsp_sft_k4b_items.json (sha256 d0eb200c4bc3a16809b888f8975b522a95637b0ed86ba9015415c4226b3a650b;
  3,714 items = 1,857 pairs).
- Content: the K4 final items, results/vsp_sft_k4_items.json (4632af51…, pinned at c2572d0 before any pilot; dev2
  core folded back). Only `target` differs: it becomes "VERDICT: <label>\nSITE: <line>", by the pilot's difflib rule.
- Build: scripts/imp_build_vsp_k4.py. The same run reproduces every committed K4 file byte for byte (verified twice,
  once independently).
- Check: `check_site_targets.py results/vsp_sft_k4b_items.json --k4a results/vsp_sft_k4_items.json` passes with 0
  failed. Its slot check uses the Qwen2.5-7B tokenizer, not the training model's.
- SITE is empty or whitespace for 472 of 3,714 items (12.7%); the pilot file had 391 of 2,902 (13.5%). Same rule;
  disclosed, not changed.

### Recipe and tags
- CI data option: "VSP-SFT K4b final: K4 final + diff-site target".
- Flags: PAIR_DOM, the pilot's own flags: --val-per-class 5 --pair-batches --pair-loss 1 --pair-sampler
  balanced_by_domain.
- Model and training: Qwen/Qwen3.8-27B, 4-bit QLoRA r16 alpha 32, --epochs 2 --lr 1e-4 (unchanged).
- Tags:
  - vsp_final_k4b: seed 0, no --seed flag;
  - vsp_final_k4b_s1: TRAIN_FLAGS `--seed 1`;
  - vsp_final_k4b_s2: TRAIN_FLAGS `--seed 2`.
- Test set: "VSP-T real-world fix pairs (VSP-T, CASTLE, PrimeVul 300)".
- Scorer: imp_selective, unchanged. It scores the VERDICT line only, never the SITE suffix.

### Deviation: pilot-to-final differences
These come from folding dev2 back, which the plan fixed in advance. They are simulated with imp_pairs.epoch_order;
seeds 0, 1 and 2 give identical counts.

| | pilot | final |
|---|---|---|
| pairs added | — | +406 (403 dev2 core, plus 3 pilot near-dev2 drops: 62332, 165603, 228874 from abseil-cpp, cups, wasmtime) |
| other-domain B pairs | 44 | 137 |
| other-domain A pairs | 769 | 1,070 |
| E pairs | 22 | 34 |
| pair-steps per epoch | 814 | 1,198 |
| total pair-steps | 1,628 | 2,396 |
| linux share of steps | 76% | 51% |
| other-domain A pairs seen over 2 epochs | — | 548 of 1,070 |

The dev2 ranking of K4a vs K4b may not carry over to the finals.

### Deviation: the rank-0 trainer quirk returns
Round 2 deviation 4 applies again.
- Pair 19393 (Bento4, other-domain A, V `rank` 0) is in the final but was not in the pilot.
- imp_train.py (`int(rk.min()) == 1`) would give it no pair term.
- By simulation, seeds 0, 1 and 2 never sample it.
- Disclosed, not fixed.

### Screens
Before its VSP-T score is read, each final's train log must show exactly these values in both epochs:
- linux A 308 / B 308 / E 1;
- other A 274 / B 274 / E 33;
- max_pair_count 2;
- pair_steps 2396 and pair_terms 2396;
- train_mode 4bit (`flags.mode` in the train log and `train_mode` in the provenance file).

Any mismatch fails the screen. A final that fails a screen never has its VSP-T result file opened. It is re-dispatched
unchanged once after a fix, and the re-dispatch is disclosed. last200.pair is reported for finals but never stops one.
The test-time device map (`hf_device_map`) is recorded where available; a test with any module on cpu or disk is
defective and is re-run.

### Failed runs
- A failed or cancelled run is re-dispatched unchanged. A fresh tag suffix _rN is used only if ci_step.sh refuses an
  existing adapter directory.
- A run whose only failure is the artifact upload is not re-run (deviation 9). Results are accepted only if the
  provenance result_sha256 matches the file used.

## Base determinism (pre-stated)
The bar uses the pinned round-1 base file results/vsp_r1/ci_ev_qwen3.8-27b_vspt.json (96cd996c…).

The base is also re-scored on VSP-T at the commit that adds this note (Spark, test only, blank tag) before any final
is read:
- If max |p_vuln difference| over the 776 per_case rows is <= 1e-4, nothing changes.
- If it is larger, the verdict is computed against BOTH base files and every bar must pass against both; the drift is
  reported.

`git diff fec6885` is empty for every scoring file, including evaluate.py and train.py. The environment, however, is
not pinned: constraints_sha256 is null, the model snapshot is not hashed, and the offload behaviour changed under
memory pressure.

## Multiplicity
- Holm with fixed m = 6, as in rounds 1-2 (single-test threshold alpha/6, z = 2.394). This is attempt 5 of 6.
- Choosing among configs on disjoint dev data adds no VSP-T multiplicity.
- Attempt 6 is the last attempt in this family, whatever attempts 5 and 6 show, and needs its own committed note. Any
  later work needs a new held-out test set and its own pre-registration.

## Bar (ALL must hold). Copied character for character from VSP_SFT_R1_PREREG_2026-11-17.md
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

Scope: the round-1 bar text applies to this round's finals vsp_final_k4b, _s1 and _s2 against the base, with the
command scripts/imp_verdict.py round (two arms, seed-0 adapter vs base). As in rounds 1-2, the command also carries
--cross bow_lr=results/ci_ev_bowlr_vspt.json for the bow_lr wording rule.

## Owner target (pre-stated; not a bar, and it never changes the verdict)
The owner's target is pooled VSP-T AUROC >= 0.7. All of the following conditions apply:
- **Precision:** the AUROC is taken at full precision, unrounded.
- **Rows:** all 776 rows of results/vsp_t_cases.json (543c4346).
- **Source file:** each seed's registered result file, meaning the first screen-passing run of that seed with a
  matched provenance result_sha256. No other run of a seed is ever read.
- **Seeds:** 0, 1 and 2 only. No extra seed is trained. Each seed must reach >= 0.7.
- **Excluded:** an ensemble of seeds, a subset of VSP-T, a different scorer or a post-hoc threshold does not count. The
  3-seed mean-score ensemble is reported descriptively only.
- **If met:** the published adapter is seed 0. It is reported with all three seeds' AUROCs and the seed-0
  project-cluster 95% CI, never the maximum.
- **Bars pass but target missed:** no new version is published.
- **Target met but a bar fails:** the target is not met.

The target decides only whether a new model version is published, per the owner's instruction. It is not a
significance claim.

## What a pass may claim (rules carried over from rounds 1-2, restrictions only)
- Unless pair_veto.ci95_cluster excludes 0, a pass reads "pooled gain on unseen projects; the within-pair direction is
  not contradicted". It never says "detects the fix".
- Any wording beyond "beats the untrained base" requires adapter - bow_lr > 2 x SE.
- A pass is attributed to the recipe as a whole. No component (sampler, linux extras, SITE target) is named as the
  cause. K4a-vs-K4b dev2 differences are descriptive.
- No claim is made that attempt 5 improves on attempt 4, pooled, on the veto, on V-longer pairs or on any stratum.
  K4b-vs-K2 VSP-T differences are descriptive.
- Each seed's veto is compared with the base-plus-length ceiling 0.6688 (round 2's auditor check). A seed at or below
  the ceiling is reported as "within-pair gain indistinguishable from a length cue".
- Every claim reports 2 dev cycles, 4 configs screened, and that this is attempt 5 of 6.
- Win claims need a recompute from per_case and an experiment-auditor pass. The wording follows the auditor.

## If FAIL
Attempt 4's registered result stands (Holm). No K4b model is published.

## Reported descriptively (never in the bar)
- The within-pair score-vs-length Spearman, and the S-longer / V-longer veto split.
- The 1-2-changed-line bucket.
- CASTLE and PrimeVul-300 transfer.
- A bow_lr refit on the K4 final items (as deviation 12).
- Every final's training curves and last200.pair.
- The K4a and K4b dev2 verdicts, the linux probe, and the base-determinism comparison.

## Code (pinned at the commit that adds this note)
- New in this commit:
  - scripts/imp_build_vsp_k4.py writes the K4b final file (no other output changes);
  - scripts/ci_plan.py, spark.yml and gpu.yml carry the K4b final option;
  - scripts/ci_data_manifest.py and data/DATA_MANIFEST.json have the new entry;
  - scripts/ci_data_hygiene.py adds the new file to the probe's scoped pools (stricter);
  - the cycle-2 gate record in results/vsp_r2/: dev2 result files with provenance, train logs, verdicts and
    dev2_gate.json.
- Checks run on this commit, all passing:
  - acceptance/improve/check_ci_k4.py PASS (9/9; that checker is unchanged);
  - check_site_targets.py on the final file PASS;
  - ci_data_manifest.py --check OK;
  - ci_data_hygiene.py --check OK (vspt 776 cases, 0 shared with any of 17 training pools) and --items on the new
    file OK.
- Unchanged since c2572d0: scripts/imp_train.py, src/cyberdef/imp_pairs.py, scripts/imp_dev_gate2.py.
- Unchanged since fec6885: everything listed under Base determinism.

## Disclosed state at the time of this note
- K4a and K4b pilot adapters exist on Spark. They are never scored on VSP-T: ci_plan refuses vsp_pilot tags with any
  VSP-T set.
- Unrelated uncommitted changes (src/cyberdef/benchdata.py, scripts/train_devign.py) are not in this commit and are
  used by no run in this note. Spark is synced from a clean checkout of this commit, never from the box's working
  tree.
- A context screen (branch ctx-study, dev2 only, base model, box GPU) runs in parallel. It informs attempt 6 only and
  has no bearing on this note.
- Estimate (judgment): the bars pass with about 35-45% probability. The owner target of 0.70 on all seeds is below
  10%: K4b's dev2 gain (+0.071) applied to the VSP-T base (0.570) suggests about 0.64.
