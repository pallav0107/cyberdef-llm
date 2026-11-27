# VSP-SFT round 4 (attempt 6 of 6): other-base screen, committed GO rule, finals

Committed 2026-11-28, before any score of any candidate base on dev2, dev3 or VSP-T exists. No VSP-T per_case file
was opened to write this note. Attempt 5 (VSP_SFT_R3_PREREG_2026-11-24.md, Qwen3.8-27B, K4b) passed all four bars
(audited VALID WITH CAVEATS): VSP-T 0.6178 / 0.6258 / 0.6297 against base 0.5703. It missed the owner target.

## Purpose and owner direction
- Owner, 2026-11-28: "make score .7 on other models dont switch to 72B yet".
- Owner target, unchanged and separate from the bars: the pooled VSP-T AUROC of EVERY seed >= 0.70, full precision,
  all 776 rows (results/vsp_t_cases.json, sha256 543c4346...), from the registered file of that seed.
- Prior (architect judgment, not a measurement): P(a non-72B base reaches the target on all three seeds) about 2%
  (range 1-5%); expected best single model about 0.63. The screen exists to turn that judgment into a pre-registered
  measurement without spending the last VSP-T attempt. NO-GO is the expected outcome.

## Multiplicity
- Holm with fixed m = 6, z = 2.394, as in rounds 1-3. This is attempt 6 of 6, and it is consumed only on GO.
- The family is closed after this note whatever the outcome. Further work needs a new held-out test set (the live
  benchmark M1 is reserved for that) and its own pre-registration.
- Selection uses dev2 and dev3 only, which adds no VSP-T multiplicity.

## Candidates (fixed list; order = tie-break order)
| id | base | status at commit |
|---|---|---|
| A1 | Qwen/Qwen2.5-32B-Instruct | weights on Spark; template check passes |
| A2 | Qwen/Qwen2.5-Coder-32B-Instruct | weights NOT on Spark; screened only if downloaded and the template check passes |
| B1 | Qwen/Qwen2.5-14B-Instruct | weights on Spark; template check passes |
| B2 | Qwen2.5-Coder-7B-Instruct | on Spark (imp_models/) and box; template check passes |
| C1 | Qwen/Qwen3-Coder-30B-A3B-Instruct (MoE) | weights NOT on Spark; screened only after download, template check and a 20-step smoke (mode 4bit, pair_terms == pair_steps, <= 64 s/step) |
| C2 | deepseek-ai/DeepSeek-R1-Distill-Qwen-32B | fails the template check (think block); screened only via a template-alias directory that passes it, with the template sha recorded |

Excluded: openai/gpt-oss-20b (MXFP4 weights; harmony header shifts the pair slot; expert tensors not LoRA-targetable
by name), Qwen2.5-72B (owner), any *-ablit variant (rule), Qwen3.8-27B (spent in attempt 5). A candidate that is not
screened (missing weights or a failed check) is recorded as "not screened" with the reason; that is not a deviation.
Default run set: A1, B1, B2.

## Stage 1: dev2 screen
- Train: CI data option "VSP pilot K4b: K4a + diff-site target (train minus dev2)" =
  results/vsp_pilot_k4b_items.json (c814527e), PAIR_DOM flags, 2 epochs, lr 1e-4, r16/a32, 4-bit, seed 0; tag
  vsp_pilot_k4b_<short>. Identical to the 27B K4b pilot except --base.
- Score: test set "VSP dev2 split" = results/vsp_dev2_cases.json (9511373d, 1010 rows), unchanged scorer. The
  untrained base of each candidate is also scored on dev2 (blank tag, test only).
- Reference on file, not re-run: 27B K4b pilot dev2 0.6074, veto 0.6598 (CI run 45185319205); 27B base 0.5365.
- dev2 shares 0 projects and 0 code hashes with the pilot training file and with VSP-T.

## Stage 2: dev3 confirmation (built and committed here, before stage 1; scored only for a stage-1 winner)
- Rule: from results/vsp_sft_k4b_items.json take the projects that are neither "linux" nor dev2 projects; order by
  sha256("vspdev3-v1|" + project) ascending; take whole projects until >= 400 pairs. Builder:
  scripts/imp_build_vsp_dev3.py (no arguments, deterministic).
- Result: results/vsp_dev3_cases.json sha256 31366b4ab3e372612f6b1433daee7e9fa6a1a180cf9b0f0066ea588560974d11:
  122 projects, 400 pairs, 800 cases, strata A 357 / B 27 / E 16; 0 projects and 0 code hashes shared with VSP-T or
  dev2.
- Matching training file: results/vsp_pilot_k4b_d3_items.json sha256
  82b732339af4edc0062e51339a3d0671f408b550cde65c4450b34947332d7d46: the final file minus every dev3 project minus any
  pair with raw or identifier-normalised Jaccard >= 0.5 to a dev3 function; 1,453 pairs, 2,906 items, items
  byte-identical to the final file's.
- No model has ever been scored on dev3. Every earlier adapter trained on dev3 projects, so only adapters trained on
  the d3 file (tag prefix vsp_pilot_k4b_d3) and untrained bases may be scored on it. scripts/ci_plan.py enforces this,
  and refuses a d3 tag with any other training data and d3 data under any other tag.

## Committed GO rule (scripts/imp_a6_gate.py; constants are literals in code; no run-time knob)
AUROC and pair veto are recomputed from per_case at full precision; headline fields are never used.
- S1 eligible(c): train-log screens pass AND dev2 AUROC >= 0.685 AND dev2 pair veto >= 0.6598 AND delta vs own base
  > 0 AND veto delta vs own base >= 0.035 AND B-stratum wins >= own base - 2.
- Stage-1 winner: highest dev2 AUROC among S1-eligible; within 0.005, the smaller parameter count, then list order.
- Ensemble fallback, only if no single is S1-eligible: per-case mean of logit(p_vuln) of the top two singles by dev2
  AUROC among the screened candidates and the 27B K4b pilot; eligible iff dev2 AUROC >= 0.690 AND veto >= 0.6598.
- S2 (winner only): dev3 AUROC >= 0.665 AND (dev2 + dev3) / 2 >= 0.685.
- GO = S1 and S2: exit 0. Attempt 6 is then spent on that predictor and nothing else.
- NO-GO: exit 3. Attempt 6 is not consumed. The record reads "0.70 on VSP-T is out of reach for the screened
  non-72B bases under the K4b recipe; best dev2 = X". No re-screen with other recipes, thresholds or candidates;
  dev2 is retired.
- Refusal: exit 2. Any VSP-T input; a wrong cases sha or row count; a null log field; a candidate off the list; a
  provenance mismatch (result sha, cases sha, model, adapter, d3/pilot tag prefix, train-log run id); a stage-1 winner
  without dev3 results.
- Operational consequence: the gate binds a pilot's train log to its result by CI run id, so a pilot's train and test
  must run in the same CI run. A failed run is re-dispatched as train + test, unchanged.

## Attempt-6 finals (only after GO)
- Data results/vsp_sft_k4b_items.json (d0eb200c), option "VSP-SFT K4b final: K4 final + diff-site target", same
  flags; tags vsp_final_k4b_<short>, _s1 (--seed 1), _s2 (--seed 2). Seeds 0, 1, 2 only. The registered file of a
  seed is its first screen-passing run whose provenance result_sha256 matches.
- Screens per final, read before its VSP-T file is opened: linux A 308 / B 308 / E 1; other A 274 / B 274 / E 33;
  max_pair_count 2; pair_steps = pair_terms = 2396; mode 4bit. Test defect rule: any module off-GPU, or test
  wall-clock > 3x the base re-score of the same model, is defective and is re-run unchanged, decided before the score
  is read.
- The winner's untrained base is scored on VSP-T (blank tag, test only) after the GO commit and before any final is
  read. It is never used for selection.
- Bars: the round-1 text character for character, z = 2.394, command
  `imp_verdict.py round --z 2.394 --cluster-bootstrap --cluster-by project --pair-veto
  --baselines length,lines,if_count,static_count --cross bow_lr=results/ci_ev_bowlr_vspt.json`.
  Stricter, never weaker: bars 1-4 must pass against BOTH the winner's untrained base AND the pinned Qwen3.8-27B base
  file (96cd996c).
- Owner target: scripts/imp_a6_target.py decides it from the three registered result files and their six verdicts
  (each verdict must list its seed's result sha256; the three result shas must differ). Target met + a bar fails =
  target not met. Bars pass + target missed = nothing is published.
- Wording caps carried over: "pooled gain on unseen projects; within-pair direction not contradicted" unless the
  veto's cluster CI excludes 0; never "detects the fix"; beyond "beats the untrained base" needs adapter - bow_lr >
  2 SE; each seed's veto compared with the base-plus-length ceiling (recomputed for a new base by the auditor method).
  New caps: no claim that one base is better than Qwen3.8-27B; every claim reports 3 dev cycles, 4 configs + N
  screened bases, attempt 6 of 6, family closed; dev2/dev3 numbers are selection results, never test results;
  per_case recompute and experiment-auditor before any claim.

## Disclosed state at commit
- Tooling in this commit: scripts/imp_build_vsp_dev3.py, scripts/imp_a6_gate.py, scripts/imp_a6_target.py,
  acceptance/improve/check_template_compat.py, acceptance/improve/check_a6_*.py, additive edits to scripts/ci_plan.py,
  scripts/ci_data_manifest.py, scripts/ci_data_hygiene.py, data/DATA_MANIFEST.json and the two workflow files.
  Checkers were written first and shown to fail; an independent review found five holes (all fixed, each pinned by
  check_a6_fixes.py) and then returned SHIP.
- Untouched, so the last attempt stays byte-comparable with attempts 1-5: scripts/imp_train.py, imp_selective.py,
  selective_eval.py, imp_verdict.py, imp_dev_gate2.py, src/cyberdef, every pinned data file, earlier notes.
- results/vsp_t_cases.json is not tracked by git; it is pinned by sha256 (543c4346) in the acceptance guard, and the
  Spark copy is sha-checked at sync.
- Spark-local, untracked scripts/gpu_job_lib.sh: gdock now names its container and removes it after `docker run`
  returns, so an OOM-killed docker client cannot orphan a container (verified: original orphans, patched does not).
- Spark ~/dropcache_guard.sh is restarted for this campaign, as in attempt 5 (bf16 32B tests offload otherwise).
- The box's 72B night cron is paused (it OOMs on its own on Spark).
- Unrelated uncommitted changes on the box (src/cyberdef/benchdata.py, scripts/train_devign.py) and three local
  benchmark-design doc commits are not in this commit and are used by no run here. Spark is synced from a clean
  export of this commit.
