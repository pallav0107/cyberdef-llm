# VSP-SFT round 2 (attempt 4 of 6): result

Recorded 2026-11-23 00:41 AEDT. Prereg acceptance/improve/VSP_SFT_R2_PREREG_2026-11-21.md (b166e20, Addenda 1-2). Code fec6885.

## Registered verdict: all four bars hold (scripts/imp_verdict.py round, script sha fc7bcef8)

| seed | run | pooled AUROC (base 0.5703) | case z | cluster z | veto (base 0.6617) | veto cluster 95% CI | vs bow_lr |
|---|---|---|---|---|---|---|---|
| 0 | (final) | 0.6283 (+0.0579) | 2.67 | 5.45 | 0.6927 (+0.0310) | [-0.072, 0.131] | +0.0725 (2.95 SE) |
| 1 | 44865634963 | 0.6285 (+0.0582) | 2.68 | 5.47 | 0.7076 (+0.0458) | [-0.039, 0.137] | +0.0727 (2.94 SE) |
| 2 | 44983981559 | 0.6259 (+0.0555) | 2.46 | 5.44 | 0.6685 (+0.0068) | [-0.093, 0.106] | +0.0701 (2.92 SE) |

Bar 1 needs z > 2.394 under both bootstraps (seed 0). Bar 3: length/lines/if_count/static_count beaten by
+0.100..+0.128 (case z 3.97-4.69). Bar 4: seeds 1 and 2 pooled and veto deltas > 0. Inputs: cases 543c4346, base
96cd996c (deterministic re-score at fec6885: max |dp| = 0.0), bow_lr d5a6f09f. Independent per_case recompute
(no imp_verdict code) matches to 4 dp; length-only veto = 0.5000.

## Permitted claim (experiment-auditor, VALID WITH CAVEATS)
"In pre-registered attempt 4 of 6 (Holm, fixed m = 6; one dev cycle, two configs screened, K2 selected), a 4-bit
QLoRA fine-tune of Qwen3.8-27B under the pair-contrastive, length-balanced recipe raised pooled AUROC on VSP-T (388
real-world fix pairs from 159 projects unseen in training) from 0.570 to 0.628 for seed 0 (+0.058, above 2.394 SE
under both case-level and project-cluster bootstraps), replicated with seeds 1 and 2 (0.629, 0.626), and beat length,
line-count, if-count and static-count baselines and a bag-of-words logistic-regression baseline fitted on the round-1
training items (+0.073, about 2.9 SE): a pooled gain on unseen projects; the within-pair direction is not
contradicted (length-balanced within-pair veto +0.031 / +0.046 / +0.007, project-cluster 95% intervals all including
0). The gain is attributed to the recipe as a whole."

Never: "detects the fix", "removes the length cue", or any component named as the cause.

## Disclosures that must accompany the claim
- Relative length cue persists: within-pair Spearman of score difference vs length difference -0.19 / -0.19 / -0.24
  (base -0.03; round 1 -0.24). The veto gain comes from S-longer pairs (0.679 -> 0.786 / 0.749 / 0.759); on the 45
  V-longer pairs the adapter is below base in 2 of 3 seeds (0.644 -> 0.600 / 0.667 / 0.578; SE ~0.07).
- Seed 2's veto (0.6685) equals the ceiling a base-plus-length rule tuned on test can reach (0.6688); its within-pair
  gain is indistinguishable from a length cue. Seeds 0-1 exceed that ceiling.
- Pooled gain is not a length artefact: base + length tuned on test reaches AUROC 0.578; length-binned AUROC 0.624;
  excluding own-pair comparisons 0.628.
- Transfer: CASTLE 0.738 -> 0.767 / 0.813 / 0.777; PrimeVul-300 REGRESSES 0.609 -> 0.583 / 0.535 / 0.568.
- Round-2 pooled AUROC is no higher than round 1 (0.630-0.652); what is new is a non-negative veto, not established.
- The recipe used round-1 VSP-T findings (strata counts, length-cue mechanism from round-1 per-pair scores).
- Leakage: check_vsp_items TEST_OVERLAP 0 projects / 0 code hashes, NEAR_DUP 0, FORK_PROJECT 0 (PROJECT_CAP linux 340
  disclosed); check_vsp_dev PASS 22/22. Residual risk: semantic/vendored clones below lexical Jaccard 0.5. Excluding
  possible Linux-derived projects: +0.057 / +0.059 / +0.055; leave-one-project-out (s0) +0.054..+0.061.
- Owed (descriptive): bow_lr refit on the K2 final items (deviation 12).
