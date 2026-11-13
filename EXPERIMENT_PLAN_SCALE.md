# Pre-registered plan: test-set size, training-data size, and 72B

Written and committed **before** any of these runs started (14 Nov 2026). Every outcome will be
reported, including ones that weaken the current headline. Nothing below changes the scoring
harness, prompt, LoRA configuration, learning rate, epochs, input length or training seed.

Fixed everywhere: QLoRA nf4, LoRA r=16 / alpha=32 on q,k,v,o,gate,up,down; 2 epochs; lr 1e-4;
4000-character inputs; training seed 0; the selective logprob verdict harness
(`scripts/selective_eval.py`); PrimeVul test split; every score recomputed from per-case outputs
by `scripts/verify_results.py`.

## A. Larger test sample (one variable: test-set size)
- Re-evaluate the existing adapters (1.5B, 7B, 14B, 32B; trained on 500 examples per class) and
  their base models on **1000 balanced PrimeVul test cases** (500 per class, sample seed 0)
  instead of 200. PrimeVul's test split has 549 vulnerable functions, so this is available.
- Purpose: cut the AUROC standard error from about 0.04 to about 0.02, so differences between
  sizes can be judged. No retraining.
- Outputs: `results/n1000_sel_<size>_{base,tuned}.json`.

## B. Four times the training data (one variable: examples per class, 500 -> 2000)
- Retrain **every** size (1.5B, 7B, 14B, 32B) with 2000 examples per class (PrimeVul train has
  4862 vulnerable functions), everything else identical, and evaluate on the same 1000 cases
  as A. All sizes get the extra data, so a size comparison is not confounded by data volume.
- Hypothesis: larger models were under-trained at 500 per class and gain more from 4x data.
- Outputs: adapters `out/qlora-<size>-d2000`, results `results/n1000_sel_<size>_d2000_tuned.json`.

## C. Qwen2.5-72B-Instruct (one variable: model size)
- Train 72B with the B setting (2000 per class) and evaluate base and tuned on the same 1000
  cases. Runs only after A and B, once the 72B weights are available on the training machine.
- Outputs: `out/qlora-72b-d2000`, `results/n1000_sel_72b_{base,d2000_tuned}.json`.

## Decision and reporting rules
- Headline claims are made only on the 1000-case results; a size or data effect is called a
  difference only if it exceeds about two standard errors of the difference.
- Hardware differences are reported (1.5B/7B/14B on an RTX PRO 4000 Blackwell; 32B and 72B on an
  NVIDIA GB10 in an aarch64 container), as is any failed or skipped run.
- The paper is updated with all of these numbers, whatever they show.

## D. Recipe tuning on the VALIDATION split (added 14 Nov 2026, before any D run)
- Goal: improve the recipe without touching the test set. Candidates for the 7B, each trained
  once with seed 0 and scored on **1000 balanced PrimeVul validation cases** (500 per class;
  the validation split has 593 vulnerable functions), never on test:
  - D1: 2000 per class, 2 epochs, lr 1e-4 (the B adapter, reused)
  - D2: all available training data (up to 4800 per class), 2 epochs, lr 1e-4
  - D3: 2000 per class, 3 epochs, lr 1e-4
  - D4: 2000 per class, 2 epochs, lr 2e-4
- Selection rule: the candidate with the highest validation AUROC is chosen; ties within 0.005
  go to the cheaper recipe. Only the chosen recipe is then scored on the 1000-case test sample,
  once. All validation scores are reported, including the losers.
- Outputs: `results/val1000_sel_7b_{base,d1,d2,d3,d4}.json`, adapters `out/qlora-7b-{d2,d3,d4}`,
  and (if the winner is not D1) `results/n1000_sel_7b_tuned_best.json`.

## Amendment (14 Nov 2026, before any B/C/D transfer result): cross-dataset leakage
- PrimeVul was assembled partly from earlier datasets, so about a third of the DiverseVul test
  functions we sample also occur in PrimeVul TRAIN (audit: `scripts/xdataset_overlap.py`,
  `results/xdataset_overlap.json`). For the existing 500-per-class adapter at most 3 of 400 test
  cases per sample were actually trained on, and the edge survives removing every overlapping case.
- Larger training sets (B: 2000/class, D2: up to 4800/class) raise that risk, so every transfer
  result from here on is reported both on the full sample and on the subset with all
  PrimeVul-TRAIN duplicates removed; claims are made on the de-duplicated subset.

## E. Independent transfer datasets from other groups (added 14 Nov 2026, before any E run)
- PrimeVul merged BigVul, CrossVul, CVEfixes and DiverseVul (PrimeVul paper, Sec. III-A), so new
  transfer tests use datasets outside that lineage:
  - **ReVeal** (Chromium + Debian; Columbia / UVA / IBM; `claudios/ReVeal`) — DiverseVul absorbed
    ReVeal, so overlap with PrimeVul is possible and is removed (below).
  - **CASTLE** (250 hand-labelled C programs, 25 CWEs; CASTLE-Benchmark, MIT licence).
  - **D2A** (IBM; static-analyser labels, expected to be noisy; `claudios/D2A`, labelled held-out slice).
  - plus a leakage audit of the existing **Devign** comparison against PrimeVul TRAIN.
- Every test sample is built with all PrimeVul-TRAIN duplicates removed (normalised exact match)
  before scoring; the number removed is reported. Balanced classes, sample seed 0, up to 200 per
  class (fewer where the clean pool is smaller, reported).
- Models: base vs the existing 7B adapter, and the D winner when available. No tuning on these
  sets; each is scored once. All results are reported, including any where the adapter does not
  beat its base.

## F. Further recipe levers (added 14 Nov 2026, before any F run; runs after D and E)
Each candidate changes ONE thing relative to the D winner (7B, seed 0) and is scored on the same
1000-case VALIDATION sample:
- F1 longer inputs: 8000 characters instead of 4000 (training and scoring).
- F2 larger adapter: LoRA r=32, alpha=64 instead of r=16, alpha=32.
- F3 ensemble: mean p_vuln of the top-3 single adapters by validation AUROC (from D1-D4, F1, F2).
Selection: the highest validation AUROC among {D winner, F1, F2, F3}; ties within 0.005 go to the
simpler option (single < ensemble; 4000 < 8000 chars; r16 < r32). Only that final choice is scored
once on the 1000-case PrimeVul test sample (the components of an ensemble are scored on test only
to form the ensemble score) and once on each step-E independent dataset. All validation results
are reported, including those that do not help.
