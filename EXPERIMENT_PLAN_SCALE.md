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
