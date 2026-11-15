# Errata to `acceptance/witness_bar.json`

The pre-registration file is left exactly as committed (commit eeb4a54, 2026-11-15 12:54:26 +11:00). Corrections are
recorded here instead, so the original stays verifiable. Both errors were found by an independent experiment audit of
the first result (Foundation-Sec-8B, run 43665351062) that recomputed everything from per_case.

## E1 — timing statement is false (low impact)
- The file says it was "written and committed BEFORE any model generated a single witness".
- In fact a pipeline smoke test (Qwen/Qwen2.5-1.5B-Instruct, base model, 6 programs) wrote
  `results/witness/eval_smoke.json` at 12:48:39, and the bar was committed at 12:54:26.
- That smoke model is not one of the registered models, it ran on 6 programs only, and it was not used to choose any
  threshold or setting. No output from the registered models (Foundation-Sec-8B, Qwen2.5-14B-Instruct) existed before
  the commit.
- Correct statement: committed before any output from the registered models existed.

## E2 — disclosure count is wrong
- The file says positives are "dominated by empty-input witnesses (40/50)".
- Correct count: **37/50** positives are empty-input witnesses (37 empty, 8 CANARY templates, 4 integer edges, 1 long
  string). The 40 came from the capture report, which counts all confirmed rows including 3 SAFE false positives.

## Audit findings that qualify the Foundation-Sec-8B result (for the record)
- Leakage: none (cross-fit verified). All AUROCs and the H1/H2/H3 calls reproduce exactly.
- H1 PASS is statistically robust but CONFOUNDED as a claim about witnessing: the gain is format compliance. The
  confirm rate among parsed witnesses is unchanged (0.543 base vs 0.548 fine-tuned). With an "unparseable -> empty
  input" fallback the zero-shot base scores 0.682, above the fine-tuned 0.672.
- The fine-tuned model reproduces training templates (112/149 outputs are the empty witness; 20 distinct strings);
  its AUROC equals an always-empty-input policy (0.6717).
- The only confirmations outside the deterministic witness list came from the zero-shot base model (SQL injection on
  CASTLE 89-2 and 89-5 via `env DB_*` variables); the fine-tuned model lost both.
- Honest claim supported: fine-tuning taught the witness output protocol; it did not improve witness finding, ties a
  no-model empty-input policy, and stays below the deterministic baseline (H2 not passed).
- This result is not to be cited without the pre-registered Qwen2.5-14B result alongside it.
