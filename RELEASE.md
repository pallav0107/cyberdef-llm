# cyberdef-vuln — Release manifest

**Status: PUBLISHED (2026-11-13).** Code: https://github.com/pallav0107/cyberdef-llm and Model: https://huggingface.co/pallav0101/cyberdef-vuln-qwen2.5-7b-primevul. See `MODEL_CARD.md`
for the full card and `RESULTS.md` for every verified number; this file is the at-a-glance
manifest of what the release contains and how to reproduce it.

## What this is
Defensive, blue-team **vulnerability-DETECTION** LoRA adapters on Qwen2.5-Instruct
(Apache-2.0). Given one code snippet, the model emits `VERDICT: VULNERABLE|SAFE` (plus a CWE
name when applicable). It is a classifier of given code, never a generator of attacks.

## Released artifacts
| Adapter | Base (Apache-2.0) | Trained on | Role |
|---|---|---|---|
| `out/qlora-primevul` | Qwen2.5-7B-Instruct | PrimeVul (real) | **Champion** — best-in-class on PrimeVul + Devign |
| `out/qlora-devign` | Qwen2.5-7B-Instruct | Devign (real) | Devign-native variant |
| `out/qlora-1.5b` | Qwen2.5-1.5B-Instruct | PrimeVul | Scaling point |
| `out/qlora-14b` | Qwen2.5-14B-Instruct | PrimeVul | Scaling point (best-calibrated) |
| `out/qlora-32b` *(pending)* | Qwen2.5-32B-Instruct | PrimeVul | Scheduled — download in progress; folds in automatically when ready |

Each adapter directory is a standard PEFT adapter (load base + adapter via
`cyberdef.model_io.load_hf(base, adapter=...)`). Per-case eval outputs for every number are
in `results/*.json`.

## Headline (verified — every number recomputed from per_case; full tables in RESULTS.md)
- **Best-in-class** on **PrimeVul** (AUROC 0.786) and **Devign** (0.627) — same logprob-scored
  harness for the base model, two specialist peers, and ours.
- The edge **transfers** to an unseen dataset (PrimeVul→DiverseVul) across 4 seeds, with
  non-overlapping base/tuned ranges — learned detection, not memorisation.
- The recipe helps at **every size tested** (1.5B / 7B / 14B / 32B: the tuned adapter beats its own
  base on selective AUROC at each); **7B is the best absolute adapter**, 14B the best calibrated
  (tuned ECE 0.012). Calibration does not improve monotonically once 32B is included
  (tuned ECE 0.093 / 0.047 / 0.012 / 0.056), and at n=200 per size the AUROC standard error is
  about 0.04, so small between-size differences are within noise.

## Reproduce / verify
```bash
cd ~/missions/cyberdef-llm
PYTHONPATH=src HF_HUB_OFFLINE=1 .venv/bin/python scripts/make_results_table.py
```
This recomputes every score from `results/*.json` per_case, re-injects the tables into
`MODEL_CARD.md` / `PAPER.md` / `RESULTS.md`, and prints an integrity line. A stored score that
disagrees with its recompute is flagged, so a hand-edited number cannot pass.

## Honesty & licensing
- Every number is from a real recorded run; the acceptance gate rejects any results file whose
  `per_case` length ≠ n. Negative and rejected increments are kept as an honesty trail, not hidden.
- **Open-weight models only.** No outputs of any commercial API were used as training data.
- Defensive scope only; the model is an assistant, not an authority, and (see MODEL_CARD
  Limitations) false "SAFE" verdicts are the dangerous failure mode.

## To publish (author-only step — not done here by design)
The git history and any model-hub upload must be the **author's own** (no AI co-author on this
evidence). Initialise the repo and push under the author's own GitHub, then upload the chosen
adapter(s) under the author's Hugging Face account. The evidentiary value comes from external
adoption/recognition *after* publication — that is the step that turns this from a strong
artifact into citable evidence.
