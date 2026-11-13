# Pre-registered plan: Java, Python and JavaScript/TypeScript (written 14 Nov 2026, before any data work)

Goal: extend the defensive vulnerability detector beyond C/C++ to Java, Python and JavaScript/
TypeScript, and enable each language in the downstream agent ONLY if it passes the bar below.

## Data
- Training and in-domain test data: real security-fix data from CVEfixes and CrossVul (CC BY 4.0;
  attributed), function level, labels from fixing commits (pre-fix function = vulnerable; unchanged
  functions from the same commits/projects = safe). Exact dataset sources and versions are recorded
  in an amendment before any training.
- Split BY PROJECT (repository), never by function, so test projects are unseen in training; exact
  and normalised duplicates removed across splits.
- Independent test where available: OWASP Benchmark (Java), plus any further independent set named
  in the amendment before scoring.

## Model and recipe
- Base: Qwen2.5-7B-Instruct (same as the C/C++ champion). One multi-language QLoRA adapter, with the
  C/C++ recipe held fixed (nf4, LoRA r16/alpha32, 2 epochs, lr 1e-4, 4000 chars, seed 0) unless the
  C/C++ step-F winner changes it, in which case that winning recipe is used (stated before training).
- Same selective, logprob-scored verdict harness; every score recomputed from per-case outputs.

## Evaluation and the activation bar (fixed now)
- Per language: base vs tuned on a balanced held-out-project test sample (up to 500 per class; fewer
  if the pool is smaller, reported) and on any independent set.
- A language is ENABLED in the agent only if the tuned model beats its base on that language's
  held-out-project test by more than two standard errors of the AUROC difference AND reaches
  AUROC >= 0.65. Otherwise it ships disabled or marked experimental, and the paper reports it as such.
- All results are reported, including languages that fail the bar.
