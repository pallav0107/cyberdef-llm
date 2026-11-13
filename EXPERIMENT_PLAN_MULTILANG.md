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

## Amendment (14 Nov 2026, before any multi-language training)
## Amendment 1 to EXPERIMENT_PLAN_MULTILANG.md (proposed 14 Nov 2026; to be applied by the author before any training; no model has been trained or scored on this data)

Exact data sources, replacing the "Data" section's "CVEfixes and CrossVul":

1. **CVEfixes is not used.** The official CVEfixes v1.0.8 (Zenodo 13118970, CC BY 4.0) is 12.71 GB (SQL dump), above the 3 GB budget for the
   mobile link; the HF mirrors examined were either larger, hunk-level, or vulnerable-only. Training and in-domain test data are
   **CrossVul only**: Zenodo 4734050 v2.0 (DOI 10.5281/zenodo.4734050, md5 aa95465e9dc98ce222ab2f3aa7af5997, CC BY 4.0).
2. **Granularity and labels.** CrossVul provides whole-file pre-fix/post-fix pairs per security-fix commit. Functions are extracted with
   tree-sitter (java 0.23.5, python 0.25.0, javascript 0.25.0, typescript 0.23.2). Vulnerable = pre-fix function absent (after
   comment-stripping and whitespace-normalisation) from the post-fix file; safe = pre-fix function present unchanged in the post-fix file
   of the same commit. Post-fix versions of changed functions are not used as safe examples.
3. **Languages / sets.** `ml_java`, `ml_python`, `ml_js` (JavaScript + TypeScript pooled; TypeScript alone has too few vulnerable examples).
4. **Split.** By repository (owner/repo from the commit URL), seed 0, 80/10/10 over 518 repositories (414/52/52), one global assignment.
   Dedup on norm(code[:4000]): conflicting-label keys dropped, cross-split duplicates kept in the highest-priority split (test > validation
   > train), within-split duplicates collapsed. Counts (vulnerable/safe): java test 56/493, python test 84/1,586, js test 112/1,265; full table
   in `data/MULTILANG_DATA.md`.
5. **Test size.** The "up to 500 per class" test is capped by the pool: balanced n = 56 (Java), 84 (Python), 112 (JS/TS) per class, reported as
   such. Confidence intervals will be wide (test projects: 9 / 17 / 27).
6. **Independent test.** OWASP Benchmark for Java, github.com/OWASP-Benchmark/BenchmarkJava @ a452b3aafd232245d0753e54eb243d6651f8ef96,
   expectedresults-1.2.csv, GPL-2.0: one servlet file per test case, vulnerable = "real vulnerability = true" (1,415), safe = false (1,325);
   test only. No independent set is named for Python or JavaScript/TypeScript; none will be added after seeing results.
7. **Pre-declared limitations / controls.** (a) Label noise: a function changed by a fix commit is not necessarily the vulnerable function.
   (b) Safe functions come only from files the fix touched. (c) Length confound: vulnerable functions are ~3x longer than safe ones
   (median 723/1099/918 vs 232/383/298 chars for java/python/js in train); a length-only baseline (AUROC from character count) will be
   reported for every language and test set next to the model's AUROC, and a language is not enabled on the strength of a result no better
   than that baseline. This control is added in the amendment, before training; the activation bar in the plan is otherwise unchanged.
8. Everything else (recipe, harness, activation bar) is as in the plan.

Build is deterministic: `scripts/build_multilang.py`; parquet SHA-256 values are in `data/multilang/out/manifest.json`.

### Stricter activation bar (added by the owner's session before any multi-language training)
Because vulnerable functions are about 3x longer than safe ones in this data, a length-only
baseline (score = function length in characters) is computed on every test set, and a language is
ENABLED only if, in addition to the original conditions, the tuned model's AUROC also exceeds the
length-only baseline's AUROC on that language's held-out-project test. OWASP Benchmark is reported
separately and does not by itself enable a language.
