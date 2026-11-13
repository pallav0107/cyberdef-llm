# Multi-language data (Java, Python, JavaScript/TypeScript) - provenance and construction

Prepared 14 Nov 2026 for `EXPERIMENT_PLAN_MULTILANG.md`. Built CPU-only by `scripts/build_multilang.py`
(deterministic; seed 0). Output: `data/multilang/out/<name>/<split>.parquet`, `data/multilang/out/manifest.json`
(counts, parameters, tool versions, SHA-256 of every parquet). Loaders: `benchdata.BENCHES` entries
`ml_java`, `ml_python`, `ml_js` (train/validation/test) and `owasp_java` (test only); all load offline.

## Sources (exact)
| Source | Id / version | Size | Licence | Used |
|---|---|---|---|---|
| CrossVul | Zenodo record 4734050, v2.0 (2021-05-03), DOI 10.5281/zenodo.4734050, file `dataset.zip`, md5 aa95465e9dc98ce222ab2f3aa7af5997 (verified) | 367 MB | CC BY 4.0 | YES: whole-file pre-fix (`bad_*`) / post-fix (`good_*`) pairs + commit URL + CVE + CWE |
| OWASP Benchmark for Java | github.com/OWASP-Benchmark/BenchmarkJava, master @ a452b3aafd232245d0753e54eb243d6651f8ef96 (12 Nov 2026), `expectedresults-1.2.csv` (Benchmark v1.2) | 76 MB clone | GPL-2.0 (code is redistributed only as derived parquet in the working tree; the licence header is stripped from the model input, attribution kept here) | YES, test only |
| CVEfixes v1.0.8 | Zenodo 13118970 (DOI 10.5281/zenodo.4476563), `CVEfixes_v1.0.8.zip` | 12.71 GB | CC BY 4.0 | NO: over the 3 GB limit, not downloaded |

CVEfixes alternatives examined and rejected (inspected, not used):
* `Thanmaisri/CVEFixesDB` 31.4 GB SQLite (too large). `starsofchance/CVEfixes_v1.0.8` 12.7 GB zip + 46 GB jsonl (too large).
  MoreFixes (Zenodo 11110595) 3.49 GB PostgreSQL dump (over limit).
* `hitoshura25/cvefixes` (rev d4f5c4ea, 1.22 GB, Apache-2.0 label): shard 0 inspected - rows are diff HUNK regions aggregated
  per commit (may span several files), not functions; unusable for function-level labels. Shard 0 deleted after inspection.
* `ecwk/vulnerable-functions-and-commits_cvefixes-2022` (rev 6e1b7fc0, 10 MB, no licence declared): function level but all 8,226
  rows are pre-fix/vulnerable only, no language column, no safe class; unusable alone (kept in `raw/ecwk`, unused).
* `rufimelo/cvefixes-cwe`, `rufimelo/crossvul-cwe`, `hitoshura25/crossvul`: tokenised/derived re-packagings; the official CrossVul
  zip was used instead.
**CVEfixes is therefore NOT used. The multi-language data is CrossVul-only; the plan's "CVEfixes and CrossVul" must be amended
to say so (see the amendment).** A faithful function-level CVEfixes (its `method_change` table) needs the 12.7 GB official
release; adding it later is a separate, owner-approved download.

## Label rule (function level, derived from file pairs)
CrossVul gives, per security-fix commit, the whole file before (`bad_`) and after (`good_`) the fix. Functions are extracted from
both with tree-sitter (java 0.23.5, python 0.25.0, javascript 0.25.0, typescript 0.23.2; tree-sitter 0.26.1). For each function in
the PRE-fix file (comment-stripped, whitespace-normalised text):
* **vulnerable (1)** = not present among the post-fix file's functions (changed or deleted by the fix);
* **safe (0)** = present unchanged in the post-fix file (same file, same commit, untouched by the fix).
Post-fix versions of changed functions are NOT used as safe examples (avoids the near-duplicate-of-vulnerable caveat).
Functions: Java method/constructor declarations with body; Python `function_definition` (incl. methods, outermost only);
JS/TS `function_declaration`, generator, `method_definition`, and variable/assignment/object-pair bound function/arrow
expressions (outermost only; if an outermost node exceeds 20,000 chars it is descended into). Skipped: functions < 40 chars or < 3
lines (8,248), functions with parse errors (81), nodes over 20,000 chars (descended), JS/TS files with a line > 1,000 chars
(minified, 42 pairs), identical pairs (17), pairs with no functions (278). `.js/.jsx/.mjs/.cjs` -> JavaScript, `.ts` -> TypeScript,
`.tsx` -> TSX grammar; JS+TS are pooled in `ml_js` (TypeScript alone has too few vulnerable examples: 346 TS + 11 TSX functions
extracted overall).
**Known caveats (label noise, not fixed):** (a) "changed by the fix commit" is not "the vulnerable function": commits also
refactor or touch unrelated functions, so some "vulnerable" labels are not security-relevant; (b) "safe" functions come only from
files the fix touched; (c) LENGTH CONFOUND: median train function length is 723/1099/918 chars (vulnerable) vs 232/383/298 (safe)
for java/python/js - changed functions are much longer. A length-only baseline should be reported alongside any result.

## Split and dedup
Repository = `owner/repo` from the commit URL (lower-cased), 518 repositories. Shuffled with `random.Random(0)` and cut 80/10/10 by
repository (414/52/52), one global assignment across all languages (so no repository appears in two splits of any language).
Dedup key = `benchdata.norm(code[:4000])` (what the model sees). Per language group: (1) any key labelled both vulnerable and safe is
dropped entirely; (2) a key present in several splits is kept only in the highest-priority split (test > validation > train);
(3) duplicates within a split are collapsed. Verified: normalised test functions in train = 0 and validation in train = 0 for all
three languages.

## Counts (functions; vulnerable / safe; projects)
| Set | train | validation | test |
|---|---|---|---|
| ml_java | 480 / 8,402 (87) | 25 / 766 (8) | 56 / 493 (9) |
| ml_python | 393 / 7,127 (117) | 40 / 1,137 (16) | 84 / 1,586 (17) |
| ml_js (JS 12,057 + TS 346 + TSX 11 before split) | 505 / 8,340 (221) | 80 / 2,112 (28) | 112 / 1,265 (27) |
| owasp_java | - | - | 1,415 / 1,325 (2,740 test cases) |

Rows extracted before dedup: java 14,887; python 15,321; js 17,245 (raw vulnerable 661 / 639 / 757). Dropped conflicting-label
duplicates 63 / 114 / 69; cross-split 9 / 120 / 15; within-split 4,593 / 4,720 / 4,747.
**Test pools are smaller than the plan's 500 per class** (56 / 84 / 112 vulnerable): per the plan, report the smaller balanced
size. `balanced_sample(..., cap_to_pool=True)` (opt-in; default unchanged) returns the balanced capped sample; without it a
request for 200 returns 200 safe + the short vulnerable count. Test project counts are 9 / 17 / 27, so confidence intervals are wide.

## OWASP Benchmark mapping
`expectedresults-1.2.csv` rows `test name, category, real vulnerability, cwe`. Each `BenchmarkTestNNNNN.java` (a complete servlet
test case) is one example; label vulnerable = `real vulnerability == true` (a true positive: the flaw is reachable), safe = `false`
(a deliberate false-positive trap: looks risky, is not exploitable). 2,740 cases, 1,415 true / 1,325 false, 11 categories. The
18-line GPL licence comment before `package` is stripped from the model input. Code is synthetic and generated from templates, so
it is an independent but distribution-shifted test; it is never used for training.

## Reproduce
`data/multilang/tsvenv/bin/python scripts/build_multilang.py data/multilang/raw data/multilang/out` (raw = unzipped CrossVul under
`raw/crossvul/x/`, clone under `raw/owasp/`). Attribution: CrossVul (Nikitopoulos et al., ESEC/FSE 2021), CC BY 4.0; OWASP
Benchmark (OWASP Foundation, D. Wichers), GPL-2.0.
