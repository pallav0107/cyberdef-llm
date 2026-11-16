# EXPERIMENT_PLAN_IMPROVE.md  (append-only; owner: improve-builder agent)

Written 2026-11-14 BEFORE any arm below was run. Never rewrite earlier entries; an amendment carries a timestamp and states
that no results had been read. Everything here is prefixed `imp_` (scripts/imp_*.py, src/cyberdef/imp_*.py, results/imp_*.json,
acceptance/improve/). It does not touch the other pipeline's files. No git commit, no publishing.

## Global rules (apply to every arm unless the arm says otherwise)
- Motivation: the published PrimeVul AUROC 0.786 is a length artifact (length-only 0.82). On the length-matched set
  (results/lenmatched_eval_cases.json, 537 pairs, 1074 cases) the published 7B scores 0.532, 7B-lenmatch 0.561, flawfinder 0.506,
  semgrep 0.505, length-only 0.50. CASTLE empty-input ASan floor: 34/99 vulnerable, 0/99 safe flagged (AUROC ~0.67).
- Metric: AUROC with Hanley-McNeil SE; difference SE = sqrt(SE1^2+SE2^2) (conservative). Pairwise win rate (binomial SE) on matched sets.
- DEFAULT BAR: delta > 2*SE_diff AND above the length-only baseline AND above flawfinder/semgrep, all on the SAME cases. A model
  number "beats chance" only if AUROC > 0.5 + 2*SE. Otherwise the result is reported as NULL.
- Every results JSON carries `per_case` with len(per_case)==n; metrics are recomputed from per_case by acceptance/improve/imp_verify.py
  and by scripts/verify_results.py where the file has the selective_eval schema. Length-only and SAST baselines are reported next to
  every model number on the same cases. Cases are never dropped; failures are counted and reported. Thresholds are never changed
  after results are seen.
- Fail-first: acceptance/improve/check_<arm>.py is written first and shown to FAIL before the work exists; mutation proofs go in
  acceptance/improve/MUTATION_PROOF.md.
- GPU: only the Spark, only via queue files ~/cyberdef-lm/queue/P<NN>_imp_<name>.sh (bands P20 #5, P21 #3/#4, P30 #2 seeds, P40 #1/#6/#7,
  P50 #8/#9a/#5-reasoning). The box GPU is never used. Open-weight models only; never any *-ablit variant. No commercial-API output
  enters training data or prompts/exemplars. Code is executed only in docker with --network none, memory/pids caps, non-root.
- Seed 0 everywhere unless stated.

## #9c Selective prediction / abstention (CPU)
- Variable: the selection signal (model confidence vs length extremity), same scorers, same cases (lenmatched_eval_cases, 1074 cases).
- Scorers: published 7B (results/ab_pub7b__lenmatched.json), 7B-lenmatch (lm_sel_lenmatch_on_matched.json), base 1.5B
  (ab_base1.5b__lenmatched.json), 1.5B-lenmatch (ab_lm1.5b__lenmatched.json), flawfinder and semgrep (reason_B_sast_*_matched.json);
  base 7B (lm_sel_base_on_matched.json / reason_A) only if a verified file exists at run time, else reported as a gap.
- Confidence: models max(p_vuln,1-p_vuln); SAST = finding score (higher = more confident "vulnerable"); ties broken by case order
  after a stable sort (reported tie counts).
- Coverage 10/25/50/100%: top-k by confidence. For each: accuracy of the hard label, precision of VULNERABLE calls, AUROC of the score
  inside the selected subset with HM SE, class balance of the subset, length-only AUROC on the same subset.
- Baseline: select by length extremity = |ln(chars) - median ln(chars)| descending, same k, SAME scorer. Plus a random-selection
  permutation null (1000 draws, seed 0) for each coverage.
- Bar: selecting by confidence "helps" only if subset AUROC(conf selection) exceeds both the scorer's full-set AUROC and the
  length-extremity selection AUROC by > 2*SE_diff, and exceeds the random-selection null mean by > 2 null-SD. Else NULL.
- Output: results/imp_9c_selective.json. Check: acceptance/improve/check_9c.py.

## #2 LLM-guided fuzzing on CASTLE (CPU in docker; seeds from GPU band P30)
- Data: the 198 CASTLE programs of results/xdata_castle_cases.json (99 vulnerable, 99 safe). Labels used only for scoring.
- Sandbox: docker aflplusplus/aflplusplus image, --network none --memory 2g --pids-limit 256 --cpus 1 --cap-drop ALL, non-root,
  compiled with AFL++ clang (AFL_USE_ASAN=1 AFL_USE_UBSAN=1; UBSan traps on error) inside the container. At most 6 programs in parallel (nproc=24; quarter of the cores).
- Input channel: stdin. Programs that reference argv get AFL++'s argv-fuzz shim (AFL_INIT_ARGV(); stdin supplies argv) inserted
  mechanically after the first `main(...) {` (label-independent). Programs reading files or env vars are NOT specially handled: reported as a limitation, not dropped.
- Time budget (same for EVERY arm): 60 s wall per program (afl-fuzz -V 60, static seed -s 0). A fixed subset - the 40 programs
  (20 vulnerable + 20 safe) with the smallest sha1(id) within each label - also gets 300 s.
- Arms (single variable = where the starting seeds come from):
  (i) fuzzer, seed corpus = one file containing a single newline (honest fuzzing floor, no model);
  (ii) fuzzer + RANDOM seeds: 5 seeds, byte length log-uniform on [1,256], printable-ASCII/newline content, drawn with Random(sha1(id)+0);
  (iii) fuzzer + LLM seeds: the model reads ONLY the program text (no labels, no crash inputs) and writes exactly 5 seeds, each <=256 bytes,
        plus an optional dictionary; generated on the Spark GPU (P30). Seed-size distribution is compared with (ii) by KS; if they differ
        (KS p<0.05) an extra control (ii') resamples random seeds with the LLM's per-program sizes - this is pre-registered now;
  (iv) LLM seeds executed directly, no fuzzing (the instrumented binary run on each seed).
- Score per program: sanitizer-confirmed crash within budget. A crash found by AFL++ is replayed on the same binary in the sandbox;
  it counts only if stderr carries an ASan/UBSan report ("confirmed"); plain abort()/signal crashes are reported separately as
  "unconfirmed". Binary score = confirmed within budget; continuous score = 1 - t_first/budget (0 if none) for AUROC.
- Report per arm: confirmed crash rate on vulnerable vs safe (every safe-program crash is listed and investigated, not hidden),
  compile failures (count), AUROC +/- HM SE against the empty-input floor (results/reason_D0_castle_preflight.json, ~0.67) and the
  length-only and flawfinder/semgrep (reason_B_sast_*_castle.json) baselines on the same cases.
- Attribution: if arm (i) already scores high, model contribution = (iii) - (i), reported with SE_diff; (iii)-(ii) controls for "any seed".
  Bar for "LLM seeds help": AUROC(iii) - AUROC(ii) > 2*SE_diff AND AUROC(iii) - AUROC(i) > 2*SE_diff.
- Output: results/imp_2_fuzz_<arm>.json (per_case, n=198). Check: acceptance/improve/check_2.py.

## #5 Stronger open models, zero-shot (GPU P20)
- Variable: the model. Same prompt, same logprob scorer, same loader as scripts/selective_eval.py (reimplemented in imp_selective.py only to
  add a chat-template suffix required by gpt-oss; for Qwen models the code path is identical).
- Models: Qwen/Qwen2.5-Coder-7B-Instruct, Qwen/Qwen2.5-Coder-32B-Instruct, Qwen/Qwen3-Coder-30B-A3B-Instruct, openai/gpt-oss-20b.
  Each is downloaded and load-tested on the Spark first; any that fail to load are reported, not silently dropped.
- Sets: PrimeVul length-matched (1074), VulSpot holdout matched (1200), VulSpot no-linux matched (1200). CONTAMINATION: PrimeVul (2024) and
  CASTLE (Mar 2025) may be in 2025-model pretraining; VulSpot (Oct 2026) is the clean test and is reported as a separate headline split and flagged.
  The reference arms are base/published/lenmatch Qwen2.5-7B on the same sets (existing results).
- Bar: default; the headline is the VulSpot clean split. Reasoning-mode 300-case subset (P50) only if time permits, with the best model.

## #3 Surrounding context (CPU build; GPU eval P21)
- Variable: context appended to the SAME functions. Data: VulSpot holdout-matched and no-linux-matched cases (id=vs<idx>), columns callees,
  types_used, macros_used, globals_used (names only; each list capped at 40 names, in source order). Context is a comment block placed AFTER the function.
  Total input capped at 6000 chars by truncating context first, never the function.
- Length handling: (a) original pairing with the length-only AUROC RECOMPUTED on the augmented total input; (b) a NEW pairing re-matched on TOTAL
  length (chars and tokens, caliper 3%, lenmatch.match_pairs). Both reported; verdict is judged on (b) (length-only must fall in [0.45,0.55]).
- Models: base 7B, published 7B (out/qlora-primevul), 7B-lenmatch (out/qlora-7b-lenmatch). Comparison: same model on the same functions without context
  (existing full-function results where the case set equals; otherwise rescored by the job). Bar: default, paired difference on (b).

## #4 Sink-centred slices (CPU build; GPU eval P21)
- Variable: full function vs slice. tree-sitter-c (venv ~/venvs/sast). Sinks: calls to memcpy/memmove/memset/strcpy/strncpy/strcat/strncat/sprintf/
  snprintf/vsprintf/printf-family/free/realloc/malloc/calloc/alloca/read/recv/fread/gets/scanf-family, subscript writes (a[i]=...), pointer arithmetic,
  pointer deref assignment. Slice = sink statements + the backward def-use closure over identifiers appearing in the sink statements
  (statements within the function that assign/declare those identifiers, iterated to a fixed point, depth<=3) + the guarding if/while/for/switch headers
  of every kept statement + function signature + closing braces; elided runs are replaced with `/* ... */`. Original line order preserved.
- Parse failures (tree has ERROR nodes at the root or no sink found) are counted and flagged; the case falls back to the full function.
- Sets: PrimeVul matched (1074), VulSpot holdout matched (1200), no-linux matched (1200). Length handling as #3: length-only recomputed on the slices; also a re-pairing on slice length.
- Models: base 7B, published 7B, 7B-lenmatch. Bar: default on the re-matched pairing.

## #1 Vulnerable-vs-patch pairs (GPU P40)
- Data: VulSpot cpp, project_holdout TRAIN, pair_status=='paired', clean==True, label_conflict dropped; a pair = vulnerable row + the row at its fixed_func_idx.
  Linux pairs capped at 30% of pairs. Overlap removal by normalised-text hash and commit_id against: PrimeVul validation+test, VulSpot
  holdout/no-linux matched cases, VulSpot test_paired_high (both split files), CASTLE. N = 1000 pairs (2000 functions), seed 0.
- Arms (single variable = pairwise ranking term): ARM = standard verdict CE + w*(-log sigmoid(s_vuln - s_fix)), w=1, s = logit(VULNERABLE) - logit(SAFE) at
  the first diverging verdict token; CONTROL = the SAME 2000 functions, identical pair batches/order, standard CE only. Base Qwen2.5-7B-Instruct QLoRA, r16, 2 epochs, lr 1e-4,
  max-chars 4000, per-device batch 2 (one pair), grad-accum 4. scripts/imp_train.py (copy of train_devign.py + flags).
- Eval (both arms): PrimeVul length-matched, VulSpot holdout/no-linux matched, VulSpot test_paired_high pair accuracy (p_v > p_f) and pair-correct rate, CASTLE.
  Bar: default on each; pair accuracy must exceed 0.5 + 2*binomial SE and exceed CONTROL by > 2*SE_diff.

## #6 Adversarial length debiasing (GPU P40)
- Variable: `--adv-length lambda` in imp_train.py: head (linear->16->1) on the final hidden state at the last prompt position, predicting ln(chars), connected
  through a gradient-reversal layer (strength lambda, 1.0). Same data/recipe as the plain run: natural unmatched PrimeVul TRAIN, n-per-class 1000, 2 epochs, lr 1e-4,
  max-chars 4000, batch 1 x accum 8 (train_devign defaults; the exact published recipe is not documented in the repo, so a plain rerun with the same script is the
  CONTROL and out/qlora-primevul is reported only as a reference).
- Mechanical checks: CPU smoke test on a tiny model (grads flow; adversary loss rises while task loss falls); after training, a linear probe predicting length from
  hidden states (held-out PrimeVul, ridge, R^2 on a 30% split) must be WORSE for the adversarial adapter than the control. If not, the arm is reported as "adversary ineffective".
- Eval: length-matched PrimeVul, VulSpot matched sets. Bar: default.

## #7 Cleaner labels (GPU P40)
- Variable: label quality. Same VulSpot project_holdout TRAIN pool, same recipe as the plain control of #1 (CE, pair batches), same size N=1000 length-matched pairs
  (chars+tokens caliper 3%, lenmatch.match_pairs, same overlap removal as #1): CLEAN = clean==True and label_conflict False; UNFILTERED = every row incl. clean==False and label_conflict==True.
- Eval: PrimeVul length-matched, VulSpot matched, CASTLE. Bar: default (Delta CLEAN-UNFILTERED > 2*SE_diff and above baselines).

## #8 Self-consistency (GPU P50)
- Cases: the 150 cases of 75 matched pairs chosen by random.Random(0).sample over sorted pair ids of lenmatched_eval_cases. Model: base Qwen2.5-7B-Instruct, SC-CoT prompt of src/cyberdef/sc_cot.py (read-only import).
- Arm: N=5 samples, T=0.7, top_p=0.95, max_new_tokens 1200; score = mean of the per-sample validator score (s_sc), and majority vote variant. Comparison: one greedy sample, same token budget.
- Report AUROC +/- SE, parse rate, N x token cost. Bar: self-consistency mean beats greedy by > 2*SE_diff and beats length-only 0.50 + 2*SE.

## #9a Localization (CPU build; GPU P50)
- Data: VulSpot cpp vulnerable functions that are in project_holdout test_paired_high (held-out projects) with non-empty changed_lines that fall inside the function body.
  Truth lines = changed_lines of the vulnerable version (relative = abs_line - func_start_line + 1; mapping validated by text equality, mismatches counted and excluded from the
  denominator ONLY as "unmappable", reported).
- Metrics: top-1, top-3 line accuracy (hit if predicted line in truth set). Baselines on the same functions: random line (expected value computed exactly), first regex sink line, flawfinder's first reported line,
  longest line. Model: direct prompt ("list the 3 line numbers most likely to contain the vulnerability", numbered source), base 7B and published 7B, greedy, 64 new tokens.
- Bar: top-1 beats the best baseline by > 2*binomial SE_diff.

## #4 amendment 1 (2026-11-14, before any model was scored on any slice; no model results had been read)
- The first slicer run (strict rule: root.has_error -> fallback) gave 74% parse-failure fallbacks (cases are truncated to 4000 chars, macro-heavy, partly C++), which would
  make the slice arm mostly the full function. Parse failure is now: no function_definition with a body found, OR ERROR nodes cover > 10% of the function's bytes.
  Statements inside tolerated local errors are simply not recognised as sinks. Fallback behaviour and counting are unchanged. The strict-rule counts remain in this note:
  primevul_matched 791/1074, vs_holdout_matched 882/1200, vs_nolinux_matched 314/624 fell back. Acceptance check_4 sink-token regex widened to include parenthesised pointer assignment `(*p) = ...` (a pre-registered sink class).

## CoT PROGRAM (owner decision, 2026-11-14; appended BEFORE any training result, trace, or imp_ GPU result existed; no results had been read)
Amends the training arms #1, #6, #7: every chain-of-thought (CoT) arm gets a VERDICT-ONLY TWIN on identical rows, identical steps and recipe; the single variable is the
training TARGET (reasoning trace vs "VERDICT: X"). The earlier verdict-only arms #1 (pairs), #6 (adv-length), #7 (clean) are exactly the twins of arms ③, ④, ⑤.

### ① Trace bank (queue P35, vLLM on the Spark, src/cyberdef/vllm_gen.py read-only, src/cyberdef/sc_cot.py read-only)
- Generators (open weights only; no Claude/commercial model): G1 Qwen2.5-7B-Instruct base, G2 base + published adapter out/qlora-primevul, G3 openai/gpt-oss-20b,
  G4 Qwen/Qwen3-Coder-30B-A3B-Instruct (if it loads in the container; else Qwen/Qwen2.5-Coder-32B-Instruct; else reported as not available).
- Prompt: the SC-CoT system prompt of sc_cot.py, numbered lines, JSON-only output; K=4 samples, T=0.7, top_p=0.95, max_new_tokens 1200; seed 0.
- Data (TRAIN data only; re-checked by normalised text AND commit id against PrimeVul val/test, VulSpot holdout/no-linux/test_paired_high, CASTLE):
  pool A = results/imp_train_pairs_items.json (1000 vuln/fix pairs, VulSpot clean paired TRAIN); pool B = imp_train_clean_lm_items.json; pool C = imp_train_unfilt_lm_items.json;
  pool J = Juliet C/C++ runnable subset (bad and good variants, <=400 functions, selected by sha1 order). G1 runs on A+B+C+J; G2-G4 run on A+J only (cost bound).
  A length-matched PrimeVul TRAIN pool is NOT used (the repo lacks a leak-clean builder for it that I may import without editing existing code).
- Tags per trace (all stored): V verdict equals ground truth (VULNERABLE/SAFE; UNCERTAIN = not V). P sc_cot.validate() passes with verdict_final == verdict_raw.
  S (vulnerable functions only, only where VulSpot line labels exist = changed_lines of the vulnerable row mapped to relative lines): some cited sink line is in the labelled set +/-0 lines.
  X (runnable code only): witness executed in the Stage-D sandbox (src/cyberdef/exec_harness.py, read-only) -> sanitizer report on the vulnerable version and none on its good twin.
  C: verdict unchanged on all of three length edits (pad = dead-comment block ~50% longer, compress = comments/blank lines removed, rename = identifiers renamed), greedy, re-generated by the SAME generator;
  C is computed only for traces already passing V+P (cost bound) and the edited-input traces are stored (used by arm ⑥).
- Output results/imp_trace_bank.jsonl (one trace per line: function id, pool, generator, sample, engine version, tags, trace text, parsed JSON). Tag counts are reported. Acceptance: acceptance/improve/check_bank.py.

### Selection rule for training traces (fixed now)
Per function: among its traces from ALL generators that carry V and P (and S for pool-A/B/C vulnerable functions that have line labels; and X for pool J), keep the one with the most tags, then the shortest, then
generator order G1<G2<G3<G4, then sample index. Functions with no qualifying trace are dropped from the CoT arm AND from its twin (the twin trains on exactly the retained functions, same order).

### Arms (each vs its twin; base Qwen2.5-7B-Instruct QLoRA r16 alpha32, 2 epochs, lr 1e-4, max-chars 4000, seed 0; effective batch 8; scripts/imp_train.py)
- ② CoT-SFT (P40): SFT on selected traces (V+P+S, +X on pool J). Twin: verdict-only SFT on the same retained functions.
- ⑥ Counterfactual CoT (P41): ② plus length-edited copies (traces generated on the edited input that kept the same verdict and pass V+P), trained to the SAME verdict, and the pair consistency term
  (vuln/fix opposite verdicts = ranking loss, weight 1, on pool-A pairs that retain both members). Twin: verdict-only on the same rows incl. the same edited copies and the same ranking term.
- ③ CoT x pairs = #1 (P42): pool-A pairs where the vuln trace passes V+P+S and the fixed trace passes V+P (SAFE with a sufficient guard for every sink = it cites the guard that protects the sink); SFT on both traces + ranking loss on verdict confidence
  (s = logit VULNERABLE - logit SAFE at the verdict token; -log sigmoid(s_vuln - s_fix), w=1). Twin = #1's verdict-only pair arm on the same retained pairs.
- ④ CoT x anti-length = #6 (P43): ② plus gradient-reversal length head (lambda 1) on the hidden state at the verdict position. Twin: verdict-only + the same head on the same rows. Plain ② is the lambda=0 reference.
- ⑤ CoT x clean = #7 (P44): ② on pool B (clean) vs ② on pool C (unfiltered), same number of retained functions (min of the two, truncated in file order). Twin pair: verdict-only clean vs unfiltered on the same rows.
- ⑦ Exec-grounded CoT (Stage E, P45): only X-tagged traces on pool J plus V+P-passing SAFE traces on their good twins. FEASIBILITY gate, not a performance gate: run iff >= 200 distinct X-verified traces exist after the bank is built; otherwise reported INFEASIBLE with the count. Twin: verdict-only on the same rows. Bar if run: default, on CASTLE witness execution and the held-out sets.
- ⑧ Loop-revision CoT (P46+): multi-turn witness -> sanitizer feedback -> revision traces built from the pipeline's Stage F outputs; waits on F's infrastructure (not on F winning). Not started until those files exist; reported as waiting.
- ⑨ Repair CoT (P46+): traces with a fix step whose patch passes the pipeline's Stage-G verifier; waits on that verifier. Not started until the artifacts exist; reported as waiting.
- ⑩ GRPO (P50): optional, only if ② shows signal by the bar below. Reward = V + S + X - penalty when the verdict flips under a length-only edit, with validator + execution in the reward. NOT implemented unless ② passes; reported as not run.

### Evaluation (every arm and its twin side by side; same cases)
(a) length-matched PrimeVul (1074); (b) VulSpot holdout matched and no-linux matched; (c) the Stage-H probe (length slope + semantic sensitivity; scripts/reason_H_*.py read-only) on both arms; (d) CASTLE: SC-CoT generation executed in the Stage-D sandbox vs the 0.67 empty-input floor
(verdict-only twins have no witness: only their verdict AUROC is reported); (e) sink-line localization accuracy (#9a set) for CoT arms.
Scoring: verdict-only models = logprob p_vuln as in selective_eval.py; CoT models = P(VULNERABLE) read from the generated trace's own verdict-token logprobs (greedy), and the validator score s_sc; both reported.
BAR (fixed now): a CoT arm "reasons beyond length" only if on BOTH (a) and (b): AUROC_arm - AUROC_twin > 2*SE_diff AND AUROC_arm > 0.5 + 2*SE AND above the length-only and SAST baselines on the same cases AND the Stage-H length slope CI inside +/-0.03 per 1000 chars.
Anything else is reported NULL (including improvements that are within 2*SE_diff).

### Dependencies and queue map
P20 #5 | P21 #3/#4 evals | P30 #2 seeds | P35 trace bank (+ its C pass) | P40 ② twin-pair | P41 ⑥ | P42 ③ | P43 ④ | P44 ⑤ | P45 ⑦ (feasibility-gated) | P46+ ⑧ ⑨ (waiting) | P50 #8, #9a, #5-reasoning, ⑩ (conditional).
Eval jobs follow their training job under the same band (suffix e). The earlier verdict-only #1/#6/#7 runs are the twins and share those jobs (no duplicate training).

## #4 amendment 2 (2026-11-14, after code review, before ANY model was scored on a slice; no model results had been read)
- Reviewer finding: the slicer dropped early-exit guards (`if (len > n) return;`) because the return is neither a sink nor a definition, which erases the usual vulnerable-vs-fixed difference
  and biases the slice arm toward 0.5. Now return/goto/break/continue statements are also kept when an enclosing if/while/for/switch condition mentions a variable of the sink closure. Slices are rebuilt.

## Training-loss normalisation note (2026-11-14, before any training ran)
- Reviewer finding: ImpTrainer.compute_loss now passes num_items_in_batch to the model (token-weighted CE over the accumulation group, like the stock Trainer); pair and adversary terms are divided by
  gradient_accumulation_steps. Therefore imp_train.py with all flags off is intended to reproduce train_devign.py's loss normalisation; this has NOT been verified by a dry run on the GPU (flagged, unmeasured).
  Verdict slot for the adversary/ranking: the position predicting the verdict token (plan text 'last prompt position' for verdict-only targets = last prompt token + the 2 teacher-forced tokens 'VERDICT:').
- imp_eval_cot records p_source per case and p_fallback_rate; a fallback rate above 1% invalidates the verdict-token AUROC for that run (reported as such).

## #2 amendment 1 (2026-11-14, after the first empty-seed run, BEFORE any random-seed or LLM-seed run; no LLM-seed result existed)
- The first empty-seed run (kept in results/imp_superseded/) classified a crash as "confirmed" only on AddressSanitizer text. UBSan with recover disabled prints "runtime error:" and aborts (SIGABRT), so 18/99 vulnerable
  crashes were mis-filed as "unconfirmed" (the other pipeline empty-input floor counts UBSan text: 34/99). Fix: "runtime error:" text also counts as a sanitizer-confirmed crash (same definition as that floor). Also: result.json is written incrementally,
  replays use a 3 s timeout and at most 10 crashes (4 programs lost their result to the container time limit), and the stderr of unconfirmed crashes is stored. Arms (i) and (ii) are RE-RUN from scratch with this harness; no number from the superseded run is used.
- Reporting additions (declared before the re-run): compile failures are intrinsic (missing sqlite3/mysql/openssl/curl headers; the empty-input floor has 33 such failures) so AUROCs are reported on all 198 AND on the programs compiled in both;
  AFL++ aborts when every seed times out or crashes (counted as afl_aborted). A secondary "any crash signal" AUROC is reported but is not the pre-registered score.

## Re-ordering amendment (owner request relayed by the coordinator, 2026-11-14 ~21:40 AEDT; NO affected output existed: no #1 adapter, no trace, no bank row)
1. #1 retraining pair moved forward: P42_imp_a_1ctl and P42_imp_b_1arm become P16a_imp_1ctl and P16b_imp_1arm, plus P16c_imp_1eval (evaluates ONLY those two adapters on PrimeVul-matched, VulSpot matched x2, CASTLE, test_paired_high pairs).
   Design, data, recipe and bar are unchanged. The verdict-only #6 (adv-length) and #7 (clean labels) pairs stay at P43 / P44.
2. The trace bank is split into two passes; every item file, adapter, training log and result of a CoT arm carries the bank it used in its NAME and in a `meta` field (bank=quick | bank=full):
   - QUICK bank (P35): generators g1 = Qwen2.5-7B-Instruct base and g14 = Qwen2.5-14B-Instruct (already in the Spark HF cache: fastest to load of the stronger open models; Qwen2.5-Coder-7B / gpt-oss-20b are still downloading over the slow uplink),
     K=2 samples, T=0.7, top_p 0.95, max_tokens 1200, seed 0, same SC-CoT prompt, same tags V/P/S/X/C, same selection rule. FIXED SUBSET (pre-registered now): pool A items[0:1600] of results/imp_train_pairs_items.json (the first 800 pairs, file order)
     + pool J: the 120 Juliet testcase files (both the bad and the good variant = 240 items) with the smallest sha1(pair name). Pools B and C are NOT in the quick bank. 1840 functions; estimated 1.5-2.5 h of Spark time (budget <= 4 h; the estimate rests on an UNMEASURED vLLM throughput).
   - Arms ② and ⑥ (CoT-SFT and counterfactual CoT, each with its verdict-only twin) are trained on the QUICK bank right after it (P36, P37): arms trained as `2cot_q`, `2twin_q`, `6cot_q`, `6twin_q`.
   - FULL bank (all generators g1-g4, K=4, pools A+B+C+J) runs later (P55); ALL CoT arms (② ③ ④ ⑤ ⑥ ⑦) are (re-)run on it as the second round (P60-P65, adapters suffixed _f). Results of the two rounds are reported side by side and never pooled.
   - Quick-bank consequences stated in advance: S/X/C tags are computed identically; arm ③ (pairs) and arm ⑤ (clean labels) need pairs / pools B,C, so they exist only in round 2; the quick round trains on fewer functions (about the retained share of 1840), so the quick round is a SMALLER-SAMPLE test of the same hypothesis, reported with its own SE.
3. Queue order from here (Spark, lowest name first): P16a 1ctl, P16b 1arm, P16c 1eval | P20 #5 | P21 #3/#4 | P30 #2 seeds | P35a-c quick bank | P36 ②-quick | P37 ⑥-quick | P43 #6 | P44 #7 | P50 #8, #9a | P55 full bank | P60-P65 round 2 (② ⑥ ③ ④ ⑤ ⑦).

## Re-ordering amendment, naming addendum (2026-11-14 ~22:00 AEDT; still no affected output)
- Queue file names: the runner sorts in en_US.utf8, where `P16a_...` sorts BEFORE `P16_Dgen_tuned7b`. To get the requested position (after P16_Dgen_*, before P17_) the #1 jobs are named P16_za_imp_1ctl, P16_zb_imp_1arm, P16_zc_imp_1eval (they sort after P16_ and before P17_ in both C and en_US collation).
- The quick bank and the quick-bank arms are placed at P19_z1* (bank), P19_z2* (arm 2), P19_z3* (arm 6): after the pipeline's own P17-P19 jobs, BEFORE my P20 (#5) and P21 (#3/#4) evals, per the owner priority that arms 2 and 6 come first. Full bank P55, round 2 P60-P65, #6 P43, #7 P44, #8/#9a P50, #2 seeds P30 are unchanged.

## Coordinator decisions, amendment batch (2026-11-14 ~22:30 AEDT; no #1/CoT adapter, no trace, no LLM-seed or random-seed fuzz result existed)
1. REORDER: quick bank and arms 2/6 move to sit right after the #1 pair: P16_zd/ze/zf (quick bank g1, g14, merge+items), P16_zg/zh/zi (arm 2 quick: twin, CoT, eval), P16_zj/zk/zl (arm 6 quick). Order: #1 pair -> quick bank -> 2 -> 6 -> pipeline C-SC / VulSpot evals.
2. GPU SMOKE gate P16_z0_imp_smoke runs before any long imp_ training. 30 steps in three configs on the same 240 items (results/imp_train_smoke_items.json = first 240 items of the pairs file): imp flags-off --pair-batches (a), imp --pair-loss 1 (b), and train_devign.py (ref).
   Criteria (scripts/imp_smoke_check.py, fixed now): F1 all logged loss/grad_norm finite; F2 (a),(b): mean of last 2 logged losses < mean of first 2; F3 median grad_norm of (a) within [1/3,3] and (b) within [1/5,5] of ref; F4 (b) logged a finite pair-loss mean.
   Every imp_ training job starts with imp_smoke_ok and refuses (exit 5) unless results/imp_smoke_result.json has pass=true. A smoke failure is reported, the criteria are not edited.
3. FUZZ RULE (applies to every arm identically): the seed corpus of each program is executed directly in the sandbox first; a sanitizer-confirmed seed crash counts as a crash at t=0 (already the harness behaviour; now the number of programs this affects is reported per arm).
   Seed TIMEOUTS: AFL++ -t stays 1000+ (seeds that time out are skipped; if every seed times out/crashes AFL aborts and the program is counted as no-further-crash) and direct-run replays use a 3 s timeout that counts as no-crash: the same in every arm. Programs affected are counted (afl_aborted).
   Arm (i) is re-scored under this rule and arms (ii), (iii), (iv) follow; all arms are re-run in the derived image below, so the earlier runs (kept in results/imp_superseded/) are not used.
4. COMPILE COVERAGE: derived image imp-castle-san:1 (docker/imp_castle_san/Dockerfile: FROM aflplusplus/aflplusplus:stable + gcc-13 as default gcc + libsqlite3-dev, default-libmysqlclient-dev, libssl-dev, libcurl4-openssl-dev; built, not host-installed). Link flags added to the compile line: -lsqlite3 -lmysqlclient -lssl -lcrypto -lcurl -lpthread.
   Before: afl-clang compile failures 35/198, gcc:13 floor compile failures 33/198. After: reported from results/imp_2_compile_coverage.json.
5. #7 (verdict-only clean vs unfiltered) moves to P85 and its CoT counterpart (arm 5, round 2) to P86. Only 4.75% of the unfiltered rows are non-clean, so the expected effect is about zero: reported as a WEAK CONTRAST if run.
6. #5 big models: HOLD (no Qwen3-Coder-30B / Coder-32B download pending the owner's decision on hotspot data cost). Coder-7B and gpt-oss-20b downloads continue; gpt-oss-20b is enqueued once it loads. Arm g4 of the full bank is therefore reported unavailable unless the owner approves.
7. CASTLE-674-10 (labelled SAFE; fibonacci(0) recurses without bound, ASan stack-overflow found by the fuzzer at 453 ms) is recorded as a SUSPECTED CASTLE LABEL ERROR in results/imp_castle_label_note.json. It stays in the data and in every metric as labelled; a sensitivity number without it is reported separately.

## #5 amendment (owner decision relayed 2026-11-14 ~22:25 AEDT; no #5 result existed)
- Qwen3-Coder-30B-A3B-Instruct and Qwen2.5-Coder-32B-Instruct are SKIPPED PERMANENTLY (hotspot data-cost decision by the owner). They were NOT tested; the write-up must say the larger models were not tested because of this decision, not because of any result.
- #5 runs with: Qwen2.5-14B-Instruct (already in the Spark HF cache; added as an arm), Qwen2.5-Coder-7B-Instruct and gpt-oss-20b (the two downloads already running). Same prompt, loader and scorer; sets as pre-registered (PrimeVul matched, VulSpot holdout/no-linux matched, VulSpot reported as the clean split).
- Full-bank generator g4 (Coder-30B/32B) is replaced by g14 = Qwen2.5-14B-Instruct (K=4, pools A+J), so the full bank is g1 base 7B, g2 published adapter, g3 gpt-oss-20b (if it loads), g14 Qwen2.5-14B.

## Trace-bank decoding amendment (coordinator request, 2026-11-14 ~22:35 AEDT; NO bank row, adapter or CoT result existed; the quick bank had not started)
- Reason: pipeline Stage C parsed only 73-85% of outputs and truncated 5-9% at 1200 tokens; SC-CoT traces are longer.
- Decoding for the trace bank AND the CoT evaluation (imp_eval_cot, imp_sc_vote) is now: vLLM structured outputs (guided JSON decoding against the SC-CoT schema in src/cyberdef/imp_sc_schema.py, key order and fields taken from the sc_cot.py SYSTEM prompt; schema sha recorded)
  and max_new_tokens = 2048. Temperature/top_p/K unchanged (bank T=0.7, top_p=0.95, K=2 quick / K=4 full; C-pass and evaluation greedy). Exception: gpt-oss-20b (harmony channels) is decoded free-form with max_new_tokens 6144 (3x, reasoning effort low) and its rows record guided=none.
- Every bank row carries decoding={guided, schema_sha, max_new_tokens, temperature, top_p, engine, generator}; results/imp_trace_bank*_counts.json reports parse rate, truncation rate and the yields V/P/S/X/C/VP per generator and pool. The P and S filters are NOT loosened: strictness is intended
  (Stage C: 68-82% of VULNERABLE verdicts failed the line/sink consistency check). Guided JSON guarantees syntax, not the line/sink semantics checked by sc_cot.validate.
- Evaluation of CoT arms uses the identical config (guided JSON, 2048 tokens) so bank traces and evaluation decode the same way; reported next to every CoT result (field `decoding`).

## Trace-bank decoding amendment, addendum (2026-11-14 ~22:45 AEDT; still no bank row)
- No separate schema implementation: src/cyberdef/imp_sc_schema.py imports the pipeline src/cyberdef/schemas_cot.py (SC schema and schema_hash, read-only) and uses the same vLLM StructuredOutputsParams(json=schema) path as vllm_gen.generate_all, with sampling params supplied by the caller
  (bank T=0.7, top_p=0.95, n=K) because generate_all is greedy-only. Decoding rows use the same keys as vllm_gen.decode_config (engine, guided, schema_hash, max_tokens, temperature) plus top_p and generator. My earlier private schema is retired (the schema and hash are now the pipeline own).
- Bank jobs P16_zd, P16_ze and P55_a refuse to start unless the pipeline queue/done/P16_y_C2_smoke.rc exists and equals 0 (guided-decoding smoke).

## #2 amendment 2: input-channel analysis and decision NOT to extend the harness (2026-11-14 ~23:05 AEDT; no random-seed or LLM-seed result existed; arm (i) unchanged)
- Coordinator question: does stdin-only feeding cap the CASTLE ceiling? Analysis: scripts/imp_input_channels.py -> results/imp_castle_input_channels.json (source regexes + one quick sandboxed run per program; labels used only for cross-tabs; the sanitizer-detectable CWE set was fixed in the script before the cross-tab was computed).
- Findings: (a) the AFL_INIT_ARGV shim feeds argv from stdin since the first run: it is active on 15/15 vulnerable argv programs, so argv was already covered. (b) 17/99 vulnerable programs read files and 3/99 read env; the harness does not feed these (20.2% of vulnerable programs unreachable;
  79.8% reachable by stdin + argv shim). (c) Only 33/99 vulnerable programs belong to sanitizer-detectable CWE classes (memory-safety / UB / assertion); the empty-input floor confirms 27 of them and the empty-seed AFL arm 22, and only 4 of the 33 need argv/file/env (822-3 argv, 787-4 argv, 822-4 file literal, 822-5 env; two already fed by the shim). So at most about 2 more sanitizer-catchable programs could be reached by a file/env extension.
  The remaining vulnerable programs are mostly non-crash classes (22, 78, 89, 253, 327, 362, 522, 761, 798, ...) that no sanitizer can flag whatever the input. The ceiling is set by the CWE class, not by the input channel.
- Decision (before any re-scoring): the harness is NOT extended with file/env feeding. Reason: expected gain <= ~2 programs, and 13 of the 17 file programs open a path held in a variable (needs data-flow to feed), which would add an unvalidated component. Arm (i) is therefore not re-run for this reason and the floor-vs-arm comparison stays as is.
  Reachability reported: before = after = 79.8% of vulnerable programs reachable. If the coordinator wants the extension anyway it is a pre-registration change for ALL arms and requires re-running arm (i).
- Seed-timeout aborts (25 programs, 15 vulnerable / 10 safe): 18 also time out in a plain 3 s run, 7 exit within 3 s (slower than AFL -t 1000 under ASan, e.g. sleep()); source cues: network wait 9, thread wait 9, infinite loop 8, sleep 7, stdin-loop 4 (non-exclusive), 12 of the 25 read no input at all. These are behaviours of the program, not input starvation.

## STRICT X amendment (coordinator request, 2026-11-14 ~23:30 AEDT; NO bank row existed)
- Why: Stage D found that 11/12 and 19/20 model-witness CASTLE catches also crash with EMPTY input; Juliet: 158/246 bad programs crash with no input (ours: x86 `exec_sanitizer`). A plain "witness crashes" X tag certifies nothing about reasoning.
- The old tag X (bad program crashes with empty input AND the trace says VULNERABLE) is kept and renamed in reports as LOOSE X (it still serves as label verification when selecting training traces for arm 2/6).
- New tag X_strict (scripts/imp_bank_strictx.py): the model WITNESS is executed in a sandbox (docker, --network none, caps dropped, non-root, mem/pids caps; on the Spark inside cyberdef-train:aarch64 with gcc ASan+UBSan, Juliet sources rsynced to ~/cyberdef-lm/imp_juliet).
  X_strict = bad program crashes (ASan/UBSan text) under the witness AND does NOT crash under empty input (recomputed in the same environment) AND the same witness does NOT crash the good twin. Only V+P traces with a concrete witness are eligible; anything else is X_strict=False (or None when not a Juliet bad function).
  Witness->input mapping (fixed now): witness.values dict with 'argv'/'stdin' keys used as given, else the scalar values in order; how_to_feed mentioning argv/command/argument -> argv, otherwise stdin joined by newlines.
- Reporting: per generator, LOOSE X count and STRICT X count (results/imp_trace_bank*_counts.json: x_loose_traces_by_gen, x_strict_traces_by_gen, x_strict_distinct_functions, juliet_VP_traces_considered, bad_programs_crashing_on_empty_input_among_considered).
  The arm 7 feasibility gate (>= 200) now uses the STRICT count only (arm7_feasible = x_strict_traces_total >= 200); arm 7 trains only on X_strict bad traces plus V+P SAFE traces of their good twins. Expect infeasibility: most Juliet bad programs crash without input, and the gate is honest about it.
- Selection rule for arms 2/6 gains a rank bonus for X_strict; the filter `X is not False` (label verification by execution) is unchanged.
- Acceptance: acceptance/improve/check_strictx.py (controls S1-S5 incl. a short witness, an empty-input-crashing program, a twin that also crashes; --broken mutant dropping the empty-input condition is caught). Architecture note: Spark executes on aarch64, my earlier Juliet labels (exec_sanitizer) came from x86; strict X uses the Spark-side empty-input result.

## #2 amendment 3: ONE shared oracle spec and per-CWE-group reporting (coordinator request, 2026-11-14 ~23:40 AEDT; NO re-scoring under it had been run; arm (i)/(ii) results so far are under the older single-variant harness and are superseded by the re-run below)
- Spec file: results/imp_castle_oracle_spec.json (generated by scripts/imp_oracle.py --write-spec; the pipeline adopts the same file for D0 / Stage D). It fixes the build flags per variant and exactly which report classes count as "confirmed":
  A = afl-clang-fast ASan+UBSan (the fuzzing build; ASan reports incl. bad-free (CWE-761), UAF, overflows, stack overflow (recursion), UBSan runtime errors, glibc assert aborts, cpu_hang = timeout>=3 s with user+sys CPU>=2 s);
  A_leak = the same binary with detect_leaks=1 (LeakSanitizer at exit, CWE-401; detect_leaks was OFF in all earlier runs); B = clang -fsanitize=integer in recover mode (signed AND unsigned overflow/wrap, divide-by-zero, shifts count; implicit-conversion reports are recorded, NOT counted);
  C = clang -fsanitize=thread (data races, CWE-362), built and run in a separate container with seccomp=unconfined because TSan calls personality(ADDR_NO_RANDOMIZE) which Docker default seccomp blocks (still --network none, --cap-drop ALL, non-root, no-new-privileges, mem/pids caps; stated relaxation);
  D = gcc 13.3 ASan+UBSan (the pipeline floor toolchain). Benign ASan classes (allocation-size-too-big, out-of-memory) are recorded but do not count.
- Program-level rule: CONFIRMED if any counted report fires on any corpus input (seeds + AFL++ queue/crash inputs, at most 40) under any variant; AFL++ fuzzes the A build only, the other variants REPLAY the corpus; time-to-first = min over firing inputs of the discovery time (seeds t=0).
- CWE groups for reporting (fixed now): (a) sanitizer-detectable = {119,120,121,122,124,125,126,127,129,131,190,191,194,369,415,416,457,476,590,680,761,787,788,822,824,825,908,401,362}; (b) crash-like-other = {617 assert, 674 recursion, 835 loop}; (c) every other CWE in CASTLE.
  Every number is reported overall AND per group (confirmed rate on vulnerable, confirmed on safe = false positives, AUROC within the group), plus per variant contribution.
- Re-scoring: a new arm `floor` (one empty-stdin input, no fuzzing, all variants) re-scores the empty-input floor under the spec; arms (i) empty-seed and (ii) random-seed are re-run under it (60 s budget, same image imp-castle-san:1); (iii)/(iv) will use it too. The old results stay in results/imp_superseded/.
- Not changed: input feeding (stdin + argv shim; files/env not fed; amendment 2), seed rule, time budget.

## Behaviour-oracle GO and SC-CoT v2 amendment (owner decision relayed 2026-11-14 ~23:20 AEDT; NO bank row, adapter, behaviour-oracle result or v2 trace existed)
1. BEHAVIOUR ORACLES, build order: command injection (CWE-78) and format string (CWE-134), then path traversal (CWE-22/23/36), then SQL injection (CWE-89); resource exhaustion (CWE-770) LAST and optional (false-positive risk). Each oracle has fail-first controls with a safe twin and a with-the-shim-disabled control,
   is added to the SHARED oracle spec (results/imp_castle_oracle_spec.json, version bumped to 2) and will be adopted by the pipeline harness. The model or fuzzer supplies the payload; the oracle only judges. cpu_hang and the v1 oracles are unchanged.
   Token convention (to be agreed with the pipeline agent / SC-CoT v2): injection payloads contain the literal string CANARY. At feeding time the harness replaces every CANARY in the witness input (stdin bytes and argv) by a per-run token T = "CNRY" + 8 random hex digits and detects T in the observation points; the model never sees T.
   Observation: an LD_PRELOAD shim (plain, non-sanitizer build, because ASan requires first position in the library list) that logs system/popen/exec*, open/fopen/stat/opendir/access, sqlite3_exec/prepare, mysql_query/real_query, and NEVER executes a command or opens a path/query containing T (it returns failure): attacker commands are logged, not run.
   Verdict rules (fixed now): cmd_injection TRUE iff a shell-spawning call (system, popen, execl/execv*-of-sh -c) receives a command string containing T within 40 characters after a shell metacharacter (; | & ` $( newline); format_string TRUE iff program output contains T immediately followed by >= 2 hex-pointer items (0x... or (nil)) produced from %p/%x payloads (not echoed literally);
   path_traversal TRUE iff an open/fopen/stat/opendir/access path contains T and a '..' component; sqli TRUE iff the SQL text handed to the sqlite3/mysql API contains T outside a quoted literal (quote-aware tokeniser) together with a quote character that closed a literal. Payload batteries are NOT supplied by the oracle: random-seed and empty-seed arms contain no CANARY and cannot confirm these oracles by construction.
2. SC-CoT v2 (owner request; the pipeline agent owns src/cyberdef/schemas_cot.py): new fields vuln_class (CWE/OWASP label), oracle (asan|ubsan|lsan|tsan|integer|cmd_injection|path_traversal|sqli|format_string|resource|none), a witness shaped for that oracle or static_evidence when oracle=none.
   THE QUICK BANK (P16_zd/ze and everything depending on it, P16_zf-zl) IS HELD until the v2 schema hash is deployed; those jobs are removed from the queue now and re-enqueued afterwards, so no v1 trace enters any CoT arm.
3. New bank tags once v2 exists: K = vuln_class correct (against the true CWE where known), O = chosen oracle consistent with the true class (map: memory-safety CWEs -> asan; 190/191/369 -> ubsan/integer; 401 -> lsan; 362 -> tsan; 78 -> cmd_injection; 134 -> format_string; 22/23/36 -> path_traversal; 89 -> sqli; 770 -> resource; others -> none).
   X_strict uses the CHOSEN oracle and, until the behaviour monitors exist in the bank pipeline, means the sanitizer oracles only; the full bank (P55) adds the behaviour oracles. CoT arms train on traces whose class AND oracle are right AND whose witness is verified by that oracle (strict).
4. Training data for the injection classes: Juliet C/C++ CWE-78, CWE-134, CWE-23, CWE-36 on the TRAIN side, input-driven console/environment/file variants only (no socket variants); CASTLE stays test-only. Juliet C has no SQL injection class, so SQLi stays untrained / zero-shot unless a non-CASTLE C source is found; this is a reported GAP.

## Pool J2 and synthetic SQLi pool amendment (coordinator request, 2026-11-15 ~00:20 AEDT; no bank row, no SQLi program and no model trained on J2 existed)
- POOL J2 (built, results/imp_train_juliet2_items.json): Juliet 1.3 CWE78, CWE134, CWE23, CWE36 `_01` testcases, console/environment/file variants only (no socket, no w32), TRAIN side; CASTLE stays test-only. Bad/good texts as in pool J.
  Label verification (author-supplied reference payloads, NOT model payloads, under the spec-v2 shim): a pair is kept only if bad+payload fires the class rule, bad+benign does not, bad+EMPTY input does not, and the good variant+same payload does not. Juliet-specific feed: console -> stdin; environment -> env ADD; file -> /tmp/file.txt.
  Result: 102 candidate files -> 51 verified pairs (CWE78 12, CWE134 15, CWE23 12, CWE36 12; 17 per feed type); rejected 16 not compiled, 35 bad variant did not fire, 0 fired on benign/empty/good. Fail-first: with the shim disabled the shim-based classes (78/23/36) verify ZERO pairs (CWE134 is judged on program output and is exempt).
  CWE23/36 are folded into class 22 for K/O; CWE36 uses the J2 label rule 'the attacker path (token) reaches open/stat unchanged' because absolute paths contain no '..' (the spec-v2 CASTLE path oracle is unchanged and still needs '..'). True CWEs updated (imp_true_cwe.json now 1921 functions).
  Strict-X on J2 in the FULL bank (P55) uses the CHOSEN behaviour oracle and the same Juliet feed with the MODEL witness: bad program fires under the witness, does NOT fire on empty input, and the good twin does NOT fire under the same witness. (Needs an image with gcc, g++ and libsqlite3 on the Spark: built there, not host-installed.)
- SYNTHETIC SQLi POOL (SQL injection has no Juliet C class): an OPEN-WEIGHT model (Qwen2.5-14B-Instruct, local; never Claude or any commercial API) writes sqlite3-based C programs that read ONE input line from stdin, each as a VULNERABLE program and a SAFE twin (bound parameter or quote escaping), across 20 scenarios x 20 samples at T=0.8 (generation is a Spark queue job, band P35).
  Keep a pair ONLY IF, under the spec-v2 sqli oracle with author-supplied reference payloads (bare CANARY token; battery: x' OR CANARY=CANARY --, 1 OR CANARY=CANARY, x" OR CANARY=CANARY --, x') OR CANARY=CANARY --): the vulnerable program fires on at least one payload, does NOT fire on benign or empty input, and the twin does NOT fire on ANY payload, benign or empty input. Both compile with gcc -lsqlite3.
  Dedupe: (1) against CASTLE: every CASTLE CWE-89 program (vulnerable and safe) by normalised-text hash AND token 5-shingle Jaccard (>= 0.5 rejects; exact Jaccard is stricter than MinHash); (2) within the pool Jaccard >= 0.8 keeps the first. Label everywhere: "synthetic, open-weight generated (Qwen2.5-14B-Instruct), oracle-verified". Report pool size, generator and rejection counts by reason.
  The pool is TRAIN data for the injection classes only; CASTLE SQLi programs stay test-only. Because the generator and the verifier share the oracle, the pool tests recognition of this oracle's notion of SQLi, not independent ground truth: stated limitation.

## Full-bank behaviour strict-X amendment (2026-11-15 ~00:55 AEDT; no bank row existed)
- Full bank pools (P55): A, B, C, J as before plus J2 (Juliet injection pool) and Q (synthetic SQLi pool) for generator g1; A, J, J2, Q for g2, g3 (gpt-oss, if it loads) and g14 (Qwen2.5-14B; the Coder-30B/32B generator g4 was dropped with the #5 decision). The P55 job refuses to start without results/imp_train_sqli_items.json and imp_train_juliet2_items.json.
- STRICT X for J2 / Q functions with a BEHAVIOUR chosen oracle (scripts/imp_bank_strictx.py, behaviour branch): the model witness payload (witness.values scalars joined by newlines; feed from how_to_feed: 'env' -> env ADD, 'file' -> /tmp/file.txt, otherwise stdin) is run on the bad program under the shim:
  X_strict = the CHOSEN oracle fires on the bad program under the witness AND does NOT fire on empty input AND does NOT fire on the good twin under the same witness. Without the literal CANARY in the witness the oracle cannot fire, so X_strict is False. If the chosen oracle is a sanitizer oracle on these pools X_strict stays None.
  Runs on the Spark in image imp-spark-beh:1 (cyberdef-train:aarch64 + libsqlite3-dev + g++, built there, --network none). Acceptance: check_strictx_beh.py (B1 token witness True, B2 no-token False, B3 twin also fires False, B4 wrong chosen oracle False, B5 no witness False; the twin-condition mutant is caught).
- Arm 2/6 training items now also draw on J2 and Q (execution-verified injection classes); arm 7 uses STRICT-X traces of every pool.

## Timestamp correction note (2026-11-14 23:30 AEDT by the box clock; append-only, earlier entries untouched)
- Several amendment headers above carry times I estimated by hand, and they run roughly 50 minutes ahead of the box clock (for example entries headed ~23:30, ~23:40, ~23:55, 2026-11-15 ~00:20 and ~00:55 were written between about 22:35 and 23:26 AEDT). The ORDER of entries is the true order of writing, and every amendment still precedes the results it governs. Authoritative wall times are the file modification times of this plan and of the artifacts.

## J2 disclosure and timestamp rule (2026-11-14 23:27:48 AEDT, machine clock)
- J2 label-verification reference payloads (x; echo CANARY, CANARY%p.%p.%p.%p, ../../CANARY/x, /CANARY/x) and the SQLi reference battery were WRITTEN BY THE RESEARCH TOOLING (me), not by an open-weight model. They only SELECT which Juliet pairs / synthetic pairs enter the pools; they are never training data and never appear in any prompt or trace.
- From now on every pre-registration or amendment timestamp is taken from the box clock by the same command that appends the entry; no time is typed by hand.

## Category balancing + O_owasp amendment (coordinator request; 2026-11-15 00:18:23 AEDT, machine clock; no quick-bank output existed yet)
- CATEGORY of a training row = the true monitor class from the pipeline CWE_ORACLE map applied to the TRUE CWE of its pair group (the SAFE twin inherits its vulnerable partner category): memory/asan, integer, lsan, tsan, resource, cmd_injection, format_string, path_traversal, sqli, none, plus unknown (no true allowed CWE known).
- BALANCING (arms 2, 3 and therefore 6 which is built from them; arms 5 and 7 are not balanced: arm 5 varies label quality, arm 7 is tiny): pair-aware stratified resampling (whole pair groups, so a SAFE twin stays with its vulnerable partner). Every runtime-monitor category that has data is upsampled WITH replacement to a floor of 5 percent of the rows;
  the largest category is shrunk WITHOUT replacement so the total stays (about) fixed (check: |rows_after - rows_before| <= 4). Seeds: arm 2 seed 0, arm 3 seed 1. The verdict-only TWIN uses the IDENTICAL row multiset (the same parallel resampling), so balancing is not a second variable.
- Reported per arm in results/imp_cot*_items_stats.json: category_rows_before / category_rows_after, SAFE fraction before / after (must stay within [0.4, 0.6]: correct SAFE traces remain in every slice because they travel with their pair group; Stage C showed about 64 percent VULNERABLE verdicts, so no VULNERABLE bias may be introduced), floor_rows, largest category shrunk.
- O_owasp tag: chosen vuln_class.owasp equals the OWASP-2021 label of a true CWE, from the pipeline CWE->OWASP map (expected as CWE_OWASP in src/cyberdef/cwe_oracle.py; the tag is None until that map exists). REPORTED ONLY, not in the selection filter; K (CWE class) and O (monitor) remain the selection criteria.

## max_new_tokens 4096 amendment (coordinator request; 2026-11-15 00:19:55 AEDT, machine clock; NO bank row existed)
- The pipeline P16_y_C2_smoke failed on ONE truncation at 2048 tokens (not on decoding). Equal caps everywhere: the trace bank (quick and full), the C2/C-SC runs and the CoT evaluations (imp_eval_cot, imp_sc_vote) now use max_new_tokens = 4096 (imp_sc_schema.MAX_NEW_TOKENS, the bank default and the eval defaults).
  gpt-oss-20b (free-form, harmony channels) uses min(3 x 4096, 5000) so that prompt plus generation fit max_model_len 8192; its rows record the cap actually used in decoding.max_tokens.
- The bank gate is UNCHANGED: jobs still require queue/done/P16_y_C2_smoke.rc == 0 (the pipeline re-runs the same smoke job name with the 4096 cap). If the pipeline moves to SC-CoT schema v2.1 (a maxLength bound) the new hash is picked up automatically through schemas_cot.SC and recorded in decoding.schema_hash.
- O_owasp points at CWE_OWASP in src/cyberdef/cwe_oracle.py (the tag was already coded to read CWE_OWASP first); it stays reported-only.
2026-11-15 01:13:58 AEDT Box training lane started: #6 (control + --adv-length adversary) runs on the BOX GPU (box venv), outputs out/imp_box_*, results/box_*; evals on length-matched PrimeVul + both VulSpot matched + CASTLE; one job at a time via .box_gpu.lock. Spark continues generation+eval in parallel. No bar or recipe changed.

## Box lane orchestrator amendment (2026-11-15 01:18:38 AEDT, machine clock; no CoT arm had been trained)
- scripts/imp_box_lane_cot.sh is a self-advancing orchestrator for box-GPU batch 2+ (launched once by the coordinator session). It shares the flock with batch 1, polls the Spark for the quick-bank CoT item files, and meanwhile uses idle GPU time for #7 (verdict-only clean vs unfiltered; a WEAK contrast: 4.75 percent of the unfiltered rows are non-clean).
  When the bank is ready it pulls the (already category-balanced) items, trains arm 2 + verdict-only twin and arm 6 + twin (out/imp_box_2cot, 2twin, 6cf, 6twin) with the pre-registered recipe, evaluates the twins on the box (logprob scorer) and copies the CoT adapters to the Spark under distinct names for vLLM generation evals (jobs P16_zn/zo), pulling the results back as results/box_ev_*.json.
- CoT-model evaluation cannot run on the box (HF generation at up to 4096 tokens for ~3000 cases is infeasible and vLLM exists only in the Spark image): the arm-vs-twin comparison therefore mixes a box-trained adapter evaluated on the Spark with a box-evaluated twin; the scoring code, cases and baselines are identical, only the generation engine for the CoT arm differs from the logprob scorer (as pre-registered: CoT arms are scored from their own verdict-token probability).
- Failure policy: a failed or OOM job is recorded in logs/box_train.log and results/box_lane.status and the orchestrator moves on; recipes and bars are never changed to rescue a run. #7 gives up after 12 attempts while waiting.

## Gradient checkpointing and engine-matched evaluation amendment (coordinator request; 2026-11-15 01:25:25 AEDT, machine clock; no CoT arm output existed)
1. scripts/imp_train.py gains --grad-ckpt on|off (default on): explicit model.gradient_checkpointing_enable(use_reentrant=False), enable_input_require_grads() and config.use_cache=False after get_peft_model. This is a PURE MEMORY OPTIMISATION: identical gradients up to numerical noise, no change to the objective, data, recipe or result; it is NOT a recipe change.
   In the 4-bit path prepare_model_for_kbit_training already enables checkpointing by default, so the call is idempotent there (the #6 plain control, already training before this edit, and the adversary run are therefore the same recipe). Purpose: stop the 3-4k-token CoT runs from running out of memory on the 24 GB card.
   Verification: scripts/imp_box_smoke_ckpt.sh (20-step box smoke, loss must stay finite and fall, grad norms finite; result results/box_smoke_ckpt.json). The smoke needs the box-GPU lock and must be launched from a session allowed to start box jobs; it has NOT run yet.
2. ENGINE-MATCHED twin-vs-CoT comparison: every box-trained CoT adapter (2cot, 6cf) is ALSO scored on the box with imp_selective (same bitsandbytes engine, the same ANSWER prompt, logprob scorer and cases as its verdict-only twin) into results/box_lp_ev_<tag>_<set>.json (script scripts/imp_box_lane_evalmatch.sh).
   This is the clean twin-vs-CoT delta for the bar. The Spark vLLM GENERATION eval of the same adapters (results/box_ev_<tag>_<set>.json) stays and is reported SEPARATELY as the distinct test of whether producing the reasoning at inference adds signal. Because the CoT adapter is trained on the SC-CoT prompt and target, the answer-prompt logprob score measures transfer to the answer-only format; this is stated in every report that uses it.

## Label-leak fix, few-shot exemplars and v2.2 re-bank amendment (2026-11-15 07:04:05 AEDT, machine clock; no regenerated bank row and no CoT arm existed)
- LABEL LEAKAGE FOUND IN THE JULIET POOLS (and fixed before any CoT arm trained): every Juliet item in pools J and J2 carried the answer in comments (header 'CWE: 121 Stack Based Buffer Overflow', FLAW / FIX markers, BadSource / GoodSource), in identifiers (CWE121_..._01_bad, goodG2B, badSink), in the guard names '#ifndef OMITBAD / OMITGOOD' and in a few string literals. 492 of 492 J items and 102 of 102 J2 items leaked.
  Consequences stated plainly: (a) the first quick bank (results/imp_superseded/, v2 schema, zero-shot) has inflated K, O and V on the Juliet pool and is SUPERSEDED; (b) any model trained on the uncleaned pools could have learned to read the comments. No CoT arm had trained on them.
- Fix: src/cyberdef/imp_clean.py removes ALL comments (string aware, including an unterminated /* at a truncation point), renames every identifier that embeds a CWE id or bad/good to fn_N, rewrites bad/good words inside string literals, drops the OMITBAD/OMITGOOD guard lines and the leftover tail of main() that the builder left behind. scripts/imp_clean_pools.py applies it (originals kept as results/imp_superseded/*_PRECLEAN.json; only a sha1 of the original text stays in the items).
  acceptance/improve/check_clean.py FAILED on the original pools (492 + 102 leaking items) and passes after cleaning (0 leaks, V and S texts still differ). The synthetic SQLi pool Q gets the same cleaning when it is built. Execution verification (strict X, labels) always uses the ORIGINAL Juliet files by base name, so it is unaffected.
- Known residual confound, NOT fixed: in J and J2 the SAFE text contains ALL good variants of a testcase (several functions plus a wrapper) while the VULNERABLE text contains only the bad function, so SAFE texts are longer and look different structurally. This is a length/structure shortcut inside the Juliet pools; it is reported with every result that uses them, and category balancing does not remove it.
- FEW-SHOT EXEMPLARS (yield lever a; the generation was zero-shot): the SC-CoT prompt gains 3 in-context exemplars, TEMPLATED by the research tooling from Juliet ground truth (known CWE plus located flaw line), NOT written by any model, never commercial, never CASTLE:
  E1 VULNERABLE memory-safety/asan (CWE131_memcpy_02: 40-byte copy into a 10-byte buffer), E2 VULNERABLE cmd_injection (char_console_system_02, witness carries CANARY), E3 SAFE (the good variant of E1, every sink guarded). Source files are Juliet '_02' variants; pools J/J2 use only '_01', so no exemplar function is in any pool. Each assistant trace passes sc_cot.validate (valid, verdict_final == verdict_raw).
  File results/imp_fewshot_exemplars.json (scripts/imp_build_exemplars.py). Exemplar choice is fixed now and not tuned on bank results. Applied to the bank generation (quick and full) and to the C-pass; CoT EVALUATION stays zero-shot (a trained model does not get exemplars). Bank max_model_len is raised to 12288 to hold the exemplars (max_new_tokens stays 4096).
- SC-CoT v2.2 (hash ecdfdd87d617f06f, static_evidence conditional on oracle) is the schema of the regenerated bank: imp_sc_schema.SCHEMA_SHA was checked on the box and equals ecdfdd87d617f06f. The bank is regenerated ONLY after the v2.2 smoke passes (gate unchanged); new job names P16_zd2 / ze2 / zf2 (quick bank g1, g14, merge + items); the superseded outputs are moved to results/imp_superseded/ on the Spark.
  The Spark no longer trains the quick-bank CoT arms (the box lane does); the Spark keeps bank generation, C-SC and the generation evals of box-trained CoT adapters.
- Yield re-measurement is reported after each lever: (1) schema v2.2, (2) few-shot (with clean pools), (3) the full bank (all generators, K=4). The strict selection (V, P, S/X not False, K, O) is NOT softened. A K/O-as-rank-bonus arm, if ever run, is a separate exploratory arm, never the headline.

## Reasoning-model Phase 1 / Phase 2 pre-registration (2026-11-15 08:23:51 AEDT, machine clock; no reasoning-model result existed)
- PHASE 1 (zero-shot DETECTOR probe, Spark only, one model at a time, queued behind the bank regeneration and C2/C-SC as P18_zs_*): every reasoning model served by the Spark Ollama is prompted with thinking ENABLED for a verdict plus a confidence on the length-matched PrimeVul set
  (results/lenmatched_eval_cases.json, n=1074; the same user text as every other zero-shot scorer, the system prompt gains one line asking for CONFIDENCE). Score p_vuln = 0.5+0.5c (VULNERABLE) or 0.5-0.5c (SAFE); unparsed or truncated = 0.5, counted and reported, never dropped; missing confidence = 0.5.
  temperature 0, num_ctx 8192, num_predict 4096 for every model (thinking and answer must fit; the cap is not tuned), thinking: gpt-oss medium, all others on. Models loaded in Ollama stay resident for 30 min by default and would block the GPU queue, so each probe unloads its model (keep_alive 0).
  Inventory (Ollama GGUF on the Spark): gpt-oss:20b (20.9B, MXFP4, Apache-2.0), nemotron-3-nano:30b (31.6B, Q4_K_M, NVIDIA Open Model License), glm-4.7-flash (29.9B, Q4_K_M, MIT), qwen3-heavy-long (34.7B qwen35moe, Q4_K_M, thinking; NO license text in the Ollama manifest: provenance unclear).
  Never any *-ablit variant. HF weights present on the Spark: gpt-oss-20b (loads in vLLM only when the bank job g3 runs: unverified until then).
- Metric and bar: AUROC +/- Hanley-McNeil SE per model, next to length-only (0.50 on these cases), SAST (flawfinder 0.506, semgrep 0.505) and the current ceiling, the length-matched 7B at 0.561 (SE 0.0175). A model "beats the ceiling" only if AUROC - 0.561 > 2 x sqrt(SE_model^2 + 0.0175^2) AND it is above length-only and SAST. The best model by AUROC is then also probed on the VulSpot holdout and no-linux matched sets and on CASTLE (same procedure).
- PHASE 2 trigger (fixed now): trace generation with the v2.2 schema + few-shot + clean pools is run only for gpt-oss-20b (already a bank generator) and for a model that beats the ceiling by the bar above; yield P/V/K/O/strict-X is reported per model. A model's traces may enter fine-tuning only if the LICENSE permits using outputs as training data:
  gpt-oss (Apache-2.0) and glm-4.7-flash (MIT) are clean; Nemotron (NVIDIA Open Model License: NVIDIA claims no ownership of outputs, outputs are not Derivative Models, no output-training restriction found in the text except a Cosmos-only attribution clause) looks permissive but is flagged for the owner to confirm before any use as training data;
  qwen3-heavy-long has no license in its manifest: PROBE ONLY (evaluation, not training data), flagged. Nothing published.

## AMENDMENT - Stage I: internal probe vs output (pre-registered 2026-11-15 08:54:57 AEDT, box clock, BEFORE any activation was dumped)
Owner-approved diagnostic: does the hidden state encode vulnerable/safe (and the weakness class) better than the printed output? This is NOT a detection claim; it is reported either way.
Data: results/lenmatched_eval_cases.json (537 pairs, n=1074, length-only AUROC ~0.50). Models in order: base Qwen2.5-7B-Instruct, length-matched 7B (out/qlora-7b-lenmatch), published 7B (out/qlora-primevul).
Features: last-prompt-token residual stream (standard detector prompt, exactly as the logprob scorer builds it) at layers 4,8,...,28, float16, one Spark GPU pass per model (queue P22_imp_stageI_*), then CPU fitting (scripts/imp_probe_fit.py).
Probe: L2 logistic regression (LBFGS), features standardised and PCA-reduced to 128 dims, BOTH fitted on the training fold only. C in {3e-4,3e-3,3e-2}.
Held-out rule: every probe score is out-of-fold. Primary CV = 5-fold GROUPED BY MATCHED PAIR (partners never split); robustness CV = grouped by PROJECT. Layer and C are chosen by an inner 3-fold grouped CV on the
training part of each outer fold only (nested), so best-of-7-layers cannot inflate the number. Per-layer tables (fixed C=3e-3) are descriptive only.
Controls through the identical nested pipeline: (1) shuffled labels, 3 repeats - mean AUROC > 0.55 marks the run INVALID; (2) length-only probe (log chars, tokens, lines) must be ~0.50.
Output comparison: the model's own logprob-scored p_vuln on the same cases (base: imp_src_base7b_matched.json; lm: lm_sel_lenmatch_on_matched.json; pub: ab_pub7b__lenmatched.json; references 0.53/0.56/0.53).
WIN BAR (fixed now): nested pair-grouped AUROC > 0.5+2SE AND > shuffled mean+2sd AND > length-only AND beats the model's output AUROC by > 2*SE_diff (SE_diff = sqrt(SE1^2+SE2^2), conservative) AND not invalid.
Reading if it wins: the label is linearly present but the readout fails. Reading if probe ~ output ~ chance: the model does not represent the label on length-matched data (the ~0.53 is the model's real ability).
Class probe (scripts/imp_probe_class.py): oracle-class (asan/integer/lsan/tsan/resource/sqli/path_traversal/cmd_injection/format_string/none) from clean-label pools only. Headline = TRANSFER: fit on Juliet+Juliet2,
score CASTLE (restricted to classes seen in training), layer/C by inner grouped CV on the train corpus; bar = max(majority-class accuracy, shuffled mean+2sd) exceeded by > 2 binomial SE; compared with the output K (~4%).
Secondary = grouped 5-fold CV over all pools; its best layer is picked on the same CV so it is reported as optimistic.
Acceptance written first: acceptance/improve/check_probe_internal.py (selftest S1-S5 incl. a leak mutant; results validator). Selftest PASS before this amendment: S1=0.957 S2=0.465 S3=0.465, leak mutant 1.000 vs real 0.493.
Caveats stated up front: n=1074 gives SE ~0.018, so only effects > ~0.05 over the output are detectable; the probe reads the last prompt token only; one prompt; hidden state of a 4-bit/bf16 load as per model_io defaults.
Queue note: dump jobs are P22 (after the already-queued P16-P21 jobs), no existing queue file touched.
