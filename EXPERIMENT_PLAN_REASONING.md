
## Stage B pre-registration (appended 14 Nov 2026, BEFORE any SAST number was produced)
- Question: do classic rule-based SAST tools separate vulnerable from safe on the LENGTH-MATCHED PrimeVul test set
  (results/lenmatched_eval_cases.json, 537 pairs, length-only AUROC 0.500)? These are the rule baselines every model
  number must be compared against.
- Tools: flawfinder (pip 2.0.20), score = sum of hit levels; semgrep (pip 1.185), registry rules r/c, score = sum of
  severity weights (ERROR 3, WARNING 2, INFO 1). Input = the case code exactly as the model sees it (<=4000 chars).
  Parse failures / tool errors = score 0 (no finding), counted, never dropped. No rule-set tuning after seeing numbers.
- Metric: AUROC + Hanley-McNeil SE, pairwise win-rate (ties 0.5), AUROC per length quartile.
- Bar (fixed now): a rule baseline has signal only if AUROC > 0.5 + 2*SE. A model beats the rules only if its AUROC
  exceeds the rule AUROC by more than 2*SE of the difference AND exceeds length-only (0.50). Not changed after the run.
- Acceptance: acceptance/reasoning/check_B.py (written first, shown failing, see MUTATION_PROOF.md).

## Stage C pre-registration (appended 14 Nov 2026, BEFORE any witness-prompt output exists)
- Question: does forcing a model to trace the code and commit to a concrete witness add real signal over its plain
  VULNERABLE/SAFE verdict, on the SAME length-matched cases (length-only AUROC 0.50)?
- Cases: fixed subset of results/lenmatched_eval_cases.json = 150 of the 537 pairs drawn with random.Random(0).sample
  (300 cases), chosen for compute (generation is ~100x the cost of logprob scoring). Same subset for every model.
- Prompt: code shown with 1-based line numbers; model must return ONLY JSON with keys inputs, sinks[{line,op}],
  guards[{line,condition}], trace[{line,state}], witness (object of concrete input values, or null), verdict
  (VULNERABLE|SAFE), confidence (0..1). Greedy decoding, max 400 new tokens, no retries, no prompt tuning after results.
- Scorings (all reported): s0 plain self-reported verdict (VULNERABLE -> 0.5+0.5*conf, SAFE -> 0.5-0.5*conf,
  unparsed -> 0.5); s1 = s0 but VULNERABLE with a null/empty witness -> UNCERTAIN (0.5); s2 = s1 plus VULNERABLE whose
  citations fail the machine check (line outside 1..N, sink op not on its cited line, empty trace) -> UNCERTAIN.
- Parse failures are scored 0.5 and counted (parse_rate reported), never dropped.
- Models: Qwen2.5-7B-Instruct base and tuned (out/qlora-primevul) via the selective_eval loader; Spark Ollama models
  (no *-ablit variants) as capacity allows; each reported whether or not it looks good.
- Metrics: AUROC +/- Hanley-McNeil SE, accuracy, pairwise win rate, per length-quartile AUROC, parse rate; next to each:
  length-only AUROC and the Stage B SAST baselines restricted to the same 300 cases, and (7B models) the model's own
  logprob p_vuln AUROC restricted to the same cases.
- Bar (fixed now): witness prompting "adds signal" only if s1 or s2 AUROC > 0.5 + 2*SE AND exceeds the plain comparator
  (logprob p_vuln / s0) by more than 2*SE_diff (SE_diff = sqrt(SE1^2+SE2^2), conservative) AND exceeds both SAST
  baselines on the same cases. Otherwise the verdict is NO ADDED SIGNAL. Nothing is changed after seeing results.
- Acceptance: acceptance/reasoning/check_C.py (written first, shown failing, then mutations in MUTATION_PROOF.md).

## Stage D pre-registration (appended 14 Nov 2026, BEFORE any witness was executed)
- Question: when a model asserts VULNERABLE with a concrete witness, does RUNNING that witness on the (compilable) program
  trigger a sanitizer, and does that execution-confirmed signal separate vulnerable from safe programs better than chance?
- Harness: src/cyberdef/exec_harness.py. Sandbox: docker gcc:13, --network none, --memory 1g, --pids-limit 64, uid 65534,
  --cap-drop ALL, no-new-privileges, 10 s timeout, compile inside the sandbox with -fsanitize=address,undefined. Only a
  sanitizer report counts (plain abort/exit/timeout does not). Witness->input mapping fixed in the harness docstring.
- Data: CASTLE C250 as loaded in results/xdata_castle_cases.json (198 deduped programs, 99 vuln / 99 safe; NOT paired),
  plus a Juliet 1.3 subset only if it can be fetched and built; otherwise stated as not run. Programs that do not compile or
  need a network/server are counted as not-executable, never dropped.
- Step D0 (exploratory, no model): compile+run every program with EMPTY input; report compile rate, timeout rate, and the
  base rate at which sanitizers fire on vulnerable vs safe programs with no witness. This bounds what Stage D can show.
- Models/witnesses: the Stage C prompt (same JSON schema) applied to the CASTLE program text; witness executed per the mapping.
  score s3 = 1 if (verdict VULNERABLE and witness non-null and sanitizer fired on that program) else 0.
- Metrics: AUROC (s3 vs label) +/- HM SE, precision and recall of the confirmed set, sanitizer-fire rate on safe programs,
  executable fraction. Comparators on the same programs: Stage B SAST (run on CASTLE), length-only AUROC, and the model's
  plain verdict/logprob.
- Bar (fixed now): execution-confirmation "adds signal" only if s3 AUROC > 0.5 + 2*SE AND above length-only AND above both SAST
  baselines AND sanitizer-fire rate on safe programs < confirmed rate on vulnerable ones by > 2*SE. If most programs are not
  executable the result is reported as NOT APPLICABLE / underpowered, not as a pass or fail of the idea.
- Acceptance: acceptance/reasoning/check_D.py (written first; harness controls c1-c4 plus mutants always_true/always_false).

## Stage G (REPAIR) pre-registration (appended 14 Nov 2026, BEFORE any patch was generated or verified)
- Question: can a model write a patch that is verified by execution, not by judgement?
- Data: COMPILABLE vulnerable programs. CASTLE C250 primary (reference safe variant = a SAFE program is NOT paired in CASTLE,
  so functional equivalence is checked against the program's own behaviour on benign input recorded from the vulnerable
  program, and only for programs where the vulnerable program runs cleanly on that benign input); Juliet 1.3 secondary and
  memorisation-caveated (reference = the -DOMITBAD good variant). Programs that do not compile or have no triggering input
  are reported as not-repairable-testable, never dropped silently.
- A fix is VERIFIED only if ALL hold, each executed in the Stage-D sandbox: (1) patched program compiles; (2) the
  triggering input (the one that makes the ORIGINAL vulnerable program fire a sanitizer: execution-found witness, not the
  model's guess) no longer fires any sanitizer; (3) on benign input the patched program's stdout and exit code equal the
  reference's.
- Metric: verified-fix rate on HELD-OUT = tested on a source and CWE set not used for any training or prompt design
  (train/choose on one source, test on the other; held-out CWEs reported separately). Model, temperature (0) and one
  attempt (pass@1) fixed now; pass@k only as a separate, labelled row.
- Baselines on the same programs: no-op patch (identical code) and delete-the-vulnerable-line (delete the sanitizer-
  reported line). Model must beat BOTH by > 2*SE (SE of the difference of two proportions) to count.
- Fail-first controls (acceptance/reasoning/check_G.py, written first): a known-correct fix verifies; an identical-to-
  vulnerable fix does NOT; a fix that silences the crash by breaking functionality does NOT; an empty or uncompilable
  patch does NOT. A broken checker (always-true / always-false) must fail these.
- Stage E-repair (self-training on verified patches) runs ONLY if the held-out verified-fix rate beats both baselines by
  > 2*SE. Otherwise reported as null. Open-weights models only for training data. Nothing published or committed.

## Stage G amendment 1 (14 Nov 2026, before any patch was generated or verified; append-only)
- Condition (3) uses MULTIPLE benign inputs: every benign argv/stdin variation the program accepts (minimum 1; per-case count
  recorded as n_benign_inputs). A patch verifies only if stdout and exit code match the reference on ALL of them. Cases with
  a single available benign input are flagged single_input=true and reported separately.
- Limitation stated up front: a verified fix means the vulnerability no longer triggers on the triggering input AND the tested
  benign behaviour is preserved. It is necessary, not a proof of full correctness, and must not be written up as one.
- CASTLE and Juliet verified-fix rates are reported SEPARATELY, never pooled. Juliet (reference = the -DOMITBAD good variant,
  a real paired fix) is the stronger reference but is memorisation-caveated (predates Qwen2.5).
- Everything else as pre-registered. Order stays C/D -> F -> G.

## Stage H pre-registration (appended 14 Nov 2026, BEFORE any probe case was built or scored)
- Question: does a model's verdict respond to LENGTH with the bug held fixed, or to SEMANTICS with length held fixed?
  Inference only, no training. Score = selective_eval logprob p_vuln (same scorer as every other number here).
- Models: published 7B (out/qlora-primevul), 7B length-matched retrain (out/qlora-7b-lenmatch), base Qwen2.5-7B.
- (a) LENGTH axis (bug unchanged): 150 base cases drawn with random.Random(0) from results/lenmatched_eval_cases.json
  restricted to full code <= 3000 chars (75 vulnerable + 75 safe, no truncation). Six semantics-preserving variants each:
  pad_comment_500 / pad_comment_1500 (neutral boilerplate comment lines prepended), pad_ws_1500 (blank lines + indentation),
  compress (strip comments, collapse blank lines and leading indentation), rename_long / rename_short (alpha-rename declared
  local variables and parameters via a tree-sitter-c parse; member names and called functions untouched). NO dead-code
  insertion. Variants whose parse fails are skipped and counted. Renames are not execution-verified (limitation stated).
  Metrics: slope of delta p_vuln against delta chars (OLS through the origin, per +1000 chars, pooled over variants; also
  vs delta tokens), per-transform slopes, verdict-flip rate (p>=0.5 changes versus the original), bootstrap 95% CI over base cases (1000 resamples).
- (b) SEMANTIC axis (length ~ constant): vulnerable function vs its own fix from VulSpot cpp full, test_paired_high rows
  of both chrono and project_holdout splits (vulnerable rows whose fixed_func_idx points at a fixed row), PrimeVul-train
  overlap removed (normalised text or fix commit), kept only if |chars_vuln - chars_fixed| / max <= 5%, up to 300 pairs
  (seed 0). Metrics: mean p_vuln(vuln) - p_vuln(fixed) with bootstrap 95% CI, pairwise accuracy (p_v > p_f; ties 0.5) with
  binomial SE, and P-C (pair-correct) rate = p_v >= 0.5 AND p_f < 0.5. CASTLE equal-length ASan-confirmed edits are NOT part of this run
  (reported as not done). PrimeVul pairing is not used (not available as a paired split under data/).
- VERDICT RULE (fixed now). length-insensitive iff the slope CI lies within +/-0.03 per +1000 chars AND the flip rate <= 5%.
  semantically-sensitive iff the mean-delta CI lower bound > 0 AND pairwise accuracy > 0.5 + 2*SE.
  "Thinks beyond length" = semantically-sensitive AND length-insensitive. Otherwise each model is placed on both axes
  and labelled: length-reader (length-sensitive, not semantic), semantic-only, both, or neither. No threshold changes after seeing results.
- Fail-first controls (acceptance/reasoning/check_H.py, written first): three stub scorers must be separated by the probe:
  length-reader stub p=f(length) -> length-sensitive, not semantic; oracle stub (uses the true label) -> the reverse;
  random stub -> neither. A broken probe (deltas zeroed) must fail the check.

## Stage H amendment 1 (14 Nov 2026, before any probe case was scored)
- Placement labels use: length-sensitive iff the slope bootstrap CI excludes 0 AND |slope| > 0.03 per +1000 chars; semantically-
  sensitive as pre-registered. semantic-only = semantic and not length-sensitive; both = semantic and length-sensitive;
  length-reader = length-sensitive, not semantic; neither otherwise. "Thinks beyond length" (strict) additionally needs the
  slope CI within +/-0.03 and flip rate <= 5%. The semantic axis also reports the length-only pairwise accuracy on the same
  pairs (fixes can be systematically longer/shorter, which would masquerade as semantics).

## Stage C-SC pre-registration (appended 14 Nov 2026, BEFORE any SC-CoT output exists)
- Design: docs/SECURE_CODE_COT.md (Secure-Code Chain-of-Thought: contract + trust boundary, CWE-tagged sinks, per-sink dataflow,
  guard audit against a fixed checklist, all paths incl. error/cleanup, executable witness, refutation, verdict + cwe +
  confidence + length_independence, optional fix). Output is JSON only. Validator: src/cyberdef/sc_cot.py.
- One-variable comparison on the SAME 300 matched cases as Stage C (150 pairs, random.Random(0).sample, seed 0), same models,
  greedy, max_new_tokens fixed in the script (SC-CoT needs a longer budget than the Stage C prompt: 1200; recorded), plus
  CASTLE (198 programs) for Stage D execution. Arms: (i) bare verdict (logprob p_vuln and Stage C s0), (ii) the Stage C witness
  prompt (s1/s2), (iii) SC-CoT. The scaffold is the only variable; budget differences are recorded and reported.
- Scoring: s_sc = validator-final verdict: VULNERABLE (valid) -> 0.5+0.5*conf, SAFE (valid) -> 0.5-0.5*conf, UNCERTAIN /
  invalid / unparsed -> 0.5. VULNERABLE with no concrete witness is downgraded to UNCERTAIN; SAFE needs a sufficient guard
  for every sink, else UNCERTAIN. Parse rate reported; if it is below 95% the PROMPT is fixed (before any scoring is read) and
  the change is logged here; cases are never dropped.
- Exemplars: ZERO-SHOT (schema description only). No few-shot exemplar is authored by a commercial model. A future few-shot bank
  may only come from open-weight generations that are execution-verified, or from Juliet ground-truth annotations, never
  from CASTLE test cases.
- Metrics: AUROC +/- Hanley-McNeil SE, accuracy, pairwise win rate, per length-quartile AUROC, parse rate, fraction downgraded,
  validator consistency rates; beside length-only 0.50, Stage B SAST, the model's own logprob AUROC on the same cases.
- Bar (fixed now): SC-CoT "adds signal" only if its AUROC > 0.5 + 2*SE AND exceeds the Stage C witness prompt AND the bare logprob by
  > 2*SE_diff (conservative sqrt(SE1^2+SE2^2)) AND exceeds both SAST baselines. For CASTLE, witnesses are executed in the Stage D
  sandbox and compared with the 0.67 execution-only floor. Otherwise: NO ADDED SIGNAL. Stage H adds the SC-CoT model to the
  counterfactual probe to test whether the scaffold reduces length sensitivity.
- Acceptance: acceptance/reasoning/check_SC.py (written first; six validator controls + always-pass mutant).

## Stage C / C-SC amendment 1 (logged 2026-11-14 20:21 AEDT, BEFORE any Stage C or C-SC generation existed and before any score was read)
- Budget parity: Stage C max_new_tokens raised from 400 to 1200 so it equals C-SC; the generation budget is no longer a second
  variable next to the scaffold. At amendment time no reason_C_* / reason_CSC_* generation cache existed on either host.
- Engine parity: ALL generation arms (Stage C, C-SC, CASTLE witnesses for D) use vLLM (version recorded in every cache row) in the
  cyberdef-train container, bf16, temperature 0, greedy, LoRA adapter via enable_lora where applicable (verified: base and the
  out/qlora-primevul adapter both generate). No Ollama in any compared arm.
- Recorded per case: tokens used and finish reason; per run: mean/max tokens and the fraction truncated at the limit (expected ~0).
- Stage H scoring runs FIRST (logprob only), then C + CASTLE witnesses, then C-SC and CASTLE SC-CoT; the H rename axis is reported
  separately with its n (62 bases parse), the comment/whitespace/compress axis is the main length test.

## Amendment (logged 2026-11-14 20:25 AEDT): line-ending normalisation only (CRLF -> LF in reason_C_witness.py, reason_CSC.py and other files written by this pipeline). Prompt CONTENT unchanged; no Stage C / C-SC / H output existed when this was done.

## Stage H post-hoc robustness note (logged 2026-11-14 21:26 AEDT; POST-HOC, does not change any pre-registered verdict)
Truncation check requested after seeing pub7b: H scoring applied NO truncation (full code is passed to the prompt), but +1500 pads push bases over 2500 chars beyond the 4000-char range used elsewhere. scripts/reason_H_robust.py recomputes per-transform slope and flip rate for (a) bases <= 2500 chars (all variants <= 4000) and (b) bases > 2500; output results/reason_H_<tag>_robust.json. Applied identically to each model.

## Stage D pre-execution amendment (logged 2026-11-14 21:58 AEDT; NO Stage D execution result exists, nothing scored)
35 of 198 CASTLE programs do not compile in the current sandbox image (gcc:13) because sqlite3/mysql/openssl/curl headers are missing, which caps the D0 floor and every Stage D number. Before ANY witness is executed: (1) exec_harness switches to the derived image (EXEC_IMAGE env; name to be supplied; same sanitizer toolchain plus dev headers; link flags derived from includes); the image name is recorded in every result; (2) the D0 empty-input floor is re-run on all 198 programs with the new image; (3) compile coverage before (165/198 = 83.3 percent) and after, and the new floor (before: sanitizer fires on 34/99 vulnerable and 0/99 safe, about 0.67 AUROC) are reported. Witness GENERATION (P15/P16) is unaffected. All other Stage D definitions unchanged.

## Stage C / C-SC amendment 2 - FORMAT FIX (logged 2026-11-14 22:35 AEDT; made AFTER the original Stage C scores were read, BEFORE any C-SC output exists)
Reason: the original Stage C run (vLLM, 1200 tokens, free-form JSON, pre-registered) had parse rate 84.7 percent (base) and 73.3 percent (tuned), below the brief's 95 percent rule, and 4.7-9.3 percent of generations hit the token limit; SC-CoT output is longer still. 1. C-SC uses vLLM structured outputs (guided JSON decoding against the exact SC-CoT schema, src/cyberdef/schemas_cot.py) with max_new_tokens 2048. 2. Stage C is RE-RUN as C2 with guided JSON against the Stage C witness schema at 2048 tokens, as the budget- and decoding-matched comparator for C-SC. 3. BOTH are reported: the original C remains THE pre-registered result and is never replaced; C2 is labelled explicitly as the format fix required by the 95 percent parse rule, made after C was scored. 4. Every cache row records decoding config (guided=json, schema hash, max tokens, temperature 0, vLLM version). C2 and C-SC run back to back (queue P17a-e) on the same engine and config. 5. Consistency-failure rate and VULNERABLE-bias are reported for C2 and C-SC again (original C: 68 percent base / 82 percent tuned of VULNERABLE verdicts fail the consistency check; VULNERABLE on 101 vs SAFE on 30 of the safe cases for base). A smoke test of guided decoding runs first (queue P16_y_C2_smoke). Everything else unchanged.

## Stage F decision (logged 2026-11-14 22:43 AEDT; no Stage F code built or run)
F deferred: gate not met under crash-only oracles. Pre-registered gate: the base model produces correct witnesses above the floor. Stage D (image imp-castle-san:1) result: witness-confirmed 12/99 (base) and 20/99 (tuned) vs execution-only floor 34/99; model-confirmed programs not already caught by the floor = 1 each; in the sanitizer-detectable class (33 vulnerable) the floor alone catches 27/33, so headroom is almost nil. F will be revisited when the shared oracle spec (LSan, ASan bad-free, UBSan integer checks, TSan) and possibly behaviour oracles for injection / format-string / traversal classes create real headroom. Stage G and E are unaffected by this entry. Reporting rule going forward: per CWE class (a) sanitizer-detectable, (b) crash-like-other, (c) non-crash, always with the 'model OR floor' union and the count of programs confirmed by the model but NOT by the floor; 'right verdict, witness did not fire' (23/39 base, 30/51 tuned) is kept in the write-up as evidence of correct-looking answers with no working witness.

## Stage D amendment 2 - ORACLE SET EXPANDED (logged 2026-11-14 22:55 AEDT; BEFORE the re-score; earlier crash-only results are KEPT, not replaced)
The shared oracle spec (results/imp_castle_oracle_spec.json, built by improve-builder) adds variants A (afl-clang ASan+UBSan plus assert and cpu_hang), A_leak (LeakSanitizer), B (clang -fsanitize=integer, recover mode: signed/unsigned overflow, div0, shift), C (separate TSan container, seccomp=unconfined, still network none / caps dropped / non-root) and D (gcc ASan+UBSan = the original oracle). A program is CONFIRMED if any counted report fires under any variant. Fixed groups (scripts/imp_oracle.py group_of): (a) 29 sanitizer-detectable CWEs incl. 401, 761, 362; (b) {617, 674, 835}; (c) everything else. This replaces my earlier ad-hoc (a)/(b)/(c) split for the re-score; the earlier split and the crash-only numbers stay in the record. Independent cross-check: D0 and Stage D are re-run with MY harness (src/cyberdef/exec_oracle.py, own report parser written from the spec text, only group_of imported) and compared program by program with the builder's floor (builder: 46/99 vulnerable, 3/99 false positives, AUROC 0.717 +/- 0.036). Every false positive is reported, none tuned away. Acceptance acceptance/reasoning/check_D2.py written first (8 controls + never/always mutants). Report per group with 'model OR floor' union and 'new beyond floor'.

## Stage D amendment 2 post-hoc note (logged 2026-11-14 23:05 AEDT; POST-HOC, does not replace any number, nothing tuned)
The only 3 floor disagreements between my harness and the builder (CASTLE-770-5, 770-6 vulnerable; 770-10 safe) are all cpu_hang; the box load average was about 16 at run time. A sensitivity column excluding cpu_hang is added to the D0 and D2 tables (scripts/reason_D2_nohang.py, results/reason_D2_nohang_posthoc.json). cpu_hang stays in the pre-registered spec numbers.

## C-SC amendment 3 - SC-CoT SCHEMA v2: class recognition and oracle routing (logged 2026-11-14 23:09 AEDT; BEFORE any C-SC or trace-bank output exists; owner decision)
The model must recognise the vulnerability CLASS and route its witness to the MONITOR that can verify it. New REQUIRED fields after sinks/guard_audit and before the witness: vuln_class {cwe: one id from the allowed list (CASTLE + Juliet + shared-spec group a/b ids; src/cyberdef/cwe_oracle.py), owasp: OWASP 2021 category label} and oracle in {asan, ubsan, lsan, tsan, integer, cmd_injection, path_traversal, sqli, format_string, resource, none}. The CWE->oracle map is FIXED and was written first (cwe_oracle.py). Witness shape must match the oracle; injection-type oracles (cmd_injection, path_traversal, sqli, format_string) need the literal token CANARY inside a string value of the witness at the injection point; oracle=none (CWE 253, 327, 522, 628, 798, 843) requires static_evidence {line, snippet} instead of a witness (validator checks the line exists and contains the snippet). Validator v2 keeps every v1 check and adds: class allowed; oracle consistent with class via the map; witness shape per oracle; none => static_evidence. New scoring: class accuracy (vuln_class vs true CWE where known, and vs CWE group), oracle-selection accuracy (vs the map applied to the true CWE), and verification by the chosen oracle once behaviour monitors exist. Stage C witness schema and C2 are UNCHANGED (C2 stays a pure format-fix comparator); only the SC-CoT schema hash changes. check_SC.py rewritten FIRST with v2 controls and mutants.

## Stage D amendment 3 - ORACLE SPEC v2 (behaviour oracles) adopted (logged 2026-11-14 23:19 AEDT; BEFORE any C-SC v2 witness exists; earlier results kept)
Spec v2 (results/imp_castle_oracle_spec.json) adds variant P (plain gcc build under the LD_PRELOAD shim scripts/imp_shim.c; replayed only on inputs containing the literal CANARY, replaced per run by T = CNRY + 8 hex), the token convention, and oracle_routing for all 11 SC-CoT oracles. exec_oracle adopts it with MY OWN judging logic (shim source reused unmodified, builds the same way). Independent fail-first controls written first (check_D3.py): a vulnerable/safe twin per class (cmd_injection, path_traversal, sqli, format_string; the sqli safe twins cover both escaped-literal and prepared statement), benign input, empty-input-P-not-run, wrong-oracle-routing, plus never/always mutants. Floor: empty input carries no CANARY so variant P cannot fire; the D0 floor under v2 is re-measured to verify it equals the v1 spec floor. Reporting for C-SC v2 witnesses, per group and per class: confirmed by the CHOSEN oracle, new beyond the floor, false positives, class accuracy, oracle-selection accuracy. Stage F gate re-evaluated on those numbers and logged with the numbers either way: F is built only if class-(c) bugs are confirmed beyond the floor.

## Stage F gate re-evaluation - spec v2 (logged 2026-11-14 23:29 AEDT; PENDING: no C-SC v2 witness exists yet, no F code built)
Verified: under oracle spec v2 the empty-input floor is UNCHANGED vs the v1 spec: 48/99 vulnerable, 4/99 safe false positives (group a 33/43 + 2 FP, b 10/11 + 0, c 5/45 + 2 FP); 0 programs changed status; no beh: class fires on empty input (variant P is never run without CANARY). Headroom for class (c) behaviour classes (22, 78, 89, 134) therefore exists only for crafted payloads. Gate rule (fixed now): Stage F is built ONLY if C-SC v2 witnesses executed under spec v2 confirm class (c) / behaviour-class bugs BEYOND the floor with the CHOSEN oracle, at a rate above chance after counting false positives on safe programs, targeting the payload classes first; otherwise F stays deferred and the numbers are logged. Decision to be logged here with numbers once scripts/reason_CSC_exec.py has run on the CASTLE C-SC cache.

## Stage D amendment 3b - FEED CHANNELS (part of amendment 3; logged 2026-11-14 23:31:14 AEDT from the clock; BEFORE any C-SC v2 witness is executed)
The fixed 'argv if how_to_feed mentions argv else stdin' mapping would score env- and file-fed payloads as failures. The feed now follows a FIXED parser (src/cyberdef/feed.py, written before the run), first match wins: (1) env: how_to_feed mentions env/environment/getenv and names a variable (NAME=..., 'environment variable NAME', getenv("NAME")) -> set it to the payload; (2) file: how_to_feed mentions file/path and names a literal path -> the payload is written there inside the sandbox before the run (scratch area; paths that cannot be created by the sandbox user are counted as file_write_failed), and the path is passed in argv when the program reads argv[1]; (3) argv: mentions argv / command line / argument -> string values as arguments; (4) stdin: mentions stdin / standard input; (5) otherwise UNPARSEABLE -> falls back to stdin and is COUNTED, never dropped. Per-channel counts (stdin/argv/env/file/unparseable) are reported with every C-SC v2 execution. Payload selection: env/file use the witness value keyed by the variable name if present, else the first string value containing CANARY, else the first string value; stdin/argv use all string values as before. CANARY substitution applies to env values and file contents too (per-run token, variant P). New fail-first controls in check_D3.py: an env-reading cmd-injection program is confirmed ONLY when fed via env (not via stdin); a file-reading one only via the file; feed-parser channel table; unparseable falls back and is counted.

(amendment 3b clarification, same day, still before any C-SC v2 execution: the file-channel trigger words are file, path, write, save, create, store, put, place together with a literal path token; found when the first fail-first control showed 'write the payload to /tmp/payload.txt' would otherwise be unparseable. No witness had been executed.)

## C2 / C-SC / bank amendment 4 - TOKEN CAP 4096 (logged 2026-11-15 00:20:08 AEDT from the clock; BEFORE any C2, C-SC or bank output exists)
Smoke test P16_y_C2_smoke (guided JSON, schema v2) failed at the 2048 cap: 5 of 6 cases parsed, the 6th hit the cap (token counts 586, 1046, 1738, 414, 863, 2048; finish=length). Guided decoding works; the budget is too tight for SC-CoT v2 (class/oracle/witness/static_evidence). max_new_tokens is set to 4096 for C2, C-SC and the trace bank, equal for all so budget parity holds (original Stage C stays as pre-registered: 1200, unguided). The decode config recorded in every cache row carries max_tokens=4096. The smoke is re-run under the same job name and criteria (not loosened). If any smoke case still reaches 4096 it is a runaway, not a budget problem: schema v2.1 adds maxLength bounds on the free-text SC-CoT fields, a new schema hash is announced and the smoke re-run.

## OWASP recognition measured - amendment 5 (logged 2026-11-15 00:20:08 AEDT from the clock; BEFORE any C-SC or quick-bank output exists)
cwe_oracle.CWE_OWASP is a FIXED CWE -> OWASP Top 10:2021 map for the allowed CWE ids, sourced from OWASP's official 2021 'List of Mapped CWEs' pages (URLs in cwe_oracle.OWASP_SOURCES; fetched and parsed, not from memory): 22 -> A01 Broken Access Control, 78 and 89 -> A03 Injection, 327 -> A02 Cryptographic Failures, 522 -> A04 Insecure Design, 798 -> A07 Identification and Authentication Failures (exactly the owner's expectations); every other allowed CWE (memory, integer, leak, race, resource, 134, 253, 628, 843, ...) is not in any 2021 list = outside Top 10. No schema change. Scoring: owasp_correct = (label == CWE_OWASP[c]) for mapped CWEs; for CWEs outside the Top 10 the label 'MEM Memory safety (outside OWASP Top 10)' counts as correct. KNOWN LIMITATION: the label set has no generic 'other', so that memory-safety label also stands for non-memory classes such as 134/253/628/843. reason_CSC_classacc.py reports OWASP accuracy overall and per true category next to CWE class accuracy and oracle-selection accuracy, plus the label's consistency with the model's OWN claimed CWE. Acceptance: check_owasp.py written first (failed: owasp_correct absent).

## C-SC schema v2.1 - runaway bound (logged 2026-11-15 01:23:18 AEDT from the clock; BEFORE any C2, C-SC or bank output exists)
The re-run of P16_y_C2_smoke at max_tokens 4096 passed the witness schema (6/6, tokens 197 194 564 351 668 356) but the SC-CoT v2 case set was 5/6 parsed with token counts 586 1046 1738 414 863 4096 (finish=length on the 6th): a runaway, not a budget problem (the other five finished well under the cap). Per the pre-set rule, schema v2.1 adds maxLength bounds on every free-text string (240 chars; fix.patch 800), maxItems 12 on every array and maxProperties 8 on witness.values. The Stage C witness schema is UNCHANGED (hash 54009e39220440df). New SC-CoT schema hash (v2.1): 92b74ceefc5cff3e (v2 was 69c767edefa4be96). The smoke criteria are not loosened; the smoke is re-run under the same job name.

## C-SC schema v2.2 - FORMAT-CONSISTENCY BUG FIX, NOT a criterion change (logged 2026-11-15 06:59:37 AEDT from the clock; BEFORE any C-SC bank-v2.2 output)
Finding: under schema v2.1 `static_evidence` is a required key, the model fills it even when oracle != none, and the validator then (correctly) rejects 'static_evidence present when oracle != none' - 1209 quick-bank traces failed on this first. The schema punished the model for obeying the schema: a measurement artefact. Fix: the SC-CoT schema is now two branches (JSON-schema anyOf): oracle != none -> witness object required and static_evidence null; oracle == none -> witness null and static_evidence object required. Guided decoding can therefore no longer produce the contradiction. EVERY content criterion stays exactly as strict and stays in the validator, not the schema: verdict correct, concrete valid witness, cited lines exist, sink on its line, class (K) correct, monitor/oracle (O) correct, CANARY for injection classes, static_evidence line/snippet check. Nothing is relaxed. Maxlength/maxItems bounds of v2.1 are kept. New SC-CoT schema hash (v2.2): ecdfdd87d617f06f (v2.1 was 92b74ceefc5cff3e; v2 69c767edefa4be96); Stage C witness schema UNCHANGED (54009e39220440df). Acceptance: check_schema.py written first and FAILED on v2.1 (4 schema-level rejections missing), passes on v2.2. Smoke re-run under the same job name; the bank regenerates under v2.2. Expected, stated up front: this removes an artefact; it does not by itself rescue the arm, because class (K) correctness (~5 percent) and VP+K+O (~0) are genuine model limitations and will be reported as such.
