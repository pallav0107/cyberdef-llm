# Secure-Code Chain-of-Thought (SC-CoT)

Part of the methodology contribution. A structured, expert-auditor reasoning scaffold whose every step is JSON, so each step can be machine-checked and, for compilable code, executed. Implementation: `src/cyberdef/sc_cot.py` (prompt + validator), `scripts/reason_CSC.py` (runner). Pre-registered as Stage C-SC in `EXPERIMENT_PLAN_REASONING.md`; acceptance: `acceptance/reasoning/check_SC.py`.

## Steps (all emitted as one JSON object)
1. `contract` + `trust_boundary`: what the function does; attacker-controlled inputs (params, globals, I/O reads); trusted inputs; stated assumptions.
2. `sinks`: every dangerous operation with a CWE tag. Writes/copies (memcpy, strcpy, strcat, sprintf, index writes, pointer arithmetic): 787/120/121/122. Reads (index, deref): 125/476. Lifetime (free, realloc, use-after): 416/415. Size/index arithmetic (+, *, casts, sign): 190/191/681. Format string: 134. Uninitialized: 457/908. Division by zero: 369.
3. `dataflow`, per sink: which attacker inputs reach its size, index or pointer, through which lines and which transforms.
4. `guard_audit`, per sink: each check on the path, with an explicit sufficiency judgement against a fixed checklist: off-by-one (`<=` vs `<`), signed/unsigned comparison, integer overflow inside the check, check on the wrong variable, check after use (TOCTOU), check missing on some path.
5. `paths`: every path including error and cleanup paths (goto, early return), where use-after-free and double-free live.
6. `witness`: concrete input values, the concrete state at each line up to the violation, and `how_to_feed` (argv, stdin or file) so it can be executed.
7. `refutation`: actively try to falsify the finding (missed guard? caller or type constraint, e.g. a `uint8_t` index into a 256-entry array?). Witnesses that depend on unseen context list it as an assumption.
8. `verdict` (VULNERABLE|SAFE|UNCERTAIN) + `cwe` + `confidence` + `length_independence`: one line naming the sink and guard the verdict rests on; it must never rest on size or complexity.
9. `fix` (optional, feeds Stage G): the minimal patch making the guard sufficient and why it closes the witness while preserving benign behaviour.

## Validator rules (`sc_cot.validate`)
- Cited lines exist (sinks, dataflow, guards, paths, witness state).
- Each sink's `op` appears on its cited line; each guard's line contains its condition (token overlap >= 0.6).
- A VULNERABLE verdict needs a concrete witness (non-empty values and `how_to_feed`); otherwise it is downgraded to UNCERTAIN.
- A SAFE verdict needs a sufficient guard listed for every sink; otherwise it is downgraded to UNCERTAIN.
- A refutation must be present.
- Parse rate is reported. Below 95% the prompt is fixed before any scoring is read (change logged in the plan); cases are never dropped.
- For compilable code the witness is EXECUTED in the Stage-D sandbox (docker `gcc:13`, no network, 1 GB, 64 pids, uid 65534, sanitizers). That is the real check; the validator only checks consistency with the source text. Stage G verifies fixes.

## Integration (each a one-variable comparison)
- **C-SC**: the same 300 length-matched cases (plus CASTLE) as Stage C. Arms: bare verdict, the Stage C witness prompt, SC-CoT. The scaffold is the only variable; the larger token budget (1200 vs 400) is recorded.
- **D/F**: SC-CoT witnesses are executed; in the exec-loop, sanitizer feedback triggers a revision of steps 4-7.
- **H**: the SC-CoT model is added to the counterfactual length/semantics probe: does the scaffold make verdicts less length-sensitive?
- **E**: SC-CoT is the target trace format for self-training; keep only traces whose witness executes and whose fix verifies.

## Clean-claim rule for exemplars
Few-shot exemplars must not be authored by a commercial model. The current runs are **zero-shot** (schema description only). A future exemplar bank may come only from (a) open-weight generations kept only when execution-verified, or (b) derivation from Juliet's ground-truth flaw annotations. Only Juliet/dev data may be used; never CASTLE test cases (test-set leakage).

## Honest limits
The validator checks internal consistency, not truth; a consistent trace can still be wrong, and only execution of the witness (or a verified fix) is grounding. A scaffold that improves format validity may leave AUROC at chance; the pre-registered bar decides, and a null is reported as a null.

## Schema v2 (class recognition and oracle routing; C-SC amendment 3)
New REQUIRED fields, after `guard_audit` and before `paths`/`witness`:
- `vuln_class`: `{cwe: <id from the allowed list>, owasp: <OWASP 2021 label or "MEM Memory safety (outside OWASP Top 10)">}`.
- `oracle`: one of `asan | ubsan | lsan | tsan | integer | cmd_injection | path_traversal | sqli | format_string | resource | none`.
- `static_evidence`: `{line, snippet}` when `oracle == none` (then `witness` is null); otherwise null.
The CWE -> oracle map is FIXED (`src/cyberdef/cwe_oracle.py`, written before the validator): memory-safety CWEs (119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 415, 416, 476, 590, 761, 787, 788, 822, 824, 825, 457, 908) -> asan;
190, 191, 194, 369, 680 -> integer; 401 -> lsan; 362 -> tsan; 400, 617, 674, 770, 835 -> resource; 78 -> cmd_injection; 22 -> path_traversal; 89 -> sqli; 134 -> format_string;
253, 327, 522, 628, 798, 843 -> none.
Injection-type witnesses (cmd_injection, path_traversal, sqli, format_string) must contain the literal token `CANARY` inside a string value at the injection point; the harness substitutes and detects it.
Validator v2 keeps every v1 check and adds: class allowed; oracle consistent with class via the map; witness shape per oracle (CANARY for injection types); `oracle == none` requires `static_evidence` whose line exists and contains the snippet.
Scoring adds class accuracy (exact and by CWE group), oracle-selection accuracy (`scripts/reason_CSC_classacc.py`), and verification by the chosen oracle once the behaviour monitors exist.
The Stage C witness schema and C2 are unchanged. Schema hash (SC v2): see the `decode.schema_hash` in each cache row.
