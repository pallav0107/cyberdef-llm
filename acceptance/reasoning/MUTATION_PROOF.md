# MUTATION PROOF (Stage B acceptance check_B.py)

## 1 before implementation: both tools FAIL (output missing) - shown above in session, rc=1
## 2 after implementation, flawfinder:
PASS
## 2 after implementation, semgrep:
FAIL: a parse failure was not scored as no-finding (0)
## 3 mutations on the flawfinder output (each must FAIL):
- drop one case:
FAIL: per_case does not cover exactly the matched cases
- inflate auroc to 0.9:
FAIL: auroc mismatch file=0.9 recomputed=0.5060
- fake parse_failures count:
FAIL: parse_failures count inconsistent with per_case
- broken scorer (--broken) control: 
{"empty": 0.0, "strcpy_fixed_buffer": 0.0}
restored original:
PASS

## 4 semgrep first run FAILED the acceptance (partial-parse files kept findings); implementation fixed to zero them; re-run:
PASS

## Stage C acceptance BEFORE implementation: check_C.py base7b / tuned7b -> FAIL (output missing), rc=1
## Stage C mutation proof (on stub run = harness test only, not a model result)
intact:
PASS
mutation: d["per_case"]=d["per_case"][:-1]
FAIL: per_case != pre-registered subset; parse_rate missing/inconsistent
mutation: d["auroc"]["s1"]=0.9
FAIL: auroc s1 mismatch
mutation: d["parse_rate"]=1.0
FAIL: parse_rate missing/inconsistent
mutation: [p.update(s1=0.9) for p in d["per_case"] if p["verdict"]=="VULNERABLE" and p["witness_null"]]
FAIL: auroc s1 mismatch; null witness not UNCERTAIN in s1
checker broken (always-consistent) control:
{"line_past_end": true, "sink_not_on_line": true, "empty_trace": true, "good": true}

## Stage G acceptance BEFORE implementation: check_G.py controls -> FAIL (repair_verify.py absent), rc=1

## Stage H acceptance BEFORE implementation: check_H.py controls -> FAIL (reason_H_analyze.py absent), rc=1

## SC-CoT acceptance BEFORE implementation: check_SC.py controls -> FAIL (sc_cot.py absent), rc=1

## SC-CoT mutation proof (stub run = harness test only)
controls (real validator all True; always-pass caught):
{"valid_trace_accepted": true, "missing_refutation_rejected": true, "vuln_no_witness_rejected": true, "nonexistent_line_rejected": true, "sink_not_on_line_rejected": true, "safe_unguarded_rejected": true}
{"valid_trace_accepted": true, "missing_refutation_rejected": false, "vuln_no_witness_rejected": false, "nonexistent_line_rejected": false, "sink_not_on_line_rejected": false, "safe_unguarded_rejected": false}
PASS
intact output:
PASS
mutation: drop a case:
FAIL: per_case != the Stage C subset (same 300 cases required); parse_rate inconsistent
mutation: fake parse_rate:
FAIL: parse_rate inconsistent

## Stage D amendment 2 acceptance BEFORE implementation: check_D2.py -> FAIL (exec_oracle.py absent), rc=1

## Stage D amendment 2 acceptance AFTER implementation (real all-True; never/always mutants caught):
PASS

## SC-CoT schema v2 acceptance BEFORE implementation: check_SC.py (v2 controls) -> FAIL against the v1 validator

## SC-CoT v2 acceptance AFTER implementation: check_SC.py controls PASS (16 controls: 6 v1 + 10 v2; always-pass mutant caught)

## Stage D spec-v2 acceptance BEFORE implementation: check_D3.py -> FAIL (--selftest2 absent), rc=1

## Stage D spec-v2 acceptance AFTER implementation: check_D3.py PASS (12 own controls: 4 classes vuln/safe twins incl. sqli escaped + prepared, benign, empty-input P not run, wrong-oracle routing; never/always mutants caught); check_D2.py (v1 controls) still PASS

## Stage D amendment 3b acceptance BEFORE implementation: check_D3.py (feed controls) -> FAIL (selftest2 lacks them), rc=1

## Stage D amendment 3b acceptance AFTER implementation: check_D3.py PASS (17 controls incl. env-only/file-only feeds, parser table, unparseable fallback; mutants caught); check_D2.py PASS

## OWASP scoring acceptance: check_owasp.py FAILED before implementation (owasp_correct absent), PASSES after (8 checks incl. wrong-category, unmapped-with-A-label and none-label negatives)

## Schema v2.2 acceptance: check_schema.py FAILED on v2.1 (4 rejection controls), PASSES on v2.2 (7 controls incl. wrong-class-still-passes-schema: content stays in the validator)
