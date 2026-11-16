"""SC-CoT acceptance, v2 (rewritten BEFORE the v2 validator existed). Usage (repo root): check_SC.py controls | output <tag>
controls: `PYTHONPATH=src python src/cyberdef/sc_cot.py --selftest [--broken]` prints JSON of flags; the real validator must give ALL True:
 v1: valid_trace_accepted, missing_refutation_rejected, vuln_no_witness_rejected, nonexistent_line_rejected, sink_not_on_line_rejected, safe_unguarded_rejected
 v2: valid_injection_accepted, valid_none_accepted, class_not_allowed_rejected, oracle_inconsistent_rejected, injection_without_canary_rejected,
     witness_shape_mismatch_rejected, oracle_none_without_static_evidence_rejected, static_evidence_line_missing_rejected,
     static_evidence_snippet_mismatch_rejected, missing_v2_fields_rejected
The --broken (always-pass) validator must fail at least one *_rejected flag; a 'never' mutant must fail an *_accepted flag.
output <tag>: results/reason_CSC_<tag>_matched.json has parse_rate, per_case with sc fields, same 300 cases as Stage C."""
import json, os, random, subprocess, sys
fails = []
if sys.argv[1] == "controls":
    env = {**os.environ, "PYTHONPATH": "src"}
    def st(*a):
        r = subprocess.run([sys.executable, "src/cyberdef/sc_cot.py", "--selftest", *a], capture_output=True, text=True, env=env)
        return json.loads(r.stdout.strip().splitlines()[-1])
    WANT = ["valid_trace_accepted", "missing_refutation_rejected", "vuln_no_witness_rejected", "nonexistent_line_rejected", "sink_not_on_line_rejected",
            "safe_unguarded_rejected", "valid_injection_accepted", "valid_none_accepted", "class_not_allowed_rejected", "oracle_inconsistent_rejected",
            "injection_without_canary_rejected", "witness_shape_mismatch_rejected", "oracle_none_without_static_evidence_rejected",
            "static_evidence_line_missing_rejected", "static_evidence_snippet_mismatch_rejected", "missing_v2_fields_rejected"]
    try:
        real = st()
        miss = [k for k in WANT if k not in real]
        bad = [k for k in WANT if k in real and real[k] is not True]
        if miss or bad:
            fails.append(f"real validator: missing controls {miss}; failed {bad}")
        bro = st("--broken")
        if all(bro.get(k, True) for k in WANT if k.endswith("_rejected")):
            fails.append("always-pass validator NOT caught")
    except Exception as e:
        fails.append(f"validator unavailable: {e}")
else:
    tag = sys.argv[2]
    R = "results/"
    try:
        d = json.load(open(R + f"reason_CSC_{tag}_matched.json"))
    except Exception as e:
        print("FAIL: output missing:", e); sys.exit(1)
    cases = json.load(open(R + "lenmatched_eval_cases.json"))["cases"]
    pairs = sorted({c["pair"] for c in cases}); keep = set(random.Random(0).sample(pairs, 150))
    want = sorted((c["id"], c["label"]) for c in cases if c["pair"] in keep)
    pc = d.get("per_case", [])
    if sorted((p["id"], p["label"]) for p in pc) != want:
        fails.append("per_case != the Stage C subset (same 300 cases required)")
    if abs(d.get("parse_rate", -1) - sum(p["parsed"] for p in pc) / max(1, len(pc))) > 1e-3:
        fails.append("parse_rate inconsistent")
    for p in pc:
        if p["verdict_raw"] == "VULNERABLE" and not p["has_witness"] and p["verdict_final"] != "UNCERTAIN":
            fails.append("VULNERABLE without evidence not downgraded"); break
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
