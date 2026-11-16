"""Stage D acceptance (written BEFORE src/cyberdef/exec_harness.py existed).
 check_D.py harness            -> harness controls
 check_D.py output <tag> <set> -> results/reason_D_<tag>_<set>.json consistency (set = castle|juliet)
Controls (all must hold on the real harness; each mutant harness must FAIL at least the stated ones):
 c1 vulnerable strcpy program + overlong witness => confirmed        (always_false mutant must fail this)
 c2 same program + short benign witness          => NOT confirmed     (always_true mutant must fail this)
 c3 identical vulnerable program as 'safe' twin  => NOT confirmed     (always_true mutant must fail this)
 c4a plain abort() is NOT a sanitizer report     (always_true mutant must fail this)
 c4b infinite loop is killed by the timeout, and c4c network is blocked (connect fails inside the sandbox)"""
import json, subprocess, sys

mode = sys.argv[1]
fails = []
if mode == "harness":
    def st(m):
        r = subprocess.run([sys.executable, "src/cyberdef/exec_harness.py", m], capture_output=True, text=True,
                           env={**__import__("os").environ, "PYTHONPATH": "src"})
        return json.loads(r.stdout.strip().splitlines()[-1])
    try:
        real = st("real")
        bad = [k for k, v in real.items() if v is not True]
        if bad:
            fails.append(f"controls failed on real harness: {bad}")
        t = st("always_true")
        if not (not t["c2_vuln_short_not_confirmed"] or not t["c3_identical_programs_not_confirmed"] or not t["c4a_plain_abort_not_sanitizer"]):
            fails.append("always_true mutant NOT caught")
        f = st("always_false")
        if f["c1_vuln_long_confirmed"]:
            fails.append("always_false mutant NOT caught")
    except Exception as e:
        fails.append(f"selftest unavailable: {e}")
else:
    tag, ds = sys.argv[2], sys.argv[3]
    try:
        d = json.load(open(f"results/reason_D_{tag}_{ds}.json"))
    except Exception as e:
        print("FAIL: output missing:", e); sys.exit(1)
    pc = d.get("per_case", [])
    if d.get("n_total") != len(pc) or not pc:
        fails.append("per_case count != n_total")
    for k in ("n_compiled", "n_compile_fail", "n_witness_null", "n_confirmed", "n_vuln_cases", "n_safe_cases"):
        if not isinstance(d.get(k), int):
            fails.append(f"{k} missing")
    if sum(1 for p in pc if p.get("compiled")) != d.get("n_compiled"):
        fails.append("n_compiled inconsistent")
    if sum(1 for p in pc if p.get("confirmed")) != d.get("n_confirmed"):
        fails.append("n_confirmed inconsistent")
    if any(p.get("confirmed") and not p.get("sanitizer") for p in pc):
        fails.append("confirmed without a sanitizer report on that program")
print("PASS" if not fails else "FAIL: " + "; ".join(fails))
sys.exit(0 if not fails else 1)
