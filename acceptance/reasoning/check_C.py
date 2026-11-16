"""Stage C acceptance (written BEFORE the implementation). Usage (repo root): check_C.py <model_tag>
Checks results/reason_C_<tag>_matched.json:
 1 per_case covers EXACTLY the pre-registered subset (150 random pairs, seed 0 -> 300 cases), none dropped
 2 parse_rate reported and equals the recount of parsed==True
 3 AUROC for s0/s1/s2 recomputed independently from per_case, must match 1e-3; per-quartile AUROCs present
 4 gating recomputed independently: VULNERABLE+null witness => s1==0.5; VULNERABLE+inconsistent => s2==0.5
 5 FAIL-FIRST controls of the consistency checker (scripts/reason_C_witness.py --selftest): a line past the end, a sink
   op absent from its cited line, and an empty trace must each be INCONSISTENT and a good example CONSISTENT; the
   --broken (always-consistent) checker must FAIL control (a)-(c)."""
import json, random, subprocess, sys
tag = sys.argv[1]
R = "results/"


def auroc(s, y):
    o = sorted(range(len(s)), key=lambda i: s[i]); r = [0.0] * len(s); i = 0
    while i < len(o):
        j = i
        while j + 1 < len(o) and s[o[j + 1]] == s[o[i]]:
            j += 1
        for k in range(i, j + 1):
            r[o[k]] = (i + j) / 2 + 1
        i = j + 1
    p = sum(y); n = len(y) - p
    return (sum(r[i] for i in range(len(y)) if y[i]) - p * (p + 1) / 2) / (p * n)


fails = []
cases = json.load(open(R + "lenmatched_eval_cases.json"))["cases"]
pairs = sorted({c["pair"] for c in cases})
keep = set(random.Random(0).sample(pairs, 150))
want = sorted((c["id"], c["label"]) for c in cases if c["pair"] in keep)
try:
    d = json.load(open(R + f"reason_C_{tag}_matched.json"))
except Exception as e:
    print("FAIL: output missing/unreadable:", e); sys.exit(1)
pc = d.get("per_case", [])
if sorted((p["id"], p["label"]) for p in pc) != want:
    fails.append("per_case != pre-registered subset")
if "parse_rate" not in d or abs(d["parse_rate"] - sum(p["parsed"] for p in pc) / max(1, len(pc))) > 1e-3:
    fails.append("parse_rate missing/inconsistent")
y = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
for k in ("s0", "s1", "s2"):
    if pc and abs(auroc([p[k] for p in pc], y) - d["auroc"][k]) > 1e-3:
        fails.append(f"auroc {k} mismatch")
if "within_length_quartile" not in d:
    fails.append("quartiles missing")
for p in pc:
    if p["verdict"] == "VULNERABLE" and p["witness_null"] and p["s1"] != 0.5:
        fails.append("null witness not UNCERTAIN in s1"); break
for p in pc:
    if p["verdict"] == "VULNERABLE" and (p["witness_null"] or not p["consistent"]) and p["s2"] != 0.5:
        fails.append("inconsistent/null not UNCERTAIN in s2"); break
r = subprocess.run([sys.executable, "scripts/reason_C_witness.py", "--selftest"], capture_output=True, text=True)
try:
    st = json.loads(r.stdout.strip().splitlines()[-1])
    if st != {"line_past_end": False, "sink_not_on_line": False, "empty_trace": False, "good": True}:
        fails.append(f"CONTROL FAILED {st}")
except Exception as e:
    fails.append(f"selftest unreadable: {e}")
r = subprocess.run([sys.executable, "scripts/reason_C_witness.py", "--selftest", "--broken"], capture_output=True, text=True)
try:
    st = json.loads(r.stdout.strip().splitlines()[-1])
    if not (st["line_past_end"] or st["sink_not_on_line"] or st["empty_trace"]):
        fails.append("broken checker NOT caught (controls vacuous)")
except Exception as e:
    fails.append(f"broken selftest unreadable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails))
sys.exit(0 if not fails else 1)
