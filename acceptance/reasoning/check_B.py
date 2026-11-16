"""Stage B acceptance (written BEFORE the implementation). Exit 0 only if every check passes.
1 output exists with per_case for EVERY case in results/lenmatched_eval_cases.json (none dropped), same ids/labels.
2 parse_failures is reported (int); failures are present in per_case with score 0 and parse_fail=true.
3 AUROC in the file is recomputed here independently from per_case and must match to 1e-3.
4 FAIL-FIRST CONTROL: scorer selftest: strcpy-into-fixed-buffer function scores strictly above an empty function,
  for the tool; a scorer that returns 0 for everything must FAIL this check (checked via --selftest --broken).
Usage: check_B.py flawfinder|semgrep   (run from the repo root)"""
import json, subprocess, sys
tool = sys.argv[1]
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
try:
    d = json.load(open(R + f"reason_B_sast_{tool}_matched.json"))
except Exception as e:
    print("FAIL: output missing/unreadable:", e); sys.exit(1)
pc = d.get("per_case", [])
if sorted((p["id"], p["label"]) for p in pc) != sorted((c["id"], c["label"]) for c in cases):
    fails.append("per_case does not cover exactly the matched cases")
if not isinstance(d.get("parse_failures"), int):
    fails.append("parse_failures not reported")
pf = [p for p in pc if p.get("parse_fail")]
if len(pf) != d.get("parse_failures"):
    fails.append("parse_failures count inconsistent with per_case")
if any(p["score"] != 0 for p in pf):
    fails.append("a parse failure was not scored as no-finding (0)")
if pc:
    a = auroc([p["score"] for p in pc], [1 if p["label"] == "VULNERABLE" else 0 for p in pc])
    if abs(a - d.get("auroc", -1)) > 1e-3:
        fails.append(f"auroc mismatch file={d.get('auroc')} recomputed={a:.4f}")
r = subprocess.run([sys.executable, "scripts/reason_B_sast.py", tool, "--selftest"], capture_output=True, text=True)
try:
    st = json.loads(r.stdout.strip().splitlines()[-1])
    if not st["strcpy_fixed_buffer"] > st["empty"]:
        fails.append(f"CONTROL FAILED selftest {st}")
except Exception as e:
    fails.append(f"selftest unreadable: {e}")
r2 = subprocess.run([sys.executable, "scripts/reason_B_sast.py", tool, "--selftest", "--broken"], capture_output=True, text=True)
try:
    st2 = json.loads(r2.stdout.strip().splitlines()[-1])
    if st2["strcpy_fixed_buffer"] > st2["empty"]:
        fails.append("broken scorer was NOT caught by the control (control is vacuous)")
except Exception as e:
    fails.append(f"broken-selftest unreadable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails))
sys.exit(0 if not fails else 1)
