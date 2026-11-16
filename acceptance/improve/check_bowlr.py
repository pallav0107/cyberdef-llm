"""Acceptance check for scripts/imp_bow_lr.py (VSP_SFT_R1 audit finding 7): a bag-of-words logistic-regression baseline
(TF-IDF over 1-2-gram code tokens, C=1, seed 0) fit on VSP-SFT training items ONLY, scored on VSP-T.
  .venv/bin/python acceptance/improve/check_bowlr.py
Fails first (script absent). Checks: per_case keys match VSP-T exactly; deterministic (two runs byte-identical);
the VSP-T scores do not change when the VSP-T labels are shuffled (no test-label use); the method marks it deterministic."""
import json
import os
import random
import subprocess
import sys
import tempfile

S = "scripts/imp_bow_lr.py"
CASES = "results/vsp_t_cases.json"
ITEMS = "results/vsp_sft_items.json"
FAILS = []


def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


if not os.path.exists(S):
    print("FAIL script missing: " + S)
    sys.exit(1)
T = tempfile.mkdtemp(prefix="bowlr_")


def run(cases, out):
    r = subprocess.run([sys.executable, S, "--items", ITEMS, "--cases", cases, "--out", out], capture_output=True, text=True, timeout=1800)
    return r.returncode == 0 and os.path.exists(out)


ok("runs on VSP-T", run(CASES, f"{T}/a.json"))
ok("second run", run(CASES, f"{T}/b.json"))
if not FAILS:
    a = json.load(open(f"{T}/a.json"))
    cs = json.load(open(CASES))["cases"]
    ok("per_case keys == VSP-T (id, label)", {(p["id"], p["label"]) for p in a["per_case"]} == {(c["id"], c["label"]) for c in cs})
    ok("deterministic: two runs byte-identical", open(f"{T}/a.json").read() == open(f"{T}/b.json").read())
    ok("method marks a deterministic scorer", str(a.get("method", "")).startswith("logprob-scored"))
    sh = json.load(open(CASES))
    labs = [c["label"] for c in sh["cases"]]
    random.Random(7).shuffle(labs)
    for c, l in zip(sh["cases"], labs):
        c["label"] = l
    json.dump(sh, open(f"{T}/shuffled.json", "w"))
    ok("runs on label-shuffled VSP-T", run(f"{T}/shuffled.json", f"{T}/c.json"))
    if os.path.exists(f"{T}/c.json"):
        c = json.load(open(f"{T}/c.json"))
        sa = {p["id"]: p["p_vuln"] for p in a["per_case"]}
        sc = {p["id"]: p["p_vuln"] for p in c["per_case"]}
        ok("VSP-T scores unchanged when VSP-T labels are shuffled (no test-label use)", sa == sc)
print(f"{len(FAILS)} failed" if FAILS else "ALL PASS")
sys.exit(1 if FAILS else 0)
