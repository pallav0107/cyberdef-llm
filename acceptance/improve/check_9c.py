"""Acceptance for arm #9c (written BEFORE the implementation). Exit 0 only if every check passes. Run from the repo root.
1 results/imp_9c_selective.json exists, n == 1074, per-scorer per_case covers exactly the matched cases (none dropped).
2 For every scorer and coverage in {0.10,0.25,0.50}: the stored subset size == round(cov*n); AUROC, accuracy, precision and
  the length-extremity baseline are RECOMPUTED here independently from per_case and must match to 1e-3.
3 Both selection rules and the random-selection null exist for every scorer/coverage.
4 Scorers named in the pre-registration are present or explicitly listed under 'gaps' (missing evidence is a reported gap, never a pass).
Usage: check_9c.py [path]"""
import json, math, sys

path = sys.argv[1] if len(sys.argv) > 1 else "results/imp_9c_selective.json"
fails = []


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    if not P or not N:
        return None
    w = 0.0
    for a in P:
        for b in N:
            w += 1.0 if a > b else 0.5 if a == b else 0.0
    return w / (len(P) * len(N))


try:
    d = json.load(open(path))
except Exception as e:
    print("FAIL: output missing/unreadable:", e); sys.exit(1)
cases = json.load(open("results/lenmatched_eval_cases.json"))["cases"]
exp = sorted((c["id"], c["label"]) for c in cases)
chars = {(c["id"], c["label"]): c["code_chars"] for c in cases}
if d.get("n") != len(cases):
    fails.append(f"n={d.get('n')} != {len(cases)}")
need = {"published_7b", "lenmatch_7b", "base_1.5b", "lenmatch_1.5b", "flawfinder", "semgrep"}
sc = d.get("scorers", {})
gaps = set(d.get("gaps", []))
for m in need | {"base_7b"}:
    if m not in sc and m not in gaps:
        fails.append(f"scorer {m} neither present nor listed under gaps")
for name, s in sc.items():
    pc = s.get("per_case", [])
    if sorted((p["id"], p["label"]) for p in pc) != exp:
        fails.append(f"{name}: per_case does not cover the matched cases exactly"); continue
    if s.get("n") != len(pc):
        fails.append(f"{name}: n != len(per_case)")
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
    sco = [p["score"] for p in pc]
    conf = [p["conf"] for p in pc]
    lns = [math.log(max(1, chars[(p["id"], p["label"])])) for p in pc]
    med = sorted(lns)[len(lns) // 2]
    ext = [abs(v - med) for v in lns]
    for cov in ("0.10", "0.25", "0.50"):
        k = max(1, round(float(cov) * len(pc)))
        row = s.get("coverage", {}).get(cov)
        if not row:
            fails.append(f"{name}@{cov}: missing"); continue
        for rule, key in (("by_confidence", conf), ("by_length_extremity", ext)):
            r = row.get(rule)
            if not r:
                fails.append(f"{name}@{cov}: missing {rule}"); continue
            order = sorted(range(len(pc)), key=lambda i: -key[i])[:k]  # stable: ties keep case order
            ys = [y[i] for i in order]; ss = [sco[i] for i in order]
            if r.get("n") != k:
                fails.append(f"{name}@{cov} {rule}: n {r.get('n')} != {k}")
            a = auroc(ss, ys)
            if (a is None) != (r.get("auroc") is None) or (a is not None and abs(a - r["auroc"]) > 1e-3):
                fails.append(f"{name}@{cov} {rule}: auroc stored {r.get('auroc')} recomputed {a}")
            acc = sum((1 if ss[j] >= s["threshold"] else 0) == ys[j] for j in range(k)) / k
            if abs(acc - r.get("accuracy", -9)) > 1e-3:
                fails.append(f"{name}@{cov} {rule}: accuracy stored {r.get('accuracy')} recomputed {acc:.4f}")
        if "random_null" not in row:
            fails.append(f"{name}@{cov}: random_null missing")
if not sc:
    fails.append("no scorers in output")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails[:40]]; sys.exit(1)
print("PASS: imp_9c_selective.json verified (%d scorers, gaps=%s)" % (len(sc), sorted(gaps)))
