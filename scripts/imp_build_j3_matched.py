"""Amendment 2c: results/j3_heldout_matched_cases.json, a per-CWE LENGTH-MATCHED subset of the J3 held-out set.
Within each CWE: 10 code-length quantile bins over that CWE's functions; in each bin an equal number of VULNERABLE and SAFE
functions drawn with random.Random(0). A CWE is kept only if its matched subset has length-only AUROC in [0.45, 0.55]
(both chars and an approximate token count) and at least 20 functions per class."""
import json, random

src = json.load(open("results/j3_heldout_cases.json"))
cases = src["cases"]

def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))

rng = random.Random(0)
keep, report = [], {}
by = {}
for c in cases:
    by.setdefault(c["cwe"], []).append(c)
for cwe, cs in sorted(by.items()):
    s = sorted(cs, key=lambda c: (c["code_chars"], c["id"]))
    edges = [s[int(len(s) * k / 10)]["code_chars"] for k in range(1, 10)]
    bins = {}
    for c in cs:
        b = sum(c["code_chars"] >= e for e in edges)
        bins.setdefault(b, {"V": [], "S": []})["V" if c["label"] == "VULNERABLE" else "S"].append(c)
    sel = []
    for b in sorted(bins):
        v, sa = bins[b]["V"], bins[b]["S"]
        rng.shuffle(v); rng.shuffle(sa)
        k = min(len(v), len(sa)); sel += v[:k] + sa[:k]
    y = [c["label"] == "VULNERABLE" for c in sel]
    nv = sum(y); ok = nv >= 20 and (len(sel) - nv) >= 20
    lc = auroc([c["code_chars"] for c in sel], y) if ok else None
    lt = auroc([c["toks"] for c in sel], y) if ok else None
    passed = ok and 0.45 <= lc <= 0.55 and 0.45 <= lt <= 0.55
    report[cwe] = {"functions_before": len(cs), "matched_vulnerable": nv, "matched_safe": len(sel) - nv,
                   "length_only_chars": None if lc is None else round(lc, 4), "length_only_toks": None if lt is None else round(lt, 4),
                   "kept": bool(passed)}
    if passed:
        keep += sel
out = {"cases": keep, "split": "test", "seed": 0,
       "pool": {"rule": "amendment 2c: per-CWE length-matched subset of j3_heldout_cases.json (10 length bins per CWE, equal V/S per bin, "
                        "random.Random(0)); a CWE is kept only if length-only AUROC is in [0.45, 0.55] and >= 20 per class",
                "by_cwe": report, "functions": len(keep)}}
json.dump(out, open("results/j3_heldout_matched_cases.json", "w"))
print(json.dumps(out["pool"], indent=1))
