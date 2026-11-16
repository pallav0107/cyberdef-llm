"""Amendment 3, J4: from results/j4_heldout_all.json keep only execution-verified pairs (bad fired a sanitizer, good did not),
refuse any function that appears in a training pool, then length-match per CWE exactly as amendment 2c (10 bins, equal V/S
per bin, random.Random(0); a CWE is kept only if length-only AUROC is in [0.45, 0.55] and >= 20 per class).
Writes results/j4_heldout_matched_cases.json."""
import glob, hashlib, json, random

d = json.load(open("results/j4_heldout_all.json"))
pairs = {}
for it in d["items"]:
    pairs.setdefault(it["pair"], {})[it["label"]] = it
ver = [p for p in pairs.values() if "VULNERABLE" in p and "SAFE" in p and p["VULNERABLE"]["compiled"] and p["SAFE"]["compiled"]
       and p["VULNERABLE"]["exec_sanitizer"] and not p["SAFE"]["exec_sanitizer"]]
norm = lambda s: " ".join(s.split()); h = lambda s: hashlib.sha256(norm(s).encode()).hexdigest()
train = set()
for f in glob.glob("results/imp_train_*_items.json"):
    for it in json.load(open(f)).get("items", []):
        if "code" in it:
            train.add(h(it["code"]))
leak = [p["VULNERABLE"]["id"] for p in ver if h(p["VULNERABLE"]["code"]) in train or h(p["SAFE"]["code"]) in train]
if leak:
    raise SystemExit(f"REFUSED: {len(leak)} held-out pairs overlap a training pool, e.g. {leak[:3]}")

def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))

cases = [{"id": p[l]["id"], "code": p[l]["code"], "code_chars": p[l]["code_chars"], "toks": p[l]["toks"], "label": l, "cwe": p[l]["cwe"], "pair": p[l]["pair"]}
         for p in ver for l in ("VULNERABLE", "SAFE")]
rng = random.Random(0); keep, report = [], {}
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
        v, sa = bins[b]["V"], bins[b]["S"]; rng.shuffle(v); rng.shuffle(sa); k = min(len(v), len(sa)); sel += v[:k] + sa[:k]
    y = [c["label"] == "VULNERABLE" for c in sel]; nv = sum(y)
    ok = nv >= 20 and len(sel) - nv >= 20
    lc = auroc([c["code_chars"] for c in sel], y) if ok else None
    passed = ok and 0.45 <= lc <= 0.55
    report[cwe] = {"verified_pairs": len(cs) // 2, "matched_per_class": nv, "length_only": None if lc is None else round(lc, 4), "kept": bool(passed)}
    if passed:
        keep += sel
json.dump({"cases": keep, "split": "test", "seed": 0, "pool": {"rule": "amendment 3 J4: verified Juliet held-out, per-CWE length-matched as 2c",
           "candidates": d["stats"], "verified_pairs": len(ver), "by_cwe": report, "functions": len(keep)}},
          open("results/j4_heldout_matched_cases.json", "w"))
print(json.dumps({"verified_pairs": len(ver), "functions_kept": len(keep), "by_cwe": report}, indent=1))
