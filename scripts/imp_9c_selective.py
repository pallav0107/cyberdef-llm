"""#9c selective prediction / abstention on the length-matched set. See EXPERIMENT_PLAN_IMPROVE.md. Read-only on existing results.
Run from the repo root: nice -n 19 python3 scripts/imp_9c_selective.py"""
import json, math, os, random, sys
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, hm_se, r4

R = "results/"
CASES = json.load(open(R + "lenmatched_eval_cases.json"))["cases"]
CH = {(c["id"], c["label"]): c["code_chars"] for c in CASES}
ORDER = [(c["id"], c["label"]) for c in CASES]
SRC = {"published_7b": "ab_pub7b__lenmatched.json", "lenmatch_7b": "lm_sel_lenmatch_on_matched.json",
       "base_1.5b": "ab_base1.5b__lenmatched.json", "lenmatch_1.5b": "ab_lm1.5b__lenmatched.json",
       "base_7b": "imp_src_base7b_matched.json",
       "flawfinder": "reason_B_sast_flawfinder_matched.json", "semgrep": "reason_B_sast_semgrep_matched.json"}
COVS = ["0.10", "0.25", "0.50", "1.00"]


def load(name, fn):
    p = R + fn
    if not os.path.exists(p):
        return None, f"{name}: {fn} not found"
    d = json.load(open(p))
    pc = d.get("per_case", [])
    if sorted((x["id"], x["label"]) for x in pc) != sorted(ORDER):
        return None, f"{name}: {fn} per_case does not cover the matched cases"
    m = {(x["id"], x["label"]): x for x in pc}
    rows, sast = [], "p_vuln" not in pc[0]
    for k in ORDER:
        x = m[k]
        s = float(x["score"]) if sast else float(x["p_vuln"])
        rows.append({"id": k[0], "label": k[1], "score": s, "conf": s if sast else max(s, 1 - s), "chars": CH[k]})
    pos = [r["score"] for r in rows if r["score"] > 0]
    thr = (min(pos) if pos else 1e9) if sast else 0.5
    return {"source": fn, "threshold": thr, "sast": sast, "rows": rows}, None


def subset_stats(rows, idx, thr):
    ys = [1 if rows[i]["label"] == "VULNERABLE" else 0 for i in idx]
    ss = [rows[i]["score"] for i in idx]
    ch = [rows[i]["chars"] for i in idx]
    k = len(idx); n1 = sum(ys); n0 = k - n1
    pred = [1 if s >= thr else 0 for s in ss]
    npv = sum(pred)
    a = auroc(ss, ys); la = auroc(ch, ys)
    return {"n": k, "n_vuln": n1, "n_safe": n0,
            "accuracy": r4(sum(1 for p, y in zip(pred, ys) if p == y) / k),
            "n_pred_vuln": npv, "precision_vuln": r4(sum(1 for p, y in zip(pred, ys) if p and y) / npv) if npv else None,
            "auroc": r4(a), "se_hm": r4(hm_se(a, n1, n0)), "length_only_auroc_same_cases": r4(la)}


def main():
    out = {"arm": "9c", "n": len(CASES), "cases_file": R + "lenmatched_eval_cases.json", "scorers": {}, "gaps": [],
           "preregistration": "EXPERIMENT_PLAN_IMPROVE.md#9c", "selection_rules": ["by_confidence", "by_length_extremity"]}
    lns = [math.log(max(1, CH[k])) for k in ORDER]
    med = sorted(lns)[len(lns) // 2]
    ext = [abs(v - med) for v in lns]
    for name, fn in SRC.items():
        s, gap = load(name, fn)
        if gap:
            out["gaps"].append(name); out.setdefault("gap_notes", {})[name] = gap; continue
        rows = s["rows"]; n = len(rows); thr = s["threshold"]
        conf = [r["conf"] for r in rows]
        res = {"source": s["source"], "n": n, "threshold": thr, "sast": s["sast"], "coverage": {},
               "ties_in_confidence": n - len(set(conf)),
               "full_auroc": r4(auroc([r["score"] for r in rows], [1 if r["label"] == "VULNERABLE" else 0 for r in rows])),
               "per_case": rows}
        for cov in COVS:
            if cov == "1.00":
                continue
            k = max(1, round(float(cov) * n))
            bc = sorted(range(n), key=lambda i: -conf[i])[:k]
            be = sorted(range(n), key=lambda i: -ext[i])[:k]
            rng = random.Random(0); aus, accs = [], []
            for _ in range(1000):
                ix = rng.sample(range(n), k); st = subset_stats(rows, ix, thr)
                if st["auroc"] is not None:
                    aus.append(st["auroc"])
                accs.append(st["accuracy"])
            mu = sum(aus) / len(aus); sd = math.sqrt(sum((x - mu) ** 2 for x in aus) / len(aus))
            res["coverage"][cov] = {"by_confidence": subset_stats(rows, bc, thr),
                                    "by_length_extremity": subset_stats(rows, be, thr),
                                    "random_null": {"draws": 1000, "auroc_mean": r4(mu), "auroc_sd": r4(sd),
                                                    "accuracy_mean": r4(sum(accs) / len(accs))}}
        # risk-coverage curve (accuracy of hard label vs coverage) for both rules
        rc = {"by_confidence": [], "by_length_extremity": []}
        for rule, key in (("by_confidence", conf), ("by_length_extremity", ext)):
            od = sorted(range(n), key=lambda i: -key[i])
            for c in (0.05, 0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.6, 0.75, 0.9, 1.0):
                k = max(1, round(c * n)); st = subset_stats(rows, od[:k], thr)
                rc[rule].append({"coverage": c, "n": k, "accuracy": st["accuracy"], "auroc": st["auroc"]})
        res["risk_coverage"] = rc
        out["scorers"][name] = res
    json.dump(out, open(R + "imp_9c_selective.json", "w"))
    for name, s in out["scorers"].items():
        c = s["coverage"]["0.25"]
        print(f"{name:14s} full={s['full_auroc']} @25% conf: auroc={c['by_confidence']['auroc']} acc={c['by_confidence']['accuracy']} | "
              f"lenext: auroc={c['by_length_extremity']['auroc']} acc={c['by_length_extremity']['accuracy']} | null={c['random_null']['auroc_mean']}+-{c['random_null']['auroc_sd']}")
    print("gaps:", out["gaps"])


if __name__ == "__main__":
    main()
