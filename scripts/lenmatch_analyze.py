"""Analyse a selective_eval result on the length-matched eval: model AUROC + Hanley-McNeil SE, length-only
AUROC on the SAME cases, within-length-bin AUROC (quartiles of chars), pairwise win-rate, ECE (from result).
Usage: lenmatch_analyze.py RESULT.json [CASES.json]"""
from __future__ import annotations
import json, sys, math
sys.path.insert(0, "scripts")
from length_baseline import auroc, hanley_mcneil_se


def main():
    res = json.load(open(sys.argv[1]))
    cf = sys.argv[2] if len(sys.argv) > 2 else res["cases_file"].replace("/work/", "")
    cases = {c["id"] + c["label"]: c for c in json.load(open(cf))["cases"]}
    per = res["per_case"]
    rows = []
    for p in per:
        c = cases[p["id"] + p["label"]]
        rows.append((p["p_vuln"], 1 if p["label"] == "VULNERABLE" else 0, c["code_chars"], c["pair"]))
    sc, y, ch, pid = zip(*rows)
    n1, n0 = sum(y), len(y) - sum(y)
    a = auroc(list(sc), list(y)); se = hanley_mcneil_se(a, n1, n0)
    la = auroc(list(ch), list(y))
    out = {"result": sys.argv[1], "n": len(y), "n_vuln": n1, "n_safe": n0, "model_auroc": round(a, 4),
           "se_hm": round(se, 4), "z_vs_0.5": round((a - 0.5) / se, 2), "length_only_auroc_same_cases": round(la, 4),
           "ece": res.get("ece"), "accuracy": res.get("accuracy")}
    # pairwise: within matched pair, is vuln scored above its safe partner?
    byp = {}
    for s, yy, _, p in rows:
        byp.setdefault(p, {})[yy] = s
    w = [(1.0 if d[1] > d[0] else 0.5 if d[1] == d[0] else 0.0) for d in byp.values() if 0 in d and 1 in d]
    out["pairwise_win_rate"] = round(sum(w) / len(w), 4); out["n_pairs"] = len(w)
    # bootstrap-free pair SE (binomial)
    out["pairwise_se_binom"] = round(math.sqrt(0.25 / len(w)), 4)
    srt = sorted(ch)
    cuts = [srt[int(len(srt) * q / 4)] for q in (1, 2, 3)]
    bins = {}
    for i, (s, yy, c, _) in enumerate(rows):
        bins.setdefault(sum(c > t for t in cuts), []).append(i)
    ob = {}
    for k in sorted(bins):
        idx = bins[k]
        ss = [sc[i] for i in idx]; yy = [y[i] for i in idx]
        b1 = sum(yy); b0 = len(yy) - b1
        ba = auroc(ss, yy)
        ob[f"Q{k+1}"] = {"n": len(idx), "chars_range": [min(ch[i] for i in idx), max(ch[i] for i in idx)],
                         "auroc": round(ba, 4), "se_hm": round(hanley_mcneil_se(ba, b1, b0), 4)}
    out["within_length_quartile"] = ob
    # score-length correlation (Spearman-ish via rank pearson)
    def ranks(v):
        o = sorted(range(len(v)), key=lambda i: v[i]); r = [0.0] * len(v)
        for k, i in enumerate(o): r[i] = k
        return r
    ra, rb = ranks(list(sc)), ranks(list(ch)); ma = sum(ra) / len(ra)
    cov = sum((x - ma) * (z - ma) for x, z in zip(ra, rb))
    out["spearman_pvuln_vs_chars"] = round(cov / sum((x - ma) ** 2 for x in ra), 3)
    print(json.dumps(out, indent=1))
    json.dump(out, open(sys.argv[1].replace(".json", "_analysis.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
