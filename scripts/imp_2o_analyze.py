"""Summary across the oracle-spec arms (results/imp_2o_<arm>_b60.json): overall and per CWE group (a sanitizer-detectable / b crash-like-other / c non-crash): confirmed on vulnerable,
false positives on safe, AUROC +/- HM SE; per-variant contributions; attribution differences with conservative SE_diff. Writes results/imp_2o_summary.json.  python3 scripts/imp_2o_analyze.py"""
import json, math, os, sys
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, hm_se, r4

R = "results/"
arms = {}
for a in ("floor", "empty", "random", "random_resized", "llm", "llm_direct"):
    f = R + f"imp_2o_{a}_b60.json"
    if os.path.exists(f):
        arms[a] = json.load(open(f))
def posthoc(d):
    """POST-HOC sensitivity (not pre-registered): confirmed' = some counted class other than cpu_hang. Programs whose ONLY counted class is cpu_hang become unconfirmed with score 0;
    other programs keep their stored score (for fuzz arms their t_first may have been set by a cpu_hang item: slight inexactness, floor arm is exact)."""
    per = []
    for p in d["per_case"]:
        cls = [c for c in p["counted_classes"] if c != "cpu_hang"]
        per.append(dict(p, confirmed=bool(cls), score=p["score"] if cls else 0.0))
    from collections import Counter
    def gs(rows):
        y = [1 if p["label"] == "VULNERABLE" else 0 for p in rows]
        n1 = sum(y); n0 = len(y) - n1
        a = auroc([p["score"] for p in rows], y) if n1 and n0 else None
        return {"n_vuln": n1, "n_safe": n0, "confirmed_vuln": sum(1 for p in rows if p["label"] == "VULNERABLE" and p["confirmed"]),
                "confirmed_safe": sum(1 for p in rows if p["label"] == "SAFE" and p["confirmed"]), "auroc": r4(a), "se_hm": r4(hm_se(a, n1, n0)) if a is not None else None}
    return {"overall": gs(per), "by_group": {g: gs([p for p in per if p["group"] == g]) for g in "abc"}}


def load_avg(d, f):
    """mean/max 1-min load average over the arm run window from /tmp-copied sampler log results/imp_2o_load.log (lines: epoch load1 load5 load15); window = [mtime - seconds, mtime]"""
    lf = R + "imp_2o_load.log"
    if not os.path.exists(lf):
        return None
    t1 = os.path.getmtime(f); t0 = t1 - d["seconds"]
    xs = []
    for l in open(lf):
        try:
            e, a, b, c = l.split()
            if t0 <= float(e) <= t1:
                xs.append(float(a))
        except Exception:
            pass
    return {"samples": len(xs), "mean_1min": r4(sum(xs) / len(xs)) if xs else None, "max_1min": max(xs) if xs else None, "note": "box load is shared with other jobs; cpu_hang is load-sensitive"}


out = {"spec": "results/imp_castle_oracle_spec.json", "arms": {}, "attribution": {}}
for a, d in arms.items():
    s = d["summary"]
    out["arms"][a] = {"overall": s["overall"], "by_group": s["by_group"], "by_variant": s["by_variant"], "safe_false_positives": s["safe_false_positives"],
                      "compile_failures_all_variants": s["compile_failures_all_variants"], "afl_aborted": s["afl_aborted"], "harness_fail": s["harness_fail"], "seconds": d["seconds"],
                      "load_average_during_run": load_avg(d, R + f"imp_2o_{a}_b60.json"),
                      "POSTHOC_excluding_cpu_hang": posthoc(d)}
def diff(x, y, ph=False):
    if x in out["arms"] and y in out["arms"]:
        g = (lambda k: out["arms"][k]["POSTHOC_excluding_cpu_hang"]["overall"]) if ph else (lambda k: out["arms"][k]["overall"])
        a, b = g(x), g(y)
        se = math.sqrt(a["se_hm"] ** 2 + b["se_hm"] ** 2)
        return {"delta_auroc": r4(a["auroc"] - b["auroc"]), "se_diff": r4(se), "over_2se": (a["auroc"] - b["auroc"]) > 2 * se}
for x, y in (("empty", "floor"), ("random", "floor"), ("random", "empty"), ("llm", "empty"), ("llm", "random"), ("llm_direct", "floor")):
    out["attribution"][f"{x}_minus_{y}"] = diff(x, y)
    out.setdefault("POSTHOC_attribution_excluding_cpu_hang", {})[f"{x}_minus_{y}"] = diff(x, y, True)
json.dump(out, open(R + "imp_2o_summary.json", "w"), indent=1)
for a, v in out["arms"].items():
    o = v["overall"]; g = v["by_group"]
    ph = v["POSTHOC_excluding_cpu_hang"]; po = ph["overall"]; pg = ph["by_group"]
    print(f"  POST-HOC excl. cpu_hang: overall {po['confirmed_vuln']}/{po['n_vuln']} v, {po['confirmed_safe']}/{po['n_safe']} s, AUROC {po['auroc']} | " + " | ".join(f"{k}: {pg[k]['confirmed_vuln']}v {pg[k]['confirmed_safe']}s" for k in "abc") + f" | load {v['load_average_during_run']}")
    print(f"{a:8s} overall {o['confirmed_vuln']}/{o['n_vuln']} vuln, {o['confirmed_safe']}/{o['n_safe']} safe FP, AUROC {o['auroc']}+-{o['se_hm']} | " +
          " | ".join(f"{k}: {g[k]['confirmed_vuln']}/{g[k]['n_vuln']} v, {g[k]['confirmed_safe']}/{g[k]['n_safe']} s, auc {g[k]['auroc']}" for k in "abc"))
print(json.dumps(out["attribution"]))
