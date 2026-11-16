"""POST-HOC sensitivity (does not replace pre-registered numbers; nothing tuned): re-score D0 and D2 with cpu_hang excluded from the counted classes."""
import json, sys
sys.path.insert(0, "scripts")
from length_baseline import auroc, hanley_mcneil_se
mine = {(p["id"], p["label"]): p for p in json.load(open("results/reason_D0_spec_mine.json"))["per_case"]}
bld = {(p["id"], p["label"]): p for p in json.load(open("results/imp_2o_floor_b60.json"))["per_case"]}
nh = lambda cl: [c for c in cl if c != "cpu_hang"]
def st(rows):
    y = [1 if r[0] == "VULNERABLE" else 0 for r in rows]; n1 = sum(y)
    a = auroc([1.0 if r[1] else 0.0 for r in rows], y)
    return {"vuln": f"{sum(1 for r,v in zip(rows,y) if v and r[1])}/{n1}", "FP": f"{sum(1 for r,v in zip(rows,y) if not v and r[1])}/{len(y)-n1}", "auroc": round(a, 3), "se": round(hanley_mcneil_se(a, n1, len(y) - n1), 3)}
out = {"note": "POST-HOC: cpu_hang excluded; pre-registered numbers unchanged"}
for g in ("a", "b", "c", "ALL"):
    ks = [k for k, p in mine.items() if g == "ALL" or p["group"] == g]
    out.setdefault("D0", {})[g] = {"mine_with_hang": st([(k[1], mine[k]["confirmed"]) for k in ks]),
                                    "mine_no_hang": st([(k[1], bool(nh(mine[k]["classes"]))) for k in ks]),
                                    "builder_no_hang": st([(k[1], bool(nh(bld[k]["counted_classes"]))) for k in ks])}
print("D0 post-hoc excluding cpu_hang (with-hang shown for reference)")
for g, v in out["D0"].items(): print(" ", g, v)
fp = [(k[0], mine[k]["group"], mine[k]["classes"]) for k in mine if k[1] == "SAFE" and nh(mine[k]["classes"])]
print("  FPs remaining without cpu_hang (mine):", fp)
for tag in ("base7b", "tuned7b"):
    ex = {(p["id"], p["label"]): p for p in json.load(open(f"results/reason_D2_{tag}_castle.json"))["per_case"]}
    print("D2", tag)
    for g in ("a", "b", "c", "ALL"):
        ks = [k for k in ex if g == "ALL" or ex[k]["group"] == g]
        mc = lambda k: ex[k]["verdict"] == "VULNERABLE" and bool(nh(ex[k]["classes"]))
        fl = lambda k: bool(nh(mine[k]["classes"]))
        m = st([(k[1], mc(k)) for k in ks]); u = st([(k[1], mc(k) or fl(k)) for k in ks])
        new = sum(1 for k in ks if k[1] == "VULNERABLE" and mc(k) and not fl(k))
        fps = [k[0] for k in ks if k[1] == "SAFE" and mc(k)]
        print("  ", g, "model", m, "| union", u, "| new beyond floor", new, "| model FPs", fps)
        out.setdefault("D2_" + tag, {})[g] = {"model": m, "union": u, "new": new, "fps": fps}
json.dump(out, open("results/reason_D2_nohang_posthoc.json", "w"), indent=1)
