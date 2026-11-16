"""POST-HOC robustness for Stage H (does not change the pre-registered verdict): per-transform slope and flip rate in subsets
by base length. (a) bases <= 2500 chars (every variant <= 4000 chars, i.e. inside the training/eval max_chars cap),
(b) bases > 2500 chars (the +1500 pads exceed 4000 chars). H scoring itself applied NO truncation (make_user passes full code)."""
import json, sys
tag = sys.argv[1]
items = {i["key"]: i for i in json.load(open("results/reason_H_items.json"))["items"]}
sc = json.load(open(f"results/reason_H_{tag}_scores.json"))
by = {}
for k, it in items.items():
    if it["group"] == "len" and k in sc:
        by.setdefault(it["base"], {})[it["transform"]] = it
def stats(bases):
    out = {}
    for tr in ("pad_comment_500", "pad_comment_1500", "pad_ws_1500", "compress", "rename_long", "rename_short"):
        pts = []
        for b in bases:
            d = by[b]
            if tr in d and "orig" in d:
                dc = len(d[tr]["code"]) - len(d["orig"]["code"]); dp = sc[d[tr]["key"]] - sc[d["orig"]["key"]]
                pts.append((dc, dp, int((sc[d[tr]["key"]] >= .5) != (sc[d["orig"]["key"]] >= .5))))
        if pts:
            out[tr] = {"n": len(pts), "mean_dchars": round(sum(p[0] for p in pts) / len(pts), 1),
                       "slope_per_1000_chars": round(1000 * sum(p[0] * p[1] for p in pts) / max(1e-9, sum(p[0] ** 2 for p in pts)), 4),
                       "mean_abs_dp": round(sum(abs(p[1]) for p in pts) / len(pts), 4),
                       "flip_rate": round(sum(p[2] for p in pts) / len(pts), 4)}
    return out
bases = list(by)
a = [b for b in bases if len(by[b]["orig"]["code"]) <= 2500]
bb = [b for b in bases if len(by[b]["orig"]["code"]) > 2500]
mx = max(len(i["code"]) for k, i in items.items() if k in sc)
res = {"tag": tag, "note": "POST-HOC robustness; pre-registered verdict unchanged", "scoring_truncation": "none (full code passed to the prompt)",
       "max_variant_chars_scored": mx, "n_bases_a": len(a), "n_bases_b": len(bb),
       "a_bases_le_2500_no_variant_over_4000": stats(a), "b_bases_gt_2500_pads_exceed_4000": stats(bb)}
json.dump(res, open(f"results/reason_H_{tag}_robust.json", "w"), indent=1)
print(tag, "n_a", len(a), "n_b", len(bb), "max variant chars", mx)
for name in ("a_bases_le_2500_no_variant_over_4000", "b_bases_gt_2500_pads_exceed_4000"):
    print(" ", name)
    for tr, v in res[name].items():
        print("    %-17s n=%-3d dchars=%-7s slope=%-8s mean|dp|=%-7s flip=%s" % (tr, v["n"], v["mean_dchars"], v["slope_per_1000_chars"], v["mean_abs_dp"], v["flip_rate"]))
