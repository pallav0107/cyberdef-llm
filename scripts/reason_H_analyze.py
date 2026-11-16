"""Stage H analysis: where does a scorer sit on the LENGTH axis and the SEMANTIC axis? (pre-registered in EXPERIMENT_PLAN_REASONING.md)
  reason_H_analyze.py <tag>             -> results/reason_H_<tag>_analysis.json from results/reason_H_items.json + results/reason_H_<tag>_scores.json
  reason_H_analyze.py --stubs [--broken] -> separates three stub scorers on a synthetic probe set (fail-first controls)
"""
import hashlib, json, math, random, sys

BROKEN = "--broken" in sys.argv


def boot_ci(xs_by_group, stat, n=1000, seed=0):
    rng = random.Random(seed); keys = list(xs_by_group); vals = []
    for _ in range(n):
        samp = [xs_by_group[rng.choice(keys)] for _ in keys]
        vals.append(stat([x for g in samp for x in g]))
    vals.sort()
    return [vals[int(0.025 * n)], vals[int(0.975 * n) - 1]]


def analyze(items, p):
    """items: list of dict(key, group, base, transform, label, code, chars, tokens); p: dict key -> p_vuln"""
    by = {}
    for it in items:
        by.setdefault((it["group"], it["base"]), {})[it["transform"]] = it
    # ---- length axis
    pts_by_base, per_tr = {}, {}
    for (g, base), d in by.items():
        if g != "len" or "orig" not in d:
            continue
        o = d["orig"]
        for tr, it in d.items():
            if tr == "orig":
                continue
            dc, dt = it["chars"] - o["chars"], it["tokens"] - o["tokens"]
            dp = 0.0 if BROKEN else p[it["key"]] - p[o["key"]]
            flip = int((p[it["key"]] >= .5) != (p[o["key"]] >= .5)) if not BROKEN else 0
            pts_by_base.setdefault(base, []).append((dc, dt, dp, flip, tr))
            per_tr.setdefault(tr, []).append((dc, dp, flip))
    slope = lambda pts: 1000 * sum(a[0] * a[2] for a in pts) / max(1e-9, sum(a[0] ** 2 for a in pts))
    slope_t = lambda pts: 1000 * sum(a[1] * a[2] for a in pts) / max(1e-9, sum(a[1] ** 2 for a in pts))
    allp = [a for v in pts_by_base.values() for a in v]
    la = {"n_base": len(pts_by_base), "n_points": len(allp), "slope_per_1000_chars": round(slope(allp), 4),
          "slope_ci95": [round(x, 4) for x in boot_ci(pts_by_base, slope)],
          "slope_per_1000_tokens": round(slope_t(allp), 4),
          "flip_rate": round(sum(a[3] for a in allp) / max(1, len(allp)), 4),
          "per_transform": {tr: {"n": len(v), "mean_dchars": round(sum(x[0] for x in v) / len(v), 1),
                                 "slope_per_1000_chars": round(1000 * sum(x[0] * x[1] for x in v) / max(1e-9, sum(x[0] ** 2 for x in v)), 4),
                                 "flip_rate": round(sum(x[2] for x in v) / len(v), 4)} for tr, v in per_tr.items()}}
    # ---- semantic axis
    pairs = []
    for (g, base), d in by.items():
        if g == "sem" and "vuln" in d and "fixed" in d:
            pv, pf = p[d["vuln"]["key"]], p[d["fixed"]["key"]]
            if BROKEN:
                pv = pf
            pairs.append((pv - pf, 1.0 if pv > pf else .5 if pv == pf else 0.0, int(pv >= .5 and pf < .5),
                          1.0 if d["vuln"]["chars"] > d["fixed"]["chars"] else .5 if d["vuln"]["chars"] == d["fixed"]["chars"] else 0.0))
    n = len(pairs)
    md = sum(x[0] for x in pairs) / n; acc = sum(x[1] for x in pairs) / n
    grp = {i: [x] for i, x in enumerate(pairs)}
    sa = {"n_pairs": n, "mean_delta": round(md, 4),
          "mean_delta_ci95": [round(x, 4) for x in boot_ci(grp, lambda xs: sum(a[0] for a in xs) / len(xs))],
          "pairwise_acc": round(acc, 4), "pairwise_se": round(math.sqrt(0.25 / n), 4),
          "pc_rate": round(sum(x[2] for x in pairs) / n, 4),
          "length_only_pairwise_acc_on_same_pairs": round(sum(x[3] for x in pairs) / n, 4)}
    sem = sa["mean_delta_ci95"][0] > 0 and acc > 0.5 + 2 * sa["pairwise_se"]
    lo, hi = la["slope_ci95"]
    len_sens = (lo > 0 or hi < 0) and abs(la["slope_per_1000_chars"]) > 0.03
    len_insens = lo >= -0.03 and hi <= 0.03 and la["flip_rate"] <= 0.05
    label = ("semantic-only" if sem and not len_sens else "both" if sem else "length-reader" if len_sens else "neither")
    return {"length_axis": la, "semantic_axis": sa, "length_sensitive": bool(len_sens), "length_insensitive_strict": bool(len_insens),
            "semantically_sensitive": bool(sem), "thinks_beyond_length": bool(sem and len_insens), "label": label}


def stub_items():
    rng = random.Random(1); items = []
    for i in range(40):
        L = rng.randint(600, 2200); code = "a" * L; lab = "VULNERABLE" if i % 2 else "SAFE"
        items.append(dict(key=f"len:{i}:orig", group="len", base=str(i), transform="orig", label=lab, code=code))
        for tr, f in (("pad500", L + 500), ("pad1500", L + 1500), ("ws1500", L + 1500), ("compress", int(L * .7)),
                      ("rename_long", int(L * 1.1)), ("rename_short", int(L * .9))):
            items.append(dict(key=f"len:{i}:{tr}", group="len", base=str(i), transform=tr, label=lab, code="a" * f))
    for i in range(80):
        L = rng.randint(800, 2500); Lf = int(L * (1.02 if i % 2 else 0.98))
        items.append(dict(key=f"sem:{i}:v", group="sem", base=str(i), transform="vuln", label="VULNERABLE", code="a" * L))
        items.append(dict(key=f"sem:{i}:f", group="sem", base=str(i), transform="fixed", label="SAFE", code="a" * Lf))
    for it in items:
        it["chars"] = len(it["code"]); it["tokens"] = it["chars"] / 3.5
    return items


def main():
    if "--stubs" in sys.argv:
        items = stub_items()
        def rnd(it): return int(hashlib.md5(it["key"].encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
        stubs = {"length_stub": lambda it: 1 / (1 + math.exp(-(it["chars"] - 1500) / 500)),
                 "oracle_stub": lambda it: 0.9 if it["label"] == "VULNERABLE" else 0.1,
                 "random_stub": rnd}
        out = {k: analyze(items, {it["key"]: f(it) for it in items}) for k, f in stubs.items()}
        print(json.dumps({k: {"label": v["label"], "slope": v["length_axis"]["slope_per_1000_chars"],
                              "mean_delta": v["semantic_axis"]["mean_delta"]} for k, v in out.items()}))
        return
    tag = sys.argv[1]
    d = json.load(open("results/reason_H_items.json")); items = d["items"]
    sc = json.load(open(f"results/reason_H_{tag}_scores.json"))
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
    for it in items:
        it["chars"] = len(it["code"]); it["tokens"] = len(tok(it["code"], add_special_tokens=False)["input_ids"])
    items = [it for it in items if it["key"] in sc]
    res = analyze(items, sc)
    res.update(tag=tag, skipped_variants=d.get("skipped"), n_items_scored=len(items))
    json.dump(res, open(f"results/reason_H_{tag}_analysis.json", "w"), indent=1)
    print(json.dumps(res))


if __name__ == "__main__":
    main()
