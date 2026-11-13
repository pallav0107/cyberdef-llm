"""Cross-dataset leakage audit for the PrimeVul -> DiverseVul transfer claim.

PrimeVul was assembled partly from earlier datasets, so some DiverseVul functions also occur in
PrimeVul's TRAIN split. This regenerates each DiverseVul test sample exactly as selective_eval drew
it (same seed, same order), matches every case to its recorded per_case score, and re-scores the
base and tuned AUROC after removing (a) cases the adapter actually trained on and (b) every case
present anywhere in PrimeVul TRAIN (normalised exact match, 4000-char truncation as in training).
Writes results/xdataset_overlap.json.

Usage: python scripts/xdataset_overlap.py [--train-n 500] [--seeds 0 1 2 3]
"""
import argparse, json, random
from cyberdef import benchdata as b


def auroc(scores, pos):
    P = [s for s, y in zip(scores, pos) if y]
    N = [s for s, y in zip(scores, pos) if not y]
    if not P or not N:
        return None
    return sum((p > n) + 0.5 * (p == n) for p in P for n in N) / (len(P) * len(N))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-n", type=int, default=500)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3])
    ap.add_argument("--base-fmt", default="results/xdataset_diversevul_base{suf}.json")
    ap.add_argument("--tuned-fmt", default="results/xdataset_diversevul_tuned{suf}.json")
    ap.add_argument("--out", default="results/xdataset_overlap.json")
    a = ap.parse_args()
    sp_dv, sp_pv = b.spec("diversevul"), b.spec("primevul")
    items, _ = b.train_items("primevul", a.train_n, 0, 4000)
    used = {b.norm(it["code"]) for it in items}
    pv_train = {b.norm(b._row_code(r, sp_pv)[:4000]) for r in b._load_split(sp_pv, "train")}
    dv_rows = list(b._load_split(sp_dv, "test"))
    out = {"train_items_used": len(items), "train_n_per_class": a.train_n, "seeds": []}
    for seed in a.seeds:
        vuln, safe = [], []
        for r in dv_rows:
            (vuln if b._is_vuln(r[sp_dv["label"]]) else safe).append(r)
        rng = random.Random(seed)
        rng.shuffle(vuln); rng.shuffle(safe)
        rows = vuln[:200] + safe[:200]
        rng.shuffle(rows)
        cases = [b._mk(r, sp_dv, 4000) for r in rows]
        suf = "" if seed == 0 else f"_s{seed}"
        B = json.load(open(a.base_fmt.format(suf=suf)))["per_case"]
        T = json.load(open(a.tuned_fmt.format(suf=suf)))["per_case"]
        assert len(B) == len(T) == len(cases), "sample size mismatch"
        assert all(c["label"] == x["label"] for c, x in zip(cases, B)), "case order mismatch"
        k_used = [b.norm(c["code"]) in used for c in cases]
        k_any = [b.norm(c["code"]) in pv_train for c in cases]

        def score(mask):
            idx = [i for i in range(len(cases)) if not mask[i]]
            y = [cases[i]["label"] == "VULNERABLE" for i in idx]
            return {"n": len(idx),
                    "auroc_base": auroc([float(B[i]["p_vuln"]) for i in idx], y),
                    "auroc_tuned": auroc([float(T[i]["p_vuln"]) for i in idx], y)}
        out["seeds"].append({"seed": seed, "n": len(cases),
                             "overlap_trained_on": sum(k_used), "overlap_any_primevul_train": sum(k_any),
                             "all": score([False] * len(cases)), "clean_vs_trained_on": score(k_used),
                             "clean_vs_all_primevul_train": score(k_any)})
    json.dump(out, open(a.out, "w"), indent=1)
    for s in out["seeds"]:
        c = s["clean_vs_all_primevul_train"]
        print(f"seed {s['seed']}: overlap trained-on {s['overlap_trained_on']}, any-train {s['overlap_any_primevul_train']}; "
              f"strict-clean AUROC {c['auroc_base']:.3f} -> {c['auroc_tuned']:.3f} (n={c['n']})")


if __name__ == "__main__":
    main()
