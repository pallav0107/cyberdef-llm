"""Leakage audit of the existing Devign class comparison (scripts/compare_class.sh devign, i.e.
results/cls_devign_{base,ours}.json) against PrimeVul TRAIN. Regenerates the exact sample
selective_eval drew (benchdata.balanced_sample('devign','test',100,0,4000), the defaults used by
compare_class.sh), asserts it matches the recorded per_case order, counts normalised-exact overlap
with PrimeVul TRAIN (4000-char truncation, as in training) and recomputes AUROC for base and ours on
all cases and on the PrimeVul-de-duplicated subset. Writes results/devign_overlap.json (new file).
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cyberdef import benchdata as b
from xdataset_overlap import auroc  # same AUROC helper as the DiverseVul audit


def main():
    cases, pool = b.balanced_sample("devign", "test", 100, 0, 4000)
    B = json.load(open("results/cls_devign_base.json"))["per_case"]
    T = json.load(open("results/cls_devign_ours.json"))["per_case"]
    assert len(B) == len(T) == len(cases), "sample size mismatch"
    assert all(c["label"] == x["label"] == y["label"] and c["id"] == x["id"] == y["id"]
               for c, x, y in zip(cases, B, T)), "case order mismatch"
    sp = b.spec("primevul")
    pv = {b.norm(b._row_code(r, sp)[:4000]) for r in b._load_split(sp, "train")}
    k = [b.norm(c["code"]) in pv for c in cases]

    def score(mask):
        idx = [i for i in range(len(cases)) if not mask[i]]
        y = [cases[i]["label"] == "VULNERABLE" for i in idx]
        return {"n": len(idx), "n_vulnerable": sum(y),
                "auroc_base": round(auroc([float(B[i]["p_vuln"]) for i in idx], y), 4),
                "auroc_ours": round(auroc([float(T[i]["p_vuln"]) for i in idx], y), 4)}
    out = {"source": "results/cls_devign_base.json vs results/cls_devign_ours.json (compare_class.sh devign)",
           "sample": "balanced_sample(devign, test, n_per_class=100, seed=0, max_chars=4000)",
           "adapter_ours": json.load(open("results/cls_devign_ours.json")).get("adapter"),
           "n": len(cases), "pool": pool,
           "overlap_any_primevul_train": sum(k),
           "overlap_by_label": {"VULNERABLE": sum(x and c["label"] == "VULNERABLE" for x, c in zip(k, cases)),
                                "SAFE": sum(x and c["label"] == "SAFE" for x, c in zip(k, cases))},
           "all": score([False] * len(cases)),
           "clean_vs_all_primevul_train": score(k)}
    json.dump(out, open("results/devign_overlap.json", "w"), indent=1)
    c = out["clean_vs_all_primevul_train"]
    print(f"devign: n={out['n']} overlap={out['overlap_any_primevul_train']} {out['overlap_by_label']}; "
          f"all {out['all']['auroc_base']}->{out['all']['auroc_ours']}; "
          f"clean(n={c['n']}) {c['auroc_base']}->{c['auroc_ours']}")


if __name__ == "__main__":
    main()
