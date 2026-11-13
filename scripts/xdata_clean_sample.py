"""Build a balanced, PrimeVul-TRAIN-deduplicated test sample from an independent transfer dataset
(plan step E). Every function whose normalised code (b.norm(code[:4000])) appears anywhere in
PrimeVul TRAIN is removed BEFORE sampling, so the sample cannot contain anything the adapter
could have trained on. Exact duplicates inside the pool are collapsed (a normalised text that
carries both labels is dropped entirely: its label is contradictory). Sampling mirrors
benchdata.balanced_sample: shuffle each class with random.Random(seed), take n per class, then
shuffle the union. If a class has fewer than n clean items, the largest balanced size is used.

Default splits (documented): reveal -> test; d2a -> validation (= official `dev`, because the
official test split is unlabelled); castle -> test (the only split; 250 programs).

Usage: python scripts/xdata_clean_sample.py --dataset reveal --n-per-class 200 --seed 0 --dump OUT.json
"""
import argparse, json, random
from cyberdef import benchdata as b

DEFAULT_SPLIT = {"reveal": "test", "d2a": "validation", "castle": "test"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, choices=sorted(DEFAULT_SPLIT))
    ap.add_argument("--n-per-class", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--split", default=None)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--dump", required=True)
    a = ap.parse_args()
    split = a.split or DEFAULT_SPLIT[a.dataset]
    sp, sp_pv = b.spec(a.dataset), b.spec("primevul")
    pv_train = {b.norm(b._row_code(r, sp_pv)[:4000]) for r in b._load_split(sp_pv, "train")}

    rows = list(b._load_split(sp, split))
    by_key = {}
    for r in rows:
        by_key.setdefault(b.norm(b._row_code(r, sp)[:a.max_chars]), []).append(r)
    vuln, safe = [], []
    removed_pv = removed_within = conflicting = 0
    for key, grp in by_key.items():
        labs = {b._is_vuln(r[sp["label"]]) for r in grp}
        if key in pv_train:
            removed_pv += len(grp)
            continue
        if len(labs) > 1:
            conflicting += len(grp)
            continue
        removed_within += len(grp) - 1
        (vuln if labs.pop() else safe).append(grp[0])
    pool = dict(rows_in_split=len(rows),
                raw_vuln=sum(b._is_vuln(r[sp["label"]]) for r in rows),
                raw_safe=sum(not b._is_vuln(r[sp["label"]]) for r in rows),
                clean_vuln=len(vuln), clean_safe=len(safe),
                removed_within_pool_dups=removed_within,
                removed_conflicting_label_dups=conflicting)
    rng = random.Random(a.seed)
    # Deterministic pre-order (dict order is insertion order = file order) then seeded shuffle.
    rng.shuffle(vuln); rng.shuffle(safe)
    n = min(a.n_per_class, len(vuln), len(safe))
    sel = vuln[:n] + safe[:n]
    rng.shuffle(sel)
    cases = [b._mk(r, sp, a.max_chars) for r in sel]
    out = dict(dataset=a.dataset, split=split, seed=a.seed, n_per_class_requested=a.n_per_class,
               n_per_class_used=n, removed_primevul_dups=removed_pv, pool=pool, cases=cases)
    json.dump(out, open(a.dump, "w"), indent=1)
    print(f"[xdata] {a.dataset}/{split}: pool {pool}; PrimeVul-train dups removed={removed_pv}; "
          f"n/class used={n} (requested {a.n_per_class}) -> {a.dump}")


if __name__ == "__main__":
    main()
