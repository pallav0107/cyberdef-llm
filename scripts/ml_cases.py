"""Build balanced case files for the multi-language test sets (same format as xdata_*_cases.json,
so selective_eval.py --cases-file scores exactly these cases). cap_to_pool balanced, seed 0.
Usage: ml_cases.py DATASET SPLIT N_PER_CLASS MAX_CHARS OUT.json"""
import json
import sys
from pathlib import Path
sys.path.insert(0, "src")
from cyberdef import benchdata

ds, split, n, mc, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
cases, pool = benchdata.balanced_sample(ds, split, n, 0, mc, cap_to_pool=True)
res = {"dataset": ds, "split": split, "seed": 0, "n_per_class_requested": n,
       "n_per_class_used": len(cases) // 2, "max_chars": mc, "pool": pool, "cases": cases}
Path(out).write_text(json.dumps(res, indent=2))
print(f"[ml_cases] {ds}/{split}: n_per_class_used={len(cases) // 2} pool={pool} -> {out}")
