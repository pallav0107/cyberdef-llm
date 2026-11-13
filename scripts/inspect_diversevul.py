import os, collections
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
from datasets import load_dataset

ds = load_dataset("bstee615/diversevul")
print("SPLITS", list(ds.keys()))
sp = list(ds.keys())[0]
d = ds[sp]
print("N", len(d), "COLS", d.column_names)
r = d[0]
for k, v in r.items():
    s = str(v)
    print("  ", k, "=", (s[:80] + "...") if len(s) > 80 else s)
c = collections.Counter(d[i]["target"] for i in range(min(5000, len(d))))
print("target balance (first 5000):", dict(c))
# code column length sanity
funcs = [d[i].get("func", "") for i in range(min(200, len(d)))]
print("sample func len mean", sum(len(x) for x in funcs) // max(1, len(funcs)))
