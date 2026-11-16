"""#3 context-augmented VulSpot matched cases. Same functions, a comment block of VulSpot context NAMES appended after the
function (callees, types_used, macros_used, globals_used; each capped at 40 names; total input capped at 6000 chars by trimming context).
  python scripts/imp_build_ctx.py vs_holdout_matched   -> results/imp_ctx_vs_holdout_matched_in.json  (then run imp_rematch.py)"""
import json, sys
sys.path.insert(0, "src")
import pandas as pd

name = sys.argv[1]
cases = json.load(open(f"results/{name}_cases.json"))
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=["idx", "callees", "types_used", "macros_used", "globals_used"]).set_index("idx")
CAP, TOTAL = 40, 6000


def names(v):
    if v is None:
        return []
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except Exception:
            return []
    out = []
    for x in list(v):
        x = str(x)
        if x and x not in out:
            out.append(x)
    return out[:CAP]


def block(r, room):
    parts = []
    for key, lab in (("callees", "callees"), ("types_used", "types"), ("macros_used", "macros"), ("globals_used", "globals")):
        n = names(r[key])
        if n:
            parts.append(f" * {lab}: " + ", ".join(n))
    txt = "\n\n/* ---- surrounding context (names only) ----\n" + "\n".join(parts) + "\n */"
    if len(txt) > room:
        txt = txt[:max(0, room - 4)] + "\n */" if room > 60 else ""
    return txt


out, n_empty = [], 0
for c in cases["cases"]:
    idx = int(c["id"][2:])
    r = df.loc[idx]
    b = block(r, TOTAL - len(c["code"]))
    n_empty += (b == "")
    out.append(dict(c, code=c["code"] + b, ctx_chars=len(b)))
json.dump({"cases": out, "pool": cases.get("pool"), "split": cases.get("split"), "seed": cases.get("seed"),
           "note": "context-augmented (names only) copy of %s" % name}, open(f"results/imp_ctx_{name}_in.json", "w"))
print(name, "cases", len(out), "without any context", n_empty, "mean ctx chars", sum(c["ctx_chars"] for c in out) / len(out))
