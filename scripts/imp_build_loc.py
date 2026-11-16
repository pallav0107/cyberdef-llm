"""#9a localization set + line labels for the trace bank (tag S).
  .venv/bin/python scripts/imp_build_loc.py
Writes results/imp_loc_cases.json (project_holdout test_paired_high vulnerable functions with mapped changed code lines; truth = relative 1-based lines of the
code lines changed by the fix, comment-only lines excluded) and results/imp_linelabels.json (same mapping for every VULNERABLE function of the imp_train_* items files).
Unmappable functions are counted in stats, never silently dropped from the denominator report."""
import json, re, sys
sys.path.insert(0, "src")
import pandas as pd

MC = 4000
df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=["idx", "project", "func_body", "func_start_line", "changed_lines", "is_vulnerable"]).set_index("idx")
ph = json.load(open("data/vulspot/cpp/full/splits/project_holdout.json"))
COMMENT = re.compile(r"^\s*(//|/\*|\*|\*/)")


def labelled(row):
    """returns (status, rel_lines) for a vulnerable row; lines are 1-based within func_body, restricted to the first MC chars."""
    body = row.func_body
    if not isinstance(body, str):
        return "no_body", []
    lines = body[:MC].split("\n")
    cl = row.changed_lines
    if isinstance(cl, str):
        try:
            cl = json.loads(cl)
        except Exception:
            cl = None
    if cl is None or len(cl) == 0:
        return "no_changed_lines", []
    out, bad = [], 0
    for item in cl:
        ln, text = int(item[0]), str(item[1]).split("\n")[0]
        t = text.strip()
        if not t or COMMENT.match(text):
            continue
        rel = ln - int(row.func_start_line) + 1
        if 1 <= rel <= len(lines) and lines[rel - 1].strip() == t:
            out.append(rel); continue
        cands = [i + 1 for i, l in enumerate(lines) if l.strip() == t]
        if len(cands) == 1:
            out.append(cands[0])
        else:
            bad += 1
    out = sorted(set(out))
    return ("ok" if out else "unmappable"), out


stats = {}
# ---- #9a cases ----
te = df.loc[ph["test_paired_high"]]
te = te[te.is_vulnerable]
cases, st = [], {"ok": 0, "unmappable": 0, "no_changed_lines": 0, "no_body": 0}
for idx, r in te.iterrows():
    s, rel = labelled(r)
    st[s] += 1
    if s == "ok":
        code = r.func_body[:MC]
        cases.append(dict(id=f"vs{idx}", code=code, code_chars=len(r.func_body), truncated=len(r.func_body) > MC, label="VULNERABLE", project=r.project,
                          lines=code.count("\n") + 1, truth_lines=rel))
json.dump({"cases": cases, "stats": st, "split": "test_paired_high(vulnerable only)", "note": "truth = relative 1-based lines changed by the fix (non-comment)"}, open("results/imp_loc_cases.json", "w"))
stats["loc"] = {"vulnerable_functions": int(len(te)), **st, "cases": len(cases),
                "mean_truth_lines": round(sum(len(c["truth_lines"]) for c in cases) / max(1, len(cases)), 2),
                "mean_function_lines": round(sum(c["lines"] for c in cases) / max(1, len(cases)), 1)}
# ---- line labels for training pools ----
ll, sl = {}, {"ok": 0, "unmappable": 0, "no_changed_lines": 0, "no_body": 0}
for f in ("imp_train_pairs_items.json", "imp_train_clean_lm_items.json", "imp_train_unfilt_lm_items.json"):
    for it in json.load(open("results/" + f))["items"]:
        if it["label"] != "VULNERABLE" or it["id"] in ll:
            continue
        s, rel = labelled(df.loc[int(it["id"][2:])])
        sl[s] += 1
        ll[it["id"]] = {"status": s, "lines": rel}
json.dump(ll, open("results/imp_linelabels.json", "w"))
stats["linelabels"] = {"vulnerable_functions": len(ll), **sl}
json.dump(stats, open("results/imp_loc_stats.json", "w"), indent=1)
print(json.dumps(stats))
