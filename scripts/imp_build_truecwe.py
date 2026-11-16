"""True CWE ids for the trace-bank K/O tags: results/imp_true_cwe.json {function id: [int CWE ids]} for VULNERABLE functions of the imp_train_* pools
(VulSpot cwe_list; Juliet from the testcase CWE, with 23 and 36 folded into their parent 22). Safe functions get no entry (K and O are None for them).
  .venv/bin/python scripts/imp_build_truecwe.py"""
import json
import pandas as pd

df = pd.read_parquet("data/vulspot/cpp/full/data.parquet", columns=["idx", "cwe_list"]).set_index("idx")
out = {}
FOLD = {23: 22, 36: 22}
for f in ("imp_train_pairs_items.json", "imp_train_clean_lm_items.json", "imp_train_unfilt_lm_items.json", "imp_train_juliet_items.json", "imp_train_juliet2_items.json", "imp_train_juliet3_items.json", "imp_train_sqli_items.json"):
    try:
        items = json.load(open("results/" + f))["items"]
    except FileNotFoundError:
        continue
    for it in items:
        if it["label"] != "VULNERABLE" or it["id"] in out:
            continue
        if it["id"].startswith("sqli:"):
            out[it["id"]] = [89]
        elif it["id"].startswith("juliet"):
            c = int(it["cwe"].replace("CWE", ""))
            out[it["id"]] = [FOLD.get(c, c)]
        else:
            l = df.loc[int(it["id"][2:])].cwe_list
            ids = sorted({int(str(x).split("-")[1]) for x in (l if l is not None else []) if str(x).startswith("CWE-") and str(x).split("-")[1].isdigit()})
            if ids:
                out[it["id"]] = ids
json.dump(out, open("results/imp_true_cwe.json", "w"))
print(len(out), "vulnerable functions with a true CWE")
