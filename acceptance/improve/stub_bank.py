"""Builds a STUB bank in $IMP_RESULTS (never results/) to test the item builder + its check. Every function gets valid-looking fake traces (engine='STUB')."""
import json, os, shutil, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
D = os.environ["IMP_RESULTS"]; os.makedirs(D, exist_ok=True)
rows = []
pools = {}
for k, f in (("A", "imp_train_pairs_items.json"), ("B", "imp_train_clean_lm_items.json"), ("C", "imp_train_unfilt_lm_items.json")):
    shutil.copy("results/" + f, D + "/" + f)
    for it in json.load(open("results/" + f))["items"]:
        pools.setdefault(it["id"], it)
shutil.copy("results/imp_train_juliet_items.json", D + "/imp_train_juliet_items.json") if os.path.exists("results/imp_train_juliet_items.json") else json.dump({"items": []}, open(D + "/imp_train_juliet_items.json", "w"))
for it in list(pools.values())[:400]:
    d = dict(S.GOOD); d["verdict"] = it["label"]
    for g in ("g1", "g2"):
        rows.append(dict(rec="trace", fn=it["id"], pools=["A"], label=it["label"], gen=g, model="STUB", adapter=None, sample=0, edit="orig", raw=json.dumps(d), ntok=10,
                         finish="stop", engine="STUB", parsed=True, V=True, P=True, S=None, X=None, verdict_raw=it["label"], verdict_final=it["label"], errors=[]))
    rows.append(dict(rows[-1], edit="pad", edited_code="/* pad */\n" + it["code"], gen="g1"))
with open(D + "/imp_trace_bank.jsonl", "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
print("stub rows", len(rows))
