#!/usr/bin/env python3
"""Build k-fold witness-generation SFT item files from data/witness_train.jsonl (role == positive only).
items_fold{k}.json trains on positives whose program is NOT in fold k; the adapter trained on it is evaluated only on
fold-k programs (cross-fitting: every CASTLE program is scored by a model that never saw it).
Item schema matches scripts/imp_train.py --items-file (system/user/target + code_chars/toks/project/label for its
balance printout). Usage: imp_witness_items.py [--k 2] [--out-dir results/witness]"""
from __future__ import annotations
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from imp_witness_common import SYSTEM_W, fold_of, user_prompt, witness_json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="data/witness_train.jsonl")
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--out-dir", default="results/witness")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.src) if l.strip()]
    pos = [r for r in rows if r.get("role") == "positive"]
    os.makedirs(a.out_dir, exist_ok=True)
    man = {"src": a.src, "k": a.k, "n_programs": len(rows), "n_positive": len(pos), "folds": []}
    for k in range(a.k):
        items = [{"id": r["id"], "label": "VULNERABLE", "code": r["code"], "code_chars": len(r["code"]),
                  "toks": len(r["code"]) // 3, "project": "castle", "system": SYSTEM_W,
                  "user": user_prompt(r["code"], r["cwe"], r["oracle"]), "target": witness_json(r["witness"])}
                 for r in pos if fold_of(r["id"], a.k) != k]
        path = os.path.join(a.out_dir, f"items_fold{k}.json")
        json.dump({"items": items, "fold": k, "k": a.k, "note": "train items = positives NOT in fold k"}, open(path, "w"))
        man["folds"].append({"fold": k, "train_items": len(items), "items_file": path,
                             "eval_programs": sum(1 for r in rows if fold_of(r["id"], a.k) == k),
                             "eval_positives_held_out": sum(1 for r in pos if fold_of(r["id"], a.k) == k)})
    json.dump(man, open(os.path.join(a.out_dir, "items_manifest.json"), "w"), indent=2)
    print(json.dumps(man, indent=2))
    if any(f["train_items"] < 5 for f in man["folds"]):
        sys.exit("too few training items in a fold")


if __name__ == "__main__":
    main()
