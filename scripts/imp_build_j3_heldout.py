"""Amendment 2b: results/j3_heldout_cases.json = every verified J3 pair NOT drawn into training, both texts per pair.
Refuses to write if any held-out function appears in any training pool file."""
import glob, hashlib, json, os

ALL = json.load(open("results/imp_train_juliet3_items_all.json"))["items"]
TRAIN = json.load(open("results/imp_train_juliet3_items.json"))["items"]
train_pairs = {it["pair"] for it in TRAIN}
held = [it for it in ALL if it["pair"] not in train_pairs]
pairs = {}
for it in held:
    pairs.setdefault(it["pair"], []).append(it)
held = [it for p in pairs.values() if len(p) == 2 for it in p]
# addendum 3b: a pair whose Juliet source file supplies a few-shot exemplar (results/imp_fewshot_exemplars*.json) is excluded
EXEMPLAR_FILES = {e["source_file"] for f in glob.glob("results/imp_fewshot_exemplars*.json") for e in json.load(open(f))["exemplars"]}
dropped = sorted({it["id"].split(":")[1] for it in held if it["id"].split(":")[1] in EXEMPLAR_FILES})
held = [it for it in held if it["id"].split(":")[1] not in EXEMPLAR_FILES]

norm = lambda s: " ".join(s.split())
h = lambda s: hashlib.sha256(norm(s).encode()).hexdigest()
train_hashes = set()
for f in glob.glob("results/imp_train_*_items.json"):
    if f.endswith("juliet3_items_all.json"):
        continue
    for it in json.load(open(f)).get("items", []):
        if "code" in it:
            train_hashes.add(h(it["code"]))
leak = [it["id"] for it in held if h(it["code"]) in train_hashes]
if leak:
    raise SystemExit(f"REFUSED: {len(leak)} held-out functions also appear in a training pool, e.g. {leak[:3]}")

def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))

cases = [{"id": it["id"].replace("juliet3:", "j3h:"), "code": it["code"], "code_chars": it["code_chars"], "toks": it["toks"],
          "label": it["label"], "cwe": it["juliet_cwe"], "flow": it.get("flow"), "pair": it["pair"]} for it in held]
y = [c["label"] == "VULNERABLE" for c in cases]
lo = auroc([c["code_chars"] for c in cases], y)
by = {}
for c in cases:
    by.setdefault(c["cwe"], [0, 0])[c["label"] == "VULNERABLE"] += 1
out = {"cases": cases, "split": "test", "seed": 0,
       "pool": {"rule": "amendment 2b: verified J3 pairs not drawn into the 500 training pairs; both texts of each pair; addendum 3b: minus pairs whose source file supplies a few-shot exemplar",
                "pairs": len(cases) // 2, "functions": len(cases), "by_cwe": {k: {"safe": v[0], "vulnerable": v[1]} for k, v in by.items()},
                "length_only_auroc_chars": round(lo, 4), "checked_against_training_pools": True,
                "excluded_exemplar_source_files": dropped}}
json.dump(out, open("results/j3_heldout_cases.json", "w"))
print(json.dumps(out["pool"]))
