"""Amendment 2 cap for pool J3: keep at most 500 verified pairs, drawn with random.Random(0), stratified by
(CWE, flow variant), proportional allocation by largest remainder. The full verified set is kept alongside."""
import json, random, shutil

CAP = 500
SRC = "results/imp_train_juliet3_items.json"
ALL = "results/imp_train_juliet3_items_all.json"
d = json.load(open(SRC))
shutil.copy(SRC, ALL)
items = d["items"]
pairs = {}
for it in items:
    pairs.setdefault(it["pair"], []).append(it)
pairs = {k: v for k, v in pairs.items() if len(v) == 2}          # a verified pair = one VULNERABLE + one SAFE text
strata = {}
for k, v in sorted(pairs.items()):
    strata.setdefault((v[0]["juliet_cwe"], v[0]["flow"]), []).append(k)
rng = random.Random(0)
for s in strata.values():
    rng.shuffle(s)
total = sum(len(s) for s in strata.values())
if total <= CAP:
    keep = [k for s in strata.values() for k in s]
else:
    quota = {s: CAP * len(v) / total for s, v in strata.items()}
    take = {s: int(q) for s, q in quota.items()}
    for s in sorted(quota, key=lambda s: -(quota[s] - take[s])):
        if sum(take.values()) >= CAP:
            break
        take[s] += 1
    keep = [k for s, v in strata.items() for k in v[:take[s]]]
keep = set(keep)
kept = [it for it in items if it["pair"] in keep]
d["items"] = kept
d["stats"]["cap"] = {"rule": "amendment 2: <= 500 verified pairs, random.Random(0), stratified by (CWE, flow variant), largest remainder",
                     "verified_pairs": total, "kept_pairs": len(keep), "strata": len(strata),
                     "by_cwe": {c: sum(1 for k in keep if pairs[k][0]["juliet_cwe"] == c) for c in sorted({v[0]["juliet_cwe"] for v in pairs.values()})}}
json.dump(d, open(SRC, "w"))
print(json.dumps(d["stats"]["cap"]))
