#!/usr/bin/env python3
"""Addendum 3g, SQLi part. Rebuild the SQLi files from their ORIGINAL texts, label-leak-cleaned exactly like the other pools
(cyberdef.imp_clean.clean_code: comments removed, bad/good/CWE identifiers renamed), and RE-VERIFY every cleaned pair by
execution with the SQLi builder's own sandbox check (scripts/imp_build_sqli.py --inside: both halves compile with sqlite3;
the vulnerable half fires the sqli oracle on >= 1 reference payload and not on benign or empty input; the safe half fires on
none). Writes:
  results/imp_train_sqli_train_items.json   the 89-pair TRAINING split, cleaned
  results/imp_train_sqli_items.json         = the training split (pool Q). Until 3g it held all 133 pairs, INCLUDING the 44
                                            pairs reserved as the SQLi held-out test, which the amendment-2 bank would
                                            have trained on.
  results/imp_train_sqli_all_items.json     all 133 pairs, cleaned, each tagged with its split (reference only; no pool reads it)
  results/q_heldout_cases.json              the 44-pair held-out set, cleaned (ids qh:...)
Originals come from the split files, which the 16 Nov 00:5x run of imp_clean_pools.py did not touch. (That run had also
cleaned imp_train_sqli_items.json with the Juliet-only tail regex, which cut the closing "return 0; }" off main() in 256/266
programs; the broken file is kept as results/before_3g/imp_train_sqli_items.broken_by_tail_regex.json.)"""
import hashlib, json, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, "src")
from cyberdef.imp_clean import clean_code, leak_hits

TR, QH = "results/imp_train_sqli_train_items.json", "results/q_heldout_cases.json"
tr = json.load(open(TR)); qh = json.load(open(QH))
assert not any(it.get("code_clean") for it in tr["items"]), "training split already cleaned: refusing to clean twice"
pairs = {}
for it in tr["items"]:
    pairs.setdefault(it["pair"], {"split": "train"})[it["label"]] = it
for c in qh["cases"]:
    p = pairs.setdefault(c["pair"], {"split": "heldout"}); p[c["label"]] = c
    assert p["split"] == "heldout", c["pair"]
assert all("VULNERABLE" in p and "SAFE" in p for p in pairs.values()) and len(pairs) == 133, len(pairs)
clean = {k: {lab: clean_code(p[lab]["code"]) for lab in ("VULNERABLE", "SAFE")} for k, p in pairs.items()}
left = {k: [lab for lab in v if leak_hits(v[lab])] for k, v in clean.items()}
assert not any(left.values()), {k: v for k, v in left.items() if v}

# re-verify the CLEANED pairs by execution, exactly as imp_build_sqli.host() does
work = tempfile.mkdtemp(prefix="impsq3g_"); os.chmod(work, 0o777)
for f in ("imp_shim.c", "imp_behaviour.py", "imp_build_sqli.py"):
    shutil.copy(f"scripts/{f}", f"{work}/{f}")
rows = [{"id": k, "vulnerable": v["VULNERABLE"], "safe": v["SAFE"]} for k, v in sorted(clean.items())]
N = int(os.environ.get("IMP_JOBS", "8"))
for k in range(N):
    json.dump(rows[k::N], open(f"{work}/shard{k}.json", "w"))
subprocess.run(["chmod", "-R", "a+rwX", work])
ps = [subprocess.Popen(["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--user", "1000:1000", "-e", "HOME=/tmp", "-v", f"{work}:/w", "-w", "/w",
                        "--entrypoint", "python3", "imp-castle-san:1", "imp_build_sqli.py", "--inside", f"/w/shard{k}.json"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for k in range(N)]
for p in ps:
    p.wait()
res = {}
for k in range(N):
    if os.path.exists(f"{work}/shard{k}.json.out"):
        for r in json.load(open(f"{work}/shard{k}.json.out")):
            res[r["id"]] = r
shutil.rmtree(work, ignore_errors=True)


def verified(x):
    return bool(x) and not x.get("error") and x["compiled"] and any(x["vuln_fires"]) and not (x["vuln_benign"] or x["vuln_empty"]) \
        and not (any(x["safe_fires"]) or x["safe_benign"] or x["safe_empty"])


bad = sorted(k for k in clean if not verified(res.get(k)))
print(f"re-verified {len(clean) - len(bad)}/{len(clean)} cleaned pairs; failed: {bad[:10]}")
if bad:
    raise SystemExit("cleaned pairs failed re-verification: nothing written (investigate before dropping any pair)")


def upd(it, code):
    it = dict(it); it["code_orig_sha"] = hashlib.sha1(it["code"].encode()).hexdigest()[:12]
    it["code"] = code[:4000]; it["code_chars"] = len(code); it["toks"] = max(1, len(code) // 3); it["code_clean"] = True
    return it


def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


note = "addendum 3g: label-leak cleaned (imp_clean.clean_code, no tail regex) and re-verified by execution"
tr_items = [upd(it, clean[it["pair"]][it["label"]]) for it in tr["items"]]
json.dump(dict(tr, items=tr_items, note=note), open(TR, "w"))
json.dump({"items": tr_items, "stats": {"pairs": len(tr_items) // 2, "split": "train", "note": note + "; pool Q = the TRAINING split only "
           "(the 44 held-out pairs are excluded)"}}, open("results/imp_train_sqli_items.json", "w"))
qh_cases = [upd(c, clean[c["pair"]][c["label"]]) for c in qh["cases"]]
y = [c["label"] == "VULNERABLE" for c in qh_cases]
lo = auroc([c["code_chars"] for c in qh_cases], y)
pool = dict(qh.get("pool") or {}); pool.update(length_only_auroc_chars=round(lo, 4), length_only_best_direction=round(max(lo, 1 - lo), 4), note_3g=note)
json.dump(dict(qh, cases=qh_cases, pool=pool), open(QH, "w"))
allit = [dict(upd(pairs[k][lab], clean[k][lab]), id=f"sqli:{k}:{lab[0]}", split=pairs[k]["split"]) for k in sorted(pairs) for lab in ("VULNERABLE", "SAFE")]
json.dump({"items": allit, "note": note + "; reference only, tagged by split; no pool reads this file"}, open("results/imp_train_sqli_all_items.json", "w"))
print(json.dumps({"train_pairs": len(tr_items) // 2, "heldout_pairs": len(qh_cases) // 2, "heldout_length_only_chars": round(lo, 4)}))
