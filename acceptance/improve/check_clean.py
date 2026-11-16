"""Acceptance: no label leak in the Juliet / synthetic-SQLi pools (written BEFORE the cleaning; it must FAIL on the original pools). Run from the repo root.
 1 no item of imp_train_juliet_items / juliet2 / sqli has any comment, CWE id, FLAW/POTENTIAL marker, Bad/Good source/sink marker, or an identifier containing bad/good (leak_hits == [])
 2 the VULNERABLE and SAFE texts of a pair still differ after cleaning (cleaning must not erase the flaw)
 3 unit controls on clean_code: a string literal containing // is kept, a comment inside is not; identifiers CWE121_x_01_bad -> fn_N consistently
 4 each cleaned item carries code_orig_sha and code_clean"""
import json, os, sys
sys.path.insert(0, "src")
from cyberdef.imp_clean import clean_code, leak_hits

fails = []
t = 'int CWE121_X_01_bad(char *a){ /* FLAW: x */ char *s = "http://a // b"; // trailing\n  return CWE121_X_01_bad(a); }'
c = clean_code(t)
if "FLAW" in c or "trailing" in c or "CWE121" in c or "http://a // b" not in c or c.count("fn_0") != 2:
    fails.append("unit control failed: " + repr(c))
for f in ("imp_train_juliet_items.json", "imp_train_juliet2_items.json", "imp_train_sqli_items.json"):
    p = "results/" + f
    if not os.path.exists(p):
        continue
    d = json.load(open(p))["items"]
    bad = [i["id"] for i in d if leak_hits(i["code"])]
    if bad:
        fails.append(f"{f}: {len(bad)} items still leak (e.g. {bad[0]})")
    if not all(i.get("code_clean") and i.get("code_orig_sha") for i in d):
        fails.append(f"{f}: items without code_clean / code_orig_sha")
    by = {}
    for i in d:
        by.setdefault(i["pair"], {})[i["label"]] = i["code"]
    same = [k for k, v in by.items() if len(v) == 2 and v["VULNERABLE"] == v["SAFE"]]
    if same:
        fails.append(f"{f}: {len(same)} pairs identical after cleaning (e.g. {same[0]})")
if fails:
    print("FAIL:"); [print(" -", x) for x in fails]; sys.exit(1)
print("PASS: pools are label-leak free")
