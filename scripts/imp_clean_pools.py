"""Rewrite pools J, J2 (and Q when present) with label-leak-free code (src/cyberdef/imp_clean.py): comments removed, CWE/bad/good identifiers renamed.
Keeps the original text hash (code_orig_sha) for audit; the original text itself is NOT kept in the items. Idempotent.  python3 scripts/imp_clean_pools.py"""
import hashlib, json, os, re, sys
sys.path.insert(0, "src")
from cyberdef.imp_clean import clean_code, leak_hits

for f in ("imp_train_juliet_items.json", "imp_train_juliet2_items.json",   # SQLi: scripts/imp_hygiene_3g_sqli.py (cleans + re-verifies)
          # addendum 3g: J3 (training + the source of its held-out sets) and J4b were built after this script and never cleaned
          "imp_train_juliet3_items.json", "imp_train_juliet3_items_all.json", "j4b_heldout_all.json"):
    p = "results/" + f
    if not os.path.exists(p):
        continue
    d = json.load(open(p))
    n_changed = 0
    for it in d["items"]:
        if it.get("code_clean"):
            continue
        it["code_orig_sha"] = hashlib.sha1(it["code"].encode()).hexdigest()[:12]
        new = clean_code(it["code"])
        # builder artifact of the J/J2 pools: the INCLUDEMAIN-removal regex stopped at the first #endif and left the tail of main() behind
        if "sqli" not in f:   # addendum 3g: a Juliet-only artifact; on the SQLi programs this regex cut the real end of main()
            new = re.sub(r"\n[ \t]*return 0;[ \t]*\n\}[ \t]*(?:\n[ \t]*#endif[ \t]*)*\s*$", "", new).rstrip()
        n_changed += new != it["code"]
        it["code"] = new[:4000]; it["code_chars"] = len(new); it["toks"] = max(1, len(new) // 3); it["code_clean"] = True
    d.setdefault("stats", {})["label_leak_cleaned"] = True
    json.dump(d, open(p, "w"))
    left = sum(1 for it in d["items"] if leak_hits(it["code"]))
    print(f, "items", len(d["items"]), "changed", n_changed, "still leaking", left)
