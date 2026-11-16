"""Addendum 3i: re-clean every Juliet-derived item file with the fixed cleaner (camelCase bad/good identifiers such as badStatic,
dataBadBuffer, helperBad survived the earlier cleaning). Collision-safe: new names start after the highest existing fn_N.
Execution checks are unaffected (they use the original Juliet files by name). Backups: results/before_3i/."""
import importlib.util, json
spec = importlib.util.spec_from_file_location("ic", "src/cyberdef/imp_clean.py"); ic = importlib.util.module_from_spec(spec); spec.loader.exec_module(ic)
for f in ("imp_train_juliet_items.json", "imp_train_juliet2_items.json", "imp_train_juliet3_items.json", "imp_train_juliet3_items_all.json", "j4b_heldout_all.json"):
    p = "results/" + f; d = json.load(open(p)); ch = 0
    for it in d["items"]:
        new = ic.clean_code(it["code"])
        ch += new != it["code"]
        it["code"] = new[:4000]; it["code_chars"] = len(new); it["toks"] = max(1, len(new) // 3); it["code_clean_3i"] = True
    json.dump(d, open(p, "w"))
    left = sum(1 for it in d["items"] if ic.leak_hits(it["code"]))
    print(f, "items", len(d["items"]), "changed", ch, "still leaking", left)
