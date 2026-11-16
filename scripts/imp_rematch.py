"""Re-measure and re-match a cases file after its inputs changed length (context augmentation #3, slices #4).
  python scripts/imp_rematch.py IN_cases.json OUT_PREFIX
Writes results/OUT_PREFIX_control.json (length-only AUROC on the ORIGINAL pairing, recomputed on the new code, and on the
re-matched pairing) and results/OUT_PREFIX_rematched_cases.json (new pairs matched on TOTAL chars+tokens, caliper 3%).
Never drops cases silently: unmatched vulnerable cases are counted in the control file."""
import json, random, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from transformers import AutoTokenizer
from cyberdef import lenmatch
from build_lenmatch_eval import len_aurocs

inp, pref = sys.argv[1], sys.argv[2]
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
d = json.load(open(inp))
cases = d["cases"]
for c in cases:
    c["code_chars"] = len(c["code"])
    c["toks"] = max(1, len(tok(c["code"], add_special_tokens=False)["input_ids"]))
    c["lines"] = c["code"].count("\n") + 1
orig = len_aurocs(cases)
json.dump({"cases": cases, "pool": d.get("pool"), "split": d.get("split"), "seed": d.get("seed"), "note": "same pairing as source; length fields recomputed on the model input"},
          open(f"results/{pref}_cases.json", "w"))
rows = [dict(c, chars=c["code_chars"]) for c in cases]
vul = [r for r in rows if r["label"] == "VULNERABLE"]
saf = [r for r in rows if r["label"] != "VULNERABLE"]
random.Random(0).shuffle(vul)
pairs, dropped = lenmatch.match_pairs(vul, saf, tok, 0.03, 0)
new = []
for i, (v, s) in enumerate(pairs):
    for r in (v, s):
        r = {k: x for k, x in r.items() if k != "chars"}
        r["pair"] = i
        new.append(r)
random.Random(0).shuffle(new)
ctl = len_aurocs(new)
ok = all(0.45 <= x["auroc"] <= 0.55 for x in ctl.values())
json.dump({"source": inp, "n_cases_in": len(cases), "orig_pairing_length_only": orig, "rematched_pairs": len(pairs), "rematched_cases": len(new),
           "vulnerable_unmatched_dropped_from_rematched_set": len(dropped), "rematched_length_only": ctl, "rematched_control_pass": ok},
          open(f"results/{pref}_control.json", "w"), indent=1)
json.dump({"cases": new, "pool": {"n_pairs": len(pairs)}, "split": d.get("split"), "seed": 0}, open(f"results/{pref}_rematched_cases.json", "w"))
print(pref, "orig length-only:", json.dumps({k: v["auroc"] for k, v in orig.items()}), "| rematched pairs", len(pairs), "of", len(vul),
      "length-only:", json.dumps({k: v["auroc"] for k, v in ctl.items()}), "PASS" if ok else "CONTROL-FAIL")
