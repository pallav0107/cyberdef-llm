"""Stage H scoring (Spark container): logprob p_vuln for every probe item, exactly as selective_eval.py (no truncation).
Usage: reason_H_score.py <tag> <base_model> [adapter]  -> results/reason_H_<tag>_scores.json {key: p_vuln}"""
import json, math, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef.evaluate import SYSTEM, make_user
from cyberdef.train import _ids
from cyberdef import model_io
from selective_eval import mean_logp, CAND

tag, base = sys.argv[1], sys.argv[2]
adapter = sys.argv[3] if len(sys.argv) > 3 else None
items = json.load(open("results/reason_H_items.json"))["items"]
model, tok = model_io.load_hf(base, adapter=adapter)
model.eval()
out = {}
for i, it in enumerate(items):
    ids = _ids(model_io.chat_prompt(tok, SYSTEM, make_user(it["code"]), tensors=False))
    sv = mean_logp(model, tok, ids, CAND["VULNERABLE"]); ss = mean_logp(model, tok, ids, CAND["SAFE"])
    out[it["key"]] = 1.0 / (1.0 + math.exp(ss - sv))
    if i % 100 == 0:
        print(f"[H {tag}] {i}/{len(items)}", flush=True)
json.dump(out, open(f"results/reason_H_{tag}_scores.json", "w"))
print("[H] done", tag, len(out))
