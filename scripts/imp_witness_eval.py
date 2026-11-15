#!/usr/bin/env python3
"""Witness-generation eval on the 198 CASTLE programs. The model writes a witness for every program (same prompt as
training, greedy); exec_oracle, routed to the program's CWE oracle, judges it; score (p_vuln) = 1 iff confirmed AND
reproduced by a second independent run, else 0. Programs whose CWE has no runtime monitor (oracle 'none') score 0.

Cross-fitting: pass --adapter 'out/imp_witness_X_f{k}' with --k K; fold k programs are scored only by the adapter that
was trained without them. No --adapter = the base model zero-shot on all programs.
Output is ci_gate-compatible: top-level auroc + per_case {id, label, p_vuln, ...}.
Usage: imp_witness_eval.py --model M [--adapter 'out/..._f{k}' --k 2] --out results/witness/eval_X.json"""
from __future__ import annotations
import argparse, gc, json, os, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "src")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cyberdef import exec_oracle as EO
from cyberdef.imp_common import auroc, hm_se, r4
from imp_witness_common import SYSTEM_W, fold_of, parse_witness, user_prompt


def _ids(x):
    return x["input_ids"] if hasattr(x, "keys") else x


def load(model_path, adapter):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    tok = AutoTokenizer.from_pretrained(adapter or model_path)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    try:
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                                 bnb_4bit_use_double_quant=True)
        m = AutoModelForCausalLM.from_pretrained(model_path, quantization_config=bnb, device_map="auto", dtype=torch.bfloat16)
        mode = "4bit"
    except Exception as e:
        print(f"[eval] 4-bit unavailable ({e}); bf16", flush=True)
        m = AutoModelForCausalLM.from_pretrained(model_path, device_map="auto", dtype=torch.bfloat16)
        mode = "bf16"
    if adapter:
        from peft import PeftModel
        m = PeftModel.from_pretrained(m, adapter)
    m.eval()
    return m, tok, mode


def generate(m, tok, rows, batch, max_new):
    import torch
    pad = tok.pad_token_id
    prompts = []
    for r in rows:
        msgs = [{"role": "system", "content": SYSTEM_W}, {"role": "user", "content": user_prompt(r["code"], r["cwe"], r["oracle"])}]
        prompts.append(_ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False)))
    order = sorted(range(len(rows)), key=lambda i: len(prompts[i]))
    out = {}
    t0 = time.time()
    for b in range(0, len(order), batch):
        idx = order[b:b + batch]
        L = max(len(prompts[i]) for i in idx)
        ids = torch.tensor([[pad] * (L - len(prompts[i])) + prompts[i] for i in idx], device=m.device)
        att = torch.tensor([[0] * (L - len(prompts[i])) + [1] * len(prompts[i]) for i in idx], device=m.device)
        with torch.no_grad():
            g = m.generate(input_ids=ids, attention_mask=att, max_new_tokens=max_new, do_sample=False, pad_token_id=pad)
        for j, i in enumerate(idx):
            out[rows[i]["id"]] = tok.decode(g[j, L:], skip_special_tokens=True)
        print(f"[eval] generated {min(b + batch, len(order))}/{len(order)} {time.time() - t0:.0f}s", flush=True)
    return out


def judge(r, raw):
    rec = {"id": r["id"], "label": r["label"], "cwe": r["cwe"], "oracle": r["oracle"], "fold": r["fold"],
           "raw": (raw or "")[:400], "parsed": False, "confirmed": False, "reproduced": False, "classes": [], "witness": None}
    if r["oracle"] == "none":
        rec["reason"] = "no_runtime_oracle"
    else:
        w = parse_witness(raw)
        if w is None:
            rec["reason"] = "unparseable"
        else:
            rec["parsed"], rec["witness"] = True, w
            kw = dict(argv=tuple(w["argv"]), stdin=w["stdin"], env=(w["env"] or None), files=([tuple(f) for f in w["files"]] or None))
            res = EO.analyze(r["code"], **kw)
            if EO.routed_confirmed(res, r["oracle"]):
                rec["confirmed"], rec["classes"] = True, sorted(set(res.get("classes", [])))
                rec["reproduced"] = bool(EO.routed_confirmed(EO.analyze(r["code"], **kw), r["oracle"]))
            rec["reason"] = "confirmed" if rec["reproduced"] else ("not_reproduced" if rec["confirmed"] else "not_confirmed")
    rec["p_vuln"] = 1.0 if rec["reproduced"] else 0.0
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default="", help="adapter dir; may contain {k} for cross-fitting")
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--src", default="data/witness_train.jsonl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--max-new", type=int, default=256)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0, help="smoke only")
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.src) if l.strip()]
    for r in rows:
        r["fold"] = fold_of(r["id"], a.k)
    if a.limit:
        rows = rows[:a.limit]
    t0 = time.time()
    raws, modes = {}, set()
    if "{k}" in a.adapter:
        groups = [(a.adapter.format(k=k), [r for r in rows if r["fold"] == k]) for k in range(a.k)]
    else:
        groups = [(a.adapter or None, rows)]
    for adapter, grp in groups:
        if not grp:
            continue
        need = [r for r in grp if r["oracle"] != "none"]        # 'none' programs score 0 without generation
        m, tok, mode = load(a.model, adapter)
        modes.add(mode)
        print(f"[eval] model={a.model} adapter={adapter} mode={mode} programs={len(grp)} generate={len(need)}", flush=True)
        raws.update(generate(m, tok, need, a.batch, a.max_new))
        del m
        gc.collect()
        import torch
        torch.cuda.empty_cache()
    print(f"[eval] generation done {time.time() - t0:.0f}s; judging with the oracle (jobs={a.jobs})", flush=True)
    with ThreadPoolExecutor(a.jobs) as ex:
        per_case = list(ex.map(lambda r: judge(r, raws.get(r["id"], "")), rows))
    s = [c["p_vuln"] for c in per_case]
    y = [1 if c["label"] == "VULNERABLE" else 0 for c in per_case]
    au = auroc(s, y)
    n1 = sum(y)
    reasons = {}
    for c in per_case:
        reasons[c["reason"]] = reasons.get(c["reason"], 0) + 1
    res = {"experiment": "witness_eval", "model": a.model, "adapter": a.adapter or None, "k": a.k,
           "cross_fitted": "{k}" in a.adapter, "mode": sorted(modes), "image": EO.image_id(), "n": len(per_case),
           "auroc": r4(au), "se_hm": r4(hm_se(au, n1, len(y) - n1)) if au is not None else None,
           "tpr": r4(sum(1 for c in per_case if c["label"] == "VULNERABLE" and c["p_vuln"]) / max(1, n1)),
           "fpr": r4(sum(1 for c in per_case if c["label"] == "SAFE" and c["p_vuln"]) / max(1, len(y) - n1)),
           "parse_rate_monitorable": r4(sum(1 for c in per_case if c["parsed"]) / max(1, sum(1 for c in per_case if c["oracle"] != "none"))),
           "reasons": reasons, "seconds": round(time.time() - t0, 1), "limit": a.limit, "per_case": per_case}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps({k: res[k] for k in ("model", "adapter", "n", "auroc", "se_hm", "tpr", "fpr", "parse_rate_monitorable", "reasons", "seconds")}, indent=1))


if __name__ == "__main__":
    main()
