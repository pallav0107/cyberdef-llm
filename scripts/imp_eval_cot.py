"""Evaluate a CoT-trained model (or any model) with the SC-CoT prompt on a cases file, greedy, vLLM (+LoRA). Scores:
  p_vuln  = P(VULNERABLE)/(P(VULNERABLE)+P(SAFE)) read from the top-10 logprobs at the token that carries the verdict value in the model's OWN trace
  s_sc    = sc_cot validator score (VULNERABLE valid -> 0.5+0.5c, SAFE valid -> 0.5-0.5c, else 0.5)
Output has the selective_eval schema (auroc from p_vuln) + per-case raw trace (for CASTLE witness execution) + auroc_s_sc.
  python3 scripts/imp_eval_cot.py --model M [--adapter A] --cases-file F --out results/X.json [--max-tokens 1200] [--gpu-util 0.45]"""
import argparse, random, json, math, os, re, sys, time
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
from cyberdef import imp_sc_schema as SS
from reason_C_witness import numbered, parse_json
import selective_eval as se

VR = re.compile(r'"verdict"\s*:\s*"(VULNERABLE|SAFE|UNCERTAIN)"')



def text_only_kwargs(model):
    """Vision-language checkpoints (e.g. Qwen3.8-27B, model_type qwen3_5) get TEXT prompts only here: disable image and video
    inputs, so vLLM skips the vision encoder and its profiling pass with a maximum-size image. That pass froze the Spark
    twice (15 Nov 23:29 and 16 Nov 01:44, both right after the weights loaded; no OOM kill). Text-only models are unchanged."""
    try:
        from transformers import AutoConfig
        if getattr(AutoConfig.from_pretrained(model), "vision_config", None) is not None:
            return {"limit_mm_per_prompt": {"image": 0, "video": 0}}
    except Exception:
        pass
    return {}

def verdict_probs(out):
    text = out.text
    m = VR.search(text)
    if not m or not out.logprobs:
        return None
    pos, idx = 0, None
    for i, lp in enumerate(out.logprobs):
        tid = out.token_ids[i]
        piece = lp[tid].decoded_token if tid in lp else ""
        if pos + len(piece) > m.start(1):
            idx = i; break
        pos += len(piece)
    if idx is None:
        return None
    pv = ps = 0.0
    for tid, l in out.logprobs[idx].items():
        t = (l.decoded_token or "").strip(" \"\n\t").upper()
        if not t:
            continue
        if "VULNERABLE".startswith(t):
            pv += math.exp(l.logprob)
        elif "SAFE".startswith(t):
            ps += math.exp(l.logprob)
    return pv / (pv + ps) if pv + ps > 0 else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--gpu-util", type=float, default=0.45)
    ap.add_argument("--meta", default="")
    ap.add_argument("--max-cases", type=int, default=0)
    ap.add_argument("--shuffle-seed", type=int, default=0,
                    help="0 = cases in file order; N > 0 = generate in random.Random(N) order (addendum 3k: K decodes with shuffled order); per_case stays in file order")
    a = ap.parse_args()
    import vllm
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest
    from transformers import AutoTokenizer
    cf = json.load(open(a.cases_file))
    cases = cf["cases"][:a.max_cases] if a.max_cases else cf["cases"]
    tok = AutoTokenizer.from_pretrained(a.model)
    prompts = [tok.apply_chat_template([{"role": "system", "content": S.SYSTEM}, {"role": "user", "content": numbered(c["code"])}],
                                       add_generation_prompt=True, tokenize=False) for c in cases]
    llm = LLM(a.model, dtype="bfloat16", enable_lora=a.adapter is not None, max_lora_rank=16, max_model_len=8192,
              gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0, **text_only_kwargs(a.model))
    lr = LoRARequest("a", 1, a.adapter) if a.adapter else None
    order = list(range(len(prompts)))
    if a.shuffle_seed:
        random.Random(a.shuffle_seed).shuffle(order)
    t0 = time.time()
    gen = llm.generate([prompts[i] for i in order], SS.sampling_params(vllm, True, temperature=0, max_tokens=a.max_tokens, logprobs=10), lora_request=lr)
    outs = [None] * len(order)
    for i, o in zip(order, gen):
        outs[i] = o
    per, sc, y, ssc, confs, corr = [], [], [], [], [], []
    for c, o in zip(cases, outs):
        g = o.outputs[0]
        d = parse_json(g.text)
        v = S.validate(d, c["code"]) if d is not None else dict(valid=False, errors=["unparsed"], verdict_raw=None, verdict_final="UNCERTAIN", has_witness=False, confidence=.5, score=.5)
        p = verdict_probs(g)
        p_source = "verdict_token"
        if p is None:
            p_source = "fallback_s_sc"
            p = 0.5 + (0.5 * v["confidence"] if v["verdict_raw"] == "VULNERABLE" else -0.5 * v["confidence"] if v["verdict_raw"] == "SAFE" else 0.0)
        pred = "VULNERABLE" if p >= 0.5 else "SAFE"
        ok = int(pred == c["label"])
        per.append({"id": c["id"], "label": c["label"], "pred": pred, "p_vuln": p, "conf": round(max(p, 1 - p), 6), "correct": ok,
                    "s_sc": v["score"], "verdict_raw": v["verdict_raw"], "verdict_final": v["verdict_final"], "valid": bool(v["valid"]), "parsed": d is not None,
                    "has_witness": bool(v["has_witness"]), "p_source": p_source, "ntok": len(g.token_ids), "finish": g.finish_reason, "raw": g.text[:6000]})
        sc.append(p); y.append(1 if c["label"] == "VULNERABLE" else 0); ssc.append(v["score"]); confs.append(max(p, 1 - p)); corr.append(ok)
    n = len(per)
    res = {"benchmark": a.cases_file, "dataset": "cases_file", "eval_split": cf.get("split"), "method": "sc-cot greedy, verdict-token logprob", "pool": cf.get("pool", {}),
           "model": a.model, "adapter": a.adapter, "meta": a.meta, "seed": 0, "shuffle_seed": a.shuffle_seed, "n": n, "n_per_class": n // 2, "max_chars": 6000, "max_new_tokens": a.max_tokens,
           "accuracy": round(sum(corr) / n, 4), "auroc": se.auroc(sc, y), "auroc_s_sc": se.auroc(ssc, y), "ece": se.ece(confs, corr),
           "p_fallback_rate": round(sum(p["p_source"] != "verdict_token" for p in per) / n, 4), "parse_rate": round(sum(p["parsed"] for p in per) / n, 4), "valid_rate": round(sum(p["valid"] for p in per) / n, 4), "truncation_rate": round(sum(p["finish"] == "length" for p in per) / n, 4),
           "risk_coverage": se.risk_coverage(confs, corr, [0.1, 0.2, 0.25, 0.3, 0.4, 0.5, 0.75, 1.0]), "engine": f"vllm {vllm.__version__} bf16 temp=0", "decoding": SS.config_row(True, a.max_tokens, 0.0, 1.0, f"vllm {vllm.__version__}", a.model),
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seconds": round(time.time() - t0), "cases_file": a.cases_file, "per_case": per}
    json.dump(res, open(a.out, "w"))
    print(f"[imp_eval_cot] n={n} auroc={res['auroc']} auroc_s_sc={res['auroc_s_sc']} parse={res['parse_rate']} valid={res['valid_rate']} {res['seconds']}s")


if __name__ == "__main__":
    main()
