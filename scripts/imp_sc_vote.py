"""#8 self-consistency vs a single greedy trace on the pre-registered fixed subset: 75 matched pairs = 150 cases chosen by random.Random(0).sample over sorted pair ids.
Arm: N samples (default 5), T=0.7, top_p=0.95, max_new_tokens 1200; score = mean per-sample validator score s_sc (and majority-vote variant). Comparison: ONE greedy trace, same token budget.
Reports AUROC +/- Hanley-McNeil SE for greedy / mean / vote, parse rate, tokens generated (N x cost). Imports sc_cot read-only.
  python3 scripts/imp_sc_vote.py --model M [--adapter A] --cases-file results/lenmatched_eval_cases.json --out results/imp_8_sc.json --n 5"""
import argparse, json, random, sys, time
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
from cyberdef import imp_sc_schema as SS
from cyberdef.imp_common import auroc, hm_se, r4
from reason_C_witness import numbered, parse_json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--gpu-util", type=float, default=0.45)
    a = ap.parse_args()
    import vllm
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest
    from transformers import AutoTokenizer
    allc = json.load(open(a.cases_file))["cases"]
    pairs = sorted({c["pair"] for c in allc})
    chosen = set(random.Random(0).sample(pairs, 75))
    cases = [c for c in allc if c["pair"] in chosen]
    tok = AutoTokenizer.from_pretrained(a.model)
    prompts = [tok.apply_chat_template([{"role": "system", "content": S.SYSTEM}, {"role": "user", "content": numbered(c["code"])}], add_generation_prompt=True, tokenize=False) for c in cases]
    llm = LLM(a.model, dtype="bfloat16", enable_lora=a.adapter is not None, max_lora_rank=16, max_model_len=8192, gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0)
    lr = LoRARequest("a", 1, a.adapter) if a.adapter else None
    t0 = time.time()
    g = llm.generate(prompts, SS.sampling_params(vllm, True, temperature=0, max_tokens=a.max_tokens), lora_request=lr)
    s = llm.generate(prompts, SS.sampling_params(vllm, True, n=a.n, temperature=0.7, top_p=0.95, max_tokens=a.max_tokens, seed=0), lora_request=lr)

    def score(text, code):
        d = parse_json(text)
        if d is None:
            return 0.5, None, False
        v = S.validate(d, code)
        return v["score"], v["verdict_final"], True

    per = []
    for c, og, os_ in zip(cases, g, s):
        sg, vg, pg = score(og.outputs[0].text, c["code"])
        ss = [score(x.text, c["code"]) for x in os_.outputs]
        votes = [1 if v == "VULNERABLE" else -1 if v == "SAFE" else 0 for _, v, _ in ss]
        per.append({"id": c["id"], "label": c["label"], "pair": c["pair"], "s_greedy": sg, "s_mean": round(sum(x[0] for x in ss) / len(ss), 6),
                    "vote": sum(votes) / len(votes), "n_parsed": sum(x[2] for x in ss), "greedy_parsed": pg,
                    "ntok_greedy": len(og.outputs[0].token_ids), "ntok_samples": sum(len(x.token_ids) for x in os_.outputs)})
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in per]
    n1 = sum(y); n0 = len(y) - n1
    res = {"experiment": "imp_8", "model": a.model, "adapter": a.adapter, "n": len(per), "n_pairs": len(chosen), "samples": a.n, "engine": f"vllm {vllm.__version__} bf16",
           "max_new_tokens": a.max_tokens, "per_case": per, "seconds": round(time.time() - t0),
           "token_cost_ratio_samples_over_greedy": r4(sum(p["ntok_samples"] for p in per) / max(1, sum(p["ntok_greedy"] for p in per))),
           "parse_rate_greedy": r4(sum(p["greedy_parsed"] for p in per) / len(per)), "parse_rate_samples": r4(sum(p["n_parsed"] for p in per) / (len(per) * a.n))}
    for k in ("s_greedy", "s_mean", "vote"):
        au = auroc([p[k] for p in per], y)
        res[f"auroc_{k}"] = r4(au); res[f"se_{k}"] = r4(hm_se(au, n1, n0))
    ch = [len(c["code"]) for c in cases]
    la = auroc(ch, y)
    res["length_only_auroc_same_cases"] = r4(la)
    json.dump(res, open(a.out, "w"))
    print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))


if __name__ == "__main__":
    main()
