"""#9a direct-prompt localisation (model arm): numbered source -> the 3 line numbers most likely to hold the vulnerability. Greedy, vLLM (+LoRA).
Writes per_case with the predicted lines and top-1 / top-3 hits against truth_lines of results/imp_loc_cases.json.
  python3 scripts/imp_loc_eval.py --model M [--adapter A] --cases-file results/imp_loc_cases.json --out results/imp_9a_X.json"""
import argparse, json, re, sys, time
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import cyberdef  # noqa: E402,F401  (chat default: no thinking)
from reason_C_witness import numbered

SYSTEM = ("You are an expert vulnerability researcher. The function below is KNOWN to contain a security vulnerability. Reply with ONLY the three line numbers "
          "(from the numbered lines shown) most likely to contain the vulnerable code, most likely first, separated by commas, e.g. 12, 7, 30.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--gpu-util", type=float, default=0.45)
    a = ap.parse_args()
    import vllm
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest
    from transformers import AutoTokenizer
    cases = json.load(open(a.cases_file))["cases"]
    tok = AutoTokenizer.from_pretrained(a.model)
    prompts = [tok.apply_chat_template([{"role": "system", "content": SYSTEM}, {"role": "user", "content": numbered(c["code"])}], add_generation_prompt=True, tokenize=False) for c in cases]
    llm = LLM(a.model, dtype="bfloat16", enable_lora=a.adapter is not None, max_lora_rank=16, max_model_len=8192, gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0)
    lr = LoRARequest("a", 1, a.adapter) if a.adapter else None
    t0 = time.time() if False else time.time()
    outs = llm.generate(prompts, SamplingParams(temperature=0, max_tokens=64), lora_request=lr)
    per = []
    for c, o in zip(cases, outs):
        txt = o.outputs[0].text
        nums = []
        for x in re.findall(r"\d+", txt):
            v = int(x)
            if 1 <= v <= c["lines"] and v not in nums:
                nums.append(v)
        truth = set(c["truth_lines"])
        per.append({"id": c["id"], "label": c["label"], "pred_lines": nums[:3], "raw": txt[:200], "truth_lines": c["truth_lines"], "n_lines": c["lines"],
                    "top1": bool(nums[:1] and nums[0] in truth), "top3": bool(set(nums[:3]) & truth), "n_pred": len(nums[:3])})
    n = len(per)
    res = {"experiment": "imp_9a", "model": a.model, "adapter": a.adapter, "n": n, "engine": f"vllm {vllm.__version__} bf16 temp=0",
           "top1": round(sum(p["top1"] for p in per) / n, 4), "top3": round(sum(p["top3"] for p in per) / n, 4),
           "answered": round(sum(1 for p in per if p["n_pred"] > 0) / n, 4), "cases_file": a.cases_file, "per_case": per, "seconds": round(time.time() - t0)}
    json.dump(res, open(a.out, "w"))
    print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))


import time

if __name__ == "__main__":
    main()
