"""#2 arm (iii)/(iv): the LLM writes exactly 5 fuzzing seeds (<=256 bytes each) + an optional dictionary for each CASTLE program, from the PROGRAM TEXT ONLY
(labels and any crashing input are never shown; case ids are used only as keys). Greedy, vLLM, base Qwen2.5-7B-Instruct (open weights).
  python3 scripts/imp_llm_seeds.py --model M --cases-file results/xdata_castle_cases.json --out results/imp_2_llm_seeds.json"""
import argparse, json, re, sys, time
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import cyberdef  # noqa: E402,F401  (chat default: no thinking)

SYSTEM = ("You are a software test engineer preparing seed inputs for a coverage-guided fuzzer. You read ONE C program and reply with ONLY one JSON object "
          '{"seeds": [s1, s2, s3, s4, s5], "dict": [t1, ...]} where each seed is a JSON string holding the exact bytes fed to the program (stdin; if the program takes '
          "command-line arguments, the fuzzer maps stdin to argv with arguments separated by NUL bytes written as \\u0000) and at most 256 bytes long, and dict is up to 20 short "
          "tokens/keywords/magic values the program parses. Choose seeds that exercise DIFFERENT input shapes, sizes and boundary values the program's own parsing logic cares about "
          "(lengths, numbers, delimiters, format specifiers, long strings). Exactly 5 seeds. No prose.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--gpu-util", type=float, default=0.45)
    a = ap.parse_args()
    import vllm
    from vllm import LLM, SamplingParams
    from transformers import AutoTokenizer
    cases = json.load(open(a.cases_file))["cases"]
    tok = AutoTokenizer.from_pretrained(a.model)
    prompts = [tok.apply_chat_template([{"role": "system", "content": SYSTEM}, {"role": "user", "content": c["code"]}], add_generation_prompt=True, tokenize=False)
               for c in cases]
    llm = LLM(a.model, dtype="bfloat16", max_model_len=8192, gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0)
    t0 = time.time()
    outs = llm.generate(prompts, SamplingParams(temperature=0, max_tokens=700))
    progs, bad = {}, 0
    for c, o in zip(cases, outs):
        raw = o.outputs[0].text
        seeds, dic = [], []
        try:
            t = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
            d = json.loads(t[t.find("{"):t.rfind("}") + 1])
            seeds = [str(s) for s in d.get("seeds", [])][:5]
            dic = [str(x) for x in d.get("dict", [])][:20]
        except Exception:
            bad += 1
        seeds = [s.encode("utf8", "replace")[:256].decode("utf8", "ignore") for s in seeds]
        progs[c["id"]] = {"seeds": seeds, "dict": dic, "raw": raw[:1500], "n_seeds": len(seeds)}
    sizes = [len(s.encode()) for p in progs.values() for s in p["seeds"]]
    res = {"model": a.model, "engine": f"vllm {vllm.__version__} bf16 temp=0", "n_programs": len(progs), "parse_failures": bad,
           "programs_with_5_seeds": sum(1 for p in progs.values() if p["n_seeds"] == 5), "seed_bytes_mean": round(sum(sizes) / max(1, len(sizes)), 1),
           "seed_bytes_sorted": sorted(sizes), "seconds": round(time.time() - t0), "programs": progs,
           "note": "prompt = program text only; no labels, no crash inputs"}
    json.dump(res, open(a.out, "w"))
    print(json.dumps({k: v for k, v in res.items() if k not in ("programs", "seed_bytes_sorted")}))


if __name__ == "__main__":
    main()
