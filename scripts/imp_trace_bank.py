"""CoT trace bank generator + tagger (Spark container, vLLM). One call per generator; writes results/imp_bank_<gen>.jsonl.
  python3 scripts/imp_trace_bank.py --gen g1 --model Qwen/Qwen2.5-7B-Instruct [--adapter out/qlora-primevul] --pools A,B,C,J --k 4
Pools (TRAIN data only): A results/imp_train_pairs_items.json, B imp_train_clean_lm_items.json, C imp_train_unfilt_lm_items.json, J imp_train_juliet_items.json.
Tags: V verdict correct | P sc_cot.validate passes (verdict_final==verdict_raw) | S a cited sink line is a labelled vulnerable line (results/imp_linelabels.json; None = no label)
| X Juliet bad program crashed in the sandbox (imp_build_juliet.py) and the trace says VULNERABLE (label verification, witness-independent; see that script)
| C (on the best V+P trace of a function) verdict unchanged on every possible length edit (pad/compress/rename), greedy re-generation by the SAME generator.
Prompt = sc_cot.SYSTEM + numbered lines (reason_C_witness.numbered). K samples T=0.7 top_p=0.95 seed 0, max_tokens --max-tokens. Open-weight generators only."""
import argparse, json, os, sys, time
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
sys.path.insert(0, os.environ.get("IMP_PYLIB", "/work/imp_pylib"))
from cyberdef import sc_cot as S
from cyberdef import imp_sc_schema as SS
from cyberdef.cwe_oracle import CWE_ORACLE
from reason_C_witness import numbered, parse_json

POOLS = {"A": "imp_train_pairs_items.json", "B": "imp_train_clean_lm_items.json", "C": "imp_train_unfilt_lm_items.json", "J": "imp_train_juliet_items.json", "J2": "imp_train_juliet2_items.json", "J3": "imp_train_juliet3_items.json", "Q": "imp_train_sqli_items.json"}
EDIT_NAMES = ("pad", "compress", "rename")
TRUE = {}      # function id -> [true CWE ids] (results/imp_true_cwe.json), loaded in main



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

def load_pool(keys, limit=0):
    funcs = {}
    for k in keys:
        # amendment 3: "ST:<category>" = the self-training pool results/st_pool_<category>.json (scripts/imp_st_pool.py)
        src = POOLS[k] if k in POOLS else (f"st_pool_{k[3:]}.json" if k.startswith("ST:") else None)
        if src is None:
            raise SystemExit(f"unknown pool {k}")
        its = json.load(open("results/" + src))["items"]
        if limit:
            its = its[:limit]
        for it in its:
            f = funcs.setdefault(it["id"], dict(id=it["id"], code=it["code"], label=it["label"], pools=[], exec_sanitizer=it.get("exec_sanitizer"), project=it.get("project")))
            if k not in f["pools"]:
                f["pools"].append(k)
    return list(funcs.values())


def load_quick():
    """QUICK bank subset (EXPERIMENT_PLAN_IMPROVE.md, re-ordering amendment): pool A items[0:1600] (first 800 pairs) + 120 Juliet testcase files (bad+good = 240 items) with the smallest sha1(pair name)."""
    import hashlib
    funcs = {}
    for it in json.load(open("results/" + POOLS["A"]))["items"][:1600]:
        funcs[it["id"]] = dict(id=it["id"], code=it["code"], label=it["label"], pools=["A"], exec_sanitizer=None, project=it.get("project"))
    jit = json.load(open("results/" + POOLS["J"]))["items"]
    names = sorted({i["pair"] for i in jit}, key=lambda n: hashlib.sha1(n.encode()).hexdigest())[:120]
    keep = set(names)
    for it in jit:
        if it["pair"] in keep:
            funcs[it["id"]] = dict(id=it["id"], code=it["code"], label=it["label"], pools=["J"], exec_sanitizer=it.get("exec_sanitizer"), project="juliet")
    return list(funcs.values())


def extract(text):
    """gpt-oss harmony: keep the final channel; others unchanged"""
    if "<|channel|>final<|message|>" in text:
        text = text.split("<|channel|>final<|message|>")[-1]
    for stop in ("<|return|>", "<|end|>", "<|im_end|>"):
        text = text.split(stop)[0]
    return text


def tag(raw, f, linelabels, check_lines=True):
    d = parse_json(raw)
    if d is None:
        return dict(parsed=False, V=False, P=False, S=None, X=None, K=None, O=None, O_owasp=None, cwe_id=None, oracle=None, verdict_raw=None, verdict_final="UNCERTAIN", errors=["unparsed"])
    r = S.validate(d, f["code"])
    vr, vf = r["verdict_raw"], r["verdict_final"]
    V = vr == f["label"]
    P = bool(r["valid"]) and vf == vr
    Sg = None
    ll = linelabels.get(f["id"])
    if check_lines and f["label"] == "VULNERABLE" and ll and ll["status"] == "ok":
        cited = set()
        for s in d.get("sinks") or []:
            try:
                cited.add(int(s.get("line")))
            except Exception:
                pass
        Sg = bool(cited & set(ll["lines"]))
    X = None
    if f.get("exec_sanitizer") is not None and f["label"] == "VULNERABLE":
        X = bool(f["exec_sanitizer"]) and vr == "VULNERABLE"
    # K = chosen vuln_class.cwe is one of the TRUE CWEs; O = chosen oracle is the fixed-map oracle of a true CWE (both only where a true allowed CWE is known; None otherwise)
    cw, orc = r.get("cwe_id"), r.get("oracle")
    K = O = None
    true = [c for c in TRUE.get(f["id"], []) if c in CWE_ORACLE]
    if true:
        K = cw in true
        O = orc in {CWE_ORACLE[c] for c in true}
    # O_owasp (REPORTED ONLY, never a selection criterion): chosen vuln_class.owasp equals the OWASP-2021 label of a true CWE, using the pipeline CWE->OWASP map when it exists in cwe_oracle
    O_ow = None
    try:
        from cyberdef import cwe_oracle as _CO
        _map = getattr(_CO, "CWE_OWASP", None) or getattr(_CO, "CWE_TO_OWASP", None)
        if _map and true:
            _tw = {_map[c] for c in true if c in _map}
            _ch = (d.get("vuln_class") or {}).get("owasp")
            O_ow = (_ch in _tw) if _tw else None
    except Exception:
        O_ow = None
    return dict(parsed=True, V=V, P=P, S=Sg, X=X, K=K, O=O, O_owasp=O_ow, cwe_id=cw, oracle=orc, verdict_raw=vr, verdict_final=vf, errors=r["errors"][:4])


def best(rows):
    """selection rule (EXPERIMENT_PLAN_IMPROVE.md): V and P, most tags, shortest"""
    c = [r for r in rows if r["V"] and r["P"]]
    c.sort(key=lambda r: (-(1 + (r["S"] is True) + (r["X"] is True)), len(r["raw"]), r["sample"]))
    return c[0] if c else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--pools", default="A,B,C,J")
    ap.add_argument("--k", type=int, default=4)
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--gpu-util", type=float, default=0.45)
    ap.add_argument("--fewshot", default=None, help="results/imp_fewshot_exemplars.json: in-context exemplars templated from Juliet ground truth")
    ap.add_argument("--max-model-len", type=int, default=12288)
    ap.add_argument("--subset", default=None, choices=[None, "quick"], help="quick = the pre-registered quick-bank subset (ignores --pools)")
    ap.add_argument("--skip-c", action="store_true", help="skip the C pass (length-edit consistency). Self-training rounds (addendum 3h) do not select on C; the default (C pass on) is unchanged for every bank build")
    ap.add_argument("--limit", type=int, default=0, help="debug only: first N items per pool")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    import vllm
    from vllm import LLM, SamplingParams
    from vllm.lora.request import LoRARequest
    from transformers import AutoTokenizer
    from cyberdef import imp_edits
    out_p = a.out or f"results/imp_bank_{a.gen}.jsonl"
    funcs = load_quick() if a.subset == "quick" else load_pool(a.pools.split(","), a.limit)
    ll = json.load(open("results/imp_linelabels.json")) if os.path.exists("results/imp_linelabels.json") else {}
    if os.path.exists("results/imp_true_cwe.json"):
        TRUE.update({k: v for k, v in json.load(open("results/imp_true_cwe.json")).items()})
    tok = AutoTokenizer.from_pretrained(a.model)
    oss = "gpt-oss" in a.model.lower()

    FEW = json.load(open(a.fewshot))["exemplars"] if a.fewshot else []

    def prompt(code):
        kw = {"reasoning_effort": "low"} if oss else {}
        msgs = [{"role": "system", "content": S.SYSTEM}]
        for ex in FEW:
            msgs += [{"role": "user", "content": ex["user"]}, {"role": "assistant", "content": ex["assistant"]}]
        msgs.append({"role": "user", "content": numbered(code)})
        return tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False, **kw)

    llm = LLM(a.model, dtype="bfloat16", enable_lora=a.adapter is not None, max_lora_rank=16, max_model_len=a.max_model_len,
              gpu_memory_utilization=a.gpu_util, enforce_eager=True, seed=0, **text_only_kwargs(a.model))
    lr = LoRARequest("a", 1, a.adapter) if a.adapter else None
    eng = f"vllm {vllm.__version__} bf16"
    mt = min(a.max_tokens * 3, 5000) if oss else a.max_tokens      # gpt-oss: longer (harmony channels) but prompt + generation must fit max_model_len 8192
    t0 = time.time()
    guided = not oss        # gpt-oss writes harmony channels: free-form JSON, recorded as guided=none
    sp = SS.sampling_params(vllm, guided, n=a.k, temperature=0.7, top_p=0.95, max_tokens=mt, seed=0, skip_special_tokens=not oss)
    dec = SS.config_row(guided, mt, 0.7, 0.95, eng, a.gen)
    outs = llm.generate([prompt(f["code"]) for f in funcs], sp, lora_request=lr)
    rows, by_fn = [], {}
    for f, o in zip(funcs, outs):
        for j, c in enumerate(o.outputs):
            raw = extract(c.text)
            t = tag(raw, f, ll)
            r = dict(rec="trace", bank=("quick" if a.subset == "quick" else "full"), fn=f["id"], pools=f["pools"], label=f["label"], gen=a.gen, model=a.model, adapter=a.adapter, sample=j, edit="orig", raw=raw,
                     ntok=len(c.token_ids), finish=c.finish_reason, truncated=(c.finish_reason == "length"), engine=eng, decoding=dict(dec, fewshot=len(FEW)), fewshot=len(FEW), **t)
            rows.append(r); by_fn.setdefault(f["id"], []).append(r)
    print(f"[bank {a.gen}] generated {len(rows)} traces for {len(funcs)} functions in {time.time()-t0:.0f}s", flush=True)
    with open(out_p + ".orig.partial", "w") as fo:   # the original traces survive a crash in the C pass
        for r in rows:
            fo.write(json.dumps(r) + "\n")
    # ---- C pass: best V+P trace per function, three length edits, greedy, same generator ----
    todo, meta = [], []
    for f in (funcs if not a.skip_c else []):
        b = best(by_fn[f["id"]])
        if not b:
            continue
        for en, ec in imp_edits.apply_all(f["code"]).items():
            todo.append(ec); meta.append((f, b, en, ec))
    csum = {}
    if todo:
        sp0 = SS.sampling_params(vllm, guided, n=1, temperature=0, max_tokens=mt, skip_special_tokens=not oss)
        dec0 = SS.config_row(guided, mt, 0.0, 1.0, eng, a.gen)
        o2 = llm.generate([prompt(c) for c in todo], sp0, lora_request=lr)
        for (f, b, en, ec), o in zip(meta, o2):
            raw = extract(o.outputs[0].text)
            t = tag(raw, dict(f, code=ec), ll, check_lines=False)
            rows.append(dict(rec="trace", bank=("quick" if a.subset == "quick" else "full"), fn=f["id"], pools=f["pools"], label=f["label"], gen=a.gen, model=a.model, adapter=a.adapter, sample=0, edit=en, raw=raw,
                             ntok=len(o.outputs[0].token_ids), finish=o.outputs[0].finish_reason, truncated=(o.outputs[0].finish_reason == "length"), engine=eng, decoding=dict(dec0, fewshot=len(FEW)), fewshot=len(FEW), edited_code=ec, **t))
            csum.setdefault(f["id"], {"sample": b["sample"], "verdict": b["verdict_final"], "edits": {}})["edits"][en] = t["verdict_final"]
    for fid, s in csum.items():
        s["C"] = all(v == s["verdict"] for v in s["edits"].values())
        for r in by_fn[fid]:
            if r["sample"] == s["sample"]:
                r["C"] = s["C"]; r["C_edits"] = s["edits"]
    with open(out_p, "w") as fo:
        for r in rows:
            fo.write(json.dumps(r) + "\n")
    tot = [r for r in rows if r["edit"] == "orig"]
    print(json.dumps({"gen": a.gen, "traces": len(tot), "parsed": sum(r["parsed"] for r in tot), "truncated": sum(r["truncated"] for r in tot), "V": sum(r["V"] for r in tot), "K": sum(r["K"] is True for r in tot), "O": sum(r["O"] is True for r in tot), "P": sum(r["P"] for r in tot),
                      "VP": sum(r["V"] and r["P"] for r in tot), "S": sum(r["S"] is True for r in tot), "X": sum(r["X"] is True for r in tot),
                      "C_functions": len(csum), "C_true": sum(s["C"] for s in csum.values()), "seconds": round(time.time() - t0)}))


if __name__ == "__main__":
    main()
