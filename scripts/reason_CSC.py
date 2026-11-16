"""Stage C-SC: Secure-Code Chain-of-Thought (src/cyberdef/sc_cot.py) on the SAME 300 matched cases as Stage C.
  reason_CSC.py hf <tag> <base> [adapter] | ollama <tag> <model> [url] | stub <tag> x
  env GEN_ONLY_CASES=<cases json> -> generate only (CASTLE for Stage D), cache results/reason_CSC_<tag>_castle_cache.jsonl
Pre-registered in EXPERIMENT_PLAN_REASONING.md (Stage C-SC)."""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
from length_baseline import auroc, hanley_mcneil_se
from reason_C_witness import parse_json, numbered, subset
from cyberdef import sc_cot as S

import os as _os
MAXTOK = int(_os.environ.get("MAXTOK", 4096))   # amendment 2 (format fix, before any C-SC output): 2048 + guided JSON


def main():
    mode, tag = sys.argv[1], sys.argv[2]
    gen_only = os.environ.get("GEN_ONLY_CASES")
    cases = json.load(open(gen_only))["cases"] if gen_only else subset()
    cache_p = Path(f"results/reason_CSC_{tag}_castle_cache.jsonl" if gen_only else f"results/reason_CSC_{tag}_cache.jsonl")
    cache = {}
    if cache_p.exists():
        for l in cache_p.read_text().splitlines():
            r = json.loads(l); cache[r["id"] + r["label"]] = r["raw"]
    meta = {}
    if mode == "vllm":
        from cyberdef import vllm_gen
        todo = [c for c in cases if c["id"] + c["label"] not in cache]
        if todo:
            from cyberdef.schemas_cot import SCHEMAS
            sch = SCHEMAS["sc"] if _os.environ.get("GUIDED_SCHEMA", "sc") != "none" else None
            dec = vllm_gen.decode_config(sch, MAXTOK)
            outs = vllm_gen.generate_all(sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None, S.SYSTEM,
                                         [numbered(c["code"]) for c in todo], MAXTOK, schema=sch)
            with cache_p.open("a") as f:
                for c, (t, nt, fin) in zip(todo, outs):
                    cache[c["id"] + c["label"]] = t; meta[c["id"] + c["label"]] = (nt, fin)
                    f.write(json.dumps({"id": c["id"], "label": c["label"], "raw": t, "ntok": nt, "finish": fin,
                                        "engine": vllm_gen.ENGINE, "decode": dec}) + chr(10))
        gen = None
    elif mode == "stub":
        gen = lambda u: json.dumps({**S.GOOD, "verdict": "UNCERTAIN"}) if sum(map(ord, u)) % 2 else "no json"
    elif mode == "hf":
        from cyberdef import model_io
        model, tok = model_io.load_hf(sys.argv[3], adapter=sys.argv[4] if len(sys.argv) > 4 else None)
        gen = lambda u: model_io.generate(model, tok, S.SYSTEM, u, max_new_tokens=MAXTOK)
    else:
        from cyberdef import model_io
        url = sys.argv[4] if len(sys.argv) > 4 else "http://127.0.0.1:11434"
        gen = lambda u: model_io.ollama_chat(url, sys.argv[3], S.SYSTEM, u, max_new_tokens=MAXTOK)
    t0 = time.time()
    with cache_p.open("a") as f:
        for i, c in enumerate(cases):
            k = c["id"] + c["label"]
            if k in cache:
                continue
            raw = gen(numbered(c["code"])); cache[k] = raw
            f.write(json.dumps({"id": c["id"], "label": c["label"], "raw": raw}) + "\n"); f.flush()
            if i % 10 == 0:
                print(f"[CSC {tag}] {i}/{len(cases)} {time.time()-t0:.0f}s", flush=True)
    if gen_only:
        print(f"[CSC-gen {tag}] cached {len(cache)}"); return
    per = []
    for c in cases:
        raw = cache[c["id"] + c["label"]]; d = parse_json(raw)
        r = S.validate(d, c["code"]) if d is not None else dict(valid=False, errors=["unparsed"], verdict_raw=None,
                                                               verdict_final="UNCERTAIN", has_witness=False, confidence=.5, score=.5)
        per.append({"id": c["id"], "label": c["label"], "pair": c["pair"], "code_chars": c["code_chars"], "raw": raw[:2000],
                    "parsed": d is not None and r["verdict_raw"] is not None, "valid": r["valid"], "errors": r["errors"][:6],
                    "verdict_raw": r["verdict_raw"], "verdict_final": r["verdict_final"], "has_witness": r["has_witness"],
                    "vuln_cwe": r.get("cwe_id"), "oracle": r.get("oracle"), "vuln_owasp": r.get("owasp"),
                    "s_sc": r["score"], "ntok": meta.get(c["id"] + c["label"], (None, None))[0],
                    "truncated_gen": meta.get(c["id"] + c["label"], (None, None))[1] == "length",
                    "s0": (0.5 + 0.5 * r["confidence"] if r["verdict_raw"] == "VULNERABLE" else 0.5 - 0.5 * r["confidence"]
                           if r["verdict_raw"] == "SAFE" else 0.5)})
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in per]; n1 = sum(y); n0 = len(y) - n1
    res = {"stage": "C-SC", "tag": tag, "model": sys.argv[3], "n": len(per), "max_new_tokens": MAXTOK,
           "parse_rate": round(sum(p["parsed"] for p in per) / len(per), 4),
           "valid_rate": round(sum(p["valid"] for p in per) / len(per), 4),
           "frac_downgraded_to_uncertain": round(sum(p["verdict_raw"] in ("VULNERABLE", "SAFE") and p["verdict_final"] == "UNCERTAIN" for p in per) / len(per), 4),
           "auroc": {}, "se_hm": {}}
    for k in ("s0", "s_sc"):
        a = auroc([p[k] for p in per], y)
        res["auroc"][k] = round(a, 4); res["se_hm"][k] = round(hanley_mcneil_se(a, n1, n0), 4)
    nt = [p["ntok"] for p in per if p["ntok"] is not None]
    res["tokens_used"] = {"max_new_tokens": MAXTOK, "mean": round(sum(nt) / len(nt), 1) if nt else None, "max": max(nt) if nt else None,
                          "frac_truncated_at_limit": round(sum(p["truncated_gen"] for p in per) / len(per), 4)}
    ch = sorted(p["code_chars"] for p in per); cuts = [ch[len(ch) * q // 4] for q in (1, 2, 3)]
    q = {}
    for i, p in enumerate(per):
        q.setdefault(sum(p["code_chars"] > t for t in cuts), []).append(i)
    res["within_length_quartile_s_sc"] = {f"Q{j+1}": round(auroc([per[i]["s_sc"] for i in v], [y[i] for i in v]), 4) for j, v in sorted(q.items())}
    byp = {}
    for p in per:
        byp.setdefault(p["pair"], {})[1 if p["label"] == "VULNERABLE" else 0] = p["s_sc"]
    w = [(1 if v[1] > v[0] else .5 if v[1] == v[0] else 0) for v in byp.values()]
    res["pairwise_win_rate_s_sc"] = round(sum(w) / len(w), 4)
    ids = {p["id"] + p["label"] for p in per}; comp = {}
    for name, f in (("stageC_witness_s1", f"results/reason_C_{tag}_matched.json"), ("logprob_pub7b", "results/ab_pub7b__lenmatched.json"),
                    ("sast_flawfinder", "results/reason_B_sast_flawfinder_matched.json"), ("sast_semgrep", "results/reason_B_sast_semgrep_matched.json")):
        if not Path(f).exists():
            continue
        dd = json.load(open(f)); rows = [r for r in dd["per_case"] if r["id"] + r["label"] in ids]
        if len(rows) != len(per):
            continue
        sk = "s1" if "s1" in rows[0] else "p_vuln" if "p_vuln" in rows[0] else "score"
        a = auroc([r[sk] for r in rows], [1 if r["label"] == "VULNERABLE" else 0 for r in rows])
        comp[name] = {"auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, n0), 4)}
    res["comparators_same_cases"] = comp; res["per_case"] = per
    Path(f"results/reason_CSC_{tag}_matched.json").write_text(json.dumps(res))
    print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))


if __name__ == "__main__":
    main()
