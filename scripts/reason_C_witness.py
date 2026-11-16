"""Stage C: witness prompting ("mentally run it") on a fixed 300-case subset of the length-matched PrimeVul eval.
Pre-registered in EXPERIMENT_PLAN_REASONING.md. Usage:
  reason_C_witness.py hf    <tag> <base_model> [adapter]     (run on the Spark in the cyberdef-train container)
  reason_C_witness.py ollama <tag> <ollama_model> [base_url]
  reason_C_witness.py --selftest [--broken]
Resumable: raw generations cached in results/reason_C_<tag>_cache.jsonl."""
import json, math, random, re, sys, time
from pathlib import Path

sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
from length_baseline import auroc, hanley_mcneil_se

import os as _os
MAXTOK = int(_os.environ.get("MAXTOK", 1200))   # pre-registered C run: 1200; C2 (format fix) sets MAXTOK=2048
GUIDED = _os.environ.get("GUIDED_SCHEMA")          # "witness" -> guided JSON decoding against schemas_cot.WITNESS
SYSTEM = ("You are a careful C/C++ security auditor. Mentally execute the function. Reply with ONLY one JSON object, "
          "no prose, no markdown, with exactly these keys: "
          '"inputs" (list of attacker-controlled inputs), "sinks" (list of {"line": int, "op": str}), '
          '"guards" (list of {"line": int, "condition": str}), "trace" (list of {"line": int, "state": str} along the '
          'path to the sink), "witness" (object mapping each input to a concrete value that triggers the bug, or null '
          'if you cannot construct one), "verdict" ("VULNERABLE" or "SAFE"), "confidence" (number 0..1). '
          "Line numbers refer to the numbered lines shown.")


def numbered(code):
    return "\n".join(f"{i+1}: {l}" for i, l in enumerate(code.split("\n")))


def parse_json(text):
    t = text.strip()
    t = re.sub(r"^```(?:json)?|```$", "", t, flags=re.M).strip()
    s = t.find("{")
    if s < 0:
        return None
    depth = 0
    for i in range(s, len(t)):
        depth += t[i] == "{"; depth -= t[i] == "}"
        if depth == 0:
            try:
                d = json.loads(t[s:i + 1])
                return d if isinstance(d, dict) else None
            except Exception:
                return None
    return None


def _ints(items, key):
    out = []
    for it in items or []:
        try:
            out.append(int(it[key]))
        except Exception:
            out.append(None)
    return out


def consistent(d, code, broken=False):
    """machine check of a witness claim: every cited line exists, each sink op appears on its cited line, trace non-empty."""
    if broken:
        return True
    lines = code.split("\n"); n = len(lines)
    try:
        trace = d.get("trace") or []
        sinks = d.get("sinks") or []
        if not trace or not sinks:
            return False
        for k in ("sinks", "guards", "trace"):
            for ln in _ints(d.get(k), "line"):
                if ln is None or not (1 <= ln <= n):
                    return False
        for s in sinks:
            line = lines[int(s["line"]) - 1].lower()
            toks = [t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(s.get("op", "")))]
            if not toks or not any(t.lower() in line for t in toks):
                return False
        return True
    except Exception:
        return False


def witness_null(d):
    w = d.get("witness") if d else None
    if w in (None, "", [], {}):
        return True
    if isinstance(w, dict):
        return all(v in (None, "", [], {}) for v in w.values())
    return False


def scores(d, code):
    if d is None or str(d.get("verdict", "")).upper() not in ("VULNERABLE", "SAFE"):
        return dict(parsed=False, verdict=None, confidence=None, witness_null=None, consistent=None, s0=.5, s1=.5, s2=.5)
    v = str(d["verdict"]).upper()
    try:
        c = min(1.0, max(0.0, float(d.get("confidence"))))
    except Exception:
        c = 0.5
    s0 = 0.5 + 0.5 * c if v == "VULNERABLE" else 0.5 - 0.5 * c
    wn = witness_null(d); ok = consistent(d, code)
    s1 = .5 if (v == "VULNERABLE" and wn) else s0
    s2 = .5 if (v == "VULNERABLE" and (wn or not ok)) else s0
    return dict(parsed=True, verdict=v, confidence=c, witness_null=wn, consistent=ok, s0=s0, s1=s1, s2=s2)


def selftest(broken):
    code = "int f(char *a) {\n  char b[8];\n  strcpy(b, a);\n  return 0;\n}"
    good = {"sinks": [{"line": 3, "op": "strcpy"}], "guards": [], "trace": [{"line": 3, "state": "overflow"}]}
    r = {"line_past_end": consistent({**good, "trace": [{"line": 99, "state": "x"}]}, code, broken),
         "sink_not_on_line": consistent({**good, "sinks": [{"line": 4, "op": "memcpy"}]}, code, broken),
         "empty_trace": consistent({**good, "trace": []}, code, broken),
         "good": consistent(good, code, broken)}
    print(json.dumps(r))


def subset():
    cases = json.load(open("results/lenmatched_eval_cases.json"))["cases"]
    pairs = sorted({c["pair"] for c in cases})
    keep = set(random.Random(0).sample(pairs, 150))
    return [c for c in cases if c["pair"] in keep]


def main():
    import os
    mode, tag = sys.argv[1], sys.argv[2]
    gen_only = os.environ.get("GEN_ONLY_CASES")          # Stage D: generate witnesses for another case file, no metrics
    cases = json.load(open(gen_only))["cases"] if gen_only else subset()
    cache_p = Path(f"results/reason_D_{tag}_castle_cache.jsonl" if gen_only else f"results/reason_C_{tag}_cache.jsonl")
    cache, meta = {}, {}
    if cache_p.exists():
        for l in cache_p.read_text().splitlines():
            r = json.loads(l); cache[r["id"] + r["label"]] = r["raw"]; meta[r["id"] + r["label"]] = (r.get("ntok"), r.get("finish"))
    if mode == "vllm":      # batched generation, same engine for every arm; records tokens used + finish reason
        from cyberdef import vllm_gen
        todo = [c for c in cases if c["id"] + c["label"] not in cache]
        if todo:
            from cyberdef.schemas_cot import SCHEMAS
            sch = SCHEMAS[GUIDED] if GUIDED else None
            dec = vllm_gen.decode_config(sch, MAXTOK)
            outs = vllm_gen.generate_all(sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None, SYSTEM,
                                         [numbered(c["code"]) for c in todo], MAXTOK, schema=sch)
            with cache_p.open("a") as f:
                for c, (t, nt, fin) in zip(todo, outs):
                    cache[c["id"] + c["label"]] = t; meta[c["id"] + c["label"]] = (nt, fin)
                    f.write(json.dumps({"id": c["id"], "label": c["label"], "raw": t, "ntok": nt, "finish": fin,
                                        "engine": vllm_gen.ENGINE, "decode": dec}) + chr(10))
        gen = None
    elif mode == "stub":      # pipeline/acceptance test only: deterministic canned replies, no model
        def gen(u):
            h = sum(map(ord, u)) % 4
            if h == 0: return "I think it is vulnerable."
            if h == 1: return json.dumps({"inputs": ["a"], "sinks": [{"line": 1, "op": "x"}], "guards": [], "trace": [], "witness": None, "verdict": "VULNERABLE", "confidence": 0.9})
            if h == 2: return json.dumps({"inputs": [], "sinks": [], "guards": [], "trace": [], "witness": None, "verdict": "SAFE", "confidence": 0.8})
            return json.dumps({"inputs": ["a"], "sinks": [{"line": 1, "op": "code"}], "guards": [], "trace": [{"line": 1, "state": "s"}], "witness": {"a": "AAAA"}, "verdict": "VULNERABLE", "confidence": 0.7})
    elif mode == "hf":
        from cyberdef import model_io
        model, tok = model_io.load_hf(sys.argv[3], adapter=sys.argv[4] if len(sys.argv) > 4 else None)
        gen = lambda u: model_io.generate(model, tok, SYSTEM, u, max_new_tokens=MAXTOK)
    else:
        from cyberdef import model_io
        url = sys.argv[4] if len(sys.argv) > 4 else "http://127.0.0.1:11434"
        gen = lambda u: model_io.ollama_chat(url, sys.argv[3], SYSTEM, u, max_new_tokens=MAXTOK)
    t0 = time.time()
    with cache_p.open("a") as f:
        for i, c in enumerate(cases):
            k = c["id"] + c["label"]
            if k in cache:
                continue
            raw = gen(numbered(c["code"]))
            cache[k] = raw
            f.write(json.dumps({"id": c["id"], "label": c["label"], "raw": raw}) + "\n"); f.flush()
            if i % 20 == 0:
                print(f"[C {tag}] {i}/{len(cases)} {time.time()-t0:.0f}s", flush=True)
    if gen_only:
        print(f"[D-gen {tag}] cached {len(cache)} generations"); return
    per = []
    for c in cases:
        raw = cache[c["id"] + c["label"]]
        per.append({"id": c["id"], "label": c["label"], "pair": c["pair"], "code_chars": c["code_chars"],
                    "raw": raw[:1500], "ntok": meta.get(c["id"] + c["label"], (None, None))[0],
                    "truncated_gen": meta.get(c["id"] + c["label"], (None, None))[1] == "length", **scores(parse_json(raw), c["code"])})
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in per]
    n1 = sum(y); n0 = len(y) - n1
    res = {"stage": "C", "tag": tag, "backend": mode, "model": sys.argv[3], "adapter": sys.argv[4] if mode == "hf" and len(sys.argv) > 4 else None,
           "n": len(per), "parse_rate": round(sum(p["parsed"] for p in per) / len(per), 4), "auroc": {}, "se_hm": {}, "accuracy": {}}
    for k in ("s0", "s1", "s2"):
        a = auroc([p[k] for p in per], y)
        res["auroc"][k] = round(a, 4); res["se_hm"][k] = round(hanley_mcneil_se(a, n1, n0), 4)
        res["accuracy"][k] = round(sum((p[k] >= .5) == bool(yy) and p[k] != .5 for p, yy in zip(per, y)) / len(per), 4)
    nt = [p["ntok"] for p in per if p["ntok"] is not None]
    res["tokens_used"] = {"max_new_tokens": MAXTOK, "mean": round(sum(nt) / len(nt), 1) if nt else None, "max": max(nt) if nt else None,
                          "frac_truncated_at_limit": round(sum(p["truncated_gen"] for p in per) / len(per), 4)}
    res["frac_vuln_verdict"] = round(sum(p["verdict"] == "VULNERABLE" for p in per) / len(per), 4)
    res["frac_vuln_with_null_witness"] = round(sum(bool(p["witness_null"]) and p["verdict"] == "VULNERABLE" for p in per) / max(1, sum(p["verdict"] == "VULNERABLE" for p in per)), 4)
    res["frac_vuln_inconsistent"] = round(sum(p["consistent"] is False and p["verdict"] == "VULNERABLE" for p in per) / max(1, sum(p["verdict"] == "VULNERABLE" for p in per)), 4)
    byp = {}
    for p in per:
        byp.setdefault(p["pair"], {})[1 if p["label"] == "VULNERABLE" else 0] = p
    for k in ("s0", "s1", "s2"):
        w = [(1 if v[1][k] > v[0][k] else .5 if v[1][k] == v[0][k] else 0) for v in byp.values()]
        res.setdefault("pairwise_win_rate", {})[k] = round(sum(w) / len(w), 4)
    ch = sorted(p["code_chars"] for p in per); cuts = [ch[len(ch) * q // 4] for q in (1, 2, 3)]
    q = {}
    for i, p in enumerate(per):
        q.setdefault(sum(p["code_chars"] > t for t in cuts), []).append(i)
    res["within_length_quartile"] = {k: {f"Q{j+1}": round(auroc([per[i][k] for i in v], [y[i] for i in v]), 4)
                                         for j, v in sorted(q.items())} for k in ("s0", "s1", "s2")}
    ids = {p["id"] + p["label"] for p in per}
    comp = {}
    for name, f in (("length_only", None), ("logprob_pub7b", "results/ab_pub7b__lenmatched.json"),
                    ("logprob_base7b", "results/ab_base7b__lenmatched.json"),
                    ("sast_flawfinder", "results/reason_B_sast_flawfinder_matched.json"),
                    ("sast_semgrep", "results/reason_B_sast_semgrep_matched.json")):
        if f is None:
            a = auroc([c["code_chars"] for c in cases], y)
        else:
            if not Path(f).exists():
                continue
            rows = [r for r in json.load(open(f))["per_case"] if r["id"] + r["label"] in ids]
            if len(rows) != len(per):
                continue
            sk = "p_vuln" if "p_vuln" in rows[0] else "score"
            a = auroc([r[sk] for r in rows], [1 if r["label"] == "VULNERABLE" else 0 for r in rows])
        comp[name] = {"auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, n0), 4)}
    res["comparators_same_cases"] = comp
    res["per_case"] = per
    Path(f"results/reason_C_{tag}_matched.json").write_text(json.dumps(res))
    print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest("--broken" in sys.argv)
    else:
        main()
