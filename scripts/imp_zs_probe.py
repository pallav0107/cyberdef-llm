"""PHASE 1 zero-shot DETECTOR probe of a reasoning model served by the Spark Ollama (http://localhost:11434), thinking enabled. Runs on the Spark HOST (urllib only).
Prompt: the repo standard detector prompt (same user text as every other zero-shot scorer) + one line asking for a CONFIDENCE. Score p_vuln = 0.5+0.5*c for VULNERABLE, 0.5-0.5*c for SAFE, 0.5 for an unparsed
answer (counted and reported, never dropped); missing confidence -> c = 0.5. temperature 0, num_ctx 8192, num_predict --num-predict (thinking + answer must fit; truncation -> unparsed).
Output (selective_eval schema + extras): results/imp_zs_<tag>_<set>.json with per_case, n == len(per_case). The model is unloaded afterwards (keep_alive 0) so the GPU queue is not blocked.
  python3 scripts/imp_zs_probe.py --model gpt-oss:20b --tag gptoss20b --think medium --cases-file results/lenmatched_eval_cases.json --set pv --out results/imp_zs_gptoss20b_pv.json"""
import argparse, json, math, os, re, sys, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

SYSTEM = ("You are a meticulous secure-code reviewer. You are given one code snippet. Decide whether it contains a security vulnerability. "
          "Answer with exactly one line 'VERDICT: VULNERABLE' or 'VERDICT: SAFE'. Then add one line 'CONFIDENCE: <a number between 0 and 1: your probability that your verdict is correct>'. "
          "If vulnerable, add a line 'CWE: <name>'. Do not output anything else.")


def make_user(code):
    return f"```python\n{code}\n```\nIs this code vulnerable?"


def auroc(scores, labels):
    n1 = sum(labels); n0 = len(labels) - n1
    if not n1 or not n0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i]); ranks = [0.0] * len(scores); i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return (sum(ranks[i] for i in range(len(scores)) if labels[i]) - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def hm_se(a, n1, n0):
    q1, q2 = a / (2 - a), 2 * a * a / (1 + a)
    return math.sqrt(max((a * (1 - a) + (n1 - 1) * (q1 - a * a) + (n0 - 1) * (q2 - a * a)) / (n1 * n0), 0.0))


def chat(url, model, system, user, think, num_predict, keep_alive):
    body = {"model": model, "stream": False, "keep_alive": keep_alive,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0, "num_predict": num_predict, "num_ctx": 8192}}
    if think:
        body["think"] = True if think == "true" else think
    req = urllib.request.Request(url.rstrip("/") + "/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as r:
        return json.loads(r.read())


def parse(text):
    vs = re.findall(r"VERDICT:\s*\**\s*(VULNERABLE|SAFE)", text or "", re.I)
    cs = re.findall(r"CONFIDENCE:\s*\**\s*([0-9]*\.?[0-9]+)", text or "", re.I)
    v = vs[-1].upper() if vs else None
    c = min(1.0, max(0.0, float(cs[-1]))) if cs else None
    if c is not None and c > 1.0:
        c = 1.0
    return v, c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--think", default="true", help="true | low | medium | high | off")
    ap.add_argument("--cases-file", required=True)
    ap.add_argument("--set", default="pv")
    ap.add_argument("--out", required=True)
    ap.add_argument("--url", default="http://localhost:11434")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--num-predict", type=int, default=3000)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    assert "ablit" not in a.model.lower()
    cf = json.load(open(a.cases_file))
    cases = cf["cases"][:a.limit] if a.limit else cf["cases"]
    cache_p = a.out + ".cache.jsonl"
    cache = {}
    if os.path.exists(cache_p):
        for l in open(cache_p):
            r = json.loads(l); cache[r["key"]] = r
    lock = threading.Lock(); t0 = time.time(); done = [0]
    think = None if a.think == "off" else a.think

    def one(c):
        key = c["id"] + "|" + c["label"]
        if key in cache:
            return cache[key]
        try:
            r = chat(a.url, a.model, SYSTEM, make_user(c["code"]), think, a.num_predict, "10m")
            m = r.get("message", {})
            rec = {"key": key, "content": (m.get("content") or "")[:1500], "think_chars": len(m.get("thinking") or ""), "ntok": r.get("eval_count"), "done_reason": r.get("done_reason"),
                   "secs": round((r.get("total_duration") or 0) / 1e9, 1)}
        except Exception as e:
            rec = {"key": key, "content": "", "think_chars": 0, "ntok": None, "done_reason": "error:" + repr(e)[:80], "secs": 0}
        with lock:
            cache[key] = rec; done[0] += 1
            open(cache_p, "a").write(json.dumps(rec) + "\n")
            if done[0] % 20 == 0:
                print(f"[zs {a.tag}] {done[0]}/{len(cases)} {time.time()-t0:.0f}s", flush=True)
        return rec
    with ThreadPoolExecutor(a.workers) as ex:
        recs = list(ex.map(one, cases))
    per, sc, y = [], [], []
    for c, r in zip(cases, recs):
        v, conf = parse(r["content"])
        p = 0.5 if v is None else (0.5 + 0.5 * (0.5 if conf is None else conf) if v == "VULNERABLE" else 0.5 - 0.5 * (0.5 if conf is None else conf))
        pred = "VULNERABLE" if p >= 0.5 and v == "VULNERABLE" else "SAFE"
        per.append({"id": c["id"], "label": c["label"], "pred": pred, "p_vuln": round(p, 6), "conf": round(max(p, 1 - p), 6), "correct": int(pred == c["label"]), "verdict_raw": v,
                    "confidence_raw": conf, "parsed": v is not None, "ntok": r["ntok"], "think_chars": r["think_chars"], "done_reason": r["done_reason"], "secs": r["secs"]})
        sc.append(p); y.append(1 if c["label"] == "VULNERABLE" else 0)
    n = len(per); n1 = sum(y); au = auroc(sc, y)
    res = {"experiment": "imp_zs_probe", "model": a.model, "tag": a.tag, "think": a.think, "engine": "ollama (GGUF)", "set": a.set, "cases_file": a.cases_file, "n": n, "n_vuln": n1,
           "num_predict": a.num_predict, "temperature": 0, "parse_rate": round(sum(p["parsed"] for p in per) / n, 4),
           "truncated_or_error": sum(1 for p in per if p["done_reason"] != "stop"), "accuracy": round(sum(p["correct"] for p in per) / n, 4),
           "auroc": round(au, 4) if au is not None else None, "se_hm": round(hm_se(au, n1, n - n1), 4) if au is not None else None,
           "mean_ntok": round(sum(p["ntok"] or 0 for p in per) / n, 1), "seconds": round(time.time() - t0), "pool": cf.get("pool", {}), "per_case": per,
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    json.dump(res, open(a.out, "w"))
    try:
        chat(a.url, a.model, "x", "x", None, 1, 0)       # unload (keep_alive 0) so the GPU queue is not blocked by a resident model
    except Exception:
        pass
    print(json.dumps({k: v for k, v in res.items() if k not in ("per_case", "pool")}))


if __name__ == "__main__":
    main()
