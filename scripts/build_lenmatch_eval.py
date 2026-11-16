"""Build the LENGTH-MATCHED held-out eval set from PrimeVul TEST and run the fail-first control:
length-only AUROC on the matched set must be ~0.5 (within [0.45, 0.55]) or this script exits 1.
Also prints the same length AUROC on the ORIGINAL unmatched n=1000 sample (must be high, ~0.8) to
show the control is able to fail. Writes results/lenmatched_eval_cases.json (selective_eval
--cases-file format) and results/lenmatched_eval_control.json."""
from __future__ import annotations
import argparse, json, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from transformers import AutoTokenizer
from cyberdef import benchdata as b, lenmatch
from length_baseline import auroc, hanley_mcneil_se


def len_aurocs(cases):
    labels = [1 if c["label"] == "VULNERABLE" else 0 for c in cases]
    n1, n0 = sum(labels), len(labels) - sum(labels)
    feats = {"chars_seen_by_model": [len(c["code"]) for c in cases],
             "chars_full_function": [c["code_chars"] for c in cases],
             "tokens_full_function": [c["toks"] for c in cases],
             "lines_full_function": [c["lines"] for c in cases]}
    out = {}
    for k, v in feats.items():
        a = auroc(v, labels)
        out[k] = {"auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, n0), 4)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--tol", type=float, default=0.03)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--out-cases", default="results/lenmatched_eval_cases.json")
    ap.add_argument("--out-control", default="results/lenmatched_eval_control.json")
    a = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(a.base)
    sp = b.spec("primevul")
    ds = b._load_split(sp, "test")
    seen, labs = {}, {}
    for r in ds:
        h = b.norm(r["func"] or "")
        labs.setdefault(h, set()).add(int(r["target"]))
        seen.setdefault(h, r)
    rows = [dict(id=str(r["idx"]), code=r["func"] or "", project=r["project"], y=int(r["target"]))
            for h, r in seen.items() if len(labs[h]) == 1]
    print(f"[eval] test rows={len(ds)} after dedup/conflict-drop={len(rows)}", flush=True)
    lenmatch.attach_len(rows, tok)
    vul = [r for r in rows if r["y"] == 1]
    saf = [r for r in rows if r["y"] == 0]
    pairs, dropped = lenmatch.match_pairs(vul, saf, tok, a.tol, a.seed)
    print(f"[eval] vulnerable={len(vul)} safe_pool={len(saf)} matched_pairs={len(pairs)} dropped_vuln={len(dropped)}", flush=True)

    def mk(r, pid):
        return dict(id=r["id"], code=r["code"][:a.max_chars], code_chars=r["chars"], truncated=r["chars"] > a.max_chars,
                    label="VULNERABLE" if r["y"] else "SAFE", pair=pid, project=r["project"],
                    toks=r["toks"], lines=r["code"].count("\n") + 1)
    cases = []
    for i, (v, s) in enumerate(pairs):
        cases += [mk(v, i), mk(s, i)]
    import random
    random.Random(a.seed).shuffle(cases)
    ctl = len_aurocs(cases)
    print("[control] length-only AUROC on MATCHED eval:", json.dumps(ctl), flush=True)

    # can-fail check: same metric on the ORIGINAL unmatched n=1000 balanced sample (seed 0)
    orig, _ = b.balanced_sample("primevul", "test", 500, 0, a.max_chars)
    o = {r["id"]: r for r in rows}
    for c in orig:
        r = o.get(c["id"])
        src = r["code"] if r else c["code"]
        c["toks"] = (r["toks"] if r and r["toks"] else max(1, len(tok(src, add_special_tokens=False)["input_ids"])))
        c["lines"] = src.count("\n") + 1
    ctl_orig = len_aurocs(orig)
    print("[control] length-only AUROC on ORIGINAL unmatched n=1000:", json.dumps(ctl_orig), flush=True)

    sizes = {"chars": [(len(c["code"]) if False else c["code_chars"]) for c in cases]}
    ok = all(0.45 <= v["auroc"] <= 0.55 for v in ctl.values())
    res = dict(tol=a.tol, seed=a.seed, n_pairs=len(pairs), n_cases=len(cases), dropped_vuln=len(dropped),
               n_vuln_pool=len(vul), n_safe_pool=len(saf), control_matched=ctl, control_original_n1000=ctl_orig,
               control_pass=ok, projects=len({c["project"] for c in cases}))
    json.dump(res, open(a.out_control, "w"), indent=2)
    json.dump(dict(cases=cases, pool=dict(n_pairs=len(pairs), tol=a.tol), split="test", seed=a.seed),
              open(a.out_cases, "w"))
    print(f"[control] PASS={ok} -> {a.out_control}; cases -> {a.out_cases}", flush=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
