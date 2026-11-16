#!/usr/bin/env python3
"""Amendment 3 (+3a): training items for ONE self-training round of ONE category, from a trace bank written by the current
model on results/st_pool_<category>.json.
  keep a VULNERABLE trace only if V, P, K and O all hold, and X_strict holds wherever the execution check applies
      (X_strict is None when no oracle covers the function, e.g. real-world pool A; then V+P+K+O decides);
  keep a SAFE trace only if V and P hold;
  one trace per function: the first kept sample in sample order (X_strict-confirmed first for vulnerable functions);
  balance the classes by drawing the larger one down to the smaller with random.Random(0);
  write results/<tag>_items.json (CoT items) and results/<tag>_twin_items.json (verdict-only, identical rows).
  python3 scripts/imp_st_items.py --bank results/st_bank_cmd_injection_r1.jsonl --category cmd_injection --tag st_cmd_r1"""
import argparse, json, os, random, sys

sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S            # noqa: E402
from reason_C_witness import numbered, parse_json   # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bank", required=True)
    ap.add_argument("--category", required=True)
    ap.add_argument("--tag", required=True)
    a = ap.parse_args()
    pool = {it["id"]: it for it in json.load(open(f"results/st_pool_{a.category}.json"))["items"]}
    rows = [json.loads(l) for l in open(a.bank)]
    rows = [r for r in rows if r.get("edit") == "orig" and r["fn"] in pool]
    rows.sort(key=lambda r: (r["fn"], r.get("sample", 0)))
    best, seen = {}, {"VULNERABLE": 0, "SAFE": 0}
    stats = {"traces": len(rows), "kept_traces": 0, "x_strict_confirmed": 0}
    for r in rows:
        lab = pool[r["fn"]]["label"]
        if lab == "VULNERABLE":
            x = r.get("X_strict")
            ok = bool(r.get("V") and r.get("P") and r.get("K") is True and r.get("O") is True and (x is None or x is True))
        else:
            ok = bool(r.get("V") and r.get("P"))
        if not ok:
            continue
        stats["kept_traces"] += 1
        cur = best.get(r["fn"])
        better = cur is None or (lab == "VULNERABLE" and r.get("X_strict") is True and cur.get("X_strict") is not True)
        if better:
            best[r["fn"]] = r
    vul = sorted(f for f in best if pool[f]["label"] == "VULNERABLE")
    saf = sorted(f for f in best if pool[f]["label"] == "SAFE")
    stats.update(functions_kept_vulnerable=len(vul), functions_kept_safe=len(saf),
                 x_strict_confirmed=sum(1 for f in vul if best[f].get("X_strict") is True))
    # addendum 3k: balance classes WITHIN source (Juliet vs real-world), never globally. X_strict drops most Juliet vulnerable
    # traces (their programs crash on empty input), so global balancing would make source predict the label.
    src = lambda f: "juliet" if str(f).startswith(("juliet:", "juliet2:", "juliet3:")) else "other"
    rng = random.Random(0)
    table, vv, ss = {}, [], []
    for s_ in ("juliet", "other"):
        v_ = [f for f in vul if src(f) == s_]; s2 = [f for f in saf if src(f) == s_]
        k = min(len(v_), len(s2))
        table[s_] = {"vulnerable_kept_fns": len(v_), "safe_kept_fns": len(s2), "items_per_class": k}
        vv += sorted(rng.sample(v_, k)); ss += sorted(rng.sample(s2, k))
    vul, saf = vv, ss
    n = len(vul)
    stats.update(balance="within source (addendum 3k)", source_table=table)
    cot, twin = [], []
    for f in vul + saf:
        it, r = pool[f], best[f]
        code = it["code"]
        base = dict(id=f, code=code, code_chars=len(code), toks=max(1, len(code) // 3), label=it["label"], project=it.get("project"), pair=it.get("pair"), rank=False)
        d = parse_json(r["raw"])
        cot.append(dict(base, system=S.SYSTEM, user=numbered(code), target=json.dumps(d, ensure_ascii=False), gen=r.get("gen")))
        twin.append(dict(base))
    stats.update(items_per_class=n, items=len(cot))
    note = f"amendment 3 self-training, category {a.category}, bank {os.path.basename(a.bank)}"
    json.dump({"items": cot, "n": len(cot), "note": note, "stats": stats}, open(f"results/{a.tag}_items.json", "w"))
    json.dump({"items": twin, "n": len(twin), "note": "verdict-only twin of " + note + " (same rows, same order)", "stats": stats},
              open(f"results/{a.tag}_twin_items.json", "w"))
    print(json.dumps(stats))
    if n == 0:
        raise SystemExit("no balanced items: nothing to train for this round")


if __name__ == "__main__":
    main()
