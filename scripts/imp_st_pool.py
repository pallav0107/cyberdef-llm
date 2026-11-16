#!/usr/bin/env python3
"""Amendment 3: the training functions of ONE monitor category, as a trace-bank pool (results/st_pool_<category>.json,
read by imp_trace_bank.py as --pools ST:<category>). A vulnerable function belongs to a category when its true CWE
(results/imp_true_cwe.json) is in the category; its fixed partner (the adjacent item with the same pair) comes with it.
Sources: pool A (real-world VulSpot pairs), J, J2, J3 (training 500), and the SQLi TRAINING split only. The held-out tests
(J3 held-out, SQLi held-out, J4) are disjoint by construction; this script also refuses any overlap.
  python3 scripts/imp_st_pool.py cmd_injection"""
import glob, hashlib, json, random, re, sys
sys.path.insert(0, "scripts")
import imp_build_structure_matched as SM   # noqa: E402  (addendum 3j)

CATS = {"cmd_injection": {78}, "path_traversal": {22, 23, 36}, "sqli": {89}, "format_string": {134},
        "memory": {119, 120, 121, 122, 124, 125, 126, 127, 131, 193, 415, 416, 476, 590, 761, 787, 805, 822, 843},
        "integer": {190, 191, 369, 680}, "leak": {401}, "resource": {400, 770, 835, 674}, "race": {362, 366, 367}}
SOURCES = ["imp_train_pairs_items.json", "imp_train_juliet_items.json", "imp_train_juliet2_items.json",
           "imp_train_juliet3_items.json", "imp_train_sqli_train_items.json"]
HELDOUT = ["j3_heldout_cases.json", "q_heldout_cases.json", "j4_heldout_matched_cases.json", "j3_heldout_matched_cases.json",
           "j3s_heldout_matched_cases.json", "j4s_heldout_matched_cases.json"]


def main():
    # addendum 3j options (defaults unchanged): --structure normalises Juliet pairs like J4s (one good variant per safe text,
    # static removed, names renumbered; flow variants _21/_22 dropped); --cap N keeps every Juliet pair and fills the rest
    # with the other pairs drawn by random.Random(0) (Juliet first: the primary tests are Juliet-based and only they have an
    # execution oracle). Pass the category first.
    structure = "--structure" in sys.argv
    cap = int(sys.argv[sys.argv.index("--cap") + 1]) if "--cap" in sys.argv else 0
    cat = sys.argv[1]
    if cat not in CATS:
        raise SystemExit(f"unknown category {cat}; one of {sorted(CATS)}")
    true = json.load(open("results/imp_true_cwe.json"))
    norm = lambda s: " ".join(s.split())
    h = lambda s: hashlib.sha256(norm(s).encode()).hexdigest()
    held = set()
    for f in HELDOUT:
        try:
            d = json.load(open("results/" + f))
            held |= {h(c["code"]) for c in (d["cases"] if isinstance(d, dict) else d)}
        except FileNotFoundError:
            pass
    # addendum 3b: a function whose Juliet source file supplies a few-shot exemplar is never a training item
    exfiles = {e["source_file"] for f in glob.glob("results/imp_fewshot_exemplars*.json") for e in json.load(open(f))["exemplars"]}
    out, by_src, ex_dropped, st_dropped, hc_dropped = [], {}, 0, 0, 0
    for src in SOURCES:
        try:
            items = json.load(open("results/" + src))["items"]
        except FileNotFoundError:
            continue
        for i in range(len(items) - 1):
            v, s = items[i], items[i + 1]
            if v["label"] != "VULNERABLE" or s["label"] != "SAFE" or v.get("pair") != s.get("pair"):
                continue
            if not (set(true.get(v["id"], [])) & CATS[cat]):
                continue
            if any(x in v["id"] or x in s["id"] for x in exfiles):
                ex_dropped += 1
                continue
            if h(v["code"]) in held or h(s["code"]) in held:
                raise SystemExit(f"REFUSED: {v['id']} or its partner appears in a held-out test")
            if structure and str(v["id"]).startswith(("juliet:", "juliet2:", "juliet3:")):
                key = v["id"].split(":")[1]
                good = None if re.search(r"_2[12][a-z]?\.(?:c|cpp)$", key) else SM.one_good(s["code"], key)
                if good is None:
                    st_dropped += 1
                    continue
                v = dict(v, code=SM.normalise(v["code"]), structure_3j=True); s = dict(s, code=SM.normalise(good), structure_3j=True)
                for x in (v, s):
                    x["code_chars"] = len(x["code"]); x["toks"] = max(1, len(x["code"]) // 3)
                if h(v["code"]) in held or h(s["code"]) in held:   # 3l: a normalised near-duplicate of a held-out case leaves training
                    hc_dropped += 1
                    continue
            out += [v, s]
            by_src[src] = by_src.get(src, 0) + 1
    capped_from = None
    if cap and len(out) // 2 > cap:
        pairs = [out[k:k + 2] for k in range(0, len(out), 2)]
        jul = [pp for pp in pairs if str(pp[0]["id"]).startswith(("juliet:", "juliet2:", "juliet3:"))]
        rest = [pp for pp in pairs if pp not in jul]
        rng = random.Random(0)
        if len(jul) >= cap:
            keep = rng.sample(range(len(jul)), cap); chosen = [jul[k] for k in sorted(keep)]
        else:
            keep = rng.sample(range(len(rest)), cap - len(jul)); chosen = jul + [rest[k] for k in sorted(keep)]
        capped_from = len(pairs)
        out = [x for pp in chosen for x in pp]
        by_src = {}
        for pp in chosen:
            src = "juliet" if str(pp[0]["id"]).startswith(("juliet:", "juliet2:", "juliet3:")) else "other"
            by_src[src] = by_src.get(src, 0) + 1
    json.dump({"items": out, "category": cat, "pairs_by_source": by_src, "exemplar_file_pairs_dropped": ex_dropped,
               "structure_3j": structure, "structure_dropped_pairs": st_dropped, "heldout_collision_dropped_pairs": hc_dropped, "cap_3j": cap or None, "capped_from_pairs": capped_from,
               "note": "amendment 3 self-training pool: vulnerable functions whose true CWE is in the category, with their fixed partners"},
              open(f"results/st_pool_{cat}.json", "w"))
    print(json.dumps({"category": cat, "pairs": len(out) // 2, "by_source": by_src, "exemplar_file_pairs_dropped": ex_dropped,
                      "structure": structure, "structure_dropped_pairs": st_dropped, "heldout_collision_dropped": hc_dropped, "cap": cap or None, "capped_from_pairs": capped_from}))


if __name__ == "__main__":
    main()
