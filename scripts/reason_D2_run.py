"""Stage D amendment 2: D0 floor and witness execution under the shared multi-variant oracle spec, with MY harness (src/cyberdef/exec_oracle.py).
  reason_D2_run.py d0 [workers] | wit <tag> [workers] | report
Earlier crash-only results (reason_D0_castle_preflight_v2.json, reason_D_<tag>_castle.json) are kept and untouched."""
import json, sys, os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import exec_oracle as eo, exec_harness as eh
from imp_oracle import group_of
from reason_C_witness import parse_json, witness_null
from length_baseline import auroc, hanley_mcneil_se

cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
mode = sys.argv[1]


def D0(c):
    r1 = eo.analyze(c["code"], [], "")
    r2 = eo.analyze(c["code"], ["in.txt"], "") if "argv[1]" in c["code"] else None
    cls = sorted(set(r1["classes"]) | set(r2["classes"] if r2 else []))
    return {"id": c["id"], "label": c["label"], "group": group_of(c["id"]), "confirmed": bool(cls), "classes": cls,
            "confirmed_stdin_only": r1["confirmed"], "compiled_any": r1["any_compiled"],
            "compiled": {v: r1["variants"][v]["compiled"] for v in r1["variants"]}, "image": r1["image"]}


def WIT(tag):
    cache = {}
    for l in Path(f"results/reason_D_{tag}_castle_cache.jsonl").read_text().splitlines():
        r = json.loads(l); cache[r["id"] + r["label"]] = r["raw"]
    def one(c):
        d = parse_json(cache[c["id"] + c["label"]]); verdict = str(d.get("verdict", "")).upper() if d else None
        parsed = verdict in ("VULNERABLE", "SAFE"); wn = True if not parsed else witness_null(d)
        row = {"id": c["id"], "label": c["label"], "group": group_of(c["id"]), "parsed": parsed, "verdict": verdict, "witness_null": wn,
               "executed": False, "oracle_fired": False, "confirmed": False, "classes": [], "compiled_any": None}
        if parsed and not wn:
            argv, stdin = eh.witness_to_input(d.get("witness"))
            r = eo.analyze(c["code"], argv, stdin)
            row.update(executed=r["any_compiled"], oracle_fired=r["confirmed"], classes=r["classes"], compiled_any=r["any_compiled"],
                       confirmed=bool(verdict == "VULNERABLE" and r["confirmed"]), image=r["image"])
        return row
    return WIT_run(one)


def WIT_run(one):
    with ThreadPoolExecutor(WORKERS) as ex:
        return list(ex.map(one, cases))


WORKERS = int(sys.argv[-1]) if sys.argv[-1].isdigit() else 4
if mode == "d0":
    with ThreadPoolExecutor(WORKERS) as ex:
        per = list(ex.map(D0, cases))
    json.dump({"image": per[0]["image"], "oracle": "results/imp_castle_oracle_spec.json (own implementation)", "per_case": per},
              open(os.environ.get("D0_OUT", "results/reason_D0_spec_mine.json"), "w"))
    print("d0 done", sum(p["confirmed"] for p in per))
elif mode == "wit":
    tag = sys.argv[2]
    per = WIT(tag)
    json.dump({"tag": tag, "oracle": "results/imp_castle_oracle_spec.json (own implementation)", "per_case": per}, open(f"results/reason_D2_{tag}_castle.json", "w"))
    print("wit done", tag, sum(p["confirmed"] for p in per))
else:
    mine = {(p["id"], p["label"]): p for p in json.load(open("results/reason_D0_spec_mine.json"))["per_case"]}
    bld = {(p["id"], p["label"]): p for p in json.load(open("results/imp_2o_floor_b60.json"))["per_case"]}
    def st(rows, key):
        y = [1 if r["label"] == "VULNERABLE" else 0 for r in rows]; n1 = sum(y)
        if n1 in (0, len(y)):
            return None
        a = auroc([1.0 if key(r) else 0.0 for r in rows], y)
        return {"n_vuln": n1, "n_safe": len(y) - n1, "vuln_hit": sum(1 for r, v in zip(rows, y) if v and key(r)),
                "safe_hit": sum(1 for r, v in zip(rows, y) if not v and key(r)), "auroc": round(a, 3), "se": round(hanley_mcneil_se(a, n1, len(y) - n1), 3)}
    out = {"floor_mine": {}, "floor_builder": {}, "disagree": [], "false_positives_mine": [], "models": {}}
    for g in ("a", "b", "c", "ALL"):
        rows = [p for p in mine.values() if g == "ALL" or p["group"] == g]
        out["floor_mine"][g] = st(rows, lambda p: p["confirmed"])
        out["floor_builder"][g] = st([dict(label=p["label"], confirmed=bld[k]["confirmed"]) for k, p in mine.items() if g == "ALL" or p["group"] == g],
                                     lambda p: p["confirmed"])
    for k, p in mine.items():
        if p["confirmed"] != bld[k]["confirmed"]:
            out["disagree"].append({"id": k[0], "label": k[1], "group": p["group"], "mine": p["confirmed"], "mine_classes": p["classes"],
                                    "builder": bld[k]["confirmed"], "builder_classes": bld[k]["counted_classes"]})
        if p["confirmed"] and p["label"] == "SAFE":
            out["false_positives_mine"].append({"id": k[0], "group": p["group"], "classes": p["classes"]})
    for tag in ("base7b", "tuned7b"):
        f = Path(f"results/reason_D2_{tag}_castle.json")
        if not f.exists():
            continue
        ex = {(p["id"], p["label"]): p for p in json.load(open(f))["per_case"]}
        res = {}
        for g in ("a", "b", "c", "ALL"):
            ks = [k for k in ex if g == "ALL" or ex[k]["group"] == g]
            rows = [dict(label=k[1], conf=ex[k]["confirmed"], floor=mine[k]["confirmed"]) for k in ks]
            res[g] = {"model": st(rows, lambda p: p["conf"]), "union": st(rows, lambda p: p["conf"] or p["floor"]),
                      "new_beyond_floor": sum(1 for r in rows if r["label"] == "VULNERABLE" and r["conf"] and not r["floor"]),
                      "both": sum(1 for r in rows if r["label"] == "VULNERABLE" and r["conf"] and r["floor"]),
                      "floor_only": sum(1 for r in rows if r["label"] == "VULNERABLE" and not r["conf"] and r["floor"]),
                      "false_confirmations_safe": [k[0] for k in ks if k[1] == "SAFE" and ex[k]["confirmed"]]}
        vv = [ex[k] for k in ex if k[1] == "VULNERABLE"]
        res["right_verdict_wrong_witness"] = {"n": sum(1 for p in vv if p["verdict"] == "VULNERABLE" and not p["witness_null"] and not p["confirmed"]),
                                              "of_vulnerable_verdicts_on_vulnerable": sum(1 for p in vv if p["verdict"] == "VULNERABLE")}
        out["models"][tag] = res
    json.dump(out, open("results/reason_D2_report.json", "w"), indent=1)
    print("FLOOR mine   ", json.dumps(out["floor_mine"]))
    print("FLOOR builder", json.dumps(out["floor_builder"]))
    print("disagreements", len(out["disagree"])); [print("  ", d) for d in out["disagree"]]
    print("FP mine", out["false_positives_mine"])
    for t, r in out["models"].items():
        print("MODEL", t)
        for g in ("a", "b", "c", "ALL"):
            x = r[g]; print("  ", g, "model", x["model"], "| union", x["union"], "| new", x["new_beyond_floor"], "both", x["both"], "floor-only", x["floor_only"], "| FP", x["false_confirmations_safe"])
        print("   right-verdict-wrong-witness", r["right_verdict_wrong_witness"])
