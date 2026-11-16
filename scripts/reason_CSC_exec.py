"""Execute C-SC (schema v2) CASTLE witnesses under oracle spec v2 with my harness (src/cyberdef/exec_oracle.py).
Usage: reason_CSC_exec.py <tag> [workers]   reads results/reason_CSC_<tag>_castle_cache.jsonl, floor from results/reason_D0_spec2_mine.json
Witness -> input via the fixed feed parser src/cyberdef/feed.py (amendment 3b): env / file / argv / stdin / unparseable (stdin fallback, counted).
Reported per group (a/b/c from imp_oracle.group_of) and per CWE: confirmed by the CHOSEN oracle, new beyond the floor, false positives on safe programs,
class accuracy (exact, group), oracle-selection accuracy (vs the fixed CWE->oracle map applied to the true CWE), static-evidence-valid count for oracle none."""
import json, re, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import exec_oracle as eo, sc_cot as S
from cyberdef.feed import parse_feed, CHANNELS
from cyberdef.cwe_oracle import CWE_ORACLE
from imp_oracle import group_of
from reason_C_witness import parse_json
from length_baseline import auroc, hanley_mcneil_se

tag = sys.argv[1]; W = int(sys.argv[2]) if len(sys.argv) > 2 else 4
cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
floor = {(p["id"], p["label"]): p["confirmed"] for p in json.load(open("results/reason_D0_spec2_mine.json"))["per_case"]}
cache = {}
for l in Path(f"results/reason_CSC_{tag}_castle_cache.jsonl").read_text().splitlines():
    r = json.loads(l); cache[r["id"] + r["label"]] = r["raw"]


def one(c):
    true_cwe = int(re.match(r"CASTLE-(\d+)-", c["id"]).group(1))
    d = parse_json(cache[c["id"] + c["label"]])
    row = {"id": c["id"], "label": c["label"], "group": group_of(c["id"]), "true_cwe": true_cwe, "parsed": False, "valid": False, "verdict": None,
           "vuln_cwe": None, "oracle": None, "oracle_expected": CWE_ORACLE.get(true_cwe), "executed": False, "confirmed_chosen": False,
           "confirmed_any": False, "classes": [], "static_evidence_valid": False, "errors": [], "channel": None}
    if d is None:
        return row
    v = S.validate(d, c["code"])
    row.update(parsed=v["verdict_raw"] is not None, valid=v["valid"], verdict=v["verdict_raw"], vuln_cwe=v.get("cwe_id"), oracle=v.get("oracle"), errors=v["errors"][:4])
    if v["verdict_raw"] == "VULNERABLE" and v.get("oracle") == "none":
        row["static_evidence_valid"] = bool(v["has_witness"])
    elif v["verdict_raw"] == "VULNERABLE" and isinstance(d.get("witness"), dict) and v.get("oracle") in eo.ROUTING:
        fd = parse_feed(d["witness"], c["code"])
        r = eo.analyze(c["code"], fd["argv"], fd["stdin"], env=fd["env"], files=fd["files"])
        row.update(channel=fd["channel"], file_write_failed=r.get("file_write_failed", False),executed=r["any_compiled"], confirmed_any=r["confirmed"], classes=r["classes"],
                   confirmed_chosen=eo.routed_confirmed(r, v["oracle"]))
    return row


with ThreadPoolExecutor(W) as ex:
    per = list(ex.map(one, cases))


def st(rows, key):
    y = [1 if r["label"] == "VULNERABLE" else 0 for r in rows]; n1 = sum(y)
    if n1 in (0, len(y)):
        return None
    a = auroc([1.0 if key(r) else 0.0 for r in rows], y)
    return {"n_vuln": n1, "n_safe": len(y) - n1, "vuln_hit": sum(1 for r, v in zip(rows, y) if v and key(r)), "safe_hit": sum(1 for r, v in zip(rows, y) if not v and key(r)),
            "auroc": round(a, 3), "se": round(hanley_mcneil_se(a, n1, len(y) - n1), 3)}


out = {"tag": tag, "oracle_spec": "v2 (own implementation)", "n": len(per), "parsed": sum(p["parsed"] for p in per), "valid": sum(p["valid"] for p in per), "groups": {}, "by_cwe": {}}
for g in ("a", "b", "c", "ALL"):
    rows = [p for p in per if g == "ALL" or p["group"] == g]
    vv = [p for p in rows if p["label"] == "VULNERABLE"]
    cls = [p for p in vv if p["vuln_cwe"] is not None]
    out["groups"][g] = {"chosen_oracle": st(rows, lambda p: p["confirmed_chosen"]),
                        "union_with_floor": st(rows, lambda p: p["confirmed_chosen"] or floor[(p["id"], p["label"])]),
                        "floor": st(rows, lambda p: floor[(p["id"], p["label"])]),
                        "new_beyond_floor": sum(1 for p in vv if p["confirmed_chosen"] and not floor[(p["id"], p["label"])]),
                        "false_positives_safe": [p["id"] for p in rows if p["label"] == "SAFE" and p["confirmed_chosen"]],
                        "static_evidence_valid_vuln": sum(p["static_evidence_valid"] for p in vv),
                        "class_acc_exact": round(sum(p["vuln_cwe"] == p["true_cwe"] for p in vv) / max(1, len(vv)), 3),
                        "class_acc_group": round(sum(p["vuln_cwe"] is not None and group_of("X-%d-0" % p["vuln_cwe"]) == p["group"] for p in vv) / max(1, len(vv)), 3),
                        "oracle_selection_acc": round(sum(p["oracle"] == p["oracle_expected"] for p in vv) / max(1, len(vv)), 3), "n_vuln": len(vv)}
for cwe in sorted({p["true_cwe"] for p in per}):
    vv = [p for p in per if p["true_cwe"] == cwe and p["label"] == "VULNERABLE"]
    out["by_cwe"][cwe] = {"n_vuln": len(vv), "oracle": CWE_ORACLE.get(cwe), "chosen_confirmed": sum(p["confirmed_chosen"] for p in vv),
                          "new_beyond_floor": sum(1 for p in vv if p["confirmed_chosen"] and not floor[(p["id"], p["label"])]),
                          "class_correct": sum(p["vuln_cwe"] == cwe for p in vv), "oracle_correct": sum(p["oracle"] == CWE_ORACLE.get(cwe) for p in vv)}
out["feed_channel_counts"] = {ch: sum(1 for p in per if p["channel"] == ch) for ch in CHANNELS}
out["feed_channel_counts"]["file_write_failed"] = sum(1 for p in per if p.get("file_write_failed"))
out["per_case"] = per
json.dump(out, open(f"results/reason_CSC_{tag}_castle_exec.json", "w"))
print(json.dumps({k: v for k, v in out.items() if k not in ("per_case", "by_cwe")}, indent=1))
for c, v in out["by_cwe"].items():
    print(c, v)
