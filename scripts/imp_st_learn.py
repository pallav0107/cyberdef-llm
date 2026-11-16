#!/usr/bin/env python3
"""The learnings of ONE self-training round, from its execution-checked trace bank (read-only).
Per class: traces, parsed, verdict right (V), validator-valid (P), CWE right (K), monitor right (O), execution-confirmed
(X_strict, vulnerable only), and functions with at least one keepable trace. For SAFE traces it separates READING errors
(the trace says VULNERABLE) from FORMAT rejections (it says SAFE but the validator rejects it), with the top validator
errors of each kind. For VULNERABLE traces: wrong verdict, right verdict but invalid, valid but K/O wrong, X_strict failed.
  python3 scripts/imp_st_learn.py results/st_bank_cmd_injection_r1_x.jsonl cmd_injection [--json out.json]"""
import collections, json, re, sys


def short(e):
    e = re.sub(r"\d+", "N", e)
    return e[:70]


def main():
    bank, cat = sys.argv[1], sys.argv[2]
    pool = {it["id"]: it for it in json.load(open(f"results/st_pool_{cat}.json"))["items"]}
    rows = [json.loads(l) for l in open(bank)]
    rows = [r for r in rows if r.get("edit") == "orig" and r["fn"] in pool]
    out = {"category": cat, "bank": bank, "traces": len(rows)}
    for lab in ("VULNERABLE", "SAFE"):
        rs = [r for r in rows if pool[r["fn"]]["label"] == lab]
        fns = {r["fn"] for r in rs}
        c = collections.Counter()
        errs = collections.Counter()
        keep_fns = set()
        for r in rs:
            c["parsed"] += bool(r.get("parsed")); c["V"] += bool(r.get("V")); c["P"] += bool(r.get("P"))
            c["K"] += r.get("K") is True; c["O"] += r.get("O") is True
            c["truncated"] += bool(r.get("truncated"))
            vr = r.get("verdict_raw")
            if lab == "SAFE":
                if vr == "VULNERABLE":
                    c["reading_error_says_vulnerable"] += 1
                elif vr == "SAFE" and not r.get("P"):
                    c["format_rejected"] += 1
                    errs.update(short(e) for e in r.get("errors") or [])
                elif vr not in ("SAFE", "VULNERABLE"):
                    c["uncertain_or_unparsed"] += 1
                if r.get("V") and r.get("P"):
                    keep_fns.add(r["fn"])
            else:
                x = r.get("X_strict")
                c["X_strict_true"] += x is True; c["X_strict_false"] += x is False; c["X_strict_none"] += x is None
                if vr != "VULNERABLE":
                    c["reading_error_says_safe_or_unsure"] += 1
                elif not r.get("P"):
                    c["format_rejected"] += 1
                    errs.update(short(e) for e in r.get("errors") or [])
                elif not (r.get("K") is True and r.get("O") is True):
                    c["valid_but_cwe_or_monitor_wrong"] += 1
                elif x is False:
                    c["valid_but_execution_failed"] += 1
                if r.get("V") and r.get("P") and r.get("K") is True and r.get("O") is True and (x is None or x is True):
                    keep_fns.add(r["fn"])
        out[lab] = {"functions": len(fns), "traces": len(rs), **dict(c), "functions_keepable": len(keep_fns),
                    "top_validator_errors": errs.most_common(6)}
    print(json.dumps(out, indent=1))
    if "--json" in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)


if __name__ == "__main__":
    main()
