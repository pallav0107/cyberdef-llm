"""Merge results/imp_bank_g*.jsonl -> results/imp_trace_bank.jsonl and write results/imp_trace_bank_counts.json (tag counts per generator and pool,
and the arm-7 feasibility count: X-verified traces). Run from the repo root (box or Spark container); plain python."""
import glob, json, sys

Q = len(sys.argv) > 1 and sys.argv[1] == "quick"
PFX = "imp_bankq_g" if Q else "imp_bank_g"
SUF = "_quick" if Q else ""
rows = []
for f in sorted(glob.glob(f"results/{PFX}*.jsonl")):
    rows += [json.loads(l) for l in open(f)]
with open(f"results/imp_trace_bank{SUF}.jsonl", "w") as fo:
    for r in rows:
        fo.write(json.dumps(r) + "\n")
cnt = {}
for r in rows:
    if r["edit"] != "orig":
        continue
    for pool in r["pools"]:
        c = cnt.setdefault(f"{r['gen']}|{pool}", dict(traces=0, truncated=0, K=0, O=0, O_owasp=0, K_evaluable=0, parsed=0, V=0, P=0, VP=0, S=0, X=0, C=0, functions=set()))
        c["traces"] += 1; c["truncated"] += bool(r.get("truncated")); c["parsed"] += r["parsed"]; c["V"] += r["V"]; c["P"] += r["P"]; c["VP"] += bool(r["V"] and r["P"])
        c["K"] += r.get("K") is True; c["O"] += r.get("O") is True; c["O_owasp"] += r.get("O_owasp") is True; c["K_evaluable"] += r.get("K") is not None; c["S"] += r["S"] is True; c["X"] += r["X"] is True; c["C"] += r.get("C") is True
        c["functions"].add(r["fn"])
for c in cnt.values():
    c["functions"] = len(c["functions"])
    t = max(1, c["traces"])
    c["parse_rate"] = round(c["parsed"] / t, 4); c["truncation_rate"] = round(c["truncated"] / t, 4)
    for k in ("V", "P", "S", "X", "C", "VP", "K", "O", "O_owasp"):
        c["yield_" + k] = round(c[k] / t, 4)
x_tr = [r for r in rows if r["edit"] == "orig" and r["X"] is True and r["P"]]
dec = sorted({json.dumps(r.get("decoding"), sort_keys=True) for r in rows if r.get("decoding")})
out = {"decodings_seen": dec, "bank": "quick" if Q else "full", "generators": sorted({r["gen"] for r in rows}), "per_gen_pool": cnt, "total_traces": sum(1 for r in rows if r["edit"] == "orig"),
       "x_verified_traces_VP": len(x_tr), "x_verified_distinct_functions": len({r["fn"] for r in x_tr}),
       "arm7_gate_min_traces": 200, "arm7_feasible": False, "arm7_note": "set by imp_bank_strictx.py on the STRICT X count; this merge-time value is a placeholder (False)"}
json.dump(out, open(f"results/imp_trace_bank{SUF}_counts.json", "w"), indent=1)
print(json.dumps(out, indent=1))
