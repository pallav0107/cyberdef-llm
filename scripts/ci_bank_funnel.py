#!/usr/bin/env python3
"""Per-category CoT funnel for one trace-bank file: CoT -> CWE class -> OWASP -> monitor -> validator -> concrete witness.
Pure python (runs on Spark's system python3). Reads the true CWE from each trace's cwe_id and the fixed CWE -> monitor map.
Reports, per monitor category, VULNERABLE traces: independent pass rate of each link, the share with a concrete witness,
and the number KEPT (V and P and K and O on the same trace), plus the decoding schema hash(es) found in the file, flagging
the known-bad v2.1/v2.2 hashes (empty-witness grammar bug).
Usage: ci_bank_funnel.py BANK.jsonl [--json OUT] [--md OUT]"""
import argparse, collections, json, re, sys
sys.path.insert(0, "src")
from cyberdef.cwe_oracle import CWE_ORACLE

BAD = {"ecdfdd87d617f06f": "v2.2 (empty-witness grammar bug)", "92b74cee": "v2.1 (empty-witness grammar bug)"}


def mon(cwe):
    m = re.search(r"\d+", str(cwe or ""))
    o = CWE_ORACLE.get(int(m.group(0))) if m else None
    return {"ubsan": "asan"}.get(o, o) or "unknown"


def pj(t):
    t = (t or "").split("<|channel|>final<|message|>")[-1]
    s, e = t.find("{"), t.rfind("}")
    try:
        return json.loads(t[s:e + 1])
    except Exception:
        return None


def concrete(d):
    w = d.get("witness") if isinstance(d, dict) else None
    if not isinstance(w, dict):
        return False
    v = w.get("values")
    return isinstance(v, dict) and any(x not in (None, "", [], {}) for x in v.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bank")
    ap.add_argument("--json", default="")
    ap.add_argument("--md", default="")
    a = ap.parse_args()
    rows = [json.loads(l) for l in open(a.bank) if l.strip()]
    hashes = collections.Counter()
    for r in rows:
        dec = r.get("decoding")
        if isinstance(dec, str):
            try:
                dec = json.loads(dec)
            except Exception:
                dec = {}
        hashes[(dec or {}).get("schema_hash")] += 1
    agg = collections.defaultdict(collections.Counter)
    for r in rows:
        m = mon(r.get("cwe_id"))
        a_ = agg[m]
        if r.get("label") != "VULNERABLE":
            a_["safe"] += 1
            continue
        a_["n"] += 1
        for k in ("V", "P", "K", "O_owasp", "O", "S"):
            a_[k] += int(bool(r.get(k)))
        a_["concrete_witness"] += int(concrete(pj(r.get("raw"))))
        a_["kept"] += int(all(r.get(k) for k in ("V", "P", "K", "O")))
        a_["VP"] += int(bool(r.get("V")) and bool(r.get("P")))
    cats = {}
    for m, c in sorted(agg.items(), key=lambda kv: -kv[1]["n"]):
        n = c["n"]
        pct = lambda k: round(100.0 * c[k] / n, 1) if n else 0.0
        cats[m] = {"n": n, "safe": c["safe"], "V%": pct("V"), "P%": pct("P"), "K%": pct("K"), "OWASP%": pct("O_owasp"),
                   "O%": pct("O"), "concrete_witness%": pct("concrete_witness"), "V_and_P": c["VP"], "kept": c["kept"]}
    tot_v = sum(c["n"] for c in cats.values())
    out = {"bank": a.bank, "traces": len(rows), "schema_hashes": {str(k): v for k, v in hashes.items()},
           "bad_schema_traces": sum(v for k, v in hashes.items() if k in BAD), "vulnerable_traces": tot_v,
           "vulnerable_with_concrete_witness": sum(round(c["concrete_witness%"] * c["n"] / 100) for c in cats.values()),
           "kept_total": sum(c["kept"] for c in cats.values()), "V_and_P_total": sum(c["V_and_P"] for c in cats.values()),
           "categories": cats}
    lines = [f"## Trace-bank funnel — `{a.bank}`", "",
             f"{len(rows)} traces · schema hash(es): " + ", ".join(f"`{k}`" + (f" ⚠️ {BAD[k]}" if k in BAD else "") + f" ×{v}" for k, v in hashes.items()), "",
             f"VULNERABLE traces: {tot_v} · with a concrete witness: {out['vulnerable_with_concrete_witness']} · "
             f"V∧P (correct verdict AND validator passes): **{out['V_and_P_total']}** · KEPT (V∧P∧K∧O): **{out['kept_total']}**", "",
             "| monitor category | vuln n | V | P | K (CWE) | OWASP | O (monitor) | concrete witness | V∧P | KEPT |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for m, c in cats.items():
        lines.append(f"| {m} | {c['n']} | {c['V%']}% | {c['P%']}% | {c['K%']}% | {c['OWASP%']}% | {c['O%']}% | {c['concrete_witness%']}% | {c['V_and_P']} | {c['kept']} |")
    md = "\n".join(lines) + "\n"
    print(md)
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)
    if a.md:
        open(a.md, "w").write(md)


if __name__ == "__main__":
    main()
