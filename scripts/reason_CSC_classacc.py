"""SC-CoT v2 scoring additions: class accuracy (vuln_class vs true CWE, exact and vs CWE group) and oracle-selection accuracy
(oracle vs the fixed map applied to the true CWE), on vulnerable cases whose true CWE is known.
Truth: CASTLE ids (CASTLE-<cwe>-n.c) or the PrimeVul test cwe list joined on idx. Usage: reason_CSC_classacc.py <cache_or_result.json> [castle|primevul]"""
import json, re, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef.cwe_oracle import CWE_ORACLE, CWE_OWASP, OWASP_OUTSIDE
from imp_oracle import group_of
def owasp_correct(label, true_cwes):
    """OWASP label correct iff it equals the Top 10:2021 category of the true CWE (CWE_OWASP); for CWEs outside the Top 10 the label
    OWASP_OUTSIDE counts as correct (known label-set limitation: no generic 'other' label). Correct if it matches ANY true CWE's expectation."""
    return label is not None and any(label == CWE_OWASP.get(c, OWASP_OUTSIDE) for c in true_cwes)


f, kind = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "primevul")
rows = json.load(open(f))["per_case"]
truth = {}
if kind == "primevul":
    from cyberdef import benchdata as b
    for r in b._load_split(b.spec("primevul"), "test"):
        truth[str(r["idx"])] = [int(x) for x in re.findall(r"\d+", str(r["cwe"]))]
def true_cwes(p):
    if kind == "castle":
        return [int(re.match(r"CASTLE-(\d+)-", p["id"]).group(1))]
    return truth.get(p["id"], [])
n = hit = ghit = ohit = nmap = 0
owh = 0; own_consistent = 0; owcat = {}
for p in rows:
    if p["label"] != "VULNERABLE": continue
    tc = true_cwes(p)
    if not tc: continue
    n += 1
    if p.get("vuln_cwe") in tc: hit += 1
    grp = lambda c: group_of("X-%d-0" % c) if c else None
    if p.get("vuln_cwe") and grp(p["vuln_cwe"]) in {grp(c) for c in tc}: ghit += 1
    if owasp_correct(p.get("vuln_owasp"), tc): owh += 1
    cat = CWE_OWASP.get(tc[0], OWASP_OUTSIDE); d = owcat.setdefault(cat, [0, 0]); d[1] += 1; d[0] += owasp_correct(p.get("vuln_owasp"), tc)
    if p.get("vuln_cwe") and p.get("vuln_owasp") == CWE_OWASP.get(p["vuln_cwe"], OWASP_OUTSIDE): own_consistent += 1
    exp = {CWE_ORACLE[c] for c in tc if c in CWE_ORACLE}
    if exp:
        nmap += 1
        if p.get("oracle") in exp: ohit += 1
print(json.dumps({"vulnerable_with_known_cwe": n, "class_acc_exact": round(hit / max(1, n), 4), "class_acc_group": round(ghit / max(1, n), 4),
                  "oracle_selection_acc": round(ohit / max(1, nmap), 4), "n_oracle_scored": nmap,
                  "owasp_acc": round(owh / max(1, n), 4), "owasp_acc_by_true_category": {c: {"correct": v[0], "n": v[1], "acc": round(v[0] / v[1], 3)} for c, v in owcat.items()},
                  "owasp_label_consistent_with_own_cwe": round(own_consistent / max(1, n), 4)}))
