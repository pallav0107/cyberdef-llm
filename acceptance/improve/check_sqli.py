"""Acceptance for the synthetic SQLi pool verifier (written to be run before real generated data is trusted). Run from the repo root on the box.
Feeds scripts/imp_build_sqli.py a hand-made raw file with six pairs and requires the exact outcome:
  A good pair (vulnerable concatenation, safe bound parameter)         -> KEPT
  B 'safe' twin is the same concatenation code                         -> rejected safe_fired
  C 'vulnerable' program is actually a bound-parameter program         -> rejected vulnerable_not_fired
  D exact duplicate of A under another id                               -> rejected pool_duplicate
  E vulnerable program does not compile                                 -> rejected not_compiled
  F unparsed pair (None)                                                -> counted as unparsed
and a dedupe unit test: a lightly edited copy of a real CASTLE CWE-89 program has token 5-shingle Jaccard >= 0.5 with the original (so the CASTLE filter would reject it)."""
import json, os, subprocess, sys
sys.path.insert(0, "scripts")
H = "#include <stdio.h>\n#include <string.h>\n#include <sqlite3.h>\n"
RD = 'char in[200]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; sqlite3*db; sqlite3_open(":memory:",&db); '
VULN = H + "int main(void){char q[400]; " + RD + 'snprintf(q,sizeof q,"SELECT * FROM u WHERE n=%c%s%c",39,in,39); sqlite3_exec(db,q,0,0,0); return 0;}'
SAFE = H + "int main(void){sqlite3_stmt*s; " + RD + 'sqlite3_prepare_v2(db,"SELECT * FROM u WHERE n=?",-1,&s,0); sqlite3_bind_text(s,1,in,-1,SQLITE_STATIC); return 0;}'
BROKEN = H + "int main(void){ this does not compile }"
def row(k, v, s):
    return {"scenario": k, "sample": 0, "vulnerable": v, "safe": s, "finish": "stop", "raw_head": ""}
raw = {"generator": "STUB-control", "n_prompts": 6, "rows": [row(0, VULN, SAFE), row(1, VULN, VULN), row(2, SAFE, SAFE), row(3, VULN, SAFE), row(4, BROKEN, SAFE), row(5, None, None)]}
raw["rows"][3]["scenario"] = 0; raw["rows"][3]["sample"] = 1          # D: same code as A, different id
json.dump(raw, open("/tmp/imp_sqli_ctl_raw.json", "w"))
env = dict(os.environ, IMP_SQLI_OUT="/tmp/imp_sqli_ctl_out.json", IMP_JOBS="1")
subprocess.run(["python3", "scripts/imp_build_sqli.py", "/tmp/imp_sqli_ctl_raw.json"], env=env, capture_output=True, text=True, timeout=600)
st = json.load(open("/tmp/imp_sqli_ctl_out.json"))["stats"]
fails = []
r = st["rejected"]
want = {"verified_pairs": 1, "unparsed": 1, "not_compiled": 1, "vulnerable_not_fired": 1, "safe_fired": 1, "pool_duplicate": 1}
got = {"verified_pairs": st["verified_pairs"], "unparsed": r["unparsed"], "not_compiled": r["not_compiled"], "vulnerable_not_fired": r["vulnerable_not_fired"], "safe_fired": r["safe_fired"], "pool_duplicate": r["pool_duplicate"]}
if got != want:
    fails.append(f"outcome {got} != expected {want}")
import imp_build_sqli as S
cas = [c for c in json.load(open("results/xdata_castle_cases.json"))["cases"] if c["id"].startswith("CASTLE-89-")][0]["code"]
edited = cas.replace("char ", "char  ", 3).replace("printf", "printf ", 2) + "\n// extra comment\n"
if S.jac(S.shingles(cas), S.shingles(edited)) < 0.5:
    fails.append("dedupe unit: edited CASTLE copy not flagged")
if S.jac(S.shingles(VULN), S.shingles(cas)) >= 0.5:
    fails.append("dedupe unit: unrelated program wrongly flagged")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: sqli pool verifier controls A-F + dedupe unit", got)
