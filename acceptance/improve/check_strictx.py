"""Acceptance for the STRICT X tag (written BEFORE scripts/imp_bank_strictx.py was trusted). Run from the repo root on the box (needs docker + image imp-castle-san:1).
Builds a tiny fake Juliet root and a stub bank, runs imp_bank_strictx.py in the sandbox (--network none, caps, non-root) and checks four controls:
  S1 program that crashes ONLY for a long stdin; witness = long stdin; good twin safe            -> X_strict True
  S2 same program, witness = short stdin                                                          -> X_strict False (witness does not crash)
  S3 program that crashes with EMPTY input too, any witness                                       -> X_strict False (loose X only)
  S4 witness crashes the good twin as well (twin also overflows on the witness)                   -> X_strict False
  S5 counts: x_loose counts S1+S2? (loose = tag X on rows) and x_strict_total == 1; arm7_feasible False
--broken sets IMP_STRICT_BROKEN=1 (the empty-input condition ignored in the checker's copy of the script) and the check must then FAIL S3."""
import json, os, shutil, subprocess, sys, tempfile

BROKEN = "--broken" in sys.argv
REPO = os.getcwd()
T = tempfile.mkdtemp(prefix="impsxchk_"); os.chmod(T, 0o777)
J = f"{T}/jroot"; os.makedirs(f"{J}/testcases/CWEX"); os.makedirs(f"{J}/testcasesupport")
for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
    shutil.copy(f"{REPO}/data/juliet_dl/x/C/testcasesupport/{s}", f"{J}/testcasesupport/{s}")
BAD = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef INCLUDEMAIN
int main(int argc, char **argv){
#ifndef OMITGOOD
  good();
#endif
#ifndef OMITBAD
  bad();
#endif
  return 0;}
#endif
"""
def prog(name, bad_body, good_body):
    src = (f"#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"
           f"#ifndef OMITBAD\nvoid bad(void){{ {bad_body} }}\n#endif\n#ifndef OMITGOOD\nvoid good(void){{ {good_body} }}\n#endif\n"
           f"#ifdef INCLUDEMAIN\nint main(void){{\n#ifndef OMITGOOD\n good();\n#endif\n#ifndef OMITBAD\n bad();\n#endif\n return 0;}}\n#endif\n")
    open(f"{J}/testcases/CWEX/{name}", "w").write(src)
NEED = "char in[256]={0}; char b[8]; if(fgets(in,sizeof in,stdin)){ if(strlen(in)>12) strcpy(b,in); }"
SAFE = "char in[256]={0}; char b[8]; if(fgets(in,sizeof in,stdin)){ strncpy(b,in,7); b[7]=0; }"
ALWAYS = "char b[8]; char *p=malloc(4); p[10]=1; free(p);"
prog("S1_01.c", NEED, SAFE); prog("S3_01.c", ALWAYS, SAFE); prog("S4_01.c", NEED, NEED)
os.makedirs(f"{T}/results")
LONG = "A" * 40
def row(base, stdin, gen="g1", sample=0):
    raw = json.dumps({"verdict": "VULNERABLE", "witness": {"values": {"input": stdin}, "state": [], "how_to_feed": "stdin"}})
    return dict(rec="trace", fn=f"juliet:{base}:V", pools=["J"], label="VULNERABLE", gen=gen, sample=sample, edit="orig", raw=raw, parsed=True, V=True, P=True, S=None,
                X=(base == "S3_01.c"), verdict_raw="VULNERABLE", verdict_final="VULNERABLE", errors=[])
rows = [row("S1_01.c", LONG, sample=0), row("S1_01.c", "A", sample=1), row("S3_01.c", LONG), row("S4_01.c", LONG)]
with open(f"{T}/results/imp_trace_bank.jsonl", "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
json.dump({"total_traces": 4, "x_verified_traces_VP": 1}, open(f"{T}/results/imp_trace_bank_counts.json", "w"))
for p in (T, f"{T}/results", f"{T}/jroot"):
    subprocess.run(["chmod", "-R", "a+rwX", p])
script = f"{REPO}/scripts/imp_bank_strictx.py"
if BROKEN:
    txt = open(script).read().replace("and not c[\"empty_crash\"] ", "")
    assert txt != open(script).read()
    os.makedirs(f"{T}/scripts", exist_ok=True)
    open(f"{T}/scripts/imp_bank_strictx.py", "w").write(txt)
    shutil.copy(f"{REPO}/scripts/reason_C_witness.py", f"{T}/scripts/"); shutil.copy(f"{REPO}/scripts/length_baseline.py", f"{T}/scripts/")
    sd = f"{T}/scripts"
else:
    sd = f"{REPO}/scripts"
cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "128", "--cpus", "1", "--cap-drop", "ALL", "--user", "1000:1000", "-e", "HOME=/tmp",
       "-e", "IMP_JULIET=/w/jroot", "-e", "PYTHONPATH=/w/src", "-v", f"{T}:/w", "-v", f"{sd}:/w/scripts:ro", "-v", f"{REPO}/src:/w/src:ro", "-w", "/w", "--entrypoint", "python3",
       "imp-castle-san:1", "scripts/imp_bank_strictx.py"]
r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
fails = []
if r.returncode != 0:
    fails.append("script failed: " + (r.stderr[-400:] or r.stdout[-400:]))
else:
    out = [json.loads(l) for l in open(f"{T}/results/imp_trace_bank.jsonl")]
    xs = {(o["fn"], o["sample"]): o["X_strict"] for o in out}
    exp = {("juliet:S1_01.c:V", 0): True, ("juliet:S1_01.c:V", 1): False, ("juliet:S3_01.c:V", 0): False, ("juliet:S4_01.c:V", 0): False}
    for k, v in exp.items():
        if xs.get(k) is not v:
            fails.append(f"{k}: X_strict={xs.get(k)} expected {v}")
    cn = json.load(open(f"{T}/results/imp_trace_bank_counts.json"))
    if cn.get("x_strict_traces_total") != 1 or cn.get("arm7_feasible") is not False or cn.get("x_loose_traces_total") != 1:
        fails.append(f"counts wrong: strict={cn.get('x_strict_traces_total')} loose={cn.get('x_loose_traces_total')} feasible={cn.get('arm7_feasible')}")
shutil.rmtree(T, ignore_errors=True)
if BROKEN:
    print("BROKEN MUTANT CAUGHT (check fails as it must): " + "; ".join(fails[:3]) if fails else "BROKEN MUTANT NOT CAUGHT"); sys.exit(0 if fails else 1)
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: strict X controls S1-S5")
