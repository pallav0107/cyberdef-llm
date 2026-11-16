"""Acceptance for the BEHAVIOUR branch of the STRICT X tag (J2 / synthetic-SQLi functions; chosen oracle = a behaviour oracle). Run from the repo root on the box (docker + imp-castle-san:1).
Fake Juliet-style root with one command-injection testcase (bad: fgets + system; good: fixed command) and a stub bank:
  B1 witness 'x; echo CANARY' fed on console                    -> X_strict True
  B2 witness 'x; echo hello' (no CANARY)                         -> X_strict False (the oracle cannot fire without the token)
  B3 same testcase where the GOOD twin also runs system(input)   -> X_strict False (twin fires under the same witness)
  B4 chosen oracle format_string on a cmd-injection program      -> X_strict False (chosen oracle is the one judged)
  B5 trace without a witness                                     -> X_strict False
--broken ignores the twin condition in a checker-local copy: B3 must then be wrongly True and the check must fail."""
import json, os, shutil, subprocess, sys, tempfile

BROKEN = "--broken" in sys.argv
REPO = os.getcwd()
T = tempfile.mkdtemp(prefix="impsxb_")
os.chmod(T, 0o777)
J = f"{T}/jroot"
os.makedirs(f"{J}/testcases/CWE78_X")
os.makedirs(f"{J}/testcasesupport")
for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
    shutil.copy(f"{REPO}/data/juliet_dl/x/C/testcasesupport/{s}", f"{J}/testcasesupport/{s}")


def prog(name, bad_body, good_body):
    src = ("#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n"
           f"#ifndef OMITBAD\nvoid bad(void){{ {bad_body} }}\n#endif\n#ifndef OMITGOOD\nvoid good(void){{ {good_body} }}\n#endif\n"
           "#ifdef INCLUDEMAIN\nint main(void){\n#ifndef OMITGOOD\n good();\n#endif\n#ifndef OMITBAD\n bad();\n#endif\n return 0;}\n#endif\n")
    open(f"{J}/testcases/CWE78_X/{name}", "w").write(src)


RD = 'char in[200], c[300]; if(!fgets(in,sizeof in,stdin)) return; in[strcspn(in,"\\n")]=0; snprintf(c,sizeof c,"ls %s",in); '
prog("CWE78_X__char_console_system_01.c", RD + "system(c);", 'system("ls /tmp");')
prog("CWE78_Y__char_console_system_01.c", RD + "system(c);", RD + "system(c);")       # twin also vulnerable
os.makedirs(f"{T}/results")
items = []
for b in ("CWE78_X__char_console_system_01.c", "CWE78_Y__char_console_system_01.c"):
    for lab in ("V", "S"):
        items.append({"id": f"juliet2:{b}:{lab}", "label": "VULNERABLE" if lab == "V" else "SAFE", "code": "x", "feed": "console", "oracle": "cmd_injection", "pair": b})
json.dump({"items": items}, open(f"{T}/results/imp_train_juliet2_items.json", "w"))


def row(base, values, oracle="cmd_injection", sample=0, witness=True):
    w = {"values": values, "state": [], "how_to_feed": "stdin"} if witness else None
    raw = json.dumps({"verdict": "VULNERABLE", "oracle": oracle, "witness": w})
    return dict(rec="trace", fn=f"juliet2:{base}:V", pools=["J2"], label="VULNERABLE", gen="g1", sample=sample, edit="orig", raw=raw, parsed=True, V=True, P=True, S=None, X=None,
                oracle=oracle, verdict_raw="VULNERABLE", verdict_final="VULNERABLE", errors=[])


X, Y = "CWE78_X__char_console_system_01.c", "CWE78_Y__char_console_system_01.c"
rows = [row(X, {"input": "x; echo CANARY"}, sample=0), row(X, {"input": "x; echo hello"}, sample=1), row(Y, {"input": "x; echo CANARY"}, sample=2),
        row(X, {"input": "x; echo CANARY"}, oracle="format_string", sample=3), row(X, None, sample=4, witness=False)]
with open(f"{T}/results/imp_trace_bank.jsonl", "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
json.dump({"total_traces": 5, "x_verified_traces_VP": 0}, open(f"{T}/results/imp_trace_bank_counts.json", "w"))
subprocess.run(["chmod", "-R", "a+rwX", T])
sd = f"{REPO}/scripts"
if BROKEN:
    txt = open(f"{sd}/imp_bank_strictx.py").read()
    new = txt.replace(" and not wg[\"verdicts\"][orc])", ")")
    assert new != txt
    os.makedirs(f"{T}/scripts", exist_ok=True)
    open(f"{T}/scripts/imp_bank_strictx.py", "w").write(new)
    for f in os.listdir(sd):
        if f != "imp_bank_strictx.py" and os.path.isfile(f"{sd}/{f}") and (f.endswith(".py") or f.endswith(".c")):
            shutil.copy(f"{sd}/{f}", f"{T}/scripts/{f}")
    sd = f"{T}/scripts"
    subprocess.run(["chmod", "-R", "a+rwX", T])
cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL", "--user", "1000:1000", "-e", "HOME=/tmp", "-e", "IMP_JULIET=/w/jroot",
       "-e", "PYTHONPATH=/w/src", "-v", f"{T}:/w", "-v", f"{sd}:/w/scripts:ro", "-v", f"{REPO}/src:/w/src:ro", "-w", "/w", "--entrypoint", "python3", "imp-castle-san:1", "scripts/imp_bank_strictx.py"]
r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
fails = []
if r.returncode != 0:
    fails.append("script failed: " + (r.stderr[-500:] or r.stdout[-300:]))
else:
    out = {o["sample"]: o["X_strict"] for o in map(json.loads, open(f"{T}/results/imp_trace_bank.jsonl"))}
    for k, v in {0: True, 1: False, 2: False, 3: False, 4: False}.items():
        if out.get(k) is not v:
            fails.append(f"B{k+1}: X_strict={out.get(k)} expected {v}")
shutil.rmtree(T, ignore_errors=True)
if BROKEN:
    print("BROKEN MUTANT CAUGHT: " + "; ".join(fails[:2]) if fails else "BROKEN MUTANT NOT CAUGHT"); sys.exit(0 if fails else 1)
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: behaviour strict-X controls B1-B5")
