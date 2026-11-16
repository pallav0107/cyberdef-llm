"""Acceptance for the behaviour oracles of spec v2 (cmd_injection, format_string, path_traversal, sqli). Run from the repo root on the box (docker + image imp-castle-san:1).
Runs scripts/imp_beh_selftest.py in the sandbox (--network none, caps dropped, non-root) and requires, for EVERY control:
  vulnerable program + payload       -> its oracle TRUE
  safe twin(s) + same payload        -> FALSE (cmd: exec-without-shell and input validation; fmt: printf("%s"); path: reject '..' and realpath prefix check; sql: bound parameter and quote escaping)
  vulnerable program + benign input  -> FALSE
  shim DISABLED (LD_PRELOAD missing) -> FALSE for the shim-based oracles (cmd/path/sql); proves the detector is the shim (format_string observes output only, so it is exempt from this one)
  no other oracle fires on a control
--broken sets IMP_BEH_BROKEN=1 (judges return False): the check must then FAIL on the vulnerable controls (exit 0 only when the mutant is caught)."""
import json, os, shutil, subprocess, sys, tempfile

BROKEN = "--broken" in sys.argv
REPO = os.getcwd()
T = tempfile.mkdtemp(prefix="impbehchk_")
os.chmod(T, 0o777)
for f in ("imp_shim.c", "imp_behaviour.py", "imp_beh_selftest.py"):
    shutil.copy(f"{REPO}/scripts/{f}", f"{T}/{f}")
subprocess.run(["chmod", "-R", "a+rwX", T])
cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "128", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000",
       "-e", "HOME=/tmp", "-e", "IMP_BEH_BROKEN=" + ("1" if BROKEN else "0"), "-v", f"{T}:/w", "-w", "/w", "--entrypoint", "python3", "imp-castle-san:1", "imp_beh_selftest.py"]
r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
shutil.rmtree(T, ignore_errors=True)
fails = []
try:
    res = json.loads(r.stdout.strip().splitlines()[-1])
except Exception:
    print("FAIL: selftest did not produce JSON:", (r.stderr or r.stdout)[-400:]); sys.exit(0 if BROKEN else 1)
for name, x in res.items():
    if "error" in x:
        fails.append(f"{name}: compile error {x['error'][:120]}"); continue
    if x["got"] != x["want"]:
        fails.append(f"{name}: oracle {x['oracle']} got {x['got']} want {x['want']} (log {x['log_sample']}, out {x['out_sample']!r})")
    if x["benign_got"]:
        fails.append(f"{name}: fired on BENIGN input")
    if x["want"] and x["oracle"] != "format_string" and x["shim_off_got"]:
        fails.append(f"{name}: fired with the shim disabled (detector is not the shim)")
    if x["other_oracles_fired"]:
        fails.append(f"{name}: other oracles fired {x['other_oracles_fired']}")
if BROKEN:
    print("BROKEN MUTANT CAUGHT: " + "; ".join(fails[:2]) if fails else "BROKEN MUTANT NOT CAUGHT"); sys.exit(0 if fails else 1)
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: behaviour oracle controls (%d programs: vulnerable fires, safe twins/benign/shim-off do not)" % len(res))
