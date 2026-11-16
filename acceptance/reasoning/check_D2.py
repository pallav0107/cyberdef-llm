"""Stage D amendment-2 acceptance (written BEFORE src/cyberdef/exec_oracle.py): the multi-variant oracle (spec results/imp_castle_oracle_spec.json).
`PYTHONPATH=src python src/cyberdef/exec_oracle.py --selftest [never|always]` prints JSON {control: bool}. Real run must be all True:
 overflow_confirmed_A_and_D, leak_confirmed_only_via_A_leak, unsigned_wrap_only_via_B, race_only_via_C, spin_is_cpu_hang,
 plain_abort_not_counted, benign_nothing_fires, implicit_conversion_not_counted.
Mutants must be caught: 'never' (nothing ever fires) must fail a positive control; 'always' (everything fires) must fail a negative control."""
import json, os, subprocess, sys
env = {**os.environ, "PYTHONPATH": "src", "EXEC_IMAGE": os.environ.get("EXEC_IMAGE", "imp-castle-san:1")}
def st(*a):
    r = subprocess.run([sys.executable, "src/cyberdef/exec_oracle.py", "--selftest", *a], capture_output=True, text=True, env=env)
    return json.loads(r.stdout.strip().splitlines()[-1])
fails = []
POS = ["overflow_confirmed_A_and_D", "leak_confirmed_only_via_A_leak", "unsigned_wrap_only_via_B", "race_only_via_C", "spin_is_cpu_hang"]
NEG = ["plain_abort_not_counted", "benign_nothing_fires", "implicit_conversion_not_counted"]
try:
    real = st()
    bad = [k for k, v in real.items() if v is not True]
    if bad:
        fails.append(f"real oracle failed controls: {bad}")
    nv = st("never")
    if all(nv[k] for k in POS):
        fails.append("'never' mutant NOT caught")
    al = st("always")
    if all(al[k] for k in NEG):
        fails.append("'always' mutant NOT caught")
except Exception as e:
    fails.append(f"oracle unavailable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
