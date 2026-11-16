"""Stage G acceptance (written BEFORE src/cyberdef/repair_verify.py exists). Usage: check_G.py controls
Runs `python src/cyberdef/repair_verify.py <mode>` (mode: real | always_true | always_false) which must print JSON with
keys: known_good_verifies (True), identical_not_verified (True), breaks_function_not_verified (True),
empty_or_uncompilable_not_verified (True). The real checker must satisfy all four; always_true must fail one of the three
negative controls; always_false must fail known_good_verifies."""
import json, os, subprocess, sys
env = {**os.environ, "PYTHONPATH": "src"}
def st(m):
    r = subprocess.run([sys.executable, "src/cyberdef/repair_verify.py", m], capture_output=True, text=True, env=env)
    return json.loads(r.stdout.strip().splitlines()[-1])
fails = []
try:
    real = st("real")
    bad = [k for k, v in real.items() if v is not True]
    if bad: fails.append(f"real checker failed controls {bad}")
    t = st("always_true")
    if all(t[k] for k in ("identical_not_verified", "breaks_function_not_verified", "empty_or_uncompilable_not_verified")):
        fails.append("always_true mutant NOT caught")
    if st("always_false")["known_good_verifies"]:
        fails.append("always_false mutant NOT caught")
except Exception as e:
    fails.append(f"checker unavailable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
