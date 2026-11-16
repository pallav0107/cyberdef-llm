"""Stage D spec-v2 (behaviour oracles) acceptance, written BEFORE exec_oracle gained variant P. My OWN controls (independent of the builder's check_beh.py):
`PYTHONPATH=src python src/cyberdef/exec_oracle.py --selftest2 [never|always]` prints JSON; the real run must be all True:
 POSITIVE (vulnerable program + CANARY payload is confirmed by the chosen oracle): cmd_vuln_confirmed, path_vuln_confirmed, sqli_vuln_confirmed, fmt_vuln_confirmed
 NEGATIVE: cmd_safe_sanitised_not_confirmed, path_safe_dotdot_stripped_not_confirmed, sqli_safe_escaped_not_confirmed, sqli_safe_prepared_not_confirmed,
           fmt_safe_literal_not_confirmed, benign_input_nothing_fires, empty_input_variant_P_not_run, wrong_oracle_routing_not_confirmed,
           env_cmd_not_confirmed_via_stdin (env-reading cmd-injection program is NOT confirmed when the payload is fed on stdin), unparseable_feed_falls_back_to_stdin_and_is_counted
 POSITIVE (feed channels, amendment 3b): env_cmd_confirmed_via_env, file_cmd_confirmed_via_file, feed_parser_channels_correct
'never' must fail a positive; 'always' must fail a negative. The v1 controls (check_D2.py) must still pass."""
import json, os, subprocess, sys
env = {**os.environ, "PYTHONPATH": "src", "EXEC_IMAGE": os.environ.get("EXEC_IMAGE", "imp-castle-san:1")}
def st(*a):
    r = subprocess.run([sys.executable, "src/cyberdef/exec_oracle.py", "--selftest2", *a], capture_output=True, text=True, env=env)
    return json.loads(r.stdout.strip().splitlines()[-1])
POS = ["cmd_vuln_confirmed", "path_vuln_confirmed", "sqli_vuln_confirmed", "fmt_vuln_confirmed",
       "env_cmd_confirmed_via_env", "file_cmd_confirmed_via_file", "feed_parser_channels_correct"]
NEG = ["cmd_safe_sanitised_not_confirmed", "path_safe_dotdot_stripped_not_confirmed", "sqli_safe_escaped_not_confirmed", "sqli_safe_prepared_not_confirmed",
       "fmt_safe_literal_not_confirmed", "benign_input_nothing_fires", "empty_input_variant_P_not_run", "wrong_oracle_routing_not_confirmed", "env_cmd_not_confirmed_via_stdin", "unparseable_feed_falls_back_to_stdin_and_is_counted"]
fails = []
try:
    real = st()
    miss = [k for k in POS + NEG if k not in real]; bad = [k for k in POS + NEG if k in real and real[k] is not True]
    if miss or bad:
        fails.append(f"real: missing {miss}; failed {bad}")
    nv = st("never")
    if all(nv.get(k) for k in POS):
        fails.append("'never' mutant NOT caught")
    al = st("always")
    if all(al.get(k) for k in NEG):
        fails.append("'always' mutant NOT caught")
except Exception as e:
    fails.append(f"selftest2 unavailable: {e}")
print("PASS" if not fails else "FAIL: " + "; ".join(fails)); sys.exit(0 if not fails else 1)
