"""Acceptance for pool J2 (written to be run after the build; its fail-first control is the shim-disabled rebuild). Run from the repo root.
  check_j2.py            : results/imp_train_juliet2_items.json: every pair has a VULNERABLE and a SAFE item with the same pair id, >= 40 verified pairs, only console/environment/file feeds (no socket),
                           CWEs only 78/134/23/36 folded to 78/134/22, no id overlaps CASTLE (ids are juliet2:*; texts are not CASTLE texts), label_verified note present.
  check_j2.py broken     : rebuilds with the shim DISABLED (IMP_J2_SHIM=/nonexistent.so, output to /tmp): the shim-based classes (78, 23, 36) must verify ZERO pairs (the detector is the shim); CWE134 is output-based and exempt."""
import json, os, subprocess, sys

if len(sys.argv) > 1 and sys.argv[1] == "broken":
    env = dict(os.environ, IMP_J2_SHIM="/nonexistent.so", IMP_J2_OUT="/tmp/imp_j2_broken.json", IMP_JOBS="1")
    subprocess.run(["python3", "scripts/imp_build_juliet2.py"], env=env, capture_output=True, text=True, timeout=1500)
    d = json.load(open("/tmp/imp_j2_broken.json"))
    bc = d["stats"]["by_cwe"]
    ok = bc["CWE78"] == 0 and bc["CWE23"] == 0 and bc["CWE36"] == 0      # CWE134 is judged on program OUTPUT only (no shim needed): exempt, as in check_beh
    print("BROKEN (shim disabled) verified by CWE:", bc, "-> MUTANT CAUGHT for the shim-based classes" if ok else "-> NOT CAUGHT"); sys.exit(0 if ok else 1)
d = json.load(open("results/imp_train_juliet2_items.json"))
it = d["items"]
fails = []
by = {}
for x in it:
    by.setdefault(x["pair"], {})[x["label"]] = x
if any(set(v) != {"VULNERABLE", "SAFE"} for v in by.values()):
    fails.append("a pair lacks one side")
if len(by) < 40:
    fails.append(f"only {len(by)} verified pairs")
if any(x["feed"] not in ("console", "environment", "file") or "socket" in x["pair"] or "w32" in x["pair"] for x in it):
    fails.append("non-input-driven / socket / w32 variant present")
if any(x["cwe"] not in ("CWE78", "CWE134", "CWE22") for x in it):
    fails.append("unexpected CWE")
cas = {c["id"] for c in json.load(open("results/xdata_castle_cases.json"))["cases"]}
if any(x["id"] in cas for x in it) or not all(x["id"].startswith("juliet2:") for x in it):
    fails.append("id collision with CASTLE or wrong prefix")
if not all("label_verified" in x for x in it):
    fails.append("label_verified note missing")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS: J2 %d pairs, %s" % (len(by), d["stats"]["by_cwe"]))
