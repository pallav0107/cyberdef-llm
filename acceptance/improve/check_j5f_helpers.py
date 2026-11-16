"""Fail-first tests for the J5f helpers: prune_protos removes only undefined prototypes; the cue counters count what they
claim; and build(post=None) leaves J3s/J4s byte-identical to the 3m sets."""
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, "scripts")
import imp_build_j5f_set as J  # noqa: E402

safe = "#include <stdio.h>\nvoid fn_2(char * data);\nvoid fn_3(char * data);\nstatic void fn_4()\n{\n    char * data = 0;\n    fn_2(data);\n}\nvoid fn_2(char * data)\n{\n    printf(\"%s\", data);\n}\n"
fails = []


def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


ok("undefined prototype counted (fn_3 declared, never defined)", J.undefined_protos(safe) == 1)
pr = J.prune_protos(safe)
ok("prune removes exactly the undefined prototype", "fn_3" not in pr and pr.count("fn_2") == safe.count("fn_2"))
ok("after pruning nothing undefined remains", J.undefined_protos(pr) == 0)
ok("no call before declaration in the safe text", J.calls_before_decl(safe) == 0)
late = "static void fn_4()\n{\n    fn_9(0);\n}\nvoid fn_9(int x)\n{\n}\n"
ok("call before any declaration is counted", J.calls_before_decl(late) == 1)
ok("a definition header is not a call", J.calls_before_decl("void fn_1(int a)\n{\n}\n") == 0)

want = {"j3s_heldout_matched_cases.json": "d0eefc70b52bad84c3a21e51a462cc2f87d2f5eeb6d895d86e441e1a165198ce",
        "j4s_heldout_matched_cases.json": "81669e115854d7fd0a7d32fbf0db123c0cc0b38c6535dd9472568cd06f67fbb2"}
os.makedirs("/tmp/j5f_repro", exist_ok=True)
r = subprocess.run([sys.executable, "scripts/imp_build_structure_matched.py", "--out-dir", "/tmp/j5f_repro"], capture_output=True, text=True)
for f, h in want.items():
    got = hashlib.sha256(open(f"/tmp/j5f_repro/{f}", "rb").read()).hexdigest() if os.path.exists(f"/tmp/j5f_repro/{f}") else None
    ok(f"build(post=None) reproduces {f} byte for byte", got == h)
print("ALL PASS" if not fails else f"{len(fails)} failed")
sys.exit(1 if fails else 0)
