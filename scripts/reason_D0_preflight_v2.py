"""Stage D0 (no model): compile+run every CASTLE program with EMPTY input in the sandbox image (EXEC_IMAGE).
Empty-input channels covered: (1) empty stdin + no extra argv; (2) programs that read argv[1] are ALSO run with argv=[in.txt] where
in.txt is an EMPTY file in the working dir. NOT covered: environment variables, network/socket inputs, files at fixed paths.
Reports the floor with channel (1) only and with (1)+(2), with and without a suspected label error (CASTLE-674-10)."""
import json, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import exec_harness as eh
from length_baseline import auroc, hanley_mcneil_se
cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
def one(c):
    r1 = eh.run_c(c["code"], [], "", timeout=5)
    uses_path = "argv[1]" in c["code"]
    r2 = eh.run_c(c["code"], ["in.txt"], "", timeout=5) if uses_path else None
    return {"id": c["id"], "label": c["label"], "truncated": c["truncated"], "uses_argv1": uses_path,
            "compiled": r1["compiled"], "san_stdin": r1["sanitizer"], "kind": r1["kind"], "timed_out": r1["timed_out"],
            "san_argvfile": (r2["sanitizer"] if r2 else None), "image": r1.get("image")}
with ThreadPoolExecutor(int(sys.argv[1]) if len(sys.argv) > 1 else 4) as ex:
    per = list(ex.map(one, cases))
for p in per:
    p["sanitizer_any"] = bool(p["san_stdin"] or p["san_argvfile"])
def A(rows, key):
    y = [1 if r["label"] == "VULNERABLE" else 0 for r in rows]; s = [1.0 if r[key] else 0.0 for r in rows]
    a = auroc(s, y); n1 = sum(y)
    return {"n": len(rows), "vuln_fired": sum(r[key] for r in rows if r["label"] == "VULNERABLE"), "safe_fired": sum(r[key] for r in rows if r["label"] == "SAFE"),
            "auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, len(y) - n1), 4)}
sus = "CASTLE-674-10.c"
no_sus = [r for r in per if r["id"] != sus]
res = {"image": per[0]["image"], "n": len(per), "compiled": sum(r["compiled"] for r in per), "compile_fail": sum(not r["compiled"] for r in per),
       "compiled_vuln": sum(r["compiled"] for r in per if r["label"] == "VULNERABLE"), "compiled_safe": sum(r["compiled"] for r in per if r["label"] == "SAFE"),
       "timed_out": sum(r["timed_out"] for r in per), "uses_argv1": sum(r["uses_argv1"] for r in per),
       "suspect_label_case_present": any(r["id"] == sus for r in per),
       "suspect_case": next((r for r in per if r["id"] == sus), None),
       "floor_stdin_only_all": A(per, "san_stdin"), "floor_stdin_plus_argvfile_all": A(per, "sanitizer_any"),
       "floor_stdin_only_without_suspect": A(no_sus, "san_stdin"), "floor_stdin_plus_argvfile_without_suspect": A(no_sus, "sanitizer_any"),
       "channels_covered": "empty stdin; no argv; argv=[empty file] for programs using argv[1]. NOT covered: env vars, sockets/network, fixed-path files",
       "per_case": per}
json.dump(res, open(sys.argv[2] if len(sys.argv) > 2 else "results/reason_D0_castle_preflight_v2.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}, indent=1))
