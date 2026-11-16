"""Stage D0 on Juliet 1.3 (NIST SARD; public domain; PREDATES Qwen2.5 -> likely in pretraining: SECONDARY, memorisation-caveated).
For each selected testcase file, compile with testcasesupport in the Stage-D sandbox twice: -DOMITGOOD (only the *_bad path runs)
and -DOMITBAD (only the good path runs); no input, no model. Reports sanitizer-fire rate on bad vs good = the execution-only baseline."""
import json, os, re, shutil, subprocess, sys, tempfile, glob
from concurrent.futures import ThreadPoolExecutor
ROOT = "data/juliet_dl/x/C"
CWES = ["CWE121_Stack_Based_Buffer_Overflow", "CWE122_Heap_Based_Buffer_Overflow", "CWE124_Buffer_Underwrite", "CWE126_Buffer_Overread",
        "CWE415_Double_Free", "CWE416_Use_After_Free", "CWE476_NULL_Pointer_Dereference", "CWE190_Integer_Overflow"]
PER = 12
SAN = re.compile(r"ERROR: AddressSanitizer|runtime error:|ERROR: UndefinedBehaviorSanitizer")
files = []
for c in CWES:
    fs = sorted(glob.glob(f"{ROOT}/testcases/{c}/**/*_01.c", recursive=True))   # flow variant 01, C only, no s0N subdir bias
    fs = [f for f in fs if not re.search(r"_[a-z]$|_\d+[a-z]\.c$", f)]
    files += fs[:PER]
def build_run(f, mode):
    d = tempfile.mkdtemp(prefix="jul_"); os.chmod(d, 0o777)
    try:
        for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
            shutil.copy(f"{ROOT}/testcasesupport/{s}", d)
        shutil.copy(f, f"{d}/t.c")
        for x in glob.glob(os.path.dirname(f) + "/*.h"):
            shutil.copy(x, d)
        for x in os.listdir(d): os.chmod(f"{d}/{x}", 0o644)
        inner = (f"cd /w && gcc -O0 -g -w -fsanitize=address,undefined -fno-sanitize-recover=undefined -DINCLUDEMAIN -D{mode} -I. t.c io.c std_thread.c -o p -lm -lpthread 2> cc.err || {{ echo CCFAIL >&2; exit 97; }}; "
                 "ASAN_OPTIONS=detect_leaks=0 timeout 10 ./p < /dev/null > o.txt 2> run.err; echo $? > rc.txt")
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64", "--user", "65534:65534", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "-v", f"{d}:/w", "-e", "HOME=/tmp", __import__("os").environ.get("EXEC_IMAGE", "gcc:13"), "sh", "-c", inner]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if r.returncode == 97 or "CCFAIL" in r.stderr:
            return {"compiled": False, "sanitizer": False}
        err = open(f"{d}/run.err", errors="replace").read() if os.path.exists(f"{d}/run.err") else ""
        return {"compiled": True, "sanitizer": bool(SAN.search(err))}
    except subprocess.TimeoutExpired:
        return {"compiled": True, "sanitizer": False, "timeout": True}
    finally:
        shutil.rmtree(d, ignore_errors=True)
def one(f):
    return {"file": os.path.basename(f), "cwe": f.split("/")[-2] if "/s0" not in f else f.split("/testcases/")[1].split("/")[0],
            "bad": build_run(f, "OMITGOOD"), "good": build_run(f, "OMITBAD")}
with ThreadPoolExecutor(4) as ex:
    per = list(ex.map(one, files))
nb = sum(p["bad"]["compiled"] for p in per); ng = sum(p["good"]["compiled"] for p in per)
res = {"set": "juliet_subset (SECONDARY, pre-Qwen2.5, memorisation-caveated)", "n_files": len(per), "bad_compiled": nb, "good_compiled": ng,
       "sanitizer_on_bad": sum(p["bad"]["sanitizer"] for p in per), "sanitizer_on_good": sum(p["good"]["sanitizer"] for p in per),
       "by_cwe": {}, "per_case": per}
for p in per:
    b = res["by_cwe"].setdefault(p["cwe"], {"n": 0, "bad_san": 0, "good_san": 0, "bad_compiled": 0})
    b["n"] += 1; b["bad_san"] += p["bad"]["sanitizer"]; b["good_san"] += p["good"]["sanitizer"]; b["bad_compiled"] += p["bad"]["compiled"]
json.dump(res, open("results/reason_D0_juliet_preflight.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))
