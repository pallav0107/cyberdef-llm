"""Compile coverage of the CASTLE programs (198) in the derived image: afl-clang-fast (ASan+UBSan, argv shim as in the fuzz harness) and plain gcc -fsanitize=address,undefined
(the pipeline floor toolchain). No network, mem/pids caps, non-root. Writes results/imp_2_compile_coverage.json.  python3 scripts/imp_compile_coverage.py [IMAGE]"""
import json, os, re, subprocess, sys, tempfile, shutil
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "scripts")
IMG = sys.argv[1] if len(sys.argv) > 1 else "imp-castle-san:1"
cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
LIBS = "-lm -lpthread -lsqlite3 -lmysqlclient -lssl -lcrypto -lcurl"


def one(c):
    d = tempfile.mkdtemp(prefix="impcc_"); os.chmod(d, 0o777)
    try:
        code = c["code"]
        m = re.search(r"\bint\s+main\s*\([^)]*argv[^)]*\)\s*\{", code)
        if m:
            code = '#include "argv-fuzz-inl.h"\n' + code[:m.end()] + " AFL_INIT_ARGV();" + code[m.end():]
        open(f"{d}/p.c", "w").write(code); open(f"{d}/q.c", "w").write(c["code"])
        os.chmod(f"{d}/p.c", 0o644); os.chmod(f"{d}/q.c", 0o644)
        inner = (f"cd /w; AFL_USE_ASAN=1 AFL_USE_UBSAN=1 AFL_QUIET=1 afl-clang-fast -w -O1 -g -I/AFLplusplus/utils/argv_fuzzing p.c -o p {LIBS} 2> a.err && echo AFL_OK; "
                 f"gcc -w -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined q.c -o q {LIBS} 2> g.err && echo GCC_OK")
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "128", "--cpus", "1", "--cap-drop", "ALL", "--user", "1000:1000",
                            "-e", "HOME=/tmp", "-v", f"{d}:/w", "--entrypoint", "sh", IMG, "-c", inner], capture_output=True, text=True, timeout=300)
        err = open(f"{d}/a.err", errors="replace").read()[-200:] if os.path.exists(f"{d}/a.err") else ""
        return {"id": c["id"], "label": c["label"], "afl_ok": "AFL_OK" in r.stdout, "gcc_ok": "GCC_OK" in r.stdout, "afl_err": err.replace("\n", " ")}
    finally:
        shutil.rmtree(d, ignore_errors=True)


with ThreadPoolExecutor(6) as ex:
    per = list(ex.map(one, cases))
res = {"image": IMG, "n": len(per), "afl_clang_ok": sum(p["afl_ok"] for p in per), "gcc_ok": sum(p["gcc_ok"] for p in per),
       "before_derived_image": {"afl_clang_compile_failures": 35, "gcc13_floor_compile_failures": 33, "source": "imp_2_fuzz_empty run3 and reason_D0_castle_preflight"},
       "by_label": {l: {"afl_ok": sum(p["afl_ok"] for p in per if p["label"] == l), "gcc_ok": sum(p["gcc_ok"] for p in per if p["label"] == l)} for l in ("VULNERABLE", "SAFE")},
       "per_case": per}
json.dump(res, open("results/imp_2_compile_coverage.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))
print([ (p["id"], p["afl_err"][-90:]) for p in per if not p["afl_ok"]][:8])
