"""Pool J (trace bank, tag X): Juliet 1.3 C testcases, bad and good VARIANT texts, each executed once in the Stage-D-style sandbox.
  nice -n 19 .venv/bin/python scripts/imp_build_juliet.py
Text shown to the model: the testcase file with the OTHER variant's #ifndef block removed (bad text keeps only bad code; good text only good code).
Execution (docker gcc:13, --network none, mem/pids caps, non-root, ASan+UBSan, empty stdin): `exec_sanitizer` = a sanitizer report fired.
NOTE (honest scope): Juliet programs need no input, so the bad program crashes with or without a model-written witness; the X tag therefore verifies the
LABEL by execution and that the trace says VULNERABLE, not that the witness values triggered the crash. Juliet predates Qwen2.5 (memorisation caveat).
Writes results/imp_train_juliet_items.json. Reuses nothing from the other agent's files except reading data/juliet_dl."""
import glob, json, os, re, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
ROOT = "data/juliet_dl/x/C"
CWES = ["CWE121_Stack_Based_Buffer_Overflow", "CWE122_Heap_Based_Buffer_Overflow", "CWE124_Buffer_Underwrite", "CWE126_Buffer_Overread",
        "CWE415_Double_Free", "CWE416_Use_After_Free", "CWE476_NULL_Pointer_Dereference", "CWE190_Integer_Overflow",
        "CWE127_Buffer_Underread", "CWE369_Divide_By_Zero", "CWE401_Memory_Leak", "CWE590_Free_Memory_Not_on_Heap"]
PER = 30
SAN = re.compile(r"ERROR: AddressSanitizer|runtime error:|ERROR: UndefinedBehaviorSanitizer")


def strip(code, drop):
    """remove the '#ifndef <drop> ... #endif /* <drop> */' block"""
    return re.sub(r"#ifndef %s\b.*?#endif\s*/\*\s*%s\s*\*/" % (drop, drop), "", code, flags=re.S)


def run(f, mode):
    d = tempfile.mkdtemp(prefix="jul_"); os.chmod(d, 0o777)
    try:
        for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
            shutil.copy(f"{ROOT}/testcasesupport/{s}", d)
        shutil.copy(f, f"{d}/t.c")
        for x in glob.glob(os.path.dirname(f) + "/*.h"):
            shutil.copy(x, d)
        for x in os.listdir(d):
            os.chmod(f"{d}/{x}", 0o644)
        inner = (f"cd /w && gcc -O0 -g -w -fsanitize=address,undefined -fno-sanitize-recover=undefined -DINCLUDEMAIN -D{mode} -I. t.c io.c std_thread.c -o p -lm -lpthread 2> cc.err || {{ echo CCFAIL >&2; exit 97; }}; "
                 "ASAN_OPTIONS=detect_leaks=0 timeout 10 ./p < /dev/null > o.txt 2> run.err; echo $? > rc.txt")
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64", "--user", "65534:65534", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "-v", f"{d}:/w", "-e", "HOME=/tmp", "gcc:13", "sh", "-c", inner]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if r.returncode == 97 or "CCFAIL" in r.stderr:
            return {"compiled": False, "sanitizer": False}
        err = open(f"{d}/run.err", errors="replace").read() if os.path.exists(f"{d}/run.err") else ""
        return {"compiled": True, "sanitizer": bool(SAN.search(err))}
    except subprocess.TimeoutExpired:
        return {"compiled": True, "sanitizer": False, "timeout": True}
    finally:
        shutil.rmtree(d, ignore_errors=True)


files = []
for c in CWES:
    fs = sorted(glob.glob(f"{ROOT}/testcases/{c}/**/*_01.c", recursive=True))
    fs = [f for f in fs if not re.search(r"_[a-z]$|_\d+[a-z]\.c$", f)]
    files += fs[:PER]


def one(f):
    code = open(f, errors="replace").read()
    base = os.path.basename(f)
    cwe = re.match(r"(CWE\d+)", base).group(1)
    out = []
    for lab, mode, drop in (("VULNERABLE", "OMITGOOD", "OMITGOOD"), ("SAFE", "OMITBAD", "OMITBAD")):
        txt = strip(code, drop)
        # drop Juliet's boilerplate main section too (not part of the tested logic)
        txt = re.sub(r"#ifdef INCLUDEMAIN.*?#endif", "", txt, flags=re.S)
        r = run(f, mode)
        out.append({"id": f"juliet:{base}:{lab[0]}", "code": txt.strip()[:4000], "code_chars": len(txt.strip()), "label": lab, "project": "juliet", "cwe": cwe,
                    "compiled": r["compiled"], "exec_sanitizer": r["sanitizer"], "pair": base})
    return out


with ThreadPoolExecutor(int(os.environ.get("IMP_JOBS", "2"))) as ex:
    items = [x for grp in ex.map(one, files) for x in grp]
stats = {"files": len(files), "items": len(items), "compiled": sum(i["compiled"] for i in items),
         "bad_sanitizer": sum(1 for i in items if i["label"] == "VULNERABLE" and i["exec_sanitizer"]),
         "good_sanitizer": sum(1 for i in items if i["label"] == "SAFE" and i["exec_sanitizer"])}
for it in items:
    it["toks"] = max(1, it["code_chars"] // 3)
json.dump({"items": items, "stats": stats}, open("results/imp_train_juliet_items.json", "w"))
print(json.dumps(stats))
