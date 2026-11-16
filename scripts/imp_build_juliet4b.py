#!/usr/bin/env python3
"""J4b HELD-OUT TEST (addendum 3e; never trained on): the J4 recipe (scripts/imp_build_juliet4.py) with its three coverage bugs fixed.
  1. Memory CWEs: 200 candidate files per CWE (J4: 60). Per-CWE length matching needs >= 20 per class; from ~45 verified pairs
     only CWE-121 survived.
  2. Leak (CWE-401): LeakSanitizer ON for CWE-401 files only, and its report counts (J4 ran detect_leaks=0 and its pattern
     lacked "ERROR: LeakSanitizer", so 0/60 leaks verified).
  3. Integer (CWE-190, CWE-191, CWE-369): J4 ran with empty stdin, so input-driven bugs never fired (190: 8/60, 191: 7/60), and
     CWE-369 matched no directory ("Divide_By_Zero" vs Juliet's "Divide_by_Zero": 0 files). J4b keeps only SIGNED int/int64
     variants whose source is a constant (max/min/zero) or stdin (fgets/fscanf), and feeds the SAME stdin to the bad and the good
     program: INT_MAX-type for overflow, INT_MIN-type for underflow, 0 for divide-by-zero. UBSan reports signed overflow and
     integer division by zero (unsigned wrap and float division are not UB, so those variants are excluded); rand and socket
     sources are excluded (nondeterministic / no network in the sandbox).
A label is kept only if the bad program fires a sanitizer and the good program does not, on the same input. Functions whose
Juliet file supplies a few-shot exemplar are excluded (addendum 3b). Flow variants _02-_22/_31-_45, single-file .c only.
  nice -n 19 env IMP_JOBS=10 .venv/bin/python scripts/imp_build_juliet4b.py [--sample N]   -> results/j4b_heldout_all.json"""
import glob, json, os, random, re, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

ROOT = "data/juliet_dl/x/C"
MEMORY = ["CWE121_Stack_Based_Buffer_Overflow", "CWE122_Heap_Based_Buffer_Overflow", "CWE124_Buffer_Underwrite", "CWE126_Buffer_Overread",
          "CWE127_Buffer_Underread", "CWE415_Double_Free", "CWE416_Use_After_Free", "CWE476_NULL_Pointer_Dereference",
          "CWE590_Free_Memory_Not_on_Heap"]
PER = 200
FLOW = re.compile(r"_(0[2-9]|1[0-9]|2[0-2]|3[1-9]|4[0-5])\.c$")
SAN = re.compile(r"ERROR: AddressSanitizer|runtime error:|ERROR: UndefinedBehaviorSanitizer|ERROR: LeakSanitizer")
INT_KEEP = {   # CWE dir -> (allowed functional-variant regex, stdin by type)
    "CWE190_Integer_Overflow": (r"__(int|int64_t)_(fgets|fscanf|max)_(add|multiply|square|postinc|preinc)_",
                                {"int": b"2147483647\n", "int64_t": b"9223372036854775807\n"}),
    "CWE191_Integer_Underflow": (r"__(int|int64_t)_(fgets|fscanf|min)_(sub|multiply|postdec|predec)_",
                                 {"int": b"-2147483648\n", "int64_t": b"-9223372036854775808\n"}),
    "CWE369_Divide_by_Zero": (r"__int_(fgets|fscanf|zero)_(divide|modulo)_", {"int": b"0\n"}),
}
CATEGORY = {"CWE401": "leak", "CWE190": "integer", "CWE191": "integer", "CWE369": "integer"}


def strip(code, drop):
    return re.sub(r"#ifndef %s\b.*?#endif\s*/\*\s*%s\s*\*/" % (drop, drop), "", code, flags=re.S)


def stdin_for(f):
    base = os.path.basename(f)
    for d, (pat, inp) in INT_KEEP.items():
        if d in f:
            typ = "int64_t" if "__int64_t_" in base else "int"
            return inp[typ]
    return b""


def run(f, mode, leaks):
    d = tempfile.mkdtemp(prefix="j4b_"); os.chmod(d, 0o777)
    try:
        for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
            shutil.copy(f"{ROOT}/testcasesupport/{s}", d)
        shutil.copy(f, f"{d}/t.c")
        for x in glob.glob(os.path.dirname(f) + "/*.h"):
            shutil.copy(x, d)
        open(f"{d}/in.txt", "wb").write(stdin_for(f))
        for x in os.listdir(d):
            os.chmod(f"{d}/{x}", 0o644)
        inner = (f"cd /w && gcc -O0 -g -w -fsanitize=address,undefined -fno-sanitize-recover=undefined -DINCLUDEMAIN -D{mode} -I. t.c io.c std_thread.c -o p -lm -lpthread 2> cc.err || {{ echo CCFAIL >&2; exit 97; }}; "
                 f"ASAN_OPTIONS=detect_leaks={1 if leaks else 0} timeout 10 ./p < in.txt > o.txt 2> run.err; echo $? > rc.txt")
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64", "--user", "65534:65534", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "-v", f"{d}:/w", "-e", "HOME=/tmp", "gcc:13", "sh", "-c", inner]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if r.returncode == 97 or "CCFAIL" in r.stderr:
            return {"compiled": False, "sanitizer": False}
        err = open(f"{d}/run.err", errors="replace").read() if os.path.exists(f"{d}/run.err") else ""
        m = SAN.search(err)
        return {"compiled": True, "sanitizer": bool(m), "report": m.group(0) if m else None,
                "lsan_broken": "LeakSanitizer has encountered a fatal error" in err}
    except subprocess.TimeoutExpired:
        return {"compiled": True, "sanitizer": False, "timeout": True}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def candidates(sample):
    exfiles = {e["source_file"] for g in glob.glob("results/imp_fewshot_exemplars*.json") for e in json.load(open(g))["exemplars"]}
    out = []
    for c in MEMORY + ["CWE401_Memory_Leak"] + list(INT_KEEP):
        fs = sorted(glob.glob(f"{ROOT}/testcases/{c}/**/*.c", recursive=True))
        fs = [f for f in fs if FLOW.search(f) and os.path.basename(f) not in exfiles]
        if c in INT_KEEP:
            fs = [f for f in fs if re.search(INT_KEEP[c][0], os.path.basename(f))]
        k = sample if sample else PER
        out += sorted(random.Random(0).sample(fs, min(k, len(fs))))
    return out


def one(f):
    code = open(f, errors="replace").read()
    base = os.path.basename(f)
    cwe = re.match(r"(CWE\d+)", base).group(1)
    leaks = cwe == "CWE401"
    out = []
    for lab, mode, drop in (("VULNERABLE", "OMITGOOD", "OMITGOOD"), ("SAFE", "OMITBAD", "OMITBAD")):
        txt = re.sub(r"#ifdef INCLUDEMAIN.*?#endif", "", strip(code, drop), flags=re.S)
        r = run(f, mode, leaks)
        out.append({"id": f"j4h:{base}:{lab[0]}", "code": txt.strip()[:4000], "code_chars": len(txt.strip()), "label": lab,
                    "project": "juliet4b_heldout", "cwe": cwe, "category": CATEGORY.get(cwe, "memory"), "stdin": stdin_for(f).decode(),
                    "compiled": r["compiled"], "exec_sanitizer": r["sanitizer"], "report": r.get("report"),
                    "lsan_broken": r.get("lsan_broken", False), "timeout": r.get("timeout", False), "pair": base})
    return out


def main():
    sample = int(sys.argv[sys.argv.index("--sample") + 1]) if "--sample" in sys.argv else 0
    files = candidates(sample)
    with ThreadPoolExecutor(int(os.environ.get("IMP_JOBS", "2"))) as ex:
        items = [x for grp in ex.map(one, files) for x in grp]
    for it in items:
        it["toks"] = max(1, it["code_chars"] // 3)
    by = {}
    for it in items:
        b = by.setdefault(it["cwe"], {"files": 0, "bad_fires": 0, "good_fires": 0, "lsan_broken": 0, "timeouts": 0})
        b["files"] += it["label"] == "VULNERABLE"
        b["bad_fires"] += it["label"] == "VULNERABLE" and it["exec_sanitizer"]
        b["good_fires"] += it["label"] == "SAFE" and it["exec_sanitizer"]
        b["lsan_broken"] += it["lsan_broken"]; b["timeouts"] += it["timeout"]
    out = "results/j4b_heldout_sample.json" if sample else "results/j4b_heldout_all.json"
    json.dump({"items": items, "by_cwe": by, "sample": sample}, open(out, "w"))
    print(out); print(json.dumps(by, indent=1))


if __name__ == "__main__":
    main()
