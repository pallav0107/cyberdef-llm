"""Runs INSIDE the imp-castle-san container (cwd /w, non-root, --network none). Oracle-spec version of the fuzz inner (results/imp_castle_oracle_spec.json):
  builds variants A (afl-clang ASan+UBSan), B (clang integer), D (gcc ASan+UBSan); optionally fuzzes A with AFL++ for BUDGET s; then replays the corpus
  (seeds + AFL queue + crashes) under A, A_leak, B, D and writes result.json. Variant C (TSan) is run by imp_oracle_tsan.py in a separate container (seccomp).
env BUDGET (0 = no fuzzing), MODE ('fuzz' | 'tsan')."""
import glob, json, os, re, resource, subprocess, sys, time

sys.path.insert(0, "/w")
import imp_oracle as O

BUDGET = int(os.environ.get("BUDGET", "60"))
MODE = os.environ.get("MODE", "fuzz")
MAXQ, MAXC, TIMEOUT, MAXTO = 25, 10, 3, 3
res = {"compiled": {}, "corpus": [], "reports": {}, "replay_stopped_after_timeouts": {}, "afl_aborted": False, "execs": None}


def save():
    json.dump(res, open("result.json" if MODE == "fuzz" else "result_tsan.json", "w"))


def sh(cmd, env=None, timeout=240):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, env=dict(os.environ, **(env or {})))


def compile_variants():
    cc = {}
    if MODE == "fuzz":
        cc["A"] = sh(f"afl-clang-fast -w -O1 -g {O.INC} p.c -o p {O.LIBS}", {"AFL_USE_ASAN": "1", "AFL_USE_UBSAN": "1", "AFL_QUIET": "1"}).returncode == 0 and os.path.exists("p")
        cc["B"] = sh(f"clang -w -O1 -g -fsanitize=integer -fsanitize-recover=all {O.INC} p.c -o pB {O.LIBS}").returncode == 0 and os.path.exists("pB")
        cc["P"] = (os.path.exists("imp_shim.c") and sh("gcc -shared -fPIC -O1 imp_shim.c -o imp_shim.so -ldl").returncode == 0 and
                   sh(f"gcc -w -O0 -g {O.INC} p.c -o pP {O.LIBS}").returncode == 0 and os.path.exists("pP"))
        cc["D"] = sh(f"gcc -w -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined {O.INC} p.c -o pD {O.LIBS}").returncode == 0 and os.path.exists("pD")
    else:
        cc["C"] = sh(f"clang -w -O1 -g -fsanitize=thread {O.INC} p.c -o pC {O.LIBS}").returncode == 0 and os.path.exists("pC")
    return cc


ENVS = {"A": {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:symbolize=0:allocator_may_return_null=0", "UBSAN_OPTIONS": "print_stacktrace=0"},
        "A_leak": {"ASAN_OPTIONS": "detect_leaks=1:abort_on_error=0:symbolize=0:exitcode=23", "UBSAN_OPTIONS": "print_stacktrace=0"},
        "B": {"UBSAN_OPTIONS": "print_stacktrace=0"}, "C": {"TSAN_OPTIONS": "exitcode=66:symbolize=0"},
        "D": {"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0:symbolize=0", "UBSAN_OPTIONS": "print_stacktrace=0"}}
BINS = {"A": "./p", "A_leak": "./p", "B": "./pB", "C": "./pC", "D": "./pD"}


def replay(variant, path):
    t0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    to = False
    try:
        with open(path, "rb") as f:
            r = subprocess.run([BINS[variant]], stdin=f, capture_output=True, timeout=TIMEOUT, env=dict(os.environ, **ENVS[variant]))
        err = r.stderr.decode("utf8", "replace"); rc = r.returncode
    except subprocess.TimeoutExpired as e:
        to = True; err = (e.stderr or b"").decode("utf8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or ""); rc = None
    t1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (t1.ru_utime - t0.ru_utime) + (t1.ru_stime - t0.ru_stime)
    return O.classify(variant, err, to, cpu), rc, to, round(cpu, 2), err[-200:]


def replay_behaviour():
    """variant P: only corpus inputs that contain the literal CANARY are replayed (the payload comes from the model/fuzzer); each run substitutes a fresh token"""
    if not res["compiled"].get("P"):
        return
    import imp_behaviour as BH
    rows = []
    for i, it in enumerate(res["corpus"]):
        data = open(it["path"], "rb").read()
        if b"CANARY" not in data:
            continue
        r = BH.run_behaviour("./pP", data, timeout=TIMEOUT, shim="/w/imp_shim.so")
        cl = BH.classes(r)
        if cl:
            rows.append({"i": i, "t_ms": it["t_ms"], "src": it["src"], "classes": cl, "rc": None, "timed_out": r["timed_out"], "cpu_s": 0.0, "tail": (r["log"][:2] or [r["out"][:100]])[0][:200]})
    res["reports"]["P"] = rows
    save()


def replay_corpus(variants):
    for v in variants:
        if not res["compiled"].get(v if v != "A_leak" else "A"):
            continue
        rows, timeouts = [], 0
        for i, it in enumerate(res["corpus"]):
            if timeouts >= MAXTO:
                res["replay_stopped_after_timeouts"][v] = i; break
            cl, rc, to, cpu, tail = replay(v, it["path"])
            timeouts += to
            if cl or to:
                rows.append({"i": i, "t_ms": it["t_ms"], "src": it["src"], "classes": cl, "rc": rc, "timed_out": to, "cpu_s": cpu, "tail": tail if cl else ""})
        res["reports"][v] = rows
        save()


res["compiled"] = compile_variants()
save()
seeds = sorted(glob.glob("seeds/*"))
if MODE == "tsan":
    res["corpus"] = json.load(open("corpus.json"))
    replay_corpus(["C"])
    save(); sys.exit(0)
res["corpus"] = [{"path": s, "t_ms": 0, "src": "seed"} for s in seeds]
if BUDGET > 0 and res["compiled"].get("A"):
    fenv = dict(os.environ, AFL_NO_UI="1", AFL_SKIP_CPUFREQ="1", AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1", AFL_NO_AFFINITY="1", AFL_SKIP_CRASHES="1", AFL_AUTORESUME="0",
                ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=0:allocator_may_return_null=0")
    cmd = ["afl-fuzz", "-i", "seeds", "-o", "out", "-V", str(BUDGET), "-m", "none", "-s", "0", "-t", "1000+"]
    if os.path.exists("dict.txt"):
        cmd += ["-x", "dict.txt"]
    cmd += ["--", "./p"]
    try:
        subprocess.run(cmd, env=fenv, stdout=open("afl.log", "w"), stderr=subprocess.STDOUT, timeout=BUDGET + 60)
    except subprocess.TimeoutExpired:
        res["afl_timeout"] = True
    try:
        lg = open("afl.log", errors="replace").read()
        res["afl_aborted"] = "PROGRAM ABORT" in lg
    except Exception:
        pass
    def tms(f):
        m = re.search(r"time:(\d+)", f)
        return int(m.group(1)) if m else 0
    q = [f for f in glob.glob("out/default/queue/id:*") if "orig:" not in f]
    q.sort(key=tms)
    c = glob.glob("out/default/crashes/id:*")
    c.sort(key=tms)
    res["corpus"] += [{"path": f, "t_ms": tms(f), "src": "queue"} for f in q[:MAXQ]] + [{"path": f, "t_ms": tms(f), "src": "crash"} for f in c[:MAXC]]
    try:
        st = dict((l.split(":", 1)[0].strip(), l.split(":", 1)[1]) for l in open("out/default/fuzzer_stats").read().splitlines() if ":" in l)
        res["execs"] = int(st["execs_done"].strip())
    except Exception:
        pass
save()
# keep a copy of the corpus for the TSan container
os.makedirs("corpus", exist_ok=True)
cj = []
for k, it in enumerate(res["corpus"]):
    dst = f"corpus/{k}"
    open(dst, "wb").write(open(it["path"], "rb").read())
    cj.append({"path": f"/w/{dst}", "t_ms": it["t_ms"], "src": it["src"]})
json.dump(cj, open("corpus.json", "w"))
replay_corpus(["A", "A_leak", "B", "D"])
replay_behaviour()
save()
