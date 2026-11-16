"""Runs INSIDE the aflplusplus container (cwd /w). Compiles p.c with ASan+UBSan(trap) via afl-clang-fast, runs every seed directly,
optionally fuzzes for BUDGET seconds, replays crashes, writes result.json.
env: BUDGET (s, 0 = no fuzzing = arm iv), DICT (1 if /w/dict.txt exists)."""
import glob, json, os, re, signal, subprocess, sys, time

BUDGET = int(os.environ.get("BUDGET", "60"))
res = {"compiled": False, "seed_crash": None, "crashes_found": 0, "confirmed": False, "unconfirmed": False, "t_first_ms": None,
       "execs": None, "kind": None, "stderr_tail": ""}
env = dict(os.environ, AFL_USE_ASAN="1", AFL_USE_UBSAN="1", AFL_QUIET="1")
if os.environ.get("NOSAN") == "1":      # mutation switch for the fail-first control: sanitizers compiled out
    env.pop("AFL_USE_ASAN"); env.pop("AFL_USE_UBSAN")
cc = subprocess.run("afl-clang-fast -w -O1 -g -I/AFLplusplus/utils/argv_fuzzing p.c -o p -lm -lpthread -lsqlite3 -lmysqlclient -lssl -lcrypto -lcurl", shell=True, env=env,
                    capture_output=True, text=True)
if cc.returncode != 0 or not os.path.exists("p"):
    res["stderr_tail"] = cc.stderr[-400:]
    json.dump(res, open("result.json", "w")); sys.exit(0)
res["compiled"] = True
def save():
    json.dump(res, open("result.json", "w"))
save()
RENV = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=0:allocator_may_return_null=0", UBSAN_OPTIONS="")


def replay(path):
    """returns (confirmed, unconfirmed, kind, tail)"""
    try:
        with open(path, "rb") as f:
            r = subprocess.run(["./p"], stdin=f, capture_output=True, env=RENV, timeout=3)
    except subprocess.TimeoutExpired:
        return False, False, "timeout", ""
    err = r.stderr.decode("utf8", "replace")
    if "AddressSanitizer" in err:
        return True, False, "asan", err[-300:]
    if "runtime error:" in err:                                     # UBSan (recover disabled -> prints, then aborts)
        return True, False, "ubsan_text", err[-300:]
    if r.returncode in (-signal.SIGILL, -signal.SIGTRAP):          # UBSan trap-on-error
        return True, False, "ubsan_trap", err[-300:]
    if r.returncode < 0:
        return False, True, "signal%d" % -r.returncode, err[-300:]
    return False, False, "ok", ""


# 1. seeds run directly (this IS arm iv, and any seed crash counts at t=0 for the fuzzing arms)
seeds = sorted(glob.glob("seeds/*"))
for s in seeds:
    c, u, k, t = replay(s)
    if c or u:
        res["seed_crash"] = res["seed_crash"] or {"seed": os.path.basename(s), "confirmed": c, "kind": k}
        if c and not res["confirmed"]:
            res.update(confirmed=True, kind=k, t_first_ms=0, stderr_tail=t)
        elif u:
            res["unconfirmed"] = True; res["unconf_tail"] = t
save()
if BUDGET > 0:
    fenv = dict(os.environ, AFL_NO_UI="1", AFL_SKIP_CPUFREQ="1", AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1", AFL_NO_AFFINITY="1",
                AFL_SKIP_CRASHES="1", AFL_AUTORESUME="0", ASAN_OPTIONS=RENV["ASAN_OPTIONS"])
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
        res["afl_log_tail"] = lg[-400:]
        res["afl_aborted"] = "PROGRAM ABORT" in lg
    except Exception:
        pass
    cr = []
    for f in glob.glob("out/default/crashes/id:*"):
        m = re.search(r"time:(\d+)", f)
        cr.append((int(m.group(1)) if m else 10 ** 9, f))
    cr.sort()
    res["crashes_found"] = len(cr)
    for tms, f in cr[:10]:
        c, u, k, t = replay(f)
        if c and (not res["confirmed"] or tms < res["t_first_ms"]):
            res.update(confirmed=True, kind=k, t_first_ms=tms, stderr_tail=t)
        if u:
            res["unconfirmed"] = True; res["unconf_tail"] = t
    save()
    try:
        st = dict((l.split(":", 1)[0].strip(), l.split(":", 1)[1]) for l in open("out/default/fuzzer_stats").read().splitlines() if ":" in l)
        res["execs"] = int(st["execs_done"].strip())
    except Exception:
        pass
json.dump(res, open("result.json", "w"))
