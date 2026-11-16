"""STRICT X tag for the trace bank (Juliet pool). Run INSIDE a docker container that has gcc (box: imp-castle-san:1; Spark: cyberdef-train:aarch64), started with --network none,
resource caps, non-root. The model witness is executed; X_strict = the bad program crashes under the WITNESS input AND does NOT crash under EMPTY input AND the same witness does NOT crash
the good twin. Loose X (old tag `X`) = the bad program crashes with empty input and the trace says VULNERABLE (certifies nothing about reasoning: Stage D found 11/12 and 19/20 CASTLE witness
catches also crash on empty input; 158/246 Juliet bad programs crash with no input).
  python3 scripts/imp_bank_strictx.py [quick]      env IMP_JULIET = root with testcases/ and testcasesupport/ (default data/juliet_dl/x/C)
Reads results/imp_trace_bank[_quick].jsonl (merged), rewrites it with X_strict / X_strict_detail on every orig row (None when not applicable) and updates
results/imp_trace_bank[_quick]_counts.json with loose and strict X counts per generator and arm-7 feasibility on the STRICT count (>= 200).
Witness -> input mapping (pre-registered here): witness.values (dict) -> if it has 'argv'/'stdin' keys use them; else the scalar values in order; how_to_feed mentioning 'argv'/'command'/'argument' -> argv,
otherwise stdin joined with newlines."""
import glob, json, os, re, shutil, subprocess, sys, tempfile
sys.path.insert(0, "scripts"); sys.path.insert(0, "src")
from reason_C_witness import parse_json

QUICK = len(sys.argv) > 1 and sys.argv[1] == "quick"
SUF = "_quick" if QUICK else ""
ROOT = os.environ.get("IMP_JULIET", "data/juliet_dl/x/C")
SAN = re.compile(r"ERROR: AddressSanitizer|runtime error:|ERROR: UndefinedBehaviorSanitizer")
LIBS = "-lm -lpthread"
IDX = {}
for p in glob.glob(f"{ROOT}/testcases/**/*.c", recursive=True) + glob.glob(f"{ROOT}/testcases/**/*.cpp", recursive=True):
    IDX.setdefault(os.path.basename(p), p)
BIN = {}
TMP = tempfile.mkdtemp(prefix="impsx_")


def build(base, mode):
    key = (base, mode)
    if key in BIN:
        return BIN[key]
    d = tempfile.mkdtemp(dir=TMP)
    src = IDX.get(base)
    if not src:
        BIN[key] = None; return None
    for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
        shutil.copy(f"{ROOT}/testcasesupport/{s}", d)
    shutil.copy(src, f"{d}/t.c")
    for x in glob.glob(os.path.dirname(src) + "/*.h"):
        shutil.copy(x, d)
    r = subprocess.run(f"cd {d} && gcc -O0 -g -w -fsanitize=address,undefined -fno-sanitize-recover=undefined -DINCLUDEMAIN -D{mode} -I. t.c io.c std_thread.c -o p {LIBS}",
                       shell=True, capture_output=True, text=True, timeout=120)
    BIN[key] = f"{d}/p" if r.returncode == 0 else None
    return BIN[key]


def run(binary, argv, stdin):
    if not binary:
        return None
    try:
        r = subprocess.run([binary] + argv, input=stdin.encode("utf8", "replace"), capture_output=True, timeout=5,
                           env=dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=0"))
        return bool(SAN.search(r.stderr.decode("utf8", "replace")))
    except subprocess.TimeoutExpired:
        return False


def witness_input(raw):
    d = parse_json(raw)
    w = d.get("witness") if isinstance(d, dict) else None
    if not isinstance(w, dict):
        return None
    vals = w.get("values")
    how = str(w.get("how_to_feed", "")).lower()
    argv, stdin = [], ""
    if isinstance(vals, dict):
        if isinstance(vals.get("argv"), list) or isinstance(vals.get("stdin"), str):
            argv = [str(a) for a in vals.get("argv", [])] if isinstance(vals.get("argv"), list) else []
            stdin = vals["stdin"] if isinstance(vals.get("stdin"), str) else ""
        else:
            sc = [str(v) for v in vals.values() if isinstance(v, (str, int, float))]
            if any(k in how for k in ("argv", "command", "argument")):
                argv = sc
            else:
                stdin = "\n".join(sc)
    elif isinstance(vals, list):
        sc = [str(v) for v in vals if isinstance(v, (str, int, float))]
        if any(k in how for k in ("argv", "command", "argument")):
            argv = sc
        else:
            stdin = "\n".join(sc)
    else:
        return None
    if not argv and not stdin:
        return None
    return argv, stdin


BEH_ORACLES = ("cmd_injection", "format_string", "path_traversal", "sqli")
SHIMDIR = tempfile.mkdtemp(prefix="impshim_", dir=TMP)
_beh_ready = {}


def beh_setup():
    """compile the LD_PRELOAD shim once; returns the imp_behaviour module"""
    if "mod" not in _beh_ready:
        shutil.copy("scripts/imp_shim.c", f"{SHIMDIR}/imp_shim.c")
        r = subprocess.run(f"cd {SHIMDIR} && gcc -shared -fPIC -O1 imp_shim.c -o imp_shim.so -ldl", shell=True, capture_output=True, text=True)
        import importlib
        _beh_ready["mod"] = importlib.import_module("imp_behaviour") if r.returncode == 0 else None
    return _beh_ready["mod"]


ITEMS2 = {}
for _f in ("imp_train_juliet2_items.json", "imp_train_juliet3_items.json", "imp_train_sqli_items.json"):
    if os.path.exists("results/" + _f):
        for _it in json.load(open("results/" + _f))["items"]:
            ITEMS2[_it["id"]] = _it


def build_beh(fn):
    """(bad_binary, good_binary) for a J2 / synthetic-SQLi function id (…:V)"""
    key = ("beh", fn)
    if key in BIN:
        return BIN[key]
    d = tempfile.mkdtemp(dir=TMP)
    res = (None, None)
    if fn.startswith(("juliet2:", "juliet3:")):
        base = fn.split(":")[1]
        src = IDX.get(base)
        if src:
            for sfile in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
                shutil.copy(f"{ROOT}/testcasesupport/{sfile}", d)
            ext = os.path.splitext(src)[1]
            shutil.copy(src, f"{d}/t{ext}")
            for x in glob.glob(os.path.dirname(src) + "/*.h"):
                shutil.copy(x, d)
            cc = "g++ -fpermissive" if ext == ".cpp" else "gcc"
            outs = []
            for mode in ("OMITGOOD", "OMITBAD"):
                r = subprocess.run(f"cd {d} && {cc} -O0 -w -DINCLUDEMAIN -D{mode} -I. t{ext} io.c std_thread.c -o p_{mode} -lm -lpthread", shell=True, capture_output=True, text=True, timeout=120)
                outs.append(f"{d}/p_{mode}" if r.returncode == 0 else None)
            res = tuple(outs)
    elif fn.startswith("sqli:"):
        outs = []
        for suffix in ("V", "S"):
            it = ITEMS2.get(fn[:-1] + suffix)
            if not it:
                outs.append(None); continue
            open(f"{d}/{suffix}.c", "w").write(it["code"])
            r = subprocess.run(f"gcc -w -O0 {d}/{suffix}.c -o {d}/{suffix} -lsqlite3", shell=True, capture_output=True, text=True, timeout=60)
            outs.append(f"{d}/{suffix}" if r.returncode == 0 else None)
        res = tuple(outs)
    BIN[key] = res
    return res


def beh_payload(raw):
    """model witness -> (payload bytes, feed kind) ; feed kind from how_to_feed: env / file / stdin"""
    d = parse_json(raw)
    w = d.get("witness") if isinstance(d, dict) else None
    if not isinstance(w, dict) or not isinstance(w.get("values"), (dict, list)):
        return None
    vals = w["values"].values() if isinstance(w["values"], dict) else w["values"]
    sc = [str(v) for v in vals if isinstance(v, (str, int, float))]
    if not sc:
        return None
    how = str(w.get("how_to_feed", "")).lower()
    kind = "environment" if "env" in how else "file" if "file" in how else "console"
    return ("\n".join(sc) + "\n").encode(), kind


def beh_strict(r, item):
    mod = beh_setup()
    det = {"behaviour": True}
    orc = r.get("oracle")
    pl = beh_payload(r["raw"])
    if mod is None or pl is None:
        det["witness_present"] = pl is not None
        return False, det
    det["witness_present"] = True
    payload, kind = pl
    bad, good = build_beh(r["fn"])
    if not (bad and good):
        det["compiled"] = False
        return False, det
    def run(binary, data, k):
        if k == "console":
            return mod.run_behaviour(binary, data, shim=f"{SHIMDIR}/imp_shim.so")
        if k == "environment":
            return mod.run_behaviour(binary, b"", env_extra={"ADD": data.decode().strip("\n")}, shim=f"{SHIMDIR}/imp_shim.so")
        return mod.run_behaviour(binary, b"", files={"/tmp/file.txt": data}, shim=f"{SHIMDIR}/imp_shim.so")
    wb, we, wg = run(bad, payload, kind), run(bad, b"", kind), run(good, payload, kind)
    det.update(compiled=True, chosen_oracle=orc, witness_fires_bad=wb["verdicts"][orc], empty_fires_bad=we["verdicts"][orc], witness_fires_good=wg["verdicts"][orc], feed=kind)
    return bool(wb["verdicts"][orc] and not we["verdicts"][orc] and not wg["verdicts"][orc]), det


rows = [json.loads(l) for l in open(f"results/imp_trace_bank{SUF}.jsonl")]
cache = {}
for r in rows:
    r["X_strict"] = None
    if r["edit"] == "orig" and r["fn"].startswith(("juliet2:", "juliet3:", "sqli:")) and r["fn"].endswith(":V") and r.get("V") and r.get("P") and r.get("oracle") in BEH_ORACLES:
        ok, det = beh_strict(r, ITEMS2.get(r["fn"]))
        r["X_strict"] = ok; r["X_strict_detail"] = det
        continue
    if r["edit"] != "orig" or not r["fn"].startswith("juliet:") or not r["fn"].endswith(":V"):
        continue
    if not (r.get("V") and r.get("P")):
        continue
    base = r["fn"].split(":")[1]
    if r.get("oracle") not in ("asan", "integer", "ubsan", None):      # chosen oracle must be sanitizer-monitored until the behaviour monitors exist in the bank pipeline
        r["X_strict"] = None; r["X_strict_detail"] = {"skipped": "chosen oracle %s has no sanitizer monitor yet" % r.get("oracle")}; continue
    wi = witness_input(r["raw"])
    det = {"witness_present": wi is not None}
    if wi is None:
        r["X_strict"] = False; r["X_strict_detail"] = det; continue
    argv, stdin = wi
    k = (base, tuple(argv), stdin)
    if k not in cache:
        bad, good = build(base, "OMITGOOD"), build(base, "OMITBAD")
        cache[k] = {"compiled": bool(bad and good), "empty_crash": run(bad, [], ""), "witness_crash_bad": run(bad, argv, stdin), "witness_crash_good": run(good, argv, stdin)}
    c = cache[k]
    det.update(c)
    r["X_strict"] = bool(c["compiled"] and c["witness_crash_bad"] and not c["empty_crash"] and not c["witness_crash_good"])
    r["X_strict_detail"] = det
with open(f"results/imp_trace_bank{SUF}.jsonl", "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
cf = f"results/imp_trace_bank{SUF}_counts.json"
cnt = json.load(open(cf))
orig = [r for r in rows if r["edit"] == "orig"]
gens = sorted({r["gen"] for r in orig})
cnt["x_loose_traces_by_gen"] = {g: sum(1 for r in orig if r["gen"] == g and r["X"] is True and r["P"]) for g in gens}
cnt["x_strict_traces_by_gen"] = {g: sum(1 for r in orig if r["gen"] == g and r.get("X_strict") is True) for g in gens}
cnt["x_loose_traces_total"] = sum(cnt["x_loose_traces_by_gen"].values())
cnt["x_strict_traces_total"] = sum(cnt["x_strict_traces_by_gen"].values())
cnt["x_strict_distinct_functions"] = len({r["fn"] for r in orig if r.get("X_strict") is True})
cnt["witness_present_among_juliet_VP_traces"] = sum(1 for r in orig if r.get("X_strict_detail", {}).get("witness_present"))
cnt["juliet_VP_traces_considered"] = sum(1 for r in orig if r.get("X_strict") is not None)
cnt["bad_programs_crashing_on_empty_input_among_considered"] = sum(1 for r in orig if r.get("X_strict_detail", {}).get("empty_crash"))
cnt["arm7_feasible_loose"] = cnt["x_loose_traces_total"] >= 200
cnt["arm7_feasible"] = cnt["x_strict_traces_total"] >= 200      # the gate uses STRICT X
cnt["arm7_gate_uses"] = "X_strict (witness crashes bad program, empty input does not, witness does not crash the good twin)"
json.dump(cnt, open(cf, "w"), indent=1)
shutil.rmtree(TMP, ignore_errors=True)
print(json.dumps({k: cnt[k] for k in ("x_loose_traces_total", "x_strict_traces_total", "x_strict_distinct_functions", "arm7_feasible", "juliet_VP_traces_considered", "witness_present_among_juliet_VP_traces")}))
