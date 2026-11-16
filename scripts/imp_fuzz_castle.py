"""#2 fuzzing on CASTLE inside docker (AFL++), arms: empty | random | llm | llm_direct | random_resized.
See EXPERIMENT_PLAN_IMPROVE.md#2. Labels are used ONLY when scoring. Usage (repo root):
  nice -n 19 python3 scripts/imp_fuzz_castle.py --arm empty --budget 60 [--subset] [--jobs 6] [--limit N]
Output: results/imp_2_fuzz_<arm>_b<budget>[_subset].json"""
import argparse, hashlib, json, math, os, random, re, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc, hm_se, r4

IMAGE = os.environ.get("IMP_AFL_IMAGE", "imp-castle-san:1")
INNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "imp_fuzz_inner.py")
NSEED, MAXB = 5, 256
PRINT = [chr(c) for c in range(32, 127)] + ["\n"] * 9


def hseed(cid):
    return int(hashlib.sha1(cid.encode()).hexdigest()[:8], 16)


def random_seeds(cid, sizes=None):
    rng = random.Random(hseed(cid))
    out = []
    for i in range(NSEED):
        n = int(math.exp(rng.uniform(0, math.log(MAXB)))) if sizes is None else sizes[i % len(sizes)]
        out.append("".join(rng.choice(PRINT) for _ in range(max(1, n))))
    return out


def shim(code):
    """label-independent: programs whose main takes argv get the AFL++ argv-fuzz shim (stdin supplies argv)."""
    m = re.search(r"\bint\s+main\s*\([^)]*argv[^)]*\)\s*\{", code)
    if not m:
        return code, False
    code = code[:m.end()] + " AFL_INIT_ARGV();" + code[m.end():]
    return '#include "argv-fuzz-inl.h"\n' + code, True


def subset_ids(cases):
    pick = []
    for lab in ("VULNERABLE", "SAFE"):
        ids = sorted((c["id"] for c in cases if c["label"] == lab), key=lambda i: hashlib.sha1(i.encode()).hexdigest())
        pick += ids[:20]
    return set(pick)


def run_one(c, arm, budget, llm):
    d = tempfile.mkdtemp(prefix="impfz_")
    os.chmod(d, 0o777)
    try:
        code, argv_shim = shim(c["code"])
        open(f"{d}/p.c", "w").write(code)
        os.makedirs(f"{d}/seeds", exist_ok=True)
        if arm == "empty":
            seeds = ["\n"]
        elif arm == "random":
            seeds = random_seeds(c["id"])
        elif arm == "random_resized":
            sz = [max(1, len(s.encode())) for s in llm.get(c["id"], {}).get("seeds", [])] or None
            seeds = random_seeds(c["id"], sz)
        else:
            seeds = [s for s in llm.get(c["id"], {}).get("seeds", [])][:NSEED] or ["\n"]
        seeds = [s.encode("utf8", "replace")[:MAXB] for s in seeds]
        for i, s in enumerate(seeds):
            open(f"{d}/seeds/s{i}", "wb").write(s)
        dic = llm.get(c["id"], {}).get("dict") if arm == "llm" else None
        if dic:
            lines = ['"%s"' % str(x).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")[:64] for x in dic[:64] if str(x)]
            open(f"{d}/dict.txt", "w").write("\n".join(lines) + "\n")
        shutil.copy(INNER, f"{d}/inner.py")
        for p in (f"{d}/p.c", f"{d}/inner.py"):
            os.chmod(p, 0o644)
        name = f"impfz_{os.getpid()}_{abs(hash(c['id'])) % 10**8}"
        b = 0 if arm == "llm_direct" else budget
        cmd = ["docker", "run", "--rm", "--name", name, "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000", "-e", "HOME=/tmp",
               "-e", f"BUDGET={b}", "-e", "NOSAN=" + os.environ.get("IMP_NOSAN", "0"), "-v", f"{d}:/w", "-w", "/w", "--entrypoint", "python3", IMAGE, "inner.py"]
        t0 = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=b + 240)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True)
        r = {"compiled": False, "harness_fail": True}
        if os.path.exists(f"{d}/result.json"):
            r = json.load(open(f"{d}/result.json"))
        conf = bool(r.get("confirmed"))
        t = r.get("t_first_ms")
        score = (1.0 - min(t, budget * 1000) / (budget * 1000.0)) if (conf and t is not None and budget > 0) else 0.0
        if arm == "llm_direct":
            score = 1.0 if conf else 0.0
        return {"id": c["id"], "label": c["label"], "arm": arm, "budget_s": b, "argv_shim": argv_shim, "n_seeds": len(seeds),
                "seed_bytes": [len(s) for s in seeds], "compiled": bool(r.get("compiled")), "confirmed_crash": conf,
                "unconfirmed_crash": bool(r.get("unconfirmed")), "crashes_found": r.get("crashes_found", 0),
                "t_first_ms": t, "seed_crash": r.get("seed_crash"), "execs": r.get("execs"), "kind": r.get("kind"),
                "harness_fail": bool(r.get("harness_fail")), "afl_log_tail": r.get("afl_log_tail", "")[-300:], "afl_aborted": bool(r.get("afl_aborted")), "unconf_tail": (r.get("unconf_tail") or "")[-200:], "stderr_tail": (r.get("stderr_tail") or "")[-200:],
                "score": round(score, 6), "wall_s": round(time.time() - t0, 1)}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def summarise(per, cases):
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in per]
    sc = [p["score"] for p in per]
    n1 = sum(y)
    n0 = len(y) - n1
    a = auroc(sc, y)
    ch = {c["id"]: c["code_chars"] for c in cases}
    la = auroc([ch[p["id"]] for p in per], y)

    def rate(lab, key):
        rows = [p for p in per if p["label"] == lab]
        k = sum(1 for p in rows if p[key])
        return {"n": len(rows), "k": k, "rate": r4(k / max(1, len(rows)))}
    return {"auroc_time_score": r4(a), "se_hm": r4(hm_se(a, n1, n0)), "length_only_auroc_same_cases": r4(la),
            "confirmed_crash_on_vulnerable": rate("VULNERABLE", "confirmed_crash"),
            "confirmed_crash_on_safe": rate("SAFE", "confirmed_crash"),
            "unconfirmed_crash_on_vulnerable": rate("VULNERABLE", "unconfirmed_crash"),
            "unconfirmed_crash_on_safe": rate("SAFE", "unconfirmed_crash"),
            "compile_failures": sum(1 for p in per if not p["compiled"]),
            "afl_aborted_all_seeds_timeout_or_crash": sum(1 for p in per if p.get("afl_aborted")),
            "safe_programs_with_confirmed_crash": [p["id"] for p in per if p["label"] == "SAFE" and p["confirmed_crash"]]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=["empty", "random", "llm", "llm_direct", "random_resized"])
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--subset", action="store_true")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0, help="debug only: first N cases per label (never used for reported runs)")
    ap.add_argument("--llm-seeds", default="results/imp_2_llm_seeds.json")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    cf = json.load(open("results/xdata_castle_cases.json"))
    cases = cf["cases"]
    if a.subset:
        keep = subset_ids(cases)
        cases = [c for c in cases if c["id"] in keep]
    if a.limit:
        cases = [c for c in cases if c["label"] == "VULNERABLE"][:a.limit] + [c for c in cases if c["label"] == "SAFE"][:a.limit]
    llm = json.load(open(a.llm_seeds))["programs"] if a.arm in ("llm", "llm_direct", "random_resized") else {}
    t0 = time.time()
    with ThreadPoolExecutor(a.jobs) as ex:
        per = list(ex.map(lambda c: run_one(c, a.arm, a.budget, llm), cases))
    res = {"arm": a.arm, "experiment": "imp_2", "image": IMAGE, "budget_s": a.budget, "subset": a.subset,
           "debug_limit": a.limit or None, "n": len(per), "jobs": a.jobs, "floor_source": "results/reason_D0_castle_preflight.json",
           "seconds": round(time.time() - t0), "summary": summarise(per, cf["cases"]), "per_case": per}
    out = a.out or "results/imp_2_fuzz_%s_b%d%s.json" % (a.arm, a.budget, "_subset" if a.subset else "")
    json.dump(res, open(out, "w"))
    print(out, json.dumps(res["summary"]))


if __name__ == "__main__":
    main()
