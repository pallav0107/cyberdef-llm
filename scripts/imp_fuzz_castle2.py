"""#2 under the shared oracle spec (results/imp_castle_oracle_spec.json): arms floor | empty | random | llm | llm_direct | random_resized on the 198 CASTLE programs in imp-castle-san:1.
  nice -n 19 python3 scripts/imp_fuzz_castle2.py --arm floor|empty|random [--budget 60] [--subset] [--jobs 6] [--limit N (debug only)]
Output results/imp_2o_<arm>_b<budget>[_subset].json with per_case (n=198), overall and per-CWE-group summaries (a sanitizer-detectable / b crash-like-other / c non-crash), per-variant contributions.
Labels are used only for scoring and for the per-group tables."""
import argparse, hashlib, json, math, os, shutil, subprocess, sys, tempfile, time
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
import imp_oracle as O
import imp_fuzz_castle as F0
from cyberdef.imp_common import auroc, hm_se, r4

IMAGE = O.IMAGE
HERE = os.path.dirname(os.path.abspath(__file__))
SAFE_OPTS = ["--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000", "-e", "HOME=/tmp"]


def run_one(c, arm, budget, llm):
    d = tempfile.mkdtemp(prefix="impo_")
    os.chmod(d, 0o777)
    try:
        code, shim = F0.shim(c["code"])
        open(f"{d}/p.c", "w").write(code)
        os.makedirs(f"{d}/seeds")
        if arm == "floor":
            seeds = [""]
        elif arm == "empty":
            seeds = ["\n"]
        elif arm == "random":
            seeds = F0.random_seeds(c["id"])
        elif arm == "random_resized":
            sz = [max(1, len(s.encode())) for s in llm.get(c["id"], {}).get("seeds", [])] or None
            seeds = F0.random_seeds(c["id"], sz)
        else:
            seeds = [s for s in llm.get(c["id"], {}).get("seeds", [])][:5] or ["\n"]
        for i, s in enumerate(seeds):
            open(f"{d}/seeds/s{i}", "wb").write(s.encode("utf8", "replace")[:256])
        dic = llm.get(c["id"], {}).get("dict") if arm == "llm" else None
        if dic:
            lines = ['"%s"' % str(x).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")[:64] for x in dic[:64] if str(x)]
            open(f"{d}/dict.txt", "w").write("\n".join(lines) + "\n")
        for f in ("imp_oracle_inner.py", "imp_oracle.py", "imp_behaviour.py", "imp_shim.c"):
            shutil.copy(f"{HERE}/{f}", f"{d}/{f}")
        for p in os.listdir(d):
            if os.path.isfile(f"{d}/{p}"):
                os.chmod(f"{d}/{p}", 0o644)
        b = 0 if arm in ("floor", "llm_direct") else budget
        name = f"impo_{os.getpid()}_{abs(hash(c['id'])) % 10**8}"
        t0 = time.time()
        try:
            subprocess.run(["docker", "run", "--rm", "--name", name] + SAFE_OPTS + ["-e", f"BUDGET={b}", "-e", "MODE=fuzz", "-e", "IMP_ORACLE_BROKEN=" + os.environ.get("IMP_ORACLE_BROKEN", "0"), "-v", f"{d}:/w", "-w", "/w", "--entrypoint", "python3", IMAGE,
                            "imp_oracle_inner.py"], capture_output=True, text=True, timeout=b + 600)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "kill", name], capture_output=True)
        # TSan container (separate: seccomp=unconfined needed by TSan; every other restriction kept)
        if os.path.exists(f"{d}/corpus.json"):
            try:
                subprocess.run(["docker", "run", "--rm", "--name", name + "t"] + SAFE_OPTS + ["--security-opt", "seccomp=unconfined", "-e", "BUDGET=0", "-e", "MODE=tsan", "-e", "IMP_ORACLE_BROKEN=" + os.environ.get("IMP_ORACLE_BROKEN", "0"),
                                "-v", f"{d}:/w", "-w", "/w", "--entrypoint", "python3", IMAGE, "imp_oracle_inner.py"], capture_output=True, text=True, timeout=400)
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "kill", name + "t"], capture_output=True)
        r = json.load(open(f"{d}/result.json")) if os.path.exists(f"{d}/result.json") else {"compiled": {}, "reports": {}, "corpus": [], "harness_fail": True}
        rt = json.load(open(f"{d}/result_tsan.json")) if os.path.exists(f"{d}/result_tsan.json") else {"compiled": {}, "reports": {}}
        comp = dict(r.get("compiled", {})); comp.update(rt.get("compiled", {}))
        reports = dict(r.get("reports", {})); reports.update(rt.get("reports", {}))
        by_var, counted_cls, noncounted_cls, t_first = {}, set(), set(), None
        for v, rows in reports.items():
            hit = [x for x in rows if any(k for _, k in x["classes"])]
            by_var[v] = bool(hit)
            for x in rows:
                for cls, k in x["classes"]:
                    (counted_cls if k else noncounted_cls).add(cls)
            for x in hit:
                t_first = x["t_ms"] if t_first is None else min(t_first, x["t_ms"])
        conf = any(by_var.values())
        score = 0.0
        if conf:
            score = (1.0 - min(t_first, b * 1000) / (b * 1000.0)) if b > 0 else 1.0
        return {"id": c["id"], "label": c["label"], "cwe": int(c["id"].split("-")[1]), "group": O.group_of(c["id"]), "arm": arm, "budget_s": b, "argv_shim": shim, "n_seeds": len(seeds),
                "compiled": comp, "any_compiled": any(comp.values()), "confirmed": conf, "confirmed_by_variant": by_var, "counted_classes": sorted(counted_cls),
                "noncounted_classes": sorted(noncounted_cls), "t_first_ms": t_first, "n_corpus": len(r.get("corpus", [])), "afl_aborted": bool(r.get("afl_aborted")),
                "execs": r.get("execs"), "replay_stopped": r.get("replay_stopped_after_timeouts", {}), "harness_fail": bool(r.get("harness_fail")), "score": round(score, 6),
                "wall_s": round(time.time() - t0, 1)}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def group_stats(rows):
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in rows]
    n1 = sum(y); n0 = len(y) - n1
    a = auroc([p["score"] for p in rows], y) if n1 and n0 else None
    return {"n_vuln": n1, "n_safe": n0, "confirmed_vuln": sum(1 for p in rows if p["label"] == "VULNERABLE" and p["confirmed"]),
            "confirmed_safe": sum(1 for p in rows if p["label"] == "SAFE" and p["confirmed"]), "auroc": r4(a), "se_hm": r4(hm_se(a, n1, n0)) if a is not None else None}


def summarise(per):
    out = {"overall": group_stats(per), "by_group": {g: group_stats([p for p in per if p["group"] == g]) for g in "abc"},
           "compile_failures_all_variants": sum(1 for p in per if not p["any_compiled"]), "afl_aborted": sum(1 for p in per if p["afl_aborted"]), "harness_fail": sum(p["harness_fail"] for p in per)}
    vs = sorted({v for p in per for v in p["confirmed_by_variant"]})
    out["by_variant"] = {v: {"vuln": sum(1 for p in per if p["label"] == "VULNERABLE" and p["confirmed_by_variant"].get(v)),
                             "safe": sum(1 for p in per if p["label"] == "SAFE" and p["confirmed_by_variant"].get(v))} for v in vs}
    out["safe_false_positives"] = [{"id": p["id"], "group": p["group"], "classes": p["counted_classes"]} for p in per if p["label"] == "SAFE" and p["confirmed"]]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=["floor", "empty", "random", "llm", "llm_direct", "random_resized"])
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--subset", action="store_true")
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--llm-seeds", default="results/imp_2_llm_seeds.json")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
    if a.subset:
        keep = F0.subset_ids(cases); cases = [c for c in cases if c["id"] in keep]
    if a.limit:
        cases = [c for c in cases if c["label"] == "VULNERABLE"][:a.limit] + [c for c in cases if c["label"] == "SAFE"][:a.limit]
    llm = json.load(open(a.llm_seeds))["programs"] if a.arm in ("llm", "llm_direct", "random_resized") else {}
    t0 = time.time()
    with ThreadPoolExecutor(a.jobs) as ex:
        per = list(ex.map(lambda c: run_one(c, a.arm, a.budget, llm), cases))
    res = {"experiment": "imp_2_oracle", "arm": a.arm, "image": IMAGE, "spec": "results/imp_castle_oracle_spec.json", "budget_s": a.budget, "subset": a.subset, "debug_limit": a.limit or None,
           "n": len(per), "jobs": a.jobs, "seconds": round(time.time() - t0), "summary": summarise(per), "per_case": per}
    out = a.out or "results/imp_2o_%s_b%d%s.json" % (a.arm, a.budget, "_subset" if a.subset else "")
    json.dump(res, open(out, "w"))
    print(out, json.dumps(res["summary"]["overall"]), json.dumps(res["summary"]["by_group"]))


if __name__ == "__main__":
    main()
