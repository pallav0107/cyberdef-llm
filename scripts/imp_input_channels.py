"""CASTLE input-channel analysis (CPU only). For every program: how does it read input (stdin / argv / file / env / network / none), from SOURCE patterns plus one quick sandboxed run
(compile without sanitizers, stdin = one newline, no argv, 3 s timeout). Cross-tabs against label, the empty-input gcc floor (reason_D0_castle_preflight, read-only),
and the AFL++ empty-seed arm (results/imp_2_fuzz_empty_b60.json: seed crash / aborted-by-seed-timeout). Diagnoses the seed-timeout aborts.
  nice -n 19 python3 scripts/imp_input_channels.py [--jobs 2]   -> results/imp_castle_input_channels.json
Labels are used only to build the cross-tabs, never to classify a program."""
import argparse, collections, json, os, re, shutil, subprocess, tempfile
from concurrent.futures import ThreadPoolExecutor

IMG = os.environ.get("IMP_AFL_IMAGE", "imp-castle-san:1")
LIBS = "-lm -lpthread -lsqlite3 -lmysqlclient -lssl -lcrypto -lcurl"
PAT = {
    "stdin": r"\b(scanf|fscanf\s*\(\s*stdin|getchar|gets|fgets\s*\([^;]*stdin|getline\s*\([^;]*stdin|fgetc\s*\(\s*stdin|read\s*\(\s*0|fread\s*\([^;]*stdin|getc\s*\(\s*stdin|std::cin|cin\s*>>|sscanf\s*\([^;]*stdin)",
    "argv": r"\bargv\s*\[|\*\s*argv\b|\bargv\s*\+",
    "file": r"\b(fopen|open|freopen|ifstream|fstream|stat|lstat|access|opendir|rename|remove|unlink|realpath|mkstemp|tmpfile)\s*\(",
    "env": r"\b(getenv|secure_getenv|environ)\b",
    "network": r"\b(socket|accept|recv|recvfrom|listen|bind|connect|curl_easy|mysql_real_connect|sqlite3_open)\b",
}
TIMEOUT_CAUSE = {
    "sleep": r"\b(sleep|usleep|nanosleep|pause)\s*\(",
    "infinite_loop": r"while\s*\(\s*(1|true)\s*\)|for\s*\(\s*;\s*;\s*\)",
    "waits_on_stdin_loop": r"(while|for)[^{;]*\{[^}]*\b(scanf|getchar|fgets|read)\b",
    "network_wait": r"\b(accept|recv|recvfrom|listen|connect|select|poll)\s*\(",
    "thread_wait": r"\b(pthread_join|wait|waitpid|sem_wait|pthread_cond_wait|pthread_mutex_lock)\s*\(",
    "argv_expected": r"\bargc\b",
}


def channels(code):
    return sorted(k for k, p in PAT.items() if re.search(p, code))


def quick(c):
    d = tempfile.mkdtemp(prefix="impic_"); os.chmod(d, 0o777)
    try:
        open(f"{d}/q.c", "w").write(c["code"]); os.chmod(f"{d}/q.c", 0o644)
        open(f"{d}/in.txt", "w").write("\n"); os.chmod(f"{d}/in.txt", 0o644)
        inner = (f"cd /w; gcc -w -O0 q.c -o q {LIBS} 2> g.err || {{ echo COMPILE_FAIL; exit 0; }}; "
                 "timeout 3 ./q < in.txt > o.txt 2> e.txt; echo RC=$?; head -c 300 o.txt | tr -d '\\000' | head -c 300 > o.head")
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64", "--cpus", "1", "--cap-drop", "ALL", "--user", "1000:1000",
                            "-e", "HOME=/tmp", "-v", f"{d}:/w", "--entrypoint", "sh", IMG, "-c", inner], capture_output=True, text=True, timeout=120)
        out = r.stdout
        head = open(f"{d}/o.head", errors="replace").read() if os.path.exists(f"{d}/o.head") else ""
        if "COMPILE_FAIL" in out:
            return {"compiled": False}
        m = re.search(r"RC=(\d+)", out)
        rc = int(m.group(1)) if m else None
        return {"compiled": True, "rc": rc, "timed_out": rc == 124, "stdout_head": head[:160].replace("\n", " | ")}
    except subprocess.TimeoutExpired:
        return {"compiled": True, "rc": None, "timed_out": True, "harness_timeout": True}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=2)
    a = ap.parse_args()
    cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
    floor = {p["id"]: p for p in json.load(open("results/reason_D0_castle_preflight.json"))["per_case"]}
    fz = {p["id"]: p for p in json.load(open("results/imp_2_fuzz_empty_b60.json"))["per_case"]}
    with ThreadPoolExecutor(a.jobs) as ex:
        qs = list(ex.map(quick, cases))
    per = []
    for c, q in zip(cases, qs):
        ch = channels(c["code"])
        prim = "+".join(ch) if ch else "none_or_hardcoded"
        f, z = floor[c["id"]], fz[c["id"]]
        seed_crash = bool((z.get("seed_crash") or {}).get("confirmed"))
        causes = sorted(k for k, p in TIMEOUT_CAUSE.items() if re.search(p, c["code"], re.S))
        per.append({"id": c["id"], "label": c["label"], "channels": ch, "channel_key": prim, "reads_stdin": "stdin" in ch,
                    "needs_argv_or_file_or_env": any(x in ch for x in ("argv", "file", "env")), "floor_confirmed": bool(f["sanitizer"]),
                    "afl_seed_crash": seed_crash, "afl_aborted": bool(z["afl_aborted"]), "afl_seed_timeout_abort": bool(z["afl_aborted"] and not z["seed_crash"]),
                    "afl_confirmed": bool(z["confirmed_crash"]), "afl_compiled": bool(z["compiled"]), "quick_run": q, "timeout_source_cues": causes})
    def xt(key, pred=lambda p: True):
        t = collections.defaultdict(lambda: collections.Counter())
        for p in per:
            if pred(p):
                t[p[key]][p["label"]] += 1
        return {k: dict(v) for k, v in sorted(t.items())}
    vul = [p for p in per if p["label"] == "VULNERABLE"]
    reach_before = [p for p in vul if not p["needs_argv_or_file_or_env"]]
    # CWE ceiling: sanitizer-detectable CWE classes, fixed BEFORE looking at the cross-tab (memory-safety / UB / assertion classes); CASTLE ids encode the CWE
    M = {119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 190, 191, 194, 369, 415, 416, 457, 476, 590, 674, 680, 787, 788, 822, 824, 825, 908}
    for p in per:
        p["cwe"] = int(p["id"].split("-")[1]); p["cwe_in_sanitizer_set"] = p["cwe"] in M
    vin = [p for p in per if p["label"] == "VULNERABLE" and p["cwe_in_sanitizer_set"]]
    vout = [p for p in per if p["label"] == "VULNERABLE" and not p["cwe_in_sanitizer_set"]]
    shim_active = sum(1 for p in vul if "argv" in p["channels"] and fz[p["id"]]["argv_shim"])
    harness_reach = [p for p in vul if not any(x in p["channels"] for x in ("file", "env"))]     # argv is fed by the AFL_INIT_ARGV shim since the first run
    ceiling = {"sanitizer_cwe_set": sorted(M), "vulnerable_in_set": len(vin), "vulnerable_outside_set": len(vout),
               "in_set_floor_confirmed": sum(p["floor_confirmed"] for p in vin), "in_set_afl_empty_confirmed": sum(p["afl_confirmed"] for p in vin),
               "outside_set_floor_confirmed": sum(p["floor_confirmed"] for p in vout), "outside_set_afl_empty_confirmed": sum(p["afl_confirmed"] for p in vout),
               "in_set_needing_argv_file_env": [(p["id"], p["channel_key"]) for p in vin if p["needs_argv_or_file_or_env"]],
               "vulnerable_cwe_counts": dict(sorted(collections.Counter(p["cwe"] for p in vul).items())),
               "argv_shim_active_on_vulnerable_argv_programs": f"{shim_active}/{sum('argv' in p['channels'] for p in vul)}",
               "share_vulnerable_reachable_by_harness_feeding_stdin+argv_shim": round(len(harness_reach) / max(1, len(vul)), 4),
               "share_vulnerable_not_reachable_(file_or_env)": round(1 - len(harness_reach) / max(1, len(vul)), 4)}
    res = {"cwe_ceiling": ceiling, "n": len(per), "channel_by_label": xt("channel_key"),
           "channel_by_floor_confirmed": {k: sum(1 for p in per if p["channel_key"] == k and p["floor_confirmed"]) for k in sorted({p["channel_key"] for p in per})},
           "channel_by_afl_seed_crash": {k: sum(1 for p in per if p["channel_key"] == k and p["afl_seed_crash"]) for k in sorted({p["channel_key"] for p in per})},
           "channel_by_afl_seed_timeout_abort": {k: sum(1 for p in per if p["channel_key"] == k and p["afl_seed_timeout_abort"]) for k in sorted({p["channel_key"] for p in per})},
           "vulnerable_programs": len(vul), "vulnerable_reading_argv_file_or_env": sum(p["needs_argv_or_file_or_env"] for p in vul),
           "vulnerable_reading_argv": sum("argv" in p["channels"] for p in vul), "vulnerable_reading_file": sum("file" in p["channels"] for p in vul),
           "vulnerable_reading_env": sum("env" in p["channels"] for p in vul), "vulnerable_reading_stdin": sum(p["reads_stdin"] for p in vul),
           "vulnerable_reading_nothing_detected": sum(1 for p in vul if not p["channels"]),
           "share_vulnerable_reachable_by_stdin_only_feeding_before": round(len(reach_before) / max(1, len(vul)), 4),
           "seed_timeout_aborts": sum(p["afl_seed_timeout_abort"] for p in per),
           "seed_timeout_quick_run": collections.Counter(("timed_out" if p["quick_run"].get("timed_out") else "exited" if p["quick_run"].get("compiled") else "no_compile")
                                                          for p in per if p["afl_seed_timeout_abort"]),
           "seed_timeout_source_cues": collections.Counter(c for p in per if p["afl_seed_timeout_abort"] for c in (p["timeout_source_cues"] or ["none_detected"])),
           "seed_timeout_by_label": collections.Counter(p["label"] for p in per if p["afl_seed_timeout_abort"]),
           "seed_timeout_channels": collections.Counter(p["channel_key"] for p in per if p["afl_seed_timeout_abort"]),
           "method_note": "channels from regexes over the source (a conservative superset: 'file' includes any fopen/open/stat); one quick run per program (no sanitizer, stdin=newline, no argv, 3 s). Labels used only for the cross-tabs.",
           "per_case": per}
    json.dump(res, open("results/imp_castle_input_channels.json", "w"), indent=1, default=dict)
    print(json.dumps({k: v for k, v in res.items() if k != "per_case"}, default=dict, indent=1))


if __name__ == "__main__":
    main()
