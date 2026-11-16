"""Pool J2 (TRAIN side): Juliet 1.3 CWE78 (OS command injection), CWE134 (format string), CWE23 (relative path traversal), CWE36 (absolute path traversal), input-driven variants only
(console / environment / file; NO socket variants, no Windows-only w32). CASTLE stays test-only. Bad and good variant TEXTS as in pool J (the other variant's #ifndef block removed).
LABEL VERIFICATION (author-supplied reference payloads, not a model payload): a pair is kept only if, under the spec-v2 shim,
  bad + payload fires the class rule, bad + benign input does not, bad + EMPTY input does not, and the good variant + the same payload does not.
Reference payloads: 78 'x; echo CANARY' (judge_cmd); 134 'CANARY%p.%p.%p.%p' (judge_fmt); 23 '../../CANARY/x' (judge_path); 36 '/CANARY/x' (J2 label rule: the attacker path reaches open/stat unchanged).
Juliet-specific feed: console -> stdin; environment -> env ADD; file -> /tmp/file.txt.
  python3 scripts/imp_build_juliet2.py            (host: select files, shard, run docker verifiers --network none, assemble)  -> results/imp_train_juliet2_items.json
  python3 imp_build_juliet2.py --inside shard.json  (in the sandbox)"""
import glob, json, os, re, shutil, subprocess, sys, tempfile

ROOT_HOST = "data/juliet_dl/x/C"
CWES = {"CWE78_OS_Command_Injection": ("cmd_injection", 78), "CWE134_Uncontrolled_Format_String": ("format_string", 134),
        "CWE23_Relative_Path_Traversal": ("path_traversal", 22), "CWE36_Absolute_Path_Traversal": ("path_traversal", 22)}
PAYLOAD = {"CWE78": b"x; echo CANARY\n", "CWE134": b"CANARY%p.%p.%p.%p\n", "CWE23": b"../../CANARY/x\n", "CWE36": b"/CANARY/x\n"}


def strip(code, drop):
    return re.sub(r"#ifndef %s\b.*?#endif\s*/\*\s*%s\s*\*/" % (drop, drop), "", code, flags=re.S)


def feed(kind, payload):
    """returns (stdin bytes, env_extra, files)"""
    if kind == "console":
        return payload, None, None
    if kind == "environment":
        return b"", {"ADD": payload.decode().strip("\n")}, None
    return b"", None, {"/tmp/file.txt": payload}


def judge(cwe, res):
    v = res["verdicts"]
    if cwe == "CWE78":
        return v["cmd_injection"]
    if cwe == "CWE134":
        return v["format_string"]
    if cwe == "CWE23":
        return v["path_traversal"]
    return any(l.split("\t", 1)[0] in ("OPEN", "DIR", "STAT") and res["T"] in l for l in res["log"])


def inside(shard_json):
    sys.path.insert(0, "/w")
    import imp_behaviour as B
    subprocess.run("gcc -shared -fPIC -O1 /w/imp_shim.c -o /w/imp_shim.so -ldl", shell=True, check=True)
    out = []
    R = "/jroot"
    for f in json.load(open(shard_json)):
        base, src, cwe, kind = f["base"], f["src"], f["cwe"], f["kind"]
        d = tempfile.mkdtemp(dir="/tmp")
        for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
            shutil.copy(f"{R}/testcasesupport/{s}", d)
        ext = os.path.splitext(src)[1]
        shutil.copy(f"{R}/{src}", f"{d}/t{ext}")
        for h in glob.glob(os.path.dirname(f"{R}/{src}") + "/*.h"):
            shutil.copy(h, d)
        cc = "g++ -fpermissive" if ext == ".cpp" else "gcc"
        rec = {"base": base, "cwe": cwe, "kind": kind, "compiled": False}
        try:
            bins = {}
            for mode in ("OMITGOOD", "OMITBAD"):
                r = subprocess.run(f"cd {d} && {cc} -O0 -w -DINCLUDEMAIN -D{mode} -I. t{ext} io.c std_thread.c -o p_{mode} -lm -lpthread", shell=True, capture_output=True, text=True, timeout=120)
                bins[mode] = f"{d}/p_{mode}" if r.returncode == 0 else None
            rec["compiled"] = bool(bins["OMITGOOD"] and bins["OMITBAD"])
            if rec["compiled"]:
                def run(binary, payload):
                    i, e, fl = feed(kind, payload)
                    return B.run_behaviour(binary, i, env_extra=e, files=fl, shim=os.environ.get("IMP_J2_SHIM", "/w/imp_shim.so"))
                pay = PAYLOAD[cwe]
                rb, rben, rem, rg = run(bins["OMITGOOD"], pay), run(bins["OMITGOOD"], b"hello\n"), run(bins["OMITGOOD"], b""), run(bins["OMITBAD"], pay)
                rec.update(bad_payload=bool(judge(cwe, rb)), bad_benign=bool(judge(cwe, rben)), bad_empty=bool(judge(cwe, rem)), good_payload=bool(judge(cwe, rg)))
                rec["verified"] = rec["bad_payload"] and not rec["bad_benign"] and not rec["bad_empty"] and not rec["good_payload"]
        except Exception as ex:
            rec["error"] = repr(ex)[:200]
        out.append(rec)
        shutil.rmtree(d, ignore_errors=True)
    json.dump(out, open(shard_json + ".out", "w"))


def host():
    files = []
    for cdir, (oracle, tcwe) in CWES.items():
        for p in sorted(glob.glob(f"{ROOT_HOST}/testcases/{cdir}/**/*_01.c*", recursive=True)):
            b = os.path.basename(p)
            if not re.search(r"_01\.(c|cpp)$", b) or "socket" in b or "w32" in b or not re.search(r"_(console|environment|file)_", b):
                continue
            kind = re.search(r"_(console|environment|file)_", b).group(1)
            files.append({"base": b, "src": os.path.relpath(p, ROOT_HOST), "cwe": cdir.split("_")[0], "kind": kind, "oracle": oracle, "true_cwe": tcwe})
    print("candidate files", len(files), flush=True)
    work = tempfile.mkdtemp(prefix="impj2_")
    os.chmod(work, 0o777)
    for f in ("imp_shim.c", "imp_behaviour.py", "imp_build_juliet2.py"):
        shutil.copy(f"scripts/{f}", f"{work}/{f}")
    N = 3
    procs = []
    for k in range(N):
        sh = f"{work}/shard{k}.json"
        json.dump(files[k::N], open(sh, "w"))
        os.chmod(sh, 0o666)
    subprocess.run(["chmod", "-R", "a+rwX", work])
    for k in range(N):
        procs.append(subprocess.Popen(["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                                       "--user", "1000:1000", "-e", "HOME=/tmp", "-e", "IMP_J2_SHIM=" + os.environ.get("IMP_J2_SHIM", "/w/imp_shim.so"), "-v", f"{work}:/w", "-v", f"{os.path.abspath(ROOT_HOST)}:/jroot:ro", "-w", "/w", "--entrypoint", "python3",
                                       "imp-castle-san:1", "imp_build_juliet2.py", "--inside", f"/w/shard{k}.json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    for p in procs:
        p.wait()
    recs = []
    for k in range(N):
        if os.path.exists(f"{work}/shard{k}.json.out"):
            recs += json.load(open(f"{work}/shard{k}.json.out"))
    meta = {f["base"]: f for f in files}
    items, rej = [], {"not_compiled": 0, "bad_not_fired": 0, "fired_on_benign": 0, "fired_on_empty": 0, "good_fired": 0, "error": 0}
    for r in recs:
        m = meta[r["base"]]
        if r.get("error"):
            rej["error"] += 1; continue
        if not r["compiled"]:
            rej["not_compiled"] += 1; continue
        if not r["verified"]:
            rej["bad_not_fired" if not r["bad_payload"] else "fired_on_benign" if r["bad_benign"] else "fired_on_empty" if r["bad_empty"] else "good_fired"] += 1; continue
        code = open(f"{ROOT_HOST}/{m['src']}", errors="replace").read()
        for lab, drop in (("VULNERABLE", "OMITGOOD"), ("SAFE", "OMITBAD")):
            txt = re.sub(r"#ifdef INCLUDEMAIN.*?#endif", "", strip(code, drop), flags=re.S).strip()
            items.append({"id": f"juliet2:{r['base']}:{lab[0]}", "code": txt[:4000], "code_chars": len(txt), "toks": max(1, len(txt) // 3), "label": lab, "project": "juliet2", "cwe": f"CWE{m['true_cwe']}",
                          "juliet_cwe": r["cwe"], "feed": r["kind"], "oracle": m["oracle"], "pair": r["base"], "label_verified": "behaviour oracle shim, author-supplied reference payload (not a model payload)"})
    stats = {"candidate_files": len(files), "results": len(recs), "verified_pairs": len(items) // 2, "rejected": rej,
             "by_cwe": {c: sum(1 for i in items if i["juliet_cwe"] == c and i["label"] == "VULNERABLE") for c in PAYLOAD},
             "by_feed": {k: sum(1 for i in items if i["feed"] == k and i["label"] == "VULNERABLE") for k in ("console", "environment", "file")}}
    for i in items:
        i["toks"] = max(1, i["code_chars"] // 3)
    json.dump({"items": items, "stats": stats}, open(os.environ.get("IMP_J2_OUT", "results/imp_train_juliet2_items.json"), "w"))
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps(stats))


if __name__ == "__main__":
    if "--inside" in sys.argv:
        inside(sys.argv[sys.argv.index("--inside") + 1])
    else:
        host()
