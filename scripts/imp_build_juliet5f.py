"""Pool J5F (held-out TEST side; brief_j5f.txt): execution-verified pairs from the MULTI-FILE Juliet 1.3
CWE-134 (Uncontrolled Format String) test cases -- cases split across several files carrying a part
letter (_51a.c + _51b.c, _54a.c .. _54e.c, ...). Same recipe as the J3 builder (scripts/imp_build_juliet3.py,
SINGLE-FILE cases), unchanged where the brief says so: same docker sandbox (image imp-castle-san:1,
--network none, same limits, 3 shards, --inside mode), same behaviour shim (scripts/imp_shim.c,
scripts/imp_behaviour.py run_behaviour), same payload b"CANARY%p.%p.%p.%p\n", same feeds
(console -> stdin; environment -> env ADD; file -> /tmp/file.txt), same judge (verdicts["format_string"]),
same verification rule (verified = bad_payload and not bad_benign and not bad_empty and not good_payload).

Differences vs J3 (all required by the brief):
- candidates: lettered part files (_<NN><letter>.c/.cpp) under CWE134, grouped by case stem; console /
  environment / file feeds only (no socket, no w32); .cpp cases compiled with g++ -fpermissive;
- ALL parts of a case are compiled together with io.c and std_thread.c, once -DOMITGOOD (bad program)
  and once -DOMITBAD (good program), plus -DINCLUDEMAIN (only the 'a' part carries main());
- text: per part (letter order) the J3 strip(code, drop) + J3 INCLUDEMAIN removal, joined with a blank
  line, then cyberdef.imp_clean.clean_code (addendum 3g style); > 4000 chars -> drop (never truncate),
  leak_hits() non-empty -> drop;
- disjointness: cases whose stem is already referenced by any results/*.json or results/before_3m/*.json
  (used_stems(), replicated from acceptance/improve/check_j5f.py) are dropped and counted.
  python3 scripts/imp_build_juliet5f.py            (host: select cases, shard, run docker verifiers, assemble) -> results/imp_juliet5f_items_all.json
  python3 imp_build_juliet5f.py --inside shard.json  (in the sandbox)"""
import glob, json, os, re, shutil, subprocess, sys, tempfile

ROOT_HOST = "data/juliet_dl/x/C"
CWE_DIR = "testcases/CWE134_Uncontrolled_Format_String"
OUT = "results/imp_juliet5f_items_all.json"
PAYLOAD = b"CANARY%p.%p.%p.%p\n"
PART = re.compile(r"^(.*)_(\d+)([a-z])\.(c|cpp)$")


def strip(code, drop):
    """J3: remove the '#ifndef <drop> ... #endif /* <drop> */' block (the other variant's text)."""
    return re.sub(r"#ifndef %s\b.*?#endif\s*/\*\s*%s\s*\*/" % (drop, drop), "", code, flags=re.S)


def part_text(path, drop):
    """J3 text for one part: strip the dropped variant, remove the INCLUDEMAIN main block."""
    code = open(path, errors="replace").read()
    return re.sub(r"#ifdef INCLUDEMAIN.*?#endif", "", strip(code, drop), flags=re.S).strip()


def feed(kind, payload):
    """J3 feeds: console -> stdin; environment -> env ADD; file -> /tmp/file.txt."""
    if kind == "console":
        return payload, None, None
    if kind == "environment":
        return b"", {"ADD": payload.decode().strip("\n")}, None
    return b"", None, {"/tmp/file.txt": payload}


def case_stem(base):
    """file name without extension and without the multi-file part letter."""
    return re.sub(r"(_\d+)[a-z]$", r"\1", re.sub(r"\.(c|cpp)$", "", base))


def used_stems():
    """replicated verbatim from acceptance/improve/check_j5f.py (disjointness oracle)."""
    out = set()
    for p in glob.glob("results/*.json") + glob.glob("results/before_3m/*.json"):
        if "juliet5f" in p or "j5f" in p:
            continue
        try:
            d = json.load(open(p))
        except Exception:
            continue
        rows = (d.get("items") or d.get("cases") or d.get("pairs") or []) if isinstance(d, dict) else d
        for r in rows if isinstance(rows, list) else []:
            if isinstance(r, dict):
                for f in ("id", "pair"):
                    for m in re.finditer(r"CWE134_[A-Za-z0-9_]+?_\d+[a-z]?(?=\.c|\.cpp|:|$|\b)", str(r.get(f, ""))):
                        out.add(case_stem(m.group(0)))
    return out


def inside(shard_json):
    """runs in the sandbox: compile every part of each case together (OMITGOOD / OMITBAD), verify."""
    sys.path.insert(0, "/w")
    import imp_behaviour as B
    subprocess.run("gcc -shared -fPIC -O1 /w/imp_shim.c -o /w/imp_shim.so -ldl", shell=True, check=True)
    out = []
    for f in json.load(open(shard_json)):
        d = tempfile.mkdtemp(dir="/tmp")
        for s in ("std_testcase.h", "std_testcase_io.h", "testcases.h", "io.c", "std_thread.c", "std_thread.h"):
            shutil.copy(f"/jroot/testcasesupport/{s}", d)
        for part in f["parts"]:
            shutil.copy(f"/jroot/{f['dir']}/{part}", d)
        for h in glob.glob(f"/jroot/{f['dir']}/*.h"):
            shutil.copy(h, d)
        cc = "g++ -fpermissive" if f["ext"] == "cpp" else "gcc"
        rec = {"stem": f["stem"], "compiled": False}
        try:
            srcs = " ".join(f["parts"])
            bins = {}
            for mode in ("OMITGOOD", "OMITBAD"):
                r = subprocess.run(f"cd {d} && {cc} -O0 -w -DINCLUDEMAIN -D{mode} -I. {srcs} io.c std_thread.c -o p_{mode} -lm -lpthread",
                                   shell=True, capture_output=True, text=True, timeout=120)
                bins[mode] = f"{d}/p_{mode}" if r.returncode == 0 else None
            rec["compiled"] = bool(bins["OMITGOOD"] and bins["OMITBAD"])
            if rec["compiled"]:
                def run(binary, payload):
                    i, e, fl = feed(f["feed"], payload)
                    return B.run_behaviour(binary, i, env_extra=e, files=fl, shim=os.environ.get("IMP_J2_SHIM", "/w/imp_shim.so"))
                rb, rben, rem, rg = run(bins["OMITGOOD"], PAYLOAD), run(bins["OMITGOOD"], b"hello\n"), run(bins["OMITGOOD"], b""), run(bins["OMITBAD"], PAYLOAD)
                rec.update(bad_payload=bool(rb["verdicts"]["format_string"]), bad_benign=bool(rben["verdicts"]["format_string"]),
                           bad_empty=bool(rem["verdicts"]["format_string"]), good_payload=bool(rg["verdicts"]["format_string"]))
                rec["verified"] = rec["bad_payload"] and not rec["bad_benign"] and not rec["bad_empty"] and not rec["good_payload"]
        except Exception as ex:
            rec["error"] = repr(ex)[:200]
        out.append(rec)
        shutil.rmtree(d, ignore_errors=True)
    json.dump(out, open(shard_json + ".out", "w"))


def host():
    sys.path.insert(0, "src")
    from cyberdef.imp_clean import clean_code, leak_hits
    groups = {}
    for p in sorted(glob.glob(f"{ROOT_HOST}/{CWE_DIR}/**/*.c", recursive=True) + glob.glob(f"{ROOT_HOST}/{CWE_DIR}/**/*.cpp", recursive=True)):
        b = os.path.basename(p)
        m = PART.match(b)
        if not m or "socket" in b or "w32" in b or not re.search(r"_(console|environment|file)_", b):
            continue
        groups.setdefault((os.path.dirname(os.path.relpath(p, ROOT_HOST)), case_stem(b)), []).append(b)
    cases, rej = [], {"single_part": 0, "disjoint": 0}
    for (cdir, stem), parts in sorted(groups.items()):
        if len(parts) < 2:
            rej["single_part"] += 1
            continue
        kinds = {re.search(r"_(console|environment|file)_", b).group(1) for b in parts}
        exts = {b.rsplit(".", 1)[1] for b in parts}
        flows = {re.search(r"_(\d+)[a-z]\.(c|cpp)$", b).group(1) for b in parts}
        if len(kinds) != 1 or len(exts) != 1 or len(flows) != 1:
            rej["inconsistent_group"] = rej.get("inconsistent_group", 0) + 1
            continue
        cases.append({"stem": stem, "dir": cdir, "parts": sorted(parts), "feed": kinds.pop(), "ext": exts.pop(), "flow": flows.pop()})
    used = used_stems()
    keep = []
    for c in cases:
        if c["stem"] in used:
            rej["disjoint"] += 1
        else:
            keep.append(c)
    print("candidate cases", len(cases), "kept after disjointness", len(keep), flush=True)
    work = tempfile.mkdtemp(prefix="impj5f_")
    os.chmod(work, 0o777)
    for f in ("imp_shim.c", "imp_behaviour.py", "imp_build_juliet5f.py"):
        shutil.copy(f"scripts/{f}", f"{work}/{f}")
    N = 3
    procs = []
    for k in range(N):
        sh = f"{work}/shard{k}.json"
        json.dump(keep[k::N], open(sh, "w"))
        os.chmod(sh, 0o666)
    subprocess.run(["chmod", "-R", "a+rwX", work])
    for k in range(N):
        procs.append(subprocess.Popen(["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                                       "--user", "1000:1000", "-e", "HOME=/tmp", "-e", "IMP_J2_SHIM=" + os.environ.get("IMP_J2_SHIM", "/w/imp_shim.so"), "-v", f"{work}:/w", "-v", f"{os.path.abspath(ROOT_HOST)}:/jroot:ro", "-w", "/w", "--entrypoint", "python3",
                                       "imp-castle-san:1", "imp_build_juliet5f.py", "--inside", f"/w/shard{k}.json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
    for p in procs:
        p.wait()
    recs = []
    for k in range(N):
        if os.path.exists(f"{work}/shard{k}.json.out"):
            recs += json.load(open(f"{work}/shard{k}.json.out"))
    meta = {c["stem"]: c for c in keep}
    ver_rej = {"not_compiled": 0, "bad_not_fired": 0, "fired_on_benign": 0, "fired_on_empty": 0, "good_fired": 0, "error": 0, "too_long": 0, "leak": 0}
    items = []
    for r in recs:
        m = meta[r["stem"]]
        if r.get("error"):
            ver_rej["error"] += 1; continue
        if not r["compiled"]:
            ver_rej["not_compiled"] += 1; continue
        if not r["verified"]:
            ver_rej["bad_not_fired" if not r["bad_payload"] else "fired_on_benign" if r["bad_benign"] else "fired_on_empty" if r["bad_empty"] else "good_fired"] += 1; continue
        texts = {}
        for lab, drop in (("VULNERABLE", "OMITGOOD"), ("SAFE", "OMITBAD")):
            texts[lab] = clean_code("\n\n".join(part_text(f"{ROOT_HOST}/{m['dir']}/{part}", drop) for part in m["parts"]))
        if any(len(t) > 4000 for t in texts.values()):
            ver_rej["too_long"] += 1; continue
        if any(leak_hits(t) for t in texts.values()):
            ver_rej["leak"] += 1; continue
        for lab in ("VULNERABLE", "SAFE"):
            t = texts[lab]
            items.append({"id": f"juliet5:{m['stem']}:{lab[0]}", "code": t, "code_chars": len(t), "toks": max(1, len(t) // 3),
                          "label": lab, "project": "juliet5", "juliet_cwe": "CWE134", "cwe": "CWE134", "feed": m["feed"],
                          "parts": m["parts"], "pair": m["stem"], "flow": m["flow"],
                          "bad_payload": r["bad_payload"], "bad_benign": r["bad_benign"], "bad_empty": r["bad_empty"],
                          "good_payload": r["good_payload"], "label_verified": "behaviour oracle shim, author-supplied reference payload (not a model payload)"})
    rej.update(ver_rej)
    stats = {"candidate_cases": len(cases), "verified_pairs": sum(1 for i in items if i["label"] == "VULNERABLE"), "rejected": rej,
             "by_feed": {k: sum(1 for i in items if i["feed"] == k and i["label"] == "VULNERABLE") for k in ("console", "environment", "file")},
             "by_flow": {k: sum(1 for i in items if i["flow"] == k and i["label"] == "VULNERABLE") for k in sorted({c["flow"] for c in keep})}}
    json.dump({"items": items, "stats": stats}, open(OUT, "w"))
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps(stats))


if __name__ == "__main__":
    if "--inside" in sys.argv:
        inside(sys.argv[sys.argv.index("--inside") + 1])
    else:
        host()
