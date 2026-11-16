"""Synthetic SQLi pool, STEP 2 (box CPU): verify the open-weight generated pairs with the spec-v2 sqli oracle, dedupe against CASTLE and within the pool, write results/imp_train_sqli_items.json.
  python3 scripts/imp_build_sqli.py [raw.json]       (host: orchestrates docker --network none verifiers)      python3 imp_build_sqli.py --inside shard.json   (sandbox)
Keep a pair ONLY IF both compile with gcc -lsqlite3; the vulnerable program fires the sqli oracle on >= 1 reference payload and NOT on benign/empty; the twin fires on NO payload, benign or empty.
Reference payloads are author-supplied for label verification only (bare CANARY token)."""
import json, os, re, shutil, subprocess, sys, tempfile

PAYLOADS = [b"x' OR CANARY=CANARY --\n", b"1 OR CANARY=CANARY\n", b"x\" OR CANARY=CANARY --\n", b"x') OR CANARY=CANARY --\n"]
BENIGN, EMPTY = b"hello\n", b""


def inside(shard):
    sys.path.insert(0, "/w")
    import imp_behaviour as B
    subprocess.run("gcc -shared -fPIC -O1 /w/imp_shim.c -o /w/imp_shim.so -ldl", shell=True, check=True)
    out = []
    for r in json.load(open(shard)):
        d = tempfile.mkdtemp(dir="/tmp")
        rec = {"id": r["id"], "compiled": False}
        try:
            for nm in ("vulnerable", "safe"):
                open(f"{d}/{nm}.c", "w").write(r[nm])
            ok = True
            for nm in ("vulnerable", "safe"):
                c = subprocess.run(f"gcc -w -O0 {d}/{nm}.c -o {d}/{nm} -lsqlite3", shell=True, capture_output=True, text=True, timeout=60)
                ok = ok and c.returncode == 0
            rec["compiled"] = ok
            if ok:
                def fires(nm, data):
                    return bool(B.run_behaviour(f"{d}/{nm}", data)["verdicts"]["sqli"])
                rec["vuln_fires"] = [fires("vulnerable", p) for p in PAYLOADS]
                rec["vuln_benign"] = fires("vulnerable", BENIGN); rec["vuln_empty"] = fires("vulnerable", EMPTY)
                rec["safe_fires"] = [fires("safe", p) for p in PAYLOADS]
                rec["safe_benign"] = fires("safe", BENIGN); rec["safe_empty"] = fires("safe", EMPTY)
        except Exception as ex:
            rec["error"] = repr(ex)[:200]
        out.append(rec)
        shutil.rmtree(d, ignore_errors=True)
    json.dump(out, open(shard + ".out", "w"))


def norm(s):
    return re.sub(r"\s+", " ", re.sub(r"/\*.*?\*/|//[^\n]*", "", s, flags=re.S)).strip()


def shingles(s, k=5):
    t = re.findall(r"[A-Za-z_]\w*|\d+|\S", norm(s))
    return {tuple(t[i:i + k]) for i in range(max(1, len(t) - k + 1))}


def jac(a, b):
    return len(a & b) / max(1, len(a | b))


def host():
    raw = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "results/imp_sqli_raw.json"))
    rows = [r for r in raw["rows"] if r["vulnerable"] and r["safe"]]
    for i, r in enumerate(rows):
        r["id"] = f"s{r['scenario']}k{r['sample']}"
    rej = {"unparsed": len(raw["rows"]) - len(rows), "not_compiled": 0, "vulnerable_not_fired": 0, "vulnerable_fired_on_benign_or_empty": 0, "safe_fired": 0, "castle_near_duplicate": 0, "pool_duplicate": 0, "error": 0}
    work = tempfile.mkdtemp(prefix="impsq_")
    os.chmod(work, 0o777)
    for f in ("imp_shim.c", "imp_behaviour.py", "imp_build_sqli.py"):
        shutil.copy(f"scripts/{f}", f"{work}/{f}")
    N = int(os.environ.get("IMP_JOBS", "1"))
    for k in range(N):
        json.dump([{"id": r["id"], "vulnerable": r["vulnerable"], "safe": r["safe"]} for r in rows[k::N]], open(f"{work}/shard{k}.json", "w"))
    subprocess.run(["chmod", "-R", "a+rwX", work])
    ps = [subprocess.Popen(["docker", "run", "--rm", "--network", "none", "--memory", "2g", "--pids-limit", "256", "--cpus", "1", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1000:1000",
                            "-e", "HOME=/tmp", "-v", f"{work}:/w", "-w", "/w", "--entrypoint", "python3", "imp-castle-san:1", "imp_build_sqli.py", "--inside", f"/w/shard{k}.json"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for k in range(N)]
    for p in ps:
        p.wait()
    res = {}
    for k in range(N):
        if os.path.exists(f"{work}/shard{k}.json.out"):
            for r in json.load(open(f"{work}/shard{k}.json.out")):
                res[r["id"]] = r
    castle = [c for c in json.load(open("results/xdata_castle_cases.json"))["cases"] if c["id"].startswith("CASTLE-89-")]
    cas_sh = [shingles(c["code"]) for c in castle]
    cas_norm = {norm(c["code"]) for c in castle}
    kept, kept_sh = [], []
    for r in rows:
        x = res.get(r["id"])
        if not x or x.get("error"):
            rej["error"] += 1; continue
        if not x["compiled"]:
            rej["not_compiled"] += 1; continue
        if not any(x["vuln_fires"]):
            rej["vulnerable_not_fired"] += 1; continue
        if x["vuln_benign"] or x["vuln_empty"]:
            rej["vulnerable_fired_on_benign_or_empty"] += 1; continue
        if any(x["safe_fires"]) or x["safe_benign"] or x["safe_empty"]:
            rej["safe_fired"] += 1; continue
        sv, ss = shingles(r["vulnerable"]), shingles(r["safe"])
        if norm(r["vulnerable"]) in cas_norm or norm(r["safe"]) in cas_norm or any(jac(s, c) >= 0.5 for s in (sv, ss) for c in cas_sh):
            rej["castle_near_duplicate"] += 1; continue
        if any(jac(sv, k) >= 0.8 for k in kept_sh):
            rej["pool_duplicate"] += 1; continue
        kept.append(r); kept_sh.append(sv)
    items = []
    for r in kept:
        for lab, key in (("VULNERABLE", "vulnerable"), ("SAFE", "safe")):
            code = r[key]
            items.append({"id": f"sqli:{r['id']}:{lab[0]}", "code": code[:4000], "code_chars": len(code), "toks": max(1, len(code) // 3), "label": lab, "project": "synthetic_sqli", "cwe": "CWE89", "feed": "console",
                          "oracle": "sqli", "pair": r["id"], "scenario": r["scenario"],
                          "provenance": "synthetic, open-weight generated (%s), oracle-verified (spec v2 sqli oracle, author-supplied reference payloads)" % raw["generator"]})
    stats = {"generator": raw["generator"], "prompts": raw["n_prompts"], "parsed_pairs": len(rows), "verified_pairs": len(kept), "rejected": rej, "castle_cwe89_programs_checked": len(castle),
             "scenarios_covered": len({r["scenario"] for r in kept}), "label": "synthetic, open-weight generated, oracle-verified",
             "limitation": "generator-independent ground truth does not exist here: the pool teaches recognition of this oracle's notion of SQLi"}
    json.dump({"items": items, "stats": stats}, open(os.environ.get("IMP_SQLI_OUT", "results/imp_train_sqli_items.json"), "w"))
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps(stats))


if __name__ == "__main__":
    if "--inside" in sys.argv:
        inside(sys.argv[sys.argv.index("--inside") + 1])
    else:
        host()
