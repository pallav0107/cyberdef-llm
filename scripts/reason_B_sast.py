"""Stage B: rule-based SAST baselines on results/lenmatched_eval_cases.json (code as the model sees it, <=4000 chars).
Tools: flawfinder (score = sum of hit levels) | semgrep with registry rules r/c (score = sum of severity weights
ERROR=3 WARNING=2 INFO=1). Parse failures / tool errors are scored 0 ("no finding") and COUNTED, never dropped.
Batch mode: every case is written as case_<i>.c into a temp dir, tool run once, findings mapped back by file.
Usage: reason_B_sast.py flawfinder|semgrep [--selftest [--broken]]"""
import csv, io, json, os, subprocess, sys, tempfile, time
sys.path.insert(0, "scripts")
from length_baseline import auroc, hanley_mcneil_se

tool = sys.argv[1]
SELF = "--selftest" in sys.argv
BROKEN = "--broken" in sys.argv
FF = os.path.expanduser("~/venvs/sast/bin/flawfinder")
SG = os.path.expanduser("~/venvs/sast/bin/semgrep")
SEV = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def idx(path):
    return int(os.path.basename(path)[5:-2])


def run_dir(d, n):
    sc, pf = [0.0] * n, [False] * n
    if tool == "flawfinder":
        r = subprocess.run([FF, "--csv", "--dataonly", "--minlevel=0", d], capture_output=True, text=True)
        for row in csv.DictReader(io.StringIO(r.stdout)):
            lv = row.get("Level", "")
            sc[idx(row["File"])] += int(lv) if lv.isdigit() else 0
        meta = {"version": subprocess.run([FF, "--version"], capture_output=True, text=True).stdout.strip()}
    else:
        r = subprocess.run([SG, "--config", "r/c", "--json", "--metrics=off", "--timeout", "10", d],
                           capture_output=True, text=True)
        j = json.loads(r.stdout)
        for x in j["results"]:
            sc[idx(x["path"])] += SEV.get(x["extra"]["severity"], 1)
        for e in j.get("errors", []):
            p = e.get("path") or ""
            if os.path.basename(p).startswith("case_"):
                pf[idx(p)] = True
        meta = {"version": j.get("version"), "rules": "registry r/c"}
    return sc, pf, meta


def score_codes(codes):
    with tempfile.TemporaryDirectory() as d:
        for i, c in enumerate(codes):
            open(f"{d}/case_{i}.c", "w").write(c)
        sc, pf, meta = run_dir(d, len(codes))
    sc = [0.0 if pf[i] else sc[i] for i in range(len(codes))]    # pre-registered: parse failure == no finding
    if BROKEN:
        sc = [0.0] * len(codes)
    return sc, pf, meta


if SELF:
    s, _, _ = score_codes(["void f(char*a){}\n", "void f(char*a){char b[8];strcpy(b,a);}\n"])
    print(json.dumps({"empty": s[0], "strcpy_fixed_buffer": s[1]}))
    sys.exit(0)

CF = os.environ.get("CASES_FILE", "results/lenmatched_eval_cases.json")
OUT = os.environ.get("OUT_SUFFIX", "matched")
cases = json.load(open(CF))["cases"]
t0 = time.time()
sc, pf, meta = score_codes([c["code"] for c in cases])
y = [1 if c["label"] == "VULNERABLE" else 0 for c in cases]
a = auroc(sc, y)
n1 = sum(y); n0 = len(y) - n1
res = {"stage": "B", "tool": tool, **meta, "cases_file": CF, "n": len(cases),
       "parse_failures": sum(pf), "frac_with_any_finding": round(sum(s > 0 for s in sc) / len(sc), 4),
       "auroc": round(a, 4), "se_hm": round(hanley_mcneil_se(a, n1, n0), 4),
       "length_only_auroc": round(auroc([c["code_chars"] for c in cases], y), 4),
       "per_case": [{"id": c["id"], "label": c["label"], "score": sc[i], "parse_fail": pf[i], "pair": c.get("pair", i),
                     "code_chars": c["code_chars"]} for i, c in enumerate(cases)],
       "seconds": round(time.time() - t0, 1)}
byp = {}
for p in res["per_case"]:
    byp.setdefault(p["pair"], {})[1 if p["label"] == "VULNERABLE" else 0] = p["score"]
w = [(1 if v[1] > v[0] else .5 if v[1] == v[0] else 0) for v in byp.values() if 0 in v and 1 in v]
res["pairwise_win_rate"] = round(sum(w) / len(w), 4) if w else None
ch = sorted(c["code_chars"] for c in cases)
cuts = [ch[len(ch) * q // 4] for q in (1, 2, 3)]
q = {}
for i, c in enumerate(cases):
    q.setdefault(sum(c["code_chars"] > t for t in cuts), []).append(i)
res["within_length_quartile"] = {f"Q{k+1}": round(auroc([sc[i] for i in v], [y[i] for i in v]), 4)
                                 for k, v in sorted(q.items())}
json.dump(res, open(f"results/reason_B_sast_{tool}_{OUT}.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))
