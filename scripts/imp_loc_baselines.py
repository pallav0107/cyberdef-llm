"""#9a baselines on the same functions as the model arm (results/imp_loc_cases.json): random line (exact expectation), first regex sink line, flawfinder's reported line,
longest line. Run with ~/venvs/sast/bin/python (flawfinder). Parse failures of flawfinder are counted as misses and reported.
  nice -n 19 ~/venvs/sast/bin/python scripts/imp_loc_baselines.py"""
import json, math, os, re, subprocess, sys, tempfile

cases = json.load(open("results/imp_loc_cases.json"))["cases"]
SINK = re.compile(r"\b(mem(cpy|move|set)|str(cpy|ncpy|cat|ncat)|s?n?printf|v?s?n?printf|free|realloc|malloc|calloc|alloca|read|recv|fread|gets|scanf|sscanf)\s*\(")
FF = os.path.join(os.path.dirname(sys.executable), "flawfinder")
LINE = re.compile(r"^[^:\n]+:(\d+):\s+\[(\d)\]")


def exp_top3(L, T):
    if L < 3:
        return 1.0 if T else 0.0
    return 1 - math.comb(L - T, 3) / math.comb(L, 3) if L - T >= 3 else 1.0


def flawfinder_lines(code):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "f.c")
        open(p, "w").write(code)
        r = subprocess.run([FF, "--singleline", "--dataonly", "--minlevel=1", p], capture_output=True, text=True, timeout=60)
        hits = []
        for l in r.stdout.splitlines():
            m = LINE.match(l)
            if m:
                hits.append((-int(m.group(2)), int(m.group(1))))
        hits.sort()
        out = []
        for _, ln in hits:
            if ln not in out:
                out.append(ln)
        return out, r.returncode not in (0, 1)


per, ff_fail = [], 0
acc = {k: [0.0, 0.0] for k in ("random", "regex_sink", "flawfinder", "longest_line")}
for c in cases:
    lines = c["code"].split("\n"); T = set(c["truth_lines"]); L = len(lines)
    row = {"id": c["id"]}
    r1, r3 = len(T) / L, exp_top3(L, len(T))
    order = sorted(range(L), key=lambda i: -len(lines[i]))[:3]
    sk = [i + 1 for i, l in enumerate(lines) if SINK.search(l)][:3]
    try:
        fl, failed = flawfinder_lines(c["code"])
    except Exception:
        fl, failed = [], True
    ff_fail += bool(failed)
    fl = fl[:3]
    vals = {"random": (r1, r3), "longest_line": (float((order[0] + 1) in T), float(bool({i + 1 for i in order} & T))),
            "regex_sink": (float(bool(sk and sk[0] in T)), float(bool(set(sk) & T))),
            "flawfinder": (float(bool(fl and fl[0] in T)), float(bool(set(fl) & T)))}
    for k, (a, b) in vals.items():
        acc[k][0] += a; acc[k][1] += b
        row[k] = {"top1": a, "top3": b}
    row["flawfinder_lines"] = fl; row["regex_sink_lines"] = sk
    per.append(row)
n = len(cases)
res = {"experiment": "imp_9a_baselines", "n": n, "flawfinder_parse_failures": ff_fail, "per_case": per,
       "baselines": {k: {"top1": round(v[0] / n, 4), "top3": round(v[1] / n, 4), "se_top1": round(math.sqrt(max(v[0] / n * (1 - v[0] / n), 1e-9) / n), 4)} for k, v in acc.items()}}
json.dump(res, open("results/imp_9a_baselines.json", "w"))
print(json.dumps(res["baselines"]), "flawfinder failures", ff_fail)
