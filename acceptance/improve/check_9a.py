"""Acceptance for #9a localisation (written BEFORE the baselines / model results). Run from repo root: check_9a.py baselines | model results/imp_9a_X.json
baselines: results/imp_9a_baselines.json must have n == len(cases of results/imp_loc_cases.json), per_case rows with a hit flag for each of
  random(expected), regex_sink, flawfinder, longest_line; top-1/top-3 recomputed here independently (random, longest, regex) from the case text must match to 1e-3;
  truth lines must lie in 1..n_lines; flawfinder parse failures reported as an int and counted as misses (never dropped).
model: per_case covers exactly the loc cases once, top1/top3 recomputed from pred_lines vs truth_lines, predicted lines within range."""
import json, math, re, sys

R = "results/"
fails = []
cases = json.load(open(R + "imp_loc_cases.json"))["cases"] if len(sys.argv) > 1 else []
SINK = re.compile(r"\b(mem(cpy|move|set)|str(cpy|ncpy|cat|ncat)|s?n?printf|v?s?n?printf|free|realloc|malloc|calloc|alloca|read|recv|fread|gets|scanf|sscanf)\s*\(")


def exp_top3(L, T):
    if L < 3:
        return 1.0 if T else 0.0
    return 1 - math.comb(L - T, 3) / math.comb(L, 3) if L - T >= 3 else 1.0


def baselines():
    try:
        d = json.load(open(R + "imp_9a_baselines.json"))
    except Exception as e:
        print("FAIL: baselines missing:", e); return 1
    if d.get("n") != len(cases) or len(d.get("per_case", [])) != d.get("n"):
        fails.append("n / per_case length mismatch")
    for c in cases:
        if not all(1 <= t <= c["lines"] for t in c["truth_lines"]):
            fails.append("truth line out of range " + c["id"]); break
    r1 = r3 = 0.0; l1 = l3 = 0; g1 = g3 = 0
    for c in cases:
        lines = c["code"].split("\n"); T = set(c["truth_lines"]); L = len(lines)
        r1 += len(T) / L; r3 += exp_top3(L, len(T))
        order = sorted(range(L), key=lambda i: -len(lines[i]))[:3]
        l1 += (order[0] + 1) in T; l3 += bool({i + 1 for i in order} & T)
        sk = [i + 1 for i, l in enumerate(lines) if SINK.search(l)][:3]
        g1 += bool(sk and sk[0] in T); g3 += bool(set(sk) & T)
    n = len(cases)
    for name, a, b in (("random", r1 / n, r3 / n), ("longest_line", l1 / n, l3 / n), ("regex_sink", g1 / n, g3 / n)):
        s = d.get("baselines", {}).get(name)
        if not s or abs(s["top1"] - a) > 1e-3 or abs(s["top3"] - b) > 1e-3:
            fails.append(f"{name}: stored {s and (s['top1'], s['top3'])} recomputed {(round(a,4), round(b,4))}")
    if not isinstance(d.get("flawfinder_parse_failures"), int) or "flawfinder" not in d.get("baselines", {}):
        fails.append("flawfinder baseline / parse_failures missing")
    return finish()


def model(path):
    try:
        d = json.load(open(path))
    except Exception as e:
        print("FAIL:", e); return 1
    pc = d["per_case"]
    if sorted(p["id"] for p in pc) != sorted(c["id"] for c in cases) or d["n"] != len(pc):
        fails.append("per_case does not cover the loc cases exactly")
    cm = {c["id"]: c for c in cases}
    t1 = t3 = 0
    for p in pc:
        c = cm[p["id"]]; T = set(c["truth_lines"])
        if any(not 1 <= x <= c["lines"] for x in p["pred_lines"]):
            fails.append("pred out of range"); break
        h1 = bool(p["pred_lines"][:1] and p["pred_lines"][0] in T); h3 = bool(set(p["pred_lines"][:3]) & T)
        if h1 != p["top1"] or h3 != p["top3"]:
            fails.append("hit flag inconsistent " + p["id"]); break
        t1 += h1; t3 += h3
    if abs(t1 / len(pc) - d["top1"]) > 1e-3 or abs(t3 / len(pc) - d["top3"]) > 1e-3:
        fails.append("aggregate top1/top3 differ from recount")
    return finish()


def finish():
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails[:15]]; return 1
    print("PASS"); return 0


if __name__ == "__main__":
    sys.exit(baselines() if sys.argv[1] == "baselines" else model(sys.argv[2]))
