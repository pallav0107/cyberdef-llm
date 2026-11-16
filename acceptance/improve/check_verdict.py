"""Acceptance check for scripts/imp_verdict.py (the pre-registered verdict code of 3k M4 / 3l and TWIN_REPLICATION).
Independent of the script's own --selftest: it builds its own synthetic per_case files, runs the CLI, and checks the
output against values it computes itself with cyberdef.imp_common.auroc. Exit 0 = every check passed.
  python3 acceptance/improve/check_verdict.py"""
import hashlib, json, os, random, subprocess, sys, tempfile
sys.path.insert(0, "src")
from cyberdef.imp_common import auroc

S = "scripts/imp_verdict.py"
COT, SEL = "vLLM SC-CoT (imp_eval_cot)", "logprob-scored verdict (imp_selective)"
FAILS = []


def ok(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        FAILS.append(name)


if not os.path.exists(S):
    print("FAIL script missing: " + S)
    sys.exit(1)
T = tempfile.mkdtemp(prefix="chkv_")


def cases(name, n1, n0, rng, longer_vuln=False):
    cs = []
    for i in range(n1 + n0):
        y = i < n1
        ln = rng.randint(300, 900) + (400 if (y and longer_vuln) else 0)
        code = "int fn_1(void) {\n" + ("x;" * (ln // 2)) + "\n}\n" + ("static int fn_2(void) { return 0; }\n" if rng.random() < 0.5 else "")
        cs.append({"id": f"{name}:{i}", "code": code, "label": "VULNERABLE" if y else "SAFE", "cwe": "CWE134", "pair": f"p{i % (n1 or 1)}"})
    p = f"{T}/{name}_cases.json"
    json.dump({"cases": cs, "split": "test", "seed": 0, "pool": "synthetic"}, open(p, "w"))
    return p, cs


def per_case(path, cs, scores, method):
    json.dump({"method": method, "per_case": [{"id": c["id"], "label": c["label"], "p_vuln": s} for c, s in zip(cs, scores)]}, open(path, "w"))
    return path


def files(tag, cs, runs, method):
    return [per_case(f"{T}/{tag}_{k}.json", cs, r, method) for k, r in enumerate(runs)]


def run(args, out):
    if os.path.exists(out):
        os.remove(out)
    r = subprocess.run([sys.executable, S] + args + ["--out", out], capture_output=True, text=True, timeout=900)
    d = json.load(open(out)) if (r.returncode == 0 and os.path.exists(out)) else None
    return r, d


def rnd(cs, rng, sig=0.0, noise=0.25):
    return [min(1.0, max(0.0, 0.5 + (sig if c["label"] == "VULNERABLE" else -sig) + rng.uniform(-noise, noise))) for c in cs]


def lab(cs):
    return [1 if c["label"] == "VULNERABLE" else 0 for c in cs]


rng = random.Random(7)
cp, cs = cases("r", 56, 56, rng)
y = lab(cs)

# T1 identical arms must FAIL with every delta exactly 0
same = rnd(cs, rng, 0.05)
r, d = run(["round", "--cases", cp, "--adapter"] + files("t1a", cs, [same] * 3, COT) + ["--base"] + files("t1b", cs, [same] * 3, COT)
           + ["--twin"] + files("t1t", cs, [same], SEL), f"{T}/t1.json")
ok("T1 runs", d is not None)
if d:
    ok("T1 identical arms -> FAIL", d["verdict"] == "FAIL")
    ok("T1 deltas exactly 0", d["comparisons"]["base"]["delta"] == 0 and d["comparisons"]["twin"]["delta"] == 0)
    ok("T1 se_boot exactly 0", d["comparisons"]["base"]["se_boot"] == 0)

# T2 planted large delta must PASS; AUROC equals an independent computation on the K-averaged scores
runs = [rnd(cs, rng, 0.3, 0.15) for _ in range(3)]
base = [rnd(cs, rng, 0.0) for _ in range(3)]
args2 = ["round", "--cases", cp, "--adapter"] + files("t2a", cs, runs, COT) + ["--base"] + files("t2b", cs, base, COT) + ["--twin"] + files("t2t", cs, [rnd(cs, rng, 0.0)], SEL)
r, d = run(args2, f"{T}/t2.json")
ok("T2 runs", d is not None)
if d:
    avg = [sum(v) / 3 for v in zip(*runs)]
    ok("T2 planted delta -> PASS", d["verdict"] == "PASS")
    ok("T2 adapter auroc = auroc(K-average)", abs(d["models"]["adapter"]["auroc"] - auroc(avg, y)) < 1e-9)
    ok("T2 k recorded", d["models"]["adapter"]["k"] == 3 and d["models"]["twin"]["k"] == 1)
    ok("T2 single-run aurocs", all(abs(a - auroc(r_, y)) < 1e-9 for a, r_ in zip(d["models"]["adapter"]["single_run_auroc"], runs)))
    ok("T2 0 < se_boot < 0.2", 0 < d["comparisons"]["base"]["se_boot"] < 0.2)
    ok("T2 pass rule", all(c["pass"] == (c["delta"] > 2 * c["se_comb"]) for c in d["comparisons"].values()))
    ok("T2 baselines present", all(k in d["baselines"] for k in ("length", "function_count", "static_count")))
    shas = {os.path.abspath(p): hashlib.sha256(open(p, "rb").read()).hexdigest() for p in args2 if p.endswith(".json") and os.path.exists(p)}
    got = {os.path.abspath(k): v for k, v in d["inputs"].items()}
    ok("T8 input sha256 recorded", all(got.get(k) == v for k, v in shas.items()))
    r2, d2 = run(args2, f"{T}/t2b.json")
    ok("T7 deterministic output", d2 is not None and open(f"{T}/t2.json").read() == open(f"{T}/t2b.json").read())

# T3 decode noise widens the SE without moving the K-average
mid = rnd(cs, rng, 0.08, 0.1)
e = [rng.uniform(-0.3, 0.3) for _ in cs]
noisy = [[m + x for m, x in zip(mid, e)], [m - x for m, x in zip(mid, e)], mid]
bse = [rnd(cs, rng, 0.0) for _ in range(3)]
tw = files("t3t", cs, [rnd(cs, rng, 0.0)], SEL)
_, dc = run(["round", "--cases", cp, "--adapter"] + files("t3c", cs, [mid] * 3, COT) + ["--base"] + files("t3b", cs, bse, COT) + ["--twin"] + tw, f"{T}/t3c.json")
_, dn = run(["round", "--cases", cp, "--adapter"] + files("t3n", cs, noisy, COT) + ["--base"] + files("t3b2", cs, bse, COT) + ["--twin"] + tw, f"{T}/t3n.json")
ok("T3 runs", dc is not None and dn is not None)
if dc and dn:
    a, b = dc["comparisons"]["base"], dn["comparisons"]["base"]
    ok("T3 same delta", abs(a["delta"] - b["delta"]) < 1e-9)
    ok("T3 noise widens se_comb", b["se_comb"] > a["se_comb"] and dn["models"]["adapter"]["sd_decode"] > 0 and dc["models"]["adapter"]["sd_decode"] == 0)

# T4 key mismatch and T5 a CoT model with fewer than 3 runs must refuse, writing nothing
short = [{"id": c["id"], "label": c["label"], "p_vuln": 0.5} for c in cs[1:]]
bad = f"{T}/t4_short.json"
json.dump({"method": COT, "per_case": short}, open(bad, "w"))
r, d = run(["round", "--cases", cp, "--adapter"] + files("t4a", cs, runs, COT) + ["--base", bad] + files("t4b", cs, base[:2], COT) + ["--twin"] + tw, f"{T}/t4.json")
ok("T4 key mismatch refused", r.returncode != 0 and not os.path.exists(f"{T}/t4.json"))
r, d = run(["round", "--cases", cp, "--adapter"] + files("t5a", cs, runs[:2], COT) + ["--base"] + files("t5b", cs, base, COT) + ["--twin"] + tw, f"{T}/t5.json")
ok("T5 CoT with K=2 refused", r.returncode != 0 and not os.path.exists(f"{T}/t5.json"))

# T6 an adapter that only reproduces length must FAIL on the length baseline
cp6, cs6 = cases("r6", 56, 56, rng, longer_vuln=True)
L = [len(c["code"]) for c in cs6]
lo, hi = min(L), max(L)
lenp = [(x - lo) / (hi - lo) for x in L]
r, d = run(["round", "--cases", cp6, "--adapter"] + files("t6a", cs6, [lenp] * 3, COT) + ["--base"] + files("t6b", cs6, [rnd(cs6, rng) for _ in range(3)], COT)
           + ["--twin"] + files("t6t", cs6, [rnd(cs6, rng)], SEL), f"{T}/t6.json")
ok("T6 runs", d is not None)
if d:
    ok("T6 length-only adapter -> FAIL", d["verdict"] == "FAIL" and d["comparisons"]["length"]["pass"] is False)

# T9 twin replication
def tset(name, sig_twin, sig_base, seeds_sig, n=100, neg_seed=False):
    p, c = cases(name, n, n, rng)
    b = per_case(f"{T}/{name}_base.json", c, rnd(c, rng, sig_base), SEL)
    t0 = per_case(f"{T}/{name}_t0.json", c, rnd(c, rng, sig_twin), SEL)
    ss = [per_case(f"{T}/{name}_s{k}.json", c, rnd(c, rng, -0.3 if (neg_seed and k == 3) else s), SEL) for k, s in zip((1, 2, 3), seeds_sig)]
    return [name, p, b, t0] + ss


def tw_run(sets, tag):
    a = ["twinrep"]
    for s in sets:
        a += ["--set"] + s
    return run(a, f"{T}/{tag}.json")


_, d = tw_run([tset("a1", 0.0, 0.0, (0.0,) * 3), tset("b1", 0.0, 0.0, (0.0,) * 3)], "t9a")
ok("T9a null -> NOT SUPPORTED", d is not None and d["verdict"] == "NOT SUPPORTED")
_, d = tw_run([tset("a2", 0.3, 0.02, (0.3,) * 3), tset("b2", 0.3, 0.02, (0.3,) * 3)], "t9b")
ok("T9b planted both -> SUPPORTED", d is not None and d["verdict"] == "SUPPORTED" and d["holm"]["pass"] is True)
_, d = tw_run([tset("a3", 0.3, 0.02, (0.3,) * 3), tset("b3", 0.02, 0.02, (0.02,) * 3)], "t9c")
ok("T9c planted one set -> NOT SUPPORTED", d is not None and d["verdict"] == "NOT SUPPORTED")
_, d = tw_run([tset("a4", 0.3, 0.02, (0.3,) * 3, neg_seed=True), tset("b4", 0.3, 0.02, (0.3,) * 3)], "t9d")
ok("T9d one strongly negative seed -> NOT SUPPORTED", d is not None and d["verdict"] == "NOT SUPPORTED" and d["pass_seeds"] is False)
if d:
    s = d["sets"]["b4"]
    ok("T9 p one-sided in (0, 0.01]", 0 < s["p_one_sided"] <= 0.01)
    ok("T9 base/twin auroc independent", abs(s["base_auroc"] - auroc([p["p_vuln"] for p in json.load(open(f"{T}/b4_base.json"))["per_case"]],
                                                                     [1 if p["label"] == "VULNERABLE" else 0 for p in json.load(open(f"{T}/b4_base.json"))["per_case"]])) < 1e-9)

# T9e the pre-registered seed bar needs seeds 1-3: without seed files it must fail even when seed 0 is strong
_, d = tw_run([tset("a5", 0.3, 0.02, ())[:4], tset("b5", 0.3, 0.02, ())[:4]], "t9e")
ok("T9e no seed files -> NOT SUPPORTED, pass_seeds false", d is not None and d["verdict"] == "NOT SUPPORTED" and d["pass_seeds"] is False)
_, d = tw_run([tset("a6", 0.3, 0.02, (0.3,) * 3)[:6], tset("b6", 0.3, 0.02, (0.3,) * 3)[:6]], "t9f")
ok("T9f only seeds 0-2 -> NOT SUPPORTED", d is not None and d["verdict"] == "NOT SUPPORTED" and d["pass_seeds"] is False)

# T4b a duplicated (id, label) row must be refused, writing nothing
dup = json.load(open(tw[0]))
dup["per_case"] = dup["per_case"] + dup["per_case"][:1]
dp = f"{T}/t4b_dup.json"
json.dump(dup, open(dp, "w"))
r, d = run(["round", "--cases", cp, "--adapter"] + files("t4ba", cs, runs, COT) + ["--base"] + files("t4bb", cs, base, COT) + ["--twin", dp], f"{T}/t4b.json")
ok("T4b duplicated row refused", r.returncode != 0 and not os.path.exists(f"{T}/t4b.json"))

# T11-T15 cluster bootstrap (cluster = Juliet file name without its flow suffix _NN[a-z].c/.cpp; real-world: one pair)
def jcases(name, design, rng):
    cs, ad, bs = [], [], []
    clusters = range(12) if design == "concentrated" else range(30)
    for c in clusters:
        n = (30 if c == 0 else 5) if design == "concentrated" else 5
        for k in range(n):
            f = f"CWE134_Uncontrolled_Format_String__char_src{c}_printf_{k + 1:02d}.c"
            for y, lab in ((1, "VULNERABLE"), (0, "SAFE")):
                b = min(1.0, max(0.0, 0.5 + rng.uniform(-0.25, 0.25)))
                if design == "concentrated":
                    a = (0.95 if y else 0.05) if c == 0 else b
                else:
                    a = min(1.0, max(0.0, 0.5 + (0.12 if y else -0.12) + rng.uniform(-0.25, 0.25)))
                cs.append({"id": f"j3s:{f}:{lab[0]}", "code": "x;" * rng.randint(100, 400), "label": lab, "cwe": "CWE134", "pair": f})
                ad.append(a); bs.append(b)
    p_ = f"{T}/{name}_cases.json"
    json.dump({"cases": cs, "split": "test", "seed": 0}, open(p_, "w"))
    return p_, cs, ad, bs


def jround(name, design, flag):
    cp_, cs_, ad, bs = jcases(name, design, random.Random(11))
    args = ["round", "--cases", cp_, "--adapter"] + files(f"{name}a", cs_, [ad] * 3, COT) + ["--base"] + files(f"{name}b", cs_, [bs] * 3, COT) \
        + ["--twin"] + files(f"{name}t", cs_, [bs], SEL) + (["--cluster-bootstrap"] if flag else [])
    return run(args, f"{T}/{name}.json")


_, d = jround("t11", "concentrated", True)
ok("T11 runs with --cluster-bootstrap", d is not None)
if d:
    b_ = d["comparisons"]["base"]
    ok("T11 concentrated advantage: case verdict PASS", d.get("verdict_case") == "PASS")
    ok("T11 concentrated advantage: cluster verdict FAIL, overall FAIL", d.get("verdict_cluster") == "FAIL" and d["verdict"] == "FAIL")
    ok("T11 cluster SE > 2 x case SE", b_.get("se_boot_cluster", 0) > 2 * b_["se_boot"])
    ok("T11 pass_cluster rule", all(c["pass_cluster"] == (c["delta"] > 2 * c["se_comb_cluster"]) for c in d["comparisons"].values()))
    ok("T11 n_clusters = 12", d.get("n_clusters") == 12)
_, d = jround("t12", "uniform", True)
ok("T12 uniform advantage over 30 clusters -> PASS under both", d is not None and d["verdict"] == "PASS" and d.get("verdict_case") == "PASS"
   and d.get("verdict_cluster") == "PASS" and d.get("n_clusters") == 30)
_, d = jround("t13", "uniform", False)
ok("T13 without the flag: no cluster fields, case verdict as before", d is not None and "n_clusters" not in d and "verdict_case" not in d
   and "se_boot_cluster" not in d["comparisons"]["base"] and d["verdict"] == "PASS")
cp_, cs_, ad, bs = jcases("t14", "uniform", random.Random(12))
extra = [{"id": f"rw{i}:{l[0]}", "code": "y;" * 150, "label": l, "cwe": "CWE134", "pair": f"rw{i}"} for i in (1, 2) for l in ("VULNERABLE", "SAFE")]
cs14 = cs_ + extra
json.dump({"cases": cs14, "split": "test", "seed": 0}, open(cp_, "w"))
ad14, bs14 = ad + [0.6, 0.4, 0.6, 0.4], bs + [0.5, 0.5, 0.5, 0.5]
r, d = run(["round", "--cases", cp_, "--adapter"] + files("t14a", cs14, [ad14] * 3, COT) + ["--base"] + files("t14b", cs14, [bs14] * 3, COT)
           + ["--twin"] + files("t14t", cs14, [bs14], SEL) + ["--cluster-bootstrap"], f"{T}/t14.json")
ok("T14 real-world pairs are their own clusters (30 Juliet + 2)", d is not None and d.get("n_clusters") == 32)
a15 = [tset("a15", 0.3, 0.02, (0.3,) * 3), tset("b15", 0.3, 0.02, (0.3,) * 3)]
_, d0 = tw_run(a15, "t15a")
args15 = ["twinrep"] + [x for s_ in a15 for x in ["--set"] + s_] + ["--cluster-bootstrap"]
_, d1 = run(args15, f"{T}/t15b.json")
ok("T15 twinrep --cluster-bootstrap adds per-set sensitivity, verdict unchanged",
   d0 is not None and d1 is not None and d1["verdict"] == d0["verdict"] and all("se_boot_cluster" in v and "n_clusters" in v for v in d1["sets"].values()))

r = subprocess.run([sys.executable, S, "--selftest"], capture_output=True, text=True, timeout=900)
ok("T10 --selftest exits 0", r.returncode == 0)
print(f"{len(FAILS)} failed" if FAILS else "ALL PASS")
sys.exit(1 if FAILS else 0)
