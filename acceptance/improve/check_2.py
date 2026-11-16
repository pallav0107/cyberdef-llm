"""Acceptance for arm #2 (fuzzing on CASTLE). Written BEFORE the implementation. Run from the repo root.
  check_2.py selftest        harness controls (needs docker + AFL++ image); exit 0 only if all hold:
      C1 known-bad stdin-overflow program: confirmed (fuzz arm 'random', 20 s, and direct run of a long seed)
      C2 its safe twin: NOT confirmed with the same seeds
      C3 with sanitizers compiled out (IMP_NOSAN=1) C1 must NOT confirm (proves the detector is the sanitizer)
      C4 a program that only needs a long input does not confirm with the empty arm's single-newline seed in direct mode
  check_2.py results <file>  structure + recomputation of a results/imp_2_fuzz_*.json:
      per_case covers every CASTLE case (or the pre-registered 40-case subset) exactly once, len(per_case)==n,
      AUROC/SE/crash rates recomputed from per_case equal the stored summary (1e-3), compile failures counted not dropped,
      every safe program with a confirmed crash is listed in safe_programs_with_confirmed_crash."""
import hashlib, json, math, os, sys

sys.path.insert(0, "src"); sys.path.insert(0, "scripts")


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    if not P or not N:
        return None
    return sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in P for b in N) / (len(P) * len(N))


def results(path):
    fails = []
    try:
        d = json.load(open(path))
    except Exception as e:
        print("FAIL: unreadable", e); return 1
    cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
    ids = {c["id"]: c for c in cases}
    pc = d.get("per_case", [])
    if d.get("subset"):
        want = set()
        for lab in ("VULNERABLE", "SAFE"):
            want |= set(sorted((i for i, c in ids.items() if c["label"] == lab), key=lambda i: hashlib.sha1(i.encode()).hexdigest())[:20])
    else:
        want = set(ids)
    if d.get("debug_limit"):
        fails.append("debug_limit set: not a reportable run")
    if len(pc) != d.get("n") or {p["id"] for p in pc} != want or len(pc) != len(want):
        fails.append("per_case does not cover the expected cases exactly once (n=%s len=%d want=%d)" % (d.get("n"), len(pc), len(want)))
    for p in pc:
        if p["id"] in ids and ids[p["id"]]["label"] != p["label"]:
            fails.append("label mismatch " + p["id"])
    y = [1 if p["label"] == "VULNERABLE" else 0 for p in pc]
    a = auroc([p["score"] for p in pc], y)
    s = d.get("summary", {})
    if a is None or s.get("auroc_time_score") is None or abs(a - s["auroc_time_score"]) > 1e-3:
        fails.append("auroc stored %s recomputed %s" % (s.get("auroc_time_score"), a))
    for lab, key, sk in (("VULNERABLE", "confirmed_crash", "confirmed_crash_on_vulnerable"), ("SAFE", "confirmed_crash", "confirmed_crash_on_safe")):
        rows = [p for p in pc if p["label"] == lab]
        k = sum(1 for p in rows if p[key])
        if s.get(sk, {}).get("k") != k or s.get(sk, {}).get("n") != len(rows):
            fails.append(f"{sk} stored {s.get(sk)} recomputed k={k} n={len(rows)}")
    if s.get("compile_failures") != sum(1 for p in pc if not p["compiled"]):
        fails.append("compile_failures inconsistent")
    if sorted(s.get("safe_programs_with_confirmed_crash", [])) != sorted(p["id"] for p in pc if p["label"] == "SAFE" and p["confirmed_crash"]):
        fails.append("safe crash list inconsistent")
    for p in pc:
        if p["confirmed_crash"] and not p["compiled"]:
            fails.append("crash without compile " + p["id"])
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails[:30]]; return 1
    print("PASS: %s n=%d auroc=%.4f" % (path, len(pc), a)); return 0


VULN = '#include <stdio.h>\n#include <string.h>\nint main(void){ char in[512]; char b[8]; if(!fgets(in,sizeof in,stdin)) return 0; strcpy(b,in); printf("%s\\n",b); return 0; }\n'
SAFE = '#include <stdio.h>\n#include <string.h>\nint main(void){ char in[512]; char b[8]; if(!fgets(in,sizeof in,stdin)) return 0; strncpy(b,in,sizeof b-1); b[7]=0; printf("%s\\n",b); return 0; }\n'


def selftest():
    import imp_fuzz_castle as fz
    fails = []
    llm = {"V": {"seeds": ["A" * 100 + "\n", "x\n", "y\n", "z\n", "w\n"]}, "S": {"seeds": ["A" * 100 + "\n", "x\n", "y\n", "z\n", "w\n"]}}
    cv = {"id": "V", "label": "VULNERABLE", "code": VULN}
    cs = {"id": "S", "label": "SAFE", "code": SAFE}
    r = fz.run_one(cv, "llm_direct", 0, llm)
    if not r["confirmed_crash"]:
        fails.append("C1 direct long seed on known-bad program not confirmed: %s" % r)
    r = fz.run_one(cs, "llm_direct", 0, llm)
    if r["confirmed_crash"]:
        fails.append("C2 safe twin confirmed")
    r = fz.run_one(cv, "empty", 20, {})
    if not r["confirmed_crash"]:
        fails.append("C1b fuzzing from an empty seed did not find the overflow in 20 s: %s" % r)
    r = fz.run_one({"id": "V0", "label": "VULNERABLE", "code": VULN}, "llm_direct", 0, {"V0": {"seeds": ["\n"]}})
    if r["confirmed_crash"]:
        fails.append("C4 trivial seed confirmed on program needing long input")
    os.environ["IMP_NOSAN"] = "1"
    r = fz.run_one(cv, "llm_direct", 0, llm)
    if r["confirmed_crash"]:
        fails.append("C3 sanitizers compiled out yet crash still 'confirmed' (control cannot fail)")
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails]; return 1
    print("PASS: harness controls C1-C4 hold"); return 0


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        sys.exit(selftest())
    if len(sys.argv) >= 3 and sys.argv[1] == "results":
        sys.exit(results(sys.argv[2]))
    print("usage: check_2.py selftest | results FILE"); sys.exit(2)
