"""Acceptance for #2 under the oracle spec (written BEFORE the harness ran). Run from repo root on the box.
  check_2o.py selftest [--broken]   synthetic programs through the REAL harness (arm 'floor': one empty-stdin input, all variants):
     L  leak                -> counted lsan:leak (variant A_leak)
     F  bad free (free(p+1)) -> counted asan:bad-free (A)
     U  unsigned wrap        -> counted int:unsigned-overflow (B) and NOT counted by A/D
     T  data race            -> counted tsan:data-race (C)
     R  infinite recursion   -> counted asan:stack-overflow (A)
     H  busy infinite loop   -> counted cpu_hang
     W  sleeping program (sleep(10)) -> NOT confirmed (waiting is not a hang)
     A  assert(0)            -> counted assert
     S  safe program         -> nothing counted in ANY variant (false-positive control)
  --broken sets IMP_ORACLE_BROKEN=1 (classifier returns nothing): the selftest must then FAIL.
  check_2o.py results FILE    per_case covers the 198 programs once (or the pre-registered subset), summary recomputed from per_case (overall and per CWE group) equals stored (1e-3),
     group assignment matches the spec, every counted class is a class listed in the spec, debug runs rejected."""
import json, os, sys

sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <pthread.h>\n#include <assert.h>\n"
PROGS = {
    "L": HDR + "int main(){char*p=malloc(100);strcpy(p,\"x\");printf(\"%s\\n\",p);p=0;return 0;}",
    "F": HDR + "int main(){char*p=malloc(16);strcpy(p,\"x\");free(p+1);return 0;}",
    "U": HDR + "int main(){volatile unsigned u=0;u--;printf(\"%u\\n\",u);return 0;}",
    "T": HDR + "int g=0;void*f(void*a){for(int i=0;i<100000;i++)g++;return 0;}int main(){pthread_t a,b;pthread_create(&a,0,f,0);pthread_create(&b,0,f,0);pthread_join(a,0);pthread_join(b,0);printf(\"%d\\n\",g);return 0;}",
    "R": HDR + "int f(int n){volatile int x[64];x[0]=n;return f(n+1)+x[0];}int main(){printf(\"%d\\n\",f(0));return 0;}",
    "H": HDR + "int main(){volatile unsigned long i=0;while(1){i++;}return 0;}",
    "W": HDR + "int main(){sleep(10);return 0;}",
    "A": HDR + "int main(){assert(0 && \"boom\");return 0;}",
    "S": HDR + "int main(){char b[16];snprintf(b,sizeof b,\"%d\",42);printf(\"%s\\n\",b);return 0;}",
}
WANT = {"L": ("lsan:leak", True), "F": ("asan:bad-free", True), "U": ("int:unsigned-overflow", True), "T": ("tsan:data-race", True), "R": ("asan:stack-overflow", True),
        "H": ("cpu_hang", True), "A": ("assert", True), "W": (None, False), "S": (None, False)}


HDR2 = HDR + "#include <sqlite3.h>\n"
RD = 'char in[200]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; '
BEH = {  # id -> (code, payload seed, expected counted class or None)
    "BC": (HDR2 + "int main(){char c[300]; " + RD + 'snprintf(c,sizeof c,"ls %s",in); system(c); return 0;}', "x; echo CANARY\n", "beh:cmd_injection"),
    "BS": (HDR2 + "int main(){" + RD + 'char*a[]={"ls",in,0}; execv("/bin/ls",a); return 0;}', "x; echo CANARY\n", None),
    "BF": (HDR2 + "int main(){" + RD + "printf(in); return 0;}", "CANARY%p.%p.%p.%p\n", "beh:format_string"),
    "BP": (HDR2 + "int main(){char p[300]; " + RD + 'snprintf(p,sizeof p,"/var/data/%s",in); FILE*f=fopen(p,"r"); if(f) fclose(f); return 0;}', "../../CANARY/x\n", "beh:path_traversal"),
}


def selftest_beh(D, fails):
    for k, (code, pay, want) in BEH.items():
        cid = f"CASTLE-998-{ord(k[1])}{ord(k[0])}.c"
        r = D.run_one({"id": cid, "label": "VULNERABLE", "code": code}, "llm_direct", 0, {cid: {"seeds": [pay]}})
        got = set(r["counted_classes"])
        if want and want not in got:
            fails.append(f"{k}: expected {want}, got {sorted(got)}")
        if not want and any(c.startswith("beh:") for c in got):
            fails.append(f"{k}: safe twin confirmed by a behaviour oracle {sorted(got)}")


def selftest(broken):
    if broken:
        os.environ["IMP_ORACLE_BROKEN"] = "1"
    import imp_fuzz_castle2 as D
    fails = []
    for k, code in PROGS.items():
        r = D.run_one({"id": f"CASTLE-999-{ord(k)}.c", "label": "VULNERABLE", "code": code}, "floor", 0, {})
        want, conf = WANT[k]
        got = set(r["counted_classes"])
        if conf and (want not in got or not r["confirmed"]):
            fails.append(f"{k}: expected counted {want}, got {sorted(got)} (noncounted {r['noncounted_classes']})")
        if not conf and r["confirmed"]:
            fails.append(f"{k}: false positive, counted {sorted(got)} by {r['confirmed_by_variant']}")
        if k == "U" and (r["confirmed_by_variant"].get("A") or r["confirmed_by_variant"].get("D")):
            fails.append("U: unsigned wrap must not be counted by A/D (it is defined behaviour)")
    selftest_beh(D, fails)
    if broken:
        print("BROKEN MUTANT CAUGHT: " + "; ".join(fails[:3]) if fails else "BROKEN MUTANT NOT CAUGHT"); return 0 if fails else 1
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails]; return 1
    print("PASS: oracle controls L F U T R H W A S"); return 0


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    return None if not P or not N else sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in P for b in N) / (len(P) * len(N))


def results(path):
    import hashlib, imp_oracle as O
    try:
        d = json.load(open(path))
    except Exception as e:
        print("FAIL: unreadable", e); return 1
    fails = []
    cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
    ids = {c["id"]: c["label"] for c in cases}
    pc = d["per_case"]
    want = set(ids)
    if d.get("subset"):
        want = set()
        for lab in ("VULNERABLE", "SAFE"):
            want |= set(sorted((i for i, l in ids.items() if l == lab), key=lambda i: hashlib.sha1(i.encode()).hexdigest())[:20])
    if d.get("debug_limit"):
        fails.append("debug run")
    if len(pc) != d.get("n") or {p["id"] for p in pc} != want or len(pc) != len(want):
        fails.append("per_case does not cover the expected programs once")
    spec = json.load(open("results/imp_castle_oracle_spec.json"))
    for p in pc:
        if O.group_of(p["id"]) != p["group"] or ids.get(p["id"]) != p["label"]:
            fails.append("group/label mismatch " + p["id"]); break
    def gs(rows):
        y = [1 if p["label"] == "VULNERABLE" else 0 for p in rows]
        return (sum(1 for p in rows if p["label"] == "VULNERABLE" and p["confirmed"]), sum(1 for p in rows if p["label"] == "SAFE" and p["confirmed"]), auroc([p["score"] for p in rows], y))
    s = d["summary"]
    for name, rows, st in [("overall", pc, s["overall"])] + [(g, [p for p in pc if p["group"] == g], s["by_group"][g]) for g in "abc"]:
        kv, ks, a = gs(rows)
        if st["confirmed_vuln"] != kv or st["confirmed_safe"] != ks or (a is None) != (st["auroc"] is None) or (a is not None and abs(a - st["auroc"]) > 1e-3):
            fails.append(f"{name}: stored {st['confirmed_vuln']}/{st['confirmed_safe']}/{st['auroc']} recomputed {kv}/{ks}/{a}")
    for p in pc:
        if p["confirmed"] != any(p["confirmed_by_variant"].values()):
            fails.append("confirmed flag inconsistent " + p["id"]); break
        if p["confirmed"] and not p["counted_classes"]:
            fails.append("confirmed without a counted class " + p["id"]); break
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails[:15]]; return 1
    print("PASS: %s n=%d overall %s" % (path, len(pc), s["overall"])); return 0


if __name__ == "__main__":
    if sys.argv[1] == "selftest":
        sys.exit(selftest("--broken" in sys.argv))
    sys.exit(results(sys.argv[2]))
