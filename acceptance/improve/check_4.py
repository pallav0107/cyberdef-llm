"""Acceptance for #4 (sink-centred slices) data build, written BEFORE the build. Run from repo root: check_4.py primevul_matched vs_holdout_matched ...
Per set S: results/imp_slice_S_cases.json (original pairing, code = slice or full fallback) + imp_slice_S_stats.json + rematched files.
 1 same ids/labels as the source cases file (none dropped); source file names: primevul_matched -> lenmatched_eval_cases.json,
   X -> X_cases.json
 2 every case has slice_status in {sliced, fallback_parse_failure, fallback_no_sink}; stats counts equal a recount from the cases
 3 for status 'sliced': each non-elided, non-empty line of the slice occurs in the original function, in order (a slice never invents code),
   the slice contains >=1 sink token, and len(slice) < len(original) OR equal (reported)
 4 for fallback statuses: code == original code exactly
 5 parse failures are counted and reported (an int in stats), never zero by construction: the self-test feeds a malformed function and
   must yield fallback_parse_failure
 6 rematched control length-only AUROC in [0.45,0.55] (chars, tokens) and pairs >= 100"""
import json, os, re, sys

R = "results/"


def auroc(s, y):
    P = [a for a, b in zip(s, y) if b]; N = [a for a, b in zip(s, y) if not b]
    return sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in P for b in N) / (len(P) * len(N))


SINK = re.compile(r"\b(mem(cpy|move|set)|str(cpy|ncpy|cat|ncat)|s?n?printf|v?s?n?printf|free|realloc|malloc|calloc|alloca|read|recv|fread|gets|scanf)\b|\[[^\]]*\]\s*=|\*[^;=]*=|->|\+\+|--|\+")
fails = []
for S in sys.argv[1:]:
    srcf = R + ("lenmatched_eval_cases.json" if S == "primevul_matched" else f"{S}_cases.json")
    try:
        src = json.load(open(srcf))["cases"]
        sl = json.load(open(R + f"imp_slice_{S}_in.json"))["cases"]
        st = json.load(open(R + f"imp_slice_{S}_stats.json"))
        rem = json.load(open(R + f"imp_slice_{S}_rematched_cases.json"))["cases"]
    except Exception as e:
        print("FAIL: %s: %s" % (S, e)); sys.exit(1)
    if sorted((c["id"], c["label"]) for c in src) != sorted((c["id"], c["label"]) for c in sl):
        fails.append(f"{S}: ids differ from source")
    so = {(c["id"], c["label"]): c for c in src}
    cnt = {}
    for c in sl:
        cnt[c.get("slice_status")] = cnt.get(c.get("slice_status"), 0) + 1
    cnt_done = dict(cnt); cnt = {}
    for c in sl:
        o = so[(c["id"], c["label"])]
        s = c.get("slice_status")
        if s not in ("sliced", "fallback_parse_failure", "fallback_no_sink"):
            fails.append(f"{S}: bad status {s}"); break
        if s != "sliced" and c["code"] != o["code"]:
            fails.append(f"{S}: fallback case {c['id']} not the full function"); break
        if s == "sliced":
            ol = [l.strip() for l in o["code"].split("\n") if l.strip()]
            pos = 0; bad = False
            for l in c["code"].split("\n"):
                t = l.strip()
                if not t or "/* ... */" in t:
                    continue
                try:
                    pos = ol.index(t, pos) + 1
                except ValueError:
                    bad = True; break
            if bad:
                fails.append(f"{S}: slice of {c['id']} contains a line not in the original (in order)"); break
            if not SINK.search(c["code"]):
                fails.append(f"{S}: slice of {c['id']} has no sink token"); break
    for k, key in (("n_sliced", "sliced"), ("n_fallback_parse_failure", "fallback_parse_failure"), ("n_fallback_no_sink", "fallback_no_sink")):
        if st.get(k) != cnt_done.get(key, 0):
            fails.append(f"{S}: stats {k}={st.get(k)} recount={cnt_done.get(key,0)}")
    if not isinstance(st.get("selftest_malformed_is_parse_failure"), bool) or not st["selftest_malformed_is_parse_failure"]:
        fails.append(f"{S}: self-test of the parse-failure path missing or failed")
    yr = [1 if c["label"] == "VULNERABLE" else 0 for c in rem]
    for k, f in (("chars", lambda c: len(c["code"])), ("tokens", lambda c: c["toks"])):
        a = auroc([f(c) for c in rem], yr)
        if not 0.45 <= a <= 0.55:
            fails.append(f"{S}: rematched length-only {k} {a:.3f} outside [0.45,0.55]")
    if len(rem) // 2 < 100:
        fails.append(f"{S}: only {len(rem)//2} rematched pairs")
if fails:
    print("FAIL:"); [print(" -", f) for f in fails]; sys.exit(1)
print("PASS:", sys.argv[1:])
