#!/usr/bin/env python3
"""Addendum 3g control: two dataset-hygiene failures that silently invalidate results.
 (a) LABEL TEXT: no Juliet-derived or synthetic item (test set, training pool, CoT item file, self-training item file) may
     still show the label: Juliet's FLAW/FIX comments, CWE numbers, bad/good identifiers (cyberdef.imp_clean.leak_hits).
     Real-world code (PrimeVul, VulSpot, CASTLE) is exempt from (a): its identifiers are real.
 (b) OVERLAP: no test case may share a source key (Juliet file or SQLi pair) or whitespace-normalised code with any item of any
     training pool (results/imp_train_*_items.json, results/st_pool_*.json).
  python3 scripts/ci_data_hygiene.py --check       every set in ci_plan.SET_FILES vs every training pool (box control, every run)
  python3 scripts/ci_data_hygiene.py --items F     the item file THIS run trains on (Dataset step, both machines)
  python3 scripts/ci_data_hygiene.py --selftest    a leaky case, a code-duplicate and a pair-key duplicate are each CAUGHT"""
import argparse, glob, hashlib, importlib.util, json, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("imp_clean", "src/cyberdef/imp_clean.py")   # by path: the package __init__ pulls in transformers
_ic = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_ic)
leak_hits = _ic.leak_hits

SYNTH = ("juliet:", "juliet2:", "juliet3:", "j3h:", "j4h:", "sqli:", "qh:")
norm = lambda s: " ".join(s.split())
h = lambda s: hashlib.sha256(norm(s).encode()).hexdigest()


def key(i):
    """source key: the Juliet file or SQLi pair behind a synthetic id, the same across train and test prefixes"""
    return i.split(":")[1] if i.startswith(SYNTH) and i.count(":") >= 2 else None


def rows(path):
    d = json.load(open(path))
    xs = (d.get("items") or d.get("cases") or []) if isinstance(d, dict) else d
    return [x for x in xs if isinstance(x, dict) and ("code" in x or "user" in x)]


def text(x):
    return x.get("code") or re.sub(r"(?m)^\s*\d+: ?", "", x.get("user", ""))


def pools():
    fs = [f for f in glob.glob("results/imp_train_*_items.json") if "_all" not in f] + glob.glob("results/st_pool_*.json")
    return sorted(fs)



def leaky(xs):
    return [x.get("id") for x in xs if str(x.get("id", "")).startswith(SYNTH) and leak_hits(text(x))]


def overlap(tests, pool_rows):
    ph = {h(text(x)) for x in pool_rows}
    pk = {key(str(x.get("id", ""))) for x in pool_rows} - {None}
    return [c.get("id") for c in tests if h(text(c)) in ph or key(str(c.get("id", ""))) in pk]


DESCRIPTIVE = {"j3m", "j3h", "j4m"}   # addendum 3i: known structural shortcut; reported, never a primary test
FNDEF = re.compile(r"(?m)^(?:static\s+)?(?:unsigned\s+|signed\s+|const\s+)*[A-Za-z_][\w\s\*]*?\bfn_\d+\s*\([^;{)]*\)\s*\{")


def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    if not pos or not neg:
        return 0.5
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def structure(cases):
    """(function-count-only, static-count-only) AUROC, best direction"""
    y = [c.get("label") == "VULNERABLE" for c in cases]
    f = auroc([len(FNDEF.findall(text(c))) for c in cases], y)
    st = auroc([len(re.findall(r"\bstatic\b", text(c))) for c in cases], y)
    return max(f, 1 - f), max(st, 1 - st)


def check():
    from ci_plan import SET_FILES
    bad, seen = [], 0
    pool_rows = [x for f in pools() for x in rows(f)]
    if not pool_rows:
        raise SystemExit("no training pool found: the control would be blind")
    for k, p in sorted(SET_FILES.items()):
        if not os.path.exists(p):
            print(f"  {k}: {p} not on this machine (not checked)"); continue
        cs = rows(p); seen += 1
        lk, ov = leaky(cs), overlap(cs, pool_rows)
        print(f"  test {k}: {len(cs)} cases; label text in {len(lk)}; shared with a training pool: {len(ov)}")
        if lk: bad.append(f"{k}: label text in {lk[:3]}")
        fb, sb = structure(cs)
        if fb > 0.60 or sb > 0.60:
            if k in DESCRIPTIVE:
                print(f"::warning::{k} is descriptive only: function count alone scores {fb:.3f}, static count {sb:.3f} (addendum 3i)")
            else:
                bad.append(f"{k}: structural shortcut (function count {fb:.3f}, static count {sb:.3f})")
        if ov: bad.append(f"{k}: in a training pool {ov[:3]}")
    for f in pools():
        lk = leaky(rows(f))
        if lk:
            print(f"  {f}: label text in {len(lk)} items"); bad.append(f"{f}: label text in {lk[:3]}")
    print(f"  checked {len(pools())} training pools for label text")
    if seen == 0:
        raise SystemExit("no test set found: the control would be blind")
    if bad:
        raise SystemExit("DATA HYGIENE FAILED: " + " | ".join(bad))
    print("data hygiene OK: no label text in synthetic data; no test case in any training pool")


def selftest():
    pool = [{"id": "sqli:s1k1:V", "code": "int f(){return 1;}"}, {"id": "juliet3:CWE78_x_02.c:V", "code": "int g(){return 2;}"}]
    clean = [{"id": "qh:s9k9:V", "code": "int h(){return 3;}"}]
    assert not leaky(clean) and not overlap(clean, pool), "clean set flagged"
    assert leaky([{"id": "j3h:CWE78_y_05.c:S", "code": "void fn_0(){ /* FIX: use a constant */ }"}]), "blind to a FIX comment"
    assert leaky([{"id": "j4h:CWE121_z_03.c:V", "code": "void CWE121_z_03_bad(){}"}]), "blind to a _bad identifier"
    assert overlap([{"id": "qh:s1k1:V", "code": "different text"}], pool), "blind to a held-out SQLi pair that is in a pool"
    assert overlap([{"id": "x:1", "code": "int  g(){return 2;}"}], pool), "blind to duplicate code under another id"
    assert not leaky([{"id": "123", "code": "int bad_count; /* FIX later */"}]), "real-world code must be exempt from (a)"
    lop = [{"id": "j4s:a:V", "label": "VULNERABLE", "code": "void fn_0(){}"}, {"id": "j4s:a:S", "label": "SAFE", "code": "void fn_0(){}\nstatic void fn_1(){}\nvoid fn_2(){ fn_0(); fn_1(); }"}] * 10
    even = [{"id": "j4s:b:V", "label": "VULNERABLE", "code": "void fn_0(){}"}, {"id": "j4s:b:S", "label": "SAFE", "code": "void fn_0(){}"}] * 10
    assert structure(lop)[0] > 0.9 and structure(even)[0] <= 0.6, "blind to a function-count shortcut"
    print("data hygiene control: clean passes; FIX comment, bad identifier, held-out pair in pool, duplicate code and a function-count shortcut are caught")


def check_items(path):
    xs = rows(path)
    lk = leaky(xs)
    print(f"  {path}: {len(xs)} items; synthetic items still showing label text or an inserted comment: {len(lk)}")
    if lk:
        raise SystemExit(f"DATA HYGIENE FAILED: {path} has label text in {len(lk)} synthetic items, e.g. {lk[:3]}. Juliet/SQLi items are comment-free after cleaning, so any comment was inserted later (e.g. a padding comment on one class only) and can be a shortcut.")
    print("training items OK: no label text in synthetic items")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--items", default=None)
    a = ap.parse_args()
    if a.selftest: selftest()
    if a.check: check()
    if a.items: check_items(a.items)
