#!/usr/bin/env python3
"""Addendum 3b control: no test case may share a source file (or, after whitespace normalisation, its code) with a few-shot
exemplar. Trace generation shows the exemplars in full, so a test function whose file supplied one would have been answered,
worked through, in the prompt that wrote the training data.
  python3 scripts/ci_exemplar_leak.py --check      every set in ci_plan.SET_FILES vs every results/imp_fewshot_exemplars*.json
  python3 scripts/ci_exemplar_leak.py --selftest   a test set with an exemplar file put back in must be CAUGHT; a clean one passes"""
import argparse, copy, glob, hashlib, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
norm = lambda s: " ".join(s.split())
h = lambda s: hashlib.sha256(norm(s).encode()).hexdigest()


def exemplars():
    ex = [e for f in sorted(glob.glob("results/imp_fewshot_exemplars*.json")) for e in json.load(open(f))["exemplars"]]
    if not ex:
        raise SystemExit("no exemplar files found: the control would be blind")
    return {e["source_file"] for e in ex}, {h(e["code"]) for e in ex}


def leaks(cases, files, hashes):
    out = []
    for c in cases:
        where = str(c.get("id", "")) + " " + str(c.get("source_file", ""))
        if h(c.get("code", "")) in hashes or any(f in where for f in files):
            out.append(c.get("id"))
    return out


def load(path):
    d = json.load(open(path))
    return d["cases"] if isinstance(d, dict) else d


def check():
    from ci_plan import SET_FILES
    files, hashes = exemplars()
    bad, seen = {}, 0
    for k, p in sorted(SET_FILES.items()):
        if not os.path.exists(p):
            print(f"  {k}: {p} not on this machine (not checked)")
            continue
        cs = load(p); seen += 1
        l = leaks(cs, files, hashes)
        print(f"  {k}: {len(cs)} cases, {len(l)} share an exemplar file or code")
        if l:
            bad[k] = l[:5]
    if seen == 0:
        raise SystemExit("no test set found: the control would be blind")
    if bad:
        raise SystemExit(f"LEAK: test cases share a few-shot exemplar source file or code: {bad}")
    print(f"no test case shares a source file or code with any of {len(files)} exemplar files")


def selftest():
    files, hashes = exemplars()
    f = sorted(files)[0]
    clean = [{"id": "j3h:CWE00_none_99.c:V", "code": "int main(){return 0;}"}]
    mut_id = clean + [{"id": f"j3h:{f}:S", "code": "something else"}]
    ex = json.load(open(sorted(glob.glob("results/imp_fewshot_exemplars*.json"))[0]))["exemplars"][0]
    mut_code = clean + [{"id": "renamed", "code": "  \n".join(ex["code"].split("\n"))}]
    assert not leaks(clean, files, hashes), "clean set flagged"
    assert leaks(mut_id, files, hashes), "control is blind: an exemplar source file in a test set was not caught"
    assert leaks(mut_code, files, hashes), "control is blind: exemplar code under another id was not caught"
    print("exemplar-leak control: clean passes; same-file and same-code mutants caught")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest: selftest()
    if a.check: check()
