"""J5f: the larger held-out format-string test (FORMAT_R1B_PREREG note, commit bce5d86, sections 3-4).

Pairs come from results/imp_juliet5f_items_all.json (scripts/imp_build_juliet5f.py; acceptance check_j5f.py). Stems matching
_2[12]$ are excluded; declared-but-undefined prototypes are pruned from BOTH labels; the set is built by
imp_build_structure_matched.build() exactly as J3s/J4s. Then the section-4 cue checks run on J5f AND on U = J3s + J5f without
re-matching; any failure REFUSES (exit 1), which under the pre-registration means the primary stays J3s alone.
  python3 scripts/imp_build_j5f_set.py [--out-dir DIR]"""
import hashlib
import json
import re
import sys

sys.path.insert(0, "src")
sys.path.insert(0, "scripts")
from cyberdef.imp_common import auroc  # noqa: E402
import imp_build_structure_matched as SM  # noqa: E402

PROTO = re.compile(r"(?m)^[ \t]*(?:static\s+)?[A-Za-z_][\w \t\*]*?\b(fn_\d+)\s*\([^;{)]*\)\s*;[ \t]*\n?")
CALL = re.compile(r"\b(fn_\d+)\s*\(")


def defined(text):
    return {m.group(3) for m in SM.FN_DEF.finditer(text)}


def prune_protos(text):
    """remove prototype lines declaring an fn_N that the text never defines (applied to both labels)"""
    have = defined(text)
    return PROTO.sub(lambda m: "" if m.group(1) not in have else m.group(0), text)


def undefined_protos(text):
    have = defined(text)
    return sum(1 for m in PROTO.finditer(text) if m.group(1) not in have)


def calls_before_decl(text):
    """calls to an fn_N with no declaration or definition earlier in the text"""
    heads = [(m.start(), m.end(), m.group(1)) for m in PROTO.finditer(text)] + \
            [(m.start(), m.end(), m.group(3)) for m in SM.FN_DEF.finditer(text)]
    first = {}
    for s, _, f in heads:
        first[f] = min(first.get(f, s), s)
    n = 0
    for m in CALL.finditer(text):
        if any(s <= m.start() < e for s, e, _ in heads):
            continue   # the name inside a prototype or a definition header is not a call
        if m.start() < first.get(m.group(1), float("inf")):
            n += 1
    return n


def best(scores, y):
    a = auroc([float(v) for v in scores], y)
    return round(max(a, 1 - a), 4)


def cues(cases, parts):
    y = [c["label"] == "VULNERABLE" for c in cases]
    t = [c["code"] for c in cases]
    out = {"n": len(cases),
           "length": best([len(x) for x in t], y),
           "function_count": best([SM.nfun(x) for x in t], y),
           "static_count": best([len(re.findall(r"\bstatic\b", x)) for x in t], y),
           "undefined_prototypes": best([undefined_protos(x) for x in t], y),
           "calls_before_declaration": best([calls_before_decl(x) for x in t], y),
           "part_count": best([parts.get(c["pair"], 1) for c in cases], y)}
    out.update(SM.artefact_cue(cases))
    return out


def failures(c):
    bad = [k for k in ("length", "function_count", "static_count") if not 0.45 <= c[k] <= 0.55]
    bad += [k for k in ("last_line", "artefact_line", "undefined_prototypes", "calls_before_declaration", "part_count") if c[k] > 0.60]
    return bad


def main():
    od = sys.argv[sys.argv.index("--out-dir") + 1] if "--out-dir" in sys.argv else "results"
    items = json.load(open("results/imp_juliet5f_items_all.json"))["items"]
    by = {}
    for i in items:
        by.setdefault(i["pair"], {})[i["label"]] = i
    pairs = [(p, d["VULNERABLE"]["code"], d["SAFE"]["code"], "CWE134", "format_string") for p, d in sorted(by.items())
             if "VULNERABLE" in d and "SAFE" in d and not re.search(r"_2[12]$", p)]
    excluded = sum(1 for p in by if re.search(r"_2[12]$", p))
    parts = {f"{p}": len(d["VULNERABLE"].get("parts", [])) for p, d in by.items() if "VULNERABLE" in d}
    out = f"{od}/j5f_heldout_matched_cases.json"
    SM.build(pairs, "j5f", out, "J5f: multi-file Juliet CWE-134, verified (imp_build_juliet5f.py), cleaned (3g); FORMAT_R1B_PREREG note bce5d86",
             post=prune_protos)
    j5f = json.load(open(out))["cases"]
    j3s = json.load(open("results/j3s_heldout_matched_cases.json"))["cases"]
    report = {"excluded_2122_stems": excluded, "j5f": cues(j5f, parts), "union": cues(j3s + j5f, parts)}
    bad = {k: failures(report[k]) for k in ("j5f", "union")}
    report["failures"] = bad
    report["sha256"] = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(json.dumps(report, indent=1))
    if len(j5f) < 100 or any(bad.values()):
        raise SystemExit(f"REFUSED: J5f invalid under FORMAT_R1B_PREREG section 2/4 (functions {len(j5f)}, failures {bad}); primary stays J3s")
    print(f"J5f VALID: {len(j5f)} functions, sha256 {report['sha256']}")


if __name__ == "__main__":
    main()
