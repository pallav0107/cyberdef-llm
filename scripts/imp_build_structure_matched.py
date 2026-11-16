#!/usr/bin/env python3
"""Addendum 3i: STRUCTURE-matched Juliet held-out sets (results/j3s_heldout_matched_cases.json, j4s_heldout_matched_cases.json).

Why: in Juliet a vulnerable text holds the bad function (plus any sink helper), while the safe text holds every good variant
(goodG2B1/2, goodB2G1/2...) plus a good() wrapper. Function count alone therefore separates the classes: AUROC 0.983 on J3
matched and 0.958 on J4b matched; the `static` keyword (good functions are static, bad ones are not) gives 0.89 / 0.74. Length
matching does not remove this. Juliet training pools carry the same layout, so a model can learn "more functions = safe".

Rule (fixed before any model is scored on these sets):
  - VULNERABLE text: the cleaned bad text, as before.
  - SAFE text: ONE good variant, chosen with random.Random(sha256(pair)) among the functions the good() root calls (the one
    function called by no other), plus the
    helper functions it calls (transitively), in source order, after the file's prefix (includes/defines). The wrapper and
    the other variants are dropped. Labels stay execution-verified: the good program ran every good variant and fired no sanitizer.
  - Both texts: `static ` removed from top-level function definitions, and fn_N identifiers renumbered in order of appearance.
  - Flow variants _21/_22 are excluded (each good variant's behaviour depends on a static flag set by good()).
  - Then per-CWE length matching exactly as amendment 2c (10 bins, equal V/S per bin, random.Random(0); chars AND tokens
    length-only AUROC in [0.45, 0.55]; >= 20 per class), and the kept set must ALSO have function-count-only and
    static-count-only AUROC in [0.45, 0.55] per CWE, or the CWE is dropped.
  python3 scripts/imp_build_structure_matched.py"""
import hashlib, json, random, re, sys

FN_DEF = re.compile(r"(?m)^(static\s+)?((?:unsigned\s+|signed\s+|const\s+)*[A-Za-z_][\w\s\*]*?)\b(fn_\d+)\s*\(([^;{)]*)\)\s*\{")


def functions(code):
    """top-level function definitions: list of (name, start, end) by brace matching (strings/chars respected)"""
    out = []
    for m in FN_DEF.finditer(code):
        i = code.index("{", m.end() - 1); depth = 0; j = i; instr = None
        while j < len(code):
            ch = code[j]
            if instr:
                if ch == "\\": j += 2; continue
                if ch == instr: instr = None
            elif ch in "\"'": instr = ch
            elif ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        out.append((m.group(3), m.start(), j + 1))
    return [f for k, f in enumerate(out) if not any(o[1] < f[1] < o[2] for o in out)]   # drop nested matches


def calls(body, names):
    return {n for n in names if re.search(r"\b%s\s*\(" % n, body)}


def normalise(code):
    code = re.sub(r"(?m)^static\s+(?=[A-Za-z_][\w\s\*]*?\bfn_\d+\s*\()", "", code)
    order = []
    for m in re.finditer(r"\bfn_\d+\b", code):
        if m.group(0) not in order: order.append(m.group(0))
    mp = {o: f"F{k}" for k, o in enumerate(order)}
    code = re.sub(r"\bfn_\d+\b", lambda m: mp[m.group(0)], code)
    return re.sub(r"\bF(\d+)\b", r"fn_\1", code)


def one_good(code, pair):
    fs = functions(code)
    if not fs:
        return None
    names = [f[0] for f in fs]
    body = {f[0]: code[f[1]:f[2]] for f in fs}
    called = {n: calls(body[n].split("{", 1)[1], set(names) - {n}) for n in names}
    callers = {n: {m for m in names if n in called[m]} for n in names}
    wrappers = [n for n in names if called[n] and not callers[n]]   # the root: calls variants, called by nobody (good())
    if len(wrappers) != 1:
        return None
    variants = sorted(called[wrappers[0]], key=names.index)
    if not variants:
        return None
    pick = random.Random(int(hashlib.sha256(pair.encode()).hexdigest()[:12], 16)).choice(variants)
    keep, todo = {pick}, [pick]
    while todo:
        for h in called[todo.pop()]:
            if h not in keep and h != wrappers[0]:
                keep.add(h); todo.append(h)
    prefix = code[:fs[0][1]]
    parts = [code[f[1]:f[2]] for f in fs if f[0] in keep]
    return (prefix + "\n\n".join(parts)).strip()


def one_bad(code):
    """addendum 3m: the vulnerable text rebuilt like one_good(): the prefix plus every function, joined. Drops leftover
    non-function text (the INCLUDEMAIN removal stopped at an inner #endif and left `return 0; } #endif` in VULNERABLE texts only)."""
    fs = functions(code)
    if not fs:
        return None
    return (code[:fs[0][1]] + "\n\n".join(code[f[1]:f[2]] for f in fs)).strip()


ARTEFACT = re.compile(r"^(#\s*\w+.*|return 0;)$")


def artefact_cue(cases):
    """addendum 3m: best AUROC (either direction) of the last line, and of any preprocessor / `return 0;` line, as a label cue."""
    y = [c["label"] == "VULNERABLE" for c in cases]
    lines = [[l.strip() for l in c["code"].split("\n") if l.strip()] for c in cases]
    best = {"last_line": 0.5, "artefact_line": 0.5}
    for key, cand in (("last_line", {ls[-1] for ls in lines if ls}), ("artefact_line", {l for ls in lines for l in ls if ARTEFACT.match(l)})):
        for t in cand:
            a = auroc([(ls[-1] == t) if key == "last_line" else (t in ls) for ls in lines], y)
            best[key] = max(best[key], a, 1 - a)
    return {k: round(v, 4) for k, v in best.items()}


def nfun(code):
    return len(functions(code))


def auroc(s, y):
    pos = [a for a, b in zip(s, y) if b]; neg = [a for a, b in zip(s, y) if not b]
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def build(pairs, tag, out_path, note, post=None):
    cases, skipped = [], 0
    for pair, v, s, cwe, cat in pairs:
        if re.search(r"_2[12][a-z]?\.(?:c|cpp)$", pair):   # static-flag flow variants: a variant's safety depends on flags set by good()
            skipped += 1; continue
        st, bt = one_good(s, pair), one_bad(v)
        if st is None or bt is None:
            skipped += 1; continue
        if post is not None:   # FORMAT_R1B_PREREG note (bce5d86): applied to BOTH labels before normalise(); default None
            bt, st = post(bt), post(st)
        for lab, txt in (("VULNERABLE", normalise(bt)), ("SAFE", normalise(st))):
            cases.append({"id": f"{tag}:{pair}:{lab[0]}", "code": txt, "code_chars": len(txt), "toks": max(1, len(txt) // 3),
                          "label": lab, "cwe": cwe, "category": cat, "pair": pair})
    rng = random.Random(0); keep, report = [], {}
    by = {}
    for c in cases:
        by.setdefault(c["cwe"], []).append(c)
    for cwe, cs in sorted(by.items()):
        s_ = sorted(cs, key=lambda c: (c["code_chars"], c["id"]))
        edges = [s_[int(len(s_) * k / 10)]["code_chars"] for k in range(1, 10)]
        bins = {}
        for c in cs:
            b = sum(c["code_chars"] >= e for e in edges)
            bins.setdefault(b, {"V": [], "S": []})["V" if c["label"] == "VULNERABLE" else "S"].append(c)
        sel = []
        for b in sorted(bins):
            vv, ss = bins[b]["V"], bins[b]["S"]; rng.shuffle(vv); rng.shuffle(ss); k = min(len(vv), len(ss)); sel += vv[:k] + ss[:k]
        y = [c["label"] == "VULNERABLE" for c in sel]; nv = sum(y)
        ok = nv >= 20 and len(sel) - nv >= 20
        r = {"category": cs[0]["category"], "pairs_before": len(cs) // 2, "matched_per_class": nv}
        if ok:
            r.update(length_only_chars=round(auroc([c["code_chars"] for c in sel], y), 4), length_only_toks=round(auroc([c["toks"] for c in sel], y), 4),
                     fn_count_only=round(auroc([nfun(c["code"]) for c in sel], y), 4),
                     static_count_only=round(auroc([len(re.findall(r"\bstatic\b", c["code"])) for c in sel], y), 4))
            band = lambda x: 0.45 <= x <= 0.55
            r["kept"] = all(band(r[k]) for k in ("length_only_chars", "length_only_toks", "fn_count_only", "static_count_only"))
        else:
            r["kept"] = False
        report[cwe] = r
        if r["kept"]:
            keep += sel
    cue = artefact_cue(keep)
    if max(cue.values()) > 0.6:
        raise SystemExit(f"REFUSED {out_path}: an artefact line predicts the label {cue} (addendum 3m)")
    out = {"cases": keep, "split": "test", "seed": 0,
           "pool": {"rule": "addendum 3i: structure-matched (one good variant per safe text; static removed; names renumbered), then per-CWE "
                            "length-matched as 2c; kept only if length-only, function-count-only and static-count-only AUROC are all in [0.45, 0.55]",
                    "source": note, "artefact_cue_3m": cue, "vulnerable_rebuilt_3m": True, "pairs_skipped_unparsed": skipped, "by_cwe": report, "functions": len(keep)}}
    json.dump(out, open(out_path, "w"))
    print(out_path, json.dumps({"functions": len(keep), "skipped": skipped}))
    for k, r in report.items():
        print("  ", k, r)


def main():
    od = sys.argv[sys.argv.index("--out-dir") + 1] if "--out-dir" in sys.argv else "results"   # 3m: build to a staging dir first
    held = {c["pair"] for c in json.load(open("results/j3_heldout_cases.json"))["cases"]}
    allj3 = json.load(open("results/imp_train_juliet3_items_all.json"))["items"]
    P = {}
    for it in allj3:
        if it["pair"] in held:
            P.setdefault(it["pair"], {})[it["label"]] = it
    cat3 = {"CWE78": "cmd_injection", "CWE23": "path_traversal", "CWE36": "path_traversal", "CWE134": "format_string"}
    pairs3 = [(p, d["VULNERABLE"]["code"], d["SAFE"]["code"], d["VULNERABLE"]["juliet_cwe"], cat3.get(d["VULNERABLE"]["juliet_cwe"], "?"))
              for p, d in sorted(P.items()) if "VULNERABLE" in d and "SAFE" in d]
    build(pairs3, "j3s", f"{od}/j3s_heldout_matched_cases.json", "J3 held-out pairs (2b/3b), cleaned (3g)")
    j4 = json.load(open("results/j4b_heldout_all.json"))["items"]
    Q = {}
    for it in j4:
        Q.setdefault(it["pair"], {})[it["label"]] = it
    pairs4 = [(p, d["VULNERABLE"]["code"], d["SAFE"]["code"], d["VULNERABLE"]["cwe"], d["VULNERABLE"]["category"]) for p, d in sorted(Q.items())
              if "VULNERABLE" in d and "SAFE" in d and d["VULNERABLE"]["compiled"] and d["SAFE"]["compiled"]
              and d["VULNERABLE"]["exec_sanitizer"] and not d["SAFE"]["exec_sanitizer"]]
    build(pairs4, "j4s", f"{od}/j4s_heldout_matched_cases.json", "J4b verified pairs (3e), cleaned (3g)")


if __name__ == "__main__":
    main()
