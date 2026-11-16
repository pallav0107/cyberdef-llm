"""Secure-Code Chain-of-Thought (SC-CoT): prompt + machine validator. Design: docs/SECURE_CODE_COT.md.

validate(d, code) checks a parsed SC-CoT JSON against the source (1-based numbered lines) and returns
{valid, errors, verdict_raw, verdict_final, has_witness, confidence, score}. A VULNERABLE verdict without a concrete witness
and a SAFE verdict with an unguarded sink are downgraded to UNCERTAIN (and reported), never dropped. The witness is EXECUTED
separately (Stage D sandbox); this module only checks internal consistency against the source text."""
from __future__ import annotations
import json, re, sys
from cyberdef.cwe_oracle import CANARY, CWE_ORACLE, INJECTION_ORACLES, ORACLES, OWASP

SYSTEM = (
    "You are an expert secure-code auditor. Audit the C/C++ function below with the Secure-Code Chain-of-Thought and reply "
    "with ONLY one JSON object (no prose, no markdown) with exactly these keys, in this order:\n"
    '1 "contract": {"summary": str}  2 "trust_boundary": {"attacker_controlled": [str], "trusted": [str], "assumptions": [str]}\n'
    '3 "sinks": [{"id": str, "line": int, "op": str, "cwe": str}] - EVERY dangerous operation: writes/copies (memcpy, strcpy, strcat, '
    "sprintf, index writes, pointer arithmetic: CWE-787/120/121/122), reads (index, deref: 125/476), lifetime (free, realloc, "
    "use-after: 416/415), size/index arithmetic (+, *, casts, sign: 190/191/681), format string (134), uninitialized (457/908), "
    "division by zero (369). Use [] only if the function has none.\n"
    '4 "dataflow": [{"sink": str, "lines": [int], "transforms": str}] - how attacker inputs reach each sink\'s size, index or pointer\n'
    '5 "guard_audit": [{"sink": str, "guards": [{"line": int, "condition": str, "sufficient": bool, "issues": [str]}]}] - every check on '
    "the path to each sink, judged against: off-by-one (<= vs <), signed/unsigned comparison, integer overflow inside the check, "
    "check on the wrong variable, check after use, check missing on some path\n"
    '5b "vuln_class": {"cwe": int, "owasp": str} - the ONE CWE class of the finding (e.g. 787 stack/heap write, 125 read, 416 use-after-free, 415 double free, '
    "190 integer overflow, 369 divide by zero, 401 leak, 362 race, 78 OS command injection, 22 path traversal, 89 SQL injection, 134 format string, "
    "617/674/835 assert, recursion, infinite loop, 770 unbounded resources, 798/327/522/253/628/843 no runtime monitor); owasp = OWASP 2021 category label "
    '(or "MEM Memory safety (outside OWASP Top 10)")\n'
    '5c "oracle": the monitor that can verify the finding, exactly one of asan|ubsan|lsan|tsan|integer|cmd_injection|path_traversal|sqli|format_string|resource|none. '
    "It MUST follow from the CWE: memory-safety classes -> asan; 190/191/369 -> integer; 401 -> lsan; 362 -> tsan; 617/674/835/770/400 -> resource; 78 -> cmd_injection; "
    '22 -> path_traversal; 89 -> sqli; 134 -> format_string; 253/327/522/628/798/843 -> none\n'
    '6 "paths": [{"description": str, "lines": [int]}] - every path including error and cleanup paths (goto, early return)\n'
    '7 "witness": {"values": {name: concrete value}, "state": [{"line": int, "note": str}], "how_to_feed": str (argv, stdin or file)} '
    'shaped for the chosen oracle. For cmd_injection, path_traversal, sqli and format_string the payload string MUST contain the literal token CANARY exactly '
    "where the injected command, path, query or format fragment goes (the harness substitutes and detects it). witness is null when oracle is none; "
    'then give "static_evidence": {"line": int, "snippet": str} (a snippet that really appears on that line) and set it to null for every other oracle\n'
    "(7 and the static_evidence key are both always present; one of them is null)\n"
    '8 "refutation": {"attempts": [str], "assumptions": [str]} - actively try to falsify your finding (missed guard? caller or type '
    "constraint?)\n"
    '9 "verdict": "VULNERABLE"|"SAFE"|"UNCERTAIN", "cwe": str, "confidence": number 0..1, "length_independence": one line naming the '
    "sink and guard the verdict rests on (never size or complexity)\n"
    '10 "fix": optional {"patch": str, "why": str}\n'
    "Line numbers refer to the numbered lines shown. Be concise: short strings."
)
REQUIRED = ("contract", "trust_boundary", "sinks", "dataflow", "guard_audit", "vuln_class", "oracle", "paths", "witness", "static_evidence",
            "refutation", "verdict", "cwe", "confidence", "length_independence")


def _toks(s):
    return set(t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", str(s)))


def _line(lines, ln):
    try:
        ln = int(ln)
    except Exception:
        return None
    return lines[ln - 1] if 1 <= ln <= len(lines) else None


def _witness_ok(w):
    if not isinstance(w, dict):
        return False
    vals = w.get("values")
    if vals in (None, "", [], {}) or (isinstance(vals, dict) and all(v in (None, "", [], {}) for v in vals.values())):
        return False
    return bool(str(w.get("how_to_feed", "")).strip())


def validate(d, code, broken=False):
    out = dict(valid=False, errors=[], cwe_id=None, oracle=None, owasp=None, verdict_raw=None, verdict_final="UNCERTAIN", has_witness=False, confidence=0.5, score=0.5)
    if broken:                                     # always-pass mutant (acceptance control)
        out.update(valid=True, verdict_raw="VULNERABLE", verdict_final="VULNERABLE", has_witness=True, score=1.0)
        return out
    if not isinstance(d, dict):
        out["errors"].append("not a JSON object"); return out
    miss = [k for k in REQUIRED if k not in d]
    if miss:
        out["errors"].append(f"missing keys {miss}")
    v = str(d.get("verdict", "")).upper()
    if v not in ("VULNERABLE", "SAFE", "UNCERTAIN"):
        out["errors"].append("bad verdict"); return out
    out["verdict_raw"] = v
    try:
        out["confidence"] = min(1.0, max(0.0, float(d.get("confidence"))))
    except Exception:
        out["confidence"] = 0.5
    lines = code.split("\n"); err = out["errors"]
    sinks = d.get("sinks") or []
    sink_ids = set()
    for s in sinks:
        if not isinstance(s, dict):
            err.append("sink not an object"); continue
        sink_ids.add(str(s.get("id")))
        L = _line(lines, s.get("line"))
        if L is None:
            err.append(f"sink line {s.get('line')} does not exist")
        elif not (_toks(s.get("op", "")) & _toks(L)):
            err.append(f"sink op {s.get('op')!r} not on line {s.get('line')}")
    for df in d.get("dataflow") or []:
        for ln in (df.get("lines") or []) if isinstance(df, dict) else []:
            if _line(lines, ln) is None:
                err.append(f"dataflow line {ln} does not exist")
    guarded = {}
    for ga in d.get("guard_audit") or []:
        if not isinstance(ga, dict):
            continue
        for g in ga.get("guards") or []:
            L = _line(lines, g.get("line")) if isinstance(g, dict) else None
            if L is None:
                err.append(f"guard line {g.get('line') if isinstance(g, dict) else g} does not exist"); continue
            ct = _toks(g.get("condition", ""))
            if ct and len(ct & _toks(L)) / len(ct) < 0.6:
                err.append(f"guard condition not on line {g.get('line')}")
            if g.get("sufficient") is True:
                guarded[str(ga.get("sink"))] = True
    for p in d.get("paths") or []:
        for ln in (p.get("lines") or []) if isinstance(p, dict) else []:
            if _line(lines, ln) is None:
                err.append(f"path line {ln} does not exist")
    # ---- v2: class + oracle routing
    vc = d.get("vuln_class"); orc = d.get("oracle"); cwe_id = None
    if not isinstance(vc, dict):
        err.append("vuln_class missing or not an object")
    else:
        try:
            cwe_id = int(vc.get("cwe"))
        except Exception:
            cwe_id = None
        if cwe_id not in CWE_ORACLE:
            err.append(f"vuln_class cwe {vc.get('cwe')} not in the allowed list")
        if vc.get("owasp") not in OWASP:
            err.append("vuln_class owasp label not in the allowed list")
    if orc not in ORACLES:
        err.append(f"oracle {orc!r} not in the allowed list")
    elif cwe_id in CWE_ORACLE and CWE_ORACLE[cwe_id] != orc:
        err.append(f"oracle {orc} inconsistent with CWE {cwe_id} (fixed map says {CWE_ORACLE[cwe_id]})")
    out["cwe_id"] = cwe_id; out["oracle"] = orc if orc in ORACLES else None
    out["owasp"] = vc.get("owasp") if isinstance(vc, dict) else None
    w = d.get("witness"); se = d.get("static_evidence")
    if orc == "none":
        ok_se = False
        if not isinstance(se, dict):
            err.append("oracle none requires static_evidence {line, snippet}")
        else:
            Ls = _line(lines, se.get("line"))
            snip = re.sub(r"\s+", " ", str(se.get("snippet", ""))).strip()
            if Ls is None:
                err.append(f"static_evidence line {se.get('line')} does not exist")
            elif not snip or snip not in re.sub(r"\s+", " ", Ls):
                err.append("static_evidence snippet not on its line")
            else:
                ok_se = True
        out["has_witness"] = ok_se
        if w not in (None, "", [], {}):
            err.append("oracle none must have witness null")
    else:
        out["has_witness"] = _witness_ok(w)
        if se not in (None, "", [], {}):
            err.append("static_evidence only allowed with oracle none")
        if orc in INJECTION_ORACLES and out["has_witness"]:
            vals = w.get("values") if isinstance(w, dict) else None
            def _strs(x):
                if isinstance(x, str):
                    yield x
                elif isinstance(x, dict):
                    for y in x.values():
                        yield from _strs(y)
                elif isinstance(x, (list, tuple)):
                    for y in x:
                        yield from _strs(y)
            if not any(CANARY in t for t in _strs(vals)):
                err.append(f"{orc} witness must contain the literal token {CANARY}")
        elif orc in INJECTION_ORACLES and not out["has_witness"]:
            pass            # missing witness is already reported by the VULNERABLE-without-witness rule
    if isinstance(w, dict):
        for st in w.get("state") or []:
            if isinstance(st, dict) and st.get("line") is not None and _line(lines, st.get("line")) is None:
                err.append(f"witness state line {st.get('line')} does not exist")
    ref = d.get("refutation")
    if ref in (None, "", [], {}) or (isinstance(ref, dict) and not any(ref.get(k) for k in ("attempts", "assumptions"))):
        err.append("refutation missing")
    if v == "VULNERABLE" and not out["has_witness"]:
        err.append("VULNERABLE without a concrete witness (or static_evidence for oracle none)")
    if v == "SAFE":
        for sid in sink_ids:
            if not guarded.get(sid):
                err.append(f"SAFE but sink {sid} has no sufficient guard"); break
    out["valid"] = not err
    out["verdict_final"] = v if out["valid"] else "UNCERTAIN"
    c = out["confidence"]
    out["score"] = 0.5 + 0.5 * c if out["verdict_final"] == "VULNERABLE" else 0.5 - 0.5 * c if out["verdict_final"] == "SAFE" else 0.5
    return out


GOOD_CODE = "int f(char *a, int n) {\n  char b[8];\n  if (n > 8) return -1;\n  memcpy(b, a, n);\n  return 0;\n}"
GOOD = {"contract": {"summary": "copies n bytes"}, "trust_boundary": {"attacker_controlled": ["a", "n"], "trusted": [], "assumptions": []},
        "sinks": [{"id": "s1", "line": 4, "op": "memcpy", "cwe": "CWE-787"}],
        "dataflow": [{"sink": "s1", "lines": [4], "transforms": "n is the size"}],
        "guard_audit": [{"sink": "s1", "guards": [{"line": 3, "condition": "n > 8", "sufficient": False, "issues": ["negative n"]}]}],
        "vuln_class": {"cwe": 787, "owasp": "MEM Memory safety (outside OWASP Top 10)"}, "oracle": "asan",
        "paths": [{"description": "main", "lines": [3, 4]}],
        "witness": {"values": {"n": -1, "a": "AAAA"}, "state": [{"line": 4, "note": "size_t(n) huge"}], "how_to_feed": "argv"}, "static_evidence": None,
        "refutation": {"attempts": ["checked guard"], "assumptions": ["n is signed"]},
        "verdict": "VULNERABLE", "cwe": "CWE-787", "confidence": 0.8, "length_independence": "memcpy size n only checked above"}
INJ_CODE = 'int run(char *q) {\n  char cmd[128];\n  sprintf(cmd, "ls %s", q);\n  return system(cmd);\n}'
INJ = {**GOOD, "sinks": [{"id": "s1", "line": 4, "op": "system", "cwe": "CWE-78"}], "dataflow": [{"sink": "s1", "lines": [3, 4], "transforms": "q into cmd"}],
       "guard_audit": [{"sink": "s1", "guards": []}], "paths": [{"description": "main", "lines": [3, 4]}],
       "vuln_class": {"cwe": 78, "owasp": "A03 Injection"}, "oracle": "cmd_injection", "cwe": "CWE-78",
       "witness": {"values": {"q": "x; CANARY"}, "state": [{"line": 4, "note": "shell runs CANARY"}], "how_to_feed": "argv"}}
NONE_CODE = 'int login(void) {\n  const char *pw = "hunter2";\n  return check(pw);\n}'
NONE = {**GOOD, "sinks": [], "dataflow": [], "guard_audit": [], "paths": [{"description": "main", "lines": [2, 3]}],
        "vuln_class": {"cwe": 798, "owasp": "A07 Identification and Authentication Failures"}, "oracle": "none", "cwe": "CWE-798",
        "witness": None, "static_evidence": {"line": 2, "snippet": 'pw = "hunter2"'}}


def selftest(broken):
    import copy
    def v(base=GOOD, code=GOOD_CODE, **ch):
        d = copy.deepcopy(base); d.update(ch); return validate(d, code, broken)
    safe = {"verdict": "SAFE", "witness": None}
    miss = copy.deepcopy(GOOD); miss.pop("vuln_class"); miss.pop("oracle")
    return {"valid_trace_accepted": validate(GOOD, GOOD_CODE, broken)["valid"],
            "missing_refutation_rejected": not v(refutation=None)["valid"],
            "vuln_no_witness_rejected": (lambda r: not r["valid"] and r["verdict_final"] == "UNCERTAIN")(v(witness=None)),
            "nonexistent_line_rejected": not v(sinks=[{"id": "s1", "line": 99, "op": "memcpy", "cwe": "CWE-787"}])["valid"],
            "sink_not_on_line_rejected": not v(sinks=[{"id": "s1", "line": 3, "op": "memcpy", "cwe": "CWE-787"}])["valid"],
            "safe_unguarded_rejected": not v(**safe)["valid"],
            "valid_injection_accepted": validate(INJ, INJ_CODE, broken)["valid"],
            "valid_none_accepted": validate(NONE, NONE_CODE, broken)["valid"],
            "class_not_allowed_rejected": not v(vuln_class={"cwe": 99999, "owasp": "A03 Injection"})["valid"],
            "oracle_inconsistent_rejected": not v(oracle="lsan")["valid"],
            "injection_without_canary_rejected": not v(INJ, INJ_CODE, witness={"values": {"q": "x; rm -rf"}, "state": [], "how_to_feed": "argv"})["valid"],
            "witness_shape_mismatch_rejected": not v(witness={"values": {"n": -1}, "state": []})["valid"],
            "oracle_none_without_static_evidence_rejected": not v(NONE, NONE_CODE, static_evidence=None)["valid"],
            "static_evidence_line_missing_rejected": not v(NONE, NONE_CODE, static_evidence={"line": 77, "snippet": "pw"})["valid"],
            "static_evidence_snippet_mismatch_rejected": not v(NONE, NONE_CODE, static_evidence={"line": 2, "snippet": "completely different"})["valid"],
            "missing_v2_fields_rejected": not validate(miss, GOOD_CODE, broken)["valid"]}


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        print(json.dumps(selftest("--broken" in sys.argv)))
