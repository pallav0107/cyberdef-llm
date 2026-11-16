"""Few-shot exemplars for the trace bank, TEMPLATED from Juliet ground truth (known CWE + known flaw line); NO model wrote them, no commercial model, no CASTLE case.
Source files are Juliet '_02' variants (pools J/J2 use only '_01', so no exemplar function is in any pool). Code is cleaned with imp_clean (comments, CWE/bad/good identifiers removed) like the pools.
Three exemplars: E1 VULNERABLE memory-safety (asan), E2 VULNERABLE command injection (cmd_injection, witness carries CANARY), E3 SAFE (the good variant of E1's file, every sink guarded).
Each assistant trace is built by a template from the located lines and MUST pass sc_cot.validate (valid and verdict_final == verdict_raw); the builder fails loudly otherwise.
  python3 scripts/imp_build_exemplars.py      -> results/imp_fewshot_exemplars.json"""
import glob, json, os, re, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
from cyberdef.imp_clean import clean_code
from reason_C_witness import numbered

R = "data/juliet_dl/x/C/testcases"
MEM = "MEM Memory safety (outside OWASP Top 10)"


def strip(code, drop):
    return re.sub(r"#ifndef %s\b.*?#endif\s*/\*\s*%s\s*\*/" % (drop, drop), "", code, flags=re.S)


def text(pattern, label):
    p = glob.glob(f"{R}/{pattern}", recursive=True)[0]
    code = open(p, errors="replace").read()
    t = re.sub(r"#ifdef INCLUDEMAIN.*?#endif", "", strip(code, "OMITGOOD" if label == "V" else "OMITBAD"), flags=re.S)
    t = clean_code(t)
    t = re.sub(r"\n[ \t]*return 0;[ \t]*\n\}[ \t]*(?:\n[ \t]*#endif[ \t]*)*\s*$", "", t).rstrip()
    t = "\n".join(l for l in t.split("\n") if l.strip() != "#endif" or True)
    return os.path.basename(p), t


def find(lines, pat, nth=0):
    hits = [i + 1 for i, l in enumerate(lines) if re.search(pat, l)]
    return hits[nth]


def base(summary, attacker, trusted, assumptions):
    return {"contract": {"summary": summary}, "trust_boundary": {"attacker_controlled": attacker, "trusted": trusted, "assumptions": assumptions}}


def e1():
    fn, code = text("CWE121*/**/*CWE131_memcpy_02.c", "V")
    L = code.split("\n")
    lm, la = find(L, r"memcpy\("), find(L, r"ALLOCA\(")
    d = base("Copies a 10-int source array into a destination that was allocated with only 10 bytes.", [], ["source"], ["data points to a buffer sized for 10 ints"])
    d.update({"sinks": [{"id": "s1", "line": lm, "op": "memcpy", "cwe": "CWE-121"}],
              "dataflow": [{"sink": "s1", "lines": [la, lm], "transforms": "destination is ALLOCA(10) = 10 bytes; the copy length is 10*sizeof(int) = 40 bytes"}],
              "guard_audit": [{"sink": "s1", "guards": []}], "vuln_class": {"cwe": 121, "owasp": MEM}, "oracle": "asan",
              "paths": [{"description": "straight line: allocate, then copy", "lines": [la, lm]}],
              "witness": {"values": {"copy_bytes": 40, "buffer_bytes": 10}, "state": [{"line": lm, "note": "writes 40 bytes into a 10-byte stack buffer"}], "how_to_feed": "no input needed: call the function"},
              "static_evidence": None, "refutation": {"attempts": ["Is the destination sized with sizeof(int)? No: ALLOCA(10) is 10 bytes."], "assumptions": []},
              "verdict": "VULNERABLE", "cwe": "CWE-121", "confidence": 0.9,
              "length_independence": f"memcpy at line {lm} copies 40 bytes into the 10-byte buffer from line {la}; nothing bounds the copy"})
    return fn, code, d, "memory-safety/asan", "VULNERABLE"


def e2():
    fn, code = text("CWE78*/**/*_char_console_system_02.c", "V")
    L = code.split("\n")
    lf, ls = find(L, r"fgets\("), find(L, r"SYSTEM\(data\)")
    d = base("Reads a line from stdin, appends it to the command prefix 'ls ' and runs the result through the shell.", ["stdin line"], ["fixed prefix 'ls '"], ["the user line is not sanitised"])
    d.update({"sinks": [{"id": "s1", "line": ls, "op": "SYSTEM", "cwe": "CWE-78"}],
              "dataflow": [{"sink": "s1", "lines": [lf, ls], "transforms": "fgets appends the raw stdin line to data; data is passed unchanged to SYSTEM"}],
              "guard_audit": [{"sink": "s1", "guards": []}], "vuln_class": {"cwe": 78, "owasp": "A03 Injection"}, "oracle": "cmd_injection",
              "paths": [{"description": "read line, build command, execute", "lines": [lf, ls]}],
              "witness": {"values": {"stdin": "x; echo CANARY"}, "state": [{"line": ls, "note": "shell runs 'ls x' then the injected echo"}], "how_to_feed": "stdin"},
              "static_evidence": None, "refutation": {"attempts": ["Is data escaped or checked before SYSTEM? No."], "assumptions": ["the shell interprets ';'"]},
              "verdict": "VULNERABLE", "cwe": "CWE-78", "confidence": 0.9,
              "length_independence": f"SYSTEM at line {ls} executes data built from the raw fgets at line {lf} with no sanitisation"})
    return fn, code, d, "cmd_injection", "VULNERABLE"


def e3():
    fn, code = text("CWE121*/**/*CWE131_memcpy_02.c", "S")
    L = code.split("\n")
    mem = [i + 1 for i, l in enumerate(L) if re.search(r"memcpy\(", l)]
    al = [i + 1 for i, l in enumerate(L) if re.search(r"ALLOCA\(10\*sizeof\(int\)\)", l)]
    sinks = [{"id": f"s{k+1}", "line": m, "op": "memcpy", "cwe": "CWE-121"} for k, m in enumerate(mem)]
    flows = [{"sink": f"s{k+1}", "lines": [al[k], mem[k]], "transforms": "destination is ALLOCA(10*sizeof(int)) = 40 bytes, copy length is 10*sizeof(int) = 40 bytes"} for k in range(len(mem))]
    gua = [{"sink": f"s{k+1}", "guards": [{"line": al[k], "condition": "ALLOCA(10*sizeof(int))", "sufficient": True, "issues": []}]} for k in range(len(mem))]
    d = base("Copies a 10-int array into a destination allocated with exactly 10 ints.", [], ["source"], ["sizes are compile-time constants"])
    d.update({"sinks": sinks, "dataflow": flows, "guard_audit": gua, "vuln_class": {"cwe": 121, "owasp": MEM}, "oracle": "asan",
              "paths": [{"description": f"allocate then copy ({k+1})", "lines": [al[k], mem[k]]} for k in range(len(mem))],
              "witness": None, "static_evidence": None, "refutation": {"attempts": ["Could the copy exceed the destination? Both are 10*sizeof(int) bytes."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-121", "confidence": 0.85,
              "length_independence": f"every memcpy copies 40 bytes into a destination allocated with 40 bytes (lines {', '.join(map(str, al))})"})
    return fn, code, d, "memory-safety/asan", "SAFE"


def main():
    out = []
    for build in (e1, e2, e3):
        fn, code, d, cls, lab = build()
        v = S.validate(d, code)
        if not (v["valid"] and v["verdict_final"] == v["verdict_raw"] == lab):
            raise SystemExit(f"EXEMPLAR {fn} INVALID: {v['errors']}")
        out.append({"source_file": fn, "label": lab, "class": cls, "user": numbered(code), "assistant": json.dumps(d, ensure_ascii=False), "code": code,
                    "validator": {"valid": v["valid"], "cwe_id": v.get("cwe_id"), "oracle": v.get("oracle")}})
    json.dump({"exemplars": out, "source": "templated from Juliet 1.3 '_02' ground truth (known CWE + flaw line) by the research tooling; no model, no commercial model, no CASTLE case; none of these files is in pool J/J2 ('_01' only)",
               "validated_with": "src/cyberdef/sc_cot.validate (v2)"}, open("results/imp_fewshot_exemplars.json", "w"), indent=1)
    print("exemplars valid:", [(o["source_file"][:50], o["label"], len(o["user"]) + len(o["assistant"])) for o in out])


if __name__ == "__main__":
    main()
