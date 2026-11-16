"""Addendum 3b: per-category few-shot exemplars for the self-training rounds, TEMPLATED from Juliet ground truth like
scripts/imp_build_exemplars.py (no model wrote them, no commercial model, no CASTLE case). A round of category C uses the three
quick-bank exemplars plus the extra exemplars listed for C in EXTRA. Every exemplar must pass sc_cot.validate with
verdict_final == verdict_raw == its label, or the builder fails loudly.
Why: 14B-written SAFE command-injection traces failed the unchanged validator (a payload witness without CANARY on safe code;
no sink marked as sufficiently guarded) and the quick set has no SAFE injection exemplar to show the valid form.
Every exemplar source file is excluded from all held-out tests (scripts/ci_exemplar_leak.py checks it).
  python3 scripts/imp_build_st_exemplars.py cmd_injection   -> results/imp_fewshot_exemplars_st_cmd_injection.json"""
import json, re, sys
sys.path.insert(0, "src"); sys.path.insert(0, "scripts")
from cyberdef import sc_cot as S
import imp_build_exemplars as B
from reason_C_witness import numbered


def e4_cmd_safe():
    """SAFE command injection: the good variant of E2 (same _02 file); data is the fixed prefix plus the literal "*.*"."""
    fn, code = B.text("CWE78*/**/*_char_console_system_02.c", "S")
    L = code.split("\n")
    sy = [i + 1 for i, l in enumerate(L) if re.search(r"SYSTEM\(data\)", l)]
    sc = [i + 1 for i, l in enumerate(L) if re.search(r"strcat\(data, \"\*\.\*\"\)", l)]
    bf = [i + 1 for i, l in enumerate(L) if re.search(r"data_buf\[100\] = FULL_COMMAND", l)]
    assert len(sy) == len(sc) == len(bf) == 2, (sy, sc, bf)
    sinks = [{"id": f"s{k+1}", "line": sy[k], "op": "SYSTEM", "cwe": "CWE-78"} for k in range(2)]
    flows = [{"sink": f"s{k+1}", "lines": [bf[k], sc[k], sy[k]], "transforms": "data is the fixed prefix FULL_COMMAND with the literal \"*.*\" appended; no external input reaches it"} for k in range(2)]
    gua = [{"sink": f"s{k+1}", "guards": [{"line": sc[k], "condition": "strcat(data, \"*.*\")", "sufficient": True, "issues": []}]} for k in range(2)]
    d = B.base("Builds a shell command from a fixed prefix and the literal \"*.*\" and runs it.", [], ["FULL_COMMAND", "the literal \"*.*\""], ["no caller input reaches data"])
    d.update({"sinks": sinks, "dataflow": flows, "guard_audit": gua, "vuln_class": {"cwe": 78, "owasp": "A03 Injection"}, "oracle": "cmd_injection",
              "paths": [{"description": f"build fixed command, execute ({k+1})", "lines": [bf[k], sc[k], sy[k]]} for k in range(2)],
              "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Can any external input reach data? No: it is built only from FULL_COMMAND and the literal \"*.*\"."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-78", "confidence": 0.85,
              "length_independence": f"SYSTEM at lines {sy[0]} and {sy[1]} runs only the constant command built at lines {sc[0]} and {sc[1]}"})
    return fn, code, d, "cmd_injection", "SAFE"


PT_FILE = "CWE23*/**/*_char_console_fopen_02.cpp"   # a J3 TRAINING file (in no held-out test); imp_st_pool drops it from the pool


def e5_path_vuln():
    """VULNERABLE path traversal (true CWE-23, recorded as its allowed parent CWE-22): a stdin line is appended to BASEPATH and opened."""
    fn, code = B.text(PT_FILE, "V")
    L = code.split("\n")
    bf, fg, fo = B.find(L, r"dataBuffer\[FILENAME_MAX\] = BASEPATH"), B.find(L, r"fgets\(data\+dataLen"), B.find(L, r"FOPEN\(data, ")
    gl = B.find(L, r"if \(FILENAME_MAX-dataLen > 1\)")
    d = B.base("Appends a line read from stdin to the base directory BASEPATH and opens the resulting path for writing.", ["stdin line"], ["BASEPATH"], ["the user line is not checked for '..' or '/'"])
    d.update({"sinks": [{"id": "s1", "line": fo, "op": "FOPEN", "cwe": "CWE-22"}],
              "dataflow": [{"sink": "s1", "lines": [bf, fg, fo], "transforms": "data starts as BASEPATH; fgets appends the raw stdin line; data is opened unchanged"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": gl, "condition": "FILENAME_MAX-dataLen > 1", "sufficient": False, "issues": ["only bounds the length; '..' and '/' pass through"]}]}],
              "vuln_class": {"cwe": 22, "owasp": "A01 Broken Access Control"}, "oracle": "path_traversal",
              "paths": [{"description": "read line, append to base path, open", "lines": [bf, fg, fo]}],
              "witness": {"values": {"stdin": "../../CANARY/x"}, "state": [{"line": fo, "note": "opens BASEPATH/../../CANARY/x, outside the base directory"}], "how_to_feed": "stdin"},
              "static_evidence": None,
              "refutation": {"attempts": ["Is '..' or '/' removed or rejected before FOPEN? No: the only check bounds the length."], "assumptions": ["the process may create files where the path points"]},
              "verdict": "VULNERABLE", "cwe": "CWE-22", "confidence": 0.9,
              "length_independence": f"FOPEN at line {fo} opens BASEPATH plus the raw stdin line from line {fg}; nothing rejects '..'"})
    return fn, code, d, "path_traversal", "VULNERABLE"


def e6_path_safe():
    """SAFE path traversal: the good half of E5's file; the path is BASEPATH plus the literal "file.txt"."""
    fn, code = B.text(PT_FILE, "S")
    L = code.split("\n")
    fo = [i + 1 for i, l in enumerate(L) if re.search(r"FOPEN\(data, ", l)]
    sc = [i + 1 for i, l in enumerate(L) if re.search(r'strcat\(data, "file\.txt"\)', l)]
    bf = [i + 1 for i, l in enumerate(L) if re.search(r"dataBuffer\[FILENAME_MAX\] = BASEPATH", l)]
    assert len(fo) == len(sc) == len(bf) == 2, (fo, sc, bf)
    sinks = [{"id": f"s{k+1}", "line": fo[k], "op": "FOPEN", "cwe": "CWE-22"} for k in range(2)]
    flows = [{"sink": f"s{k+1}", "lines": [bf[k], sc[k], fo[k]], "transforms": "data is BASEPATH with the literal \"file.txt\" appended; no external input reaches it"} for k in range(2)]
    gua = [{"sink": f"s{k+1}", "guards": [{"line": sc[k], "condition": 'strcat(data, "file.txt")', "sufficient": True, "issues": []}]} for k in range(2)]
    d = B.base("Opens a fixed file, BASEPATH plus the literal \"file.txt\", for writing.", [], ["BASEPATH", "the literal \"file.txt\""], ["no caller input reaches data"])
    d.update({"sinks": sinks, "dataflow": flows, "guard_audit": gua, "vuln_class": {"cwe": 22, "owasp": "A01 Broken Access Control"}, "oracle": "path_traversal",
              "paths": [{"description": f"build fixed path, open ({k+1})", "lines": [bf[k], sc[k], fo[k]]} for k in range(2)],
              "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Can any external input reach data? No: it is built only from BASEPATH and the literal \"file.txt\"."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-22", "confidence": 0.85,
              "length_independence": f"FOPEN at lines {fo[0]} and {fo[1]} opens only the constant path built at lines {sc[0]} and {sc[1]}"})
    return fn, code, d, "path_traversal", "SAFE"


SQ_PAIR = "s17k1"      # a SQLi TRAINING pair (imp_train_sqli_train_items.json; not in q_heldout); imp_st_pool drops it from the pool


def _sqli(label):
    items = json.load(open("results/imp_train_sqli_train_items.json"))["items"]
    it = [x for x in items if x.get("pair") == SQ_PAIR and x["label"] == label]
    assert len(it) == 1, (SQ_PAIR, label, len(it))
    return f"sqli:{SQ_PAIR}:", it[0]["code"]     # trailing colon: matches sqli:s17k1:V/S only, never s17k10


def e7_sqli_vuln():
    """VULNERABLE SQL injection: a stdin line is pasted inside quotes into the query with snprintf and executed."""
    fn, code = _sqli("VULNERABLE")
    L = code.split("\n")
    fg, sn, ex = B.find(L, r"fgets\(input"), B.find(L, r"snprintf\(sql"), B.find(L, r"sqlite3_exec\(db, sql")
    st = B.find(L, r"strcspn\(input")
    d = B.base("Reads a title from stdin, pastes it into a SELECT query between single quotes and executes the query.", ["stdin line"], ["the fixed query text"], ["the title is not escaped"])
    d.update({"sinks": [{"id": "s1", "line": ex, "op": "sqlite3_exec", "cwe": "CWE-89"}],
              "dataflow": [{"sink": "s1", "lines": [fg, sn, ex], "transforms": "fgets reads the raw line into input; snprintf pastes it inside quotes into sql; sql is executed unchanged"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": st, "condition": 'strcspn(input, "\\n")', "sufficient": False, "issues": ["removes only the newline; quotes and SQL pass through"]}]}],
              "vuln_class": {"cwe": 89, "owasp": "A03 Injection"}, "oracle": "sqli",
              "paths": [{"description": "read title, build query, execute", "lines": [fg, sn, ex]}],
              "witness": {"values": {"stdin": "x' OR CANARY=CANARY --"}, "state": [{"line": ex, "note": "the query becomes ... WHERE title='x' OR CANARY=CANARY --'"}], "how_to_feed": "stdin"},
              "static_evidence": None,
              "refutation": {"attempts": ["Is the title escaped or bound as a parameter? No: it is pasted into the SQL text."], "assumptions": []},
              "verdict": "VULNERABLE", "cwe": "CWE-89", "confidence": 0.9,
              "length_independence": f"sqlite3_exec at line {ex} runs SQL built at line {sn} from the raw stdin line read at line {fg}"})
    return fn, code, d, "sqli", "VULNERABLE"


def e8_sqli_safe():
    """SAFE SQL injection: the pair's fixed half; constant query text, the title bound with sqlite3_bind_text."""
    fn, code = _sqli("SAFE")
    L = code.split("\n")
    fg, pr, bd = B.find(L, r"fgets\(input"), B.find(L, r"sqlite3_prepare_v2\("), B.find(L, r"sqlite3_bind_text\(")
    d = B.base("Reads a title from stdin and looks it up with a prepared statement; the title is bound as a parameter.", ["stdin line"], ["the constant query text"], [])
    d.update({"sinks": [{"id": "s1", "line": pr, "op": "sqlite3_prepare_v2", "cwe": "CWE-89"}],
              "dataflow": [{"sink": "s1", "lines": [fg, pr, bd], "transforms": "the query text is a constant with a ? placeholder; input only reaches the statement through sqlite3_bind_text"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": bd, "condition": "sqlite3_bind_text(stmt, 1, input", "sufficient": True, "issues": []}]}],
              "vuln_class": {"cwe": 89, "owasp": "A03 Injection"}, "oracle": "sqli",
              "paths": [{"description": "read title, prepare constant query, bind, step", "lines": [fg, pr, bd]}],
              "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Does the input ever become SQL text? No: the query is a constant and the title is bound as a value."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-89", "confidence": 0.85,
              "length_independence": f"the only query built from input is the constant prepared at line {pr}; the title is bound at line {bd}"})
    return fn, code, d, "sqli", "SAFE"


FS_FILE = "CWE134*/**/*_char_console_printf_02.c"   # a J3 TRAINING file (in no held-out test); imp_st_pool drops it from the pool


def _owasp(cwe):
    from cyberdef.cwe_oracle import CWE_OWASP
    return CWE_OWASP.get(cwe, "A03 Injection")


def e9_fmt_vuln():
    """VULNERABLE format string: a stdin line is passed to printf as the FORMAT."""
    fn, code = B.text(FS_FILE, "V")
    L = code.split("\n")
    bf, fg, pf = B.find(L, r'dataBuffer\[100\] = ""'), B.find(L, r"fgets\(data\+dataLen"), B.find(L, r"printf\(data\)")
    gl = B.find(L, r"if \(100-dataLen > 1\)")
    d = B.base("Reads a line from stdin and prints it with printf, using the line itself as the format string.", ["stdin line"], [], ["the line may contain % directives"])
    d.update({"sinks": [{"id": "s1", "line": pf, "op": "printf", "cwe": "CWE-134"}],
              "dataflow": [{"sink": "s1", "lines": [bf, fg, pf], "transforms": "fgets reads the raw line into data; data is passed as printf's format argument"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": gl, "condition": "100-dataLen > 1", "sufficient": False, "issues": ["only bounds the length; % directives pass through"]}]}],
              "vuln_class": {"cwe": 134, "owasp": _owasp(134)}, "oracle": "format_string",
              "paths": [{"description": "read line, print it as a format", "lines": [bf, fg, pf]}],
              "witness": {"values": {"stdin": "CANARY%p.%p.%p.%p"}, "state": [{"line": pf, "note": "printf reads four pointers from the stack and prints them after CANARY"}], "how_to_feed": "stdin"},
              "static_evidence": None,
              "refutation": {"attempts": ["Is the line printed through a constant format such as \"%s\"? No: it is the format."], "assumptions": []},
              "verdict": "VULNERABLE", "cwe": "CWE-134", "confidence": 0.9,
              "length_independence": f"printf at line {pf} uses the raw stdin line read at line {fg} as its format string"})
    return fn, code, d, "format_string", "VULNERABLE"


def e10_fmt_safe():
    """SAFE format string: the good half of E9's file. Two sinks print stdin through the constant format "%s\n"; two print the
    constant "fixedstringtest", which has no % directive."""
    fn, code = B.text(FS_FILE, "S")
    L = code.split("\n")
    fg = [i + 1 for i, l in enumerate(L) if re.search(r"fgets\(data\+dataLen", l)]
    ps = [i + 1 for i, l in enumerate(L) if re.search(r'printf\("%s\\n", data\)', l)]
    pd = [i + 1 for i, l in enumerate(L) if re.search(r"printf\(data\)", l)]
    sc = [i + 1 for i, l in enumerate(L) if re.search(r'strcpy\(data, "fixedstringtest"\)', l)]
    assert len(fg) == len(ps) == len(pd) == len(sc) == 2, (fg, ps, pd, sc)
    sinks, flows, gua, paths = [], [], [], []
    for k in range(2):
        sid = f"s{k+1}"
        sinks.append({"id": sid, "line": ps[k], "op": "printf", "cwe": "CWE-134"})
        flows.append({"sink": sid, "lines": [fg[k], ps[k]], "transforms": "the stdin line reaches printf only as the argument of the constant format \"%s\\n\""})
        gua.append({"sink": sid, "guards": [{"line": ps[k], "condition": 'printf("%s\\n", data)', "sufficient": True, "issues": []}]})
        paths.append({"description": f"read line, print through a constant format ({k+1})", "lines": [fg[k], ps[k]]})
    for k in range(2):
        sid = f"s{k+3}"
        sinks.append({"id": sid, "line": pd[k], "op": "printf", "cwe": "CWE-134"})
        flows.append({"sink": sid, "lines": [sc[k], pd[k]], "transforms": "data is the constant \"fixedstringtest\"; no external input reaches it"})
        gua.append({"sink": sid, "guards": [{"line": sc[k], "condition": 'strcpy(data, "fixedstringtest")', "sufficient": True, "issues": []}]})
        paths.append({"description": f"copy a constant, print it ({k+1})", "lines": [sc[k], pd[k]]})
    d = B.base("Prints a stdin line through the constant format \"%s\\n\", and prints a constant string that has no % directive.", ["stdin line"], ["the format \"%s\\n\"", "the literal \"fixedstringtest\""], [])
    d.update({"sinks": sinks, "dataflow": flows, "guard_audit": gua, "vuln_class": {"cwe": 134, "owasp": _owasp(134)}, "oracle": "format_string",
              "paths": paths, "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Can input ever become a format string? No: input is only an argument of \"%s\\n\"; printf(data) only ever sees the constant."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-134", "confidence": 0.85,
              "length_independence": f"input reaches printf only through \"%s\\n\" (lines {ps[0]}, {ps[1]}); printf(data) at lines {pd[0]}, {pd[1]} prints the constant copied at lines {sc[0]}, {sc[1]}"})
    return fn, code, d, "format_string", "SAFE"


INT_FILE = "CWE190*/**/*__int_max_add_01.c"     # a Juliet _01 file in NO pool and NO test (J4b samples only _02-_45)
LEAK_FILE = "CWE401*/**/*__char_malloc_01.c"    # a pool-J file (every CWE-401 _01 file is in pool J); imp_st_pool drops it


def _ow(cwe):
    from cyberdef.cwe_oracle import CWE_OWASP, OWASP_OUTSIDE
    return CWE_OWASP.get(cwe, OWASP_OUTSIDE)


def e11_int_vuln():
    """VULNERABLE integer overflow: data = INT_MAX; data + 1."""
    fn, code = B.text(INT_FILE, "V")
    L = code.split("\n")
    sv, ad = B.find(L, r"data = INT_MAX;"), B.find(L, r"int result = data \+ 1;")
    d = B.base("Sets data to INT_MAX and computes data + 1 in a signed int.", [], ["INT_MAX"], [])
    d.update({"sinks": [{"id": "s1", "line": ad, "op": "data + 1", "cwe": "CWE-190"}],
              "dataflow": [{"sink": "s1", "lines": [sv, ad], "transforms": "data is INT_MAX; data + 1 exceeds the largest int"}],
              "guard_audit": [{"sink": "s1", "guards": []}], "vuln_class": {"cwe": 190, "owasp": _ow(190)}, "oracle": "integer",
              "paths": [{"description": "set INT_MAX, add one", "lines": [sv, ad]}],
              "witness": {"values": {"data": 2147483647}, "state": [{"line": ad, "note": "INT_MAX + 1 overflows a signed int"}], "how_to_feed": "no input needed: call the function"},
              "static_evidence": None,
              "refutation": {"attempts": ["Is data checked against INT_MAX before the addition? No."], "assumptions": ["int is 32 bits"]},
              "verdict": "VULNERABLE", "cwe": "CWE-190", "confidence": 0.9,
              "length_independence": f"line {ad} adds 1 to the INT_MAX assigned at line {sv} with no check"})
    return fn, code, d, "integer", "VULNERABLE"


def e12_int_safe():
    """SAFE integer: the good half. One function uses data = 2; the other checks data < INT_MAX before adding."""
    fn, code = B.text(INT_FILE, "S")
    L = code.split("\n")
    ad = [i + 1 for i, l in enumerate(L) if re.search(r"int result = data \+ 1;", l)]
    two, chk = B.find(L, r"data = 2;"), B.find(L, r"if \(data < INT_MAX\)")
    assert len(ad) == 2, ad
    d = B.base("Adds 1 to data only when the result fits: data is the constant 2, or it is checked against INT_MAX first.", [], ["the constant 2", "INT_MAX"], [])
    d.update({"sinks": [{"id": "s1", "line": ad[0], "op": "data + 1", "cwe": "CWE-190"}, {"id": "s2", "line": ad[1], "op": "data + 1", "cwe": "CWE-190"}],
              "dataflow": [{"sink": "s1", "lines": [two, ad[0]], "transforms": "data is 2; 2 + 1 fits"},
                           {"sink": "s2", "lines": [chk, ad[1]], "transforms": "the addition runs only when data < INT_MAX"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": two, "condition": "data = 2", "sufficient": True, "issues": []}]},
                              {"sink": "s2", "guards": [{"line": chk, "condition": "data < INT_MAX", "sufficient": True, "issues": []}]}],
              "vuln_class": {"cwe": 190, "owasp": _ow(190)}, "oracle": "integer",
              "paths": [{"description": "constant 2, add one", "lines": [two, ad[0]]}, {"description": "check, then add one", "lines": [chk, ad[1]]}],
              "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Can either addition overflow? No: 2 + 1 fits, and the other runs only below INT_MAX."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-190", "confidence": 0.85,
              "length_independence": f"line {ad[0]} adds to the constant 2 (line {two}); line {ad[1]} is reached only when data < INT_MAX (line {chk})"})
    return fn, code, d, "integer", "SAFE"


def e13_leak_vuln():
    """VULNERABLE memory leak: 100 bytes from malloc, never freed."""
    fn, code = B.text(LEAK_FILE, "V")
    L = code.split("\n")
    ma, pl = B.find(L, r"data = \(char \*\)malloc\(100\*sizeof\(char\)\);"), B.find(L, r"printLine\(data\);")
    d = B.base("Allocates 100 bytes with malloc, copies a string in, prints it and returns without freeing.", [], [], [])
    d.update({"sinks": [{"id": "s1", "line": ma, "op": "malloc", "cwe": "CWE-401"}],
              "dataflow": [{"sink": "s1", "lines": [ma, pl], "transforms": "the only pointer to the block is data; the function returns without free(data)"}],
              "guard_audit": [{"sink": "s1", "guards": []}], "vuln_class": {"cwe": 401, "owasp": _ow(401)}, "oracle": "lsan",
              "paths": [{"description": "allocate, use, return", "lines": [ma, pl]}],
              "witness": {"values": {"allocated_bytes": 100, "freed": 0}, "state": [{"line": pl, "note": "last use of data; the block is never freed"}], "how_to_feed": "no input needed: call the function"},
              "static_evidence": None,
              "refutation": {"attempts": ["Is data freed on any path, or returned to the caller? No."], "assumptions": []},
              "verdict": "VULNERABLE", "cwe": "CWE-401", "confidence": 0.9,
              "length_independence": f"the block allocated at line {ma} is never freed and its pointer is lost on return"})
    return fn, code, d, "leak", "VULNERABLE"


def e14_leak_safe():
    """SAFE memory: the good half. One buffer is on the stack (ALLOCA); the malloc'd one is freed."""
    fn, code = B.text(LEAK_FILE, "S")
    L = code.split("\n")
    al, ma, fr = B.find(L, r"data = \(char \*\)ALLOCA\(100\*sizeof\(char\)\);"), B.find(L, r"data = \(char \*\)malloc\(100\*sizeof\(char\)\);"), B.find(L, r"free\(data\);")
    d = B.base("Uses a 100-byte stack buffer, and a 100-byte heap buffer that is freed after use.", [], [], [])
    d.update({"sinks": [{"id": "s1", "line": al, "op": "ALLOCA", "cwe": "CWE-401"}, {"id": "s2", "line": ma, "op": "malloc", "cwe": "CWE-401"}],
              "dataflow": [{"sink": "s1", "lines": [al], "transforms": "stack memory is released when the function returns"},
                           {"sink": "s2", "lines": [ma, fr], "transforms": "the heap block is freed before return"}],
              "guard_audit": [{"sink": "s1", "guards": [{"line": al, "condition": "ALLOCA(100*sizeof(char))", "sufficient": True, "issues": []}]},
                              {"sink": "s2", "guards": [{"line": fr, "condition": "free(data)", "sufficient": True, "issues": []}]}],
              "vuln_class": {"cwe": 401, "owasp": _ow(401)}, "oracle": "lsan",
              "paths": [{"description": "stack buffer", "lines": [al]}, {"description": "allocate, use, free", "lines": [ma, fr]}],
              "witness": None, "static_evidence": None,
              "refutation": {"attempts": ["Is any heap block left unfreed? No: the only malloc is freed at the end."], "assumptions": []},
              "verdict": "SAFE", "cwe": "CWE-401", "confidence": 0.85,
              "length_independence": f"line {al} is stack memory; the malloc at line {ma} is freed at line {fr}"})
    return fn, code, d, "leak", "SAFE"


EXTRA = {"cmd_injection": [e4_cmd_safe], "path_traversal": [e5_path_vuln, e6_path_safe], "sqli": [e7_sqli_vuln, e8_sqli_safe],
         "format_string": [e9_fmt_vuln, e10_fmt_safe], "integer": [e11_int_vuln, e12_int_safe], "leak": [e13_leak_vuln, e14_leak_safe]}


def main():
    cat = sys.argv[1]
    if cat not in EXTRA:
        raise SystemExit(f"no extra exemplars defined for {cat}: the round uses results/imp_fewshot_exemplars.json")
    quick = json.load(open("results/imp_fewshot_exemplars.json"))
    out = list(quick["exemplars"])
    for build in EXTRA[cat]:
        fn, code, d, cls, lab = build()
        v = S.validate(d, code)
        if not (v["valid"] and v["verdict_final"] == v["verdict_raw"] == lab):
            raise SystemExit(f"EXEMPLAR {fn} INVALID: {v['errors']}")
        out.append({"source_file": fn, "label": lab, "class": cls, "user": numbered(code), "assistant": json.dumps(d, ensure_ascii=False), "code": code,
                    "validator": {"valid": v["valid"], "cwe_id": v.get("cwe_id"), "oracle": v.get("oracle")}})
    for e in quick["exemplars"]:      # the quick ones must still pass the CURRENT validator
        v = S.validate(json.loads(e["assistant"]), e["code"])
        if not (v["valid"] and v["verdict_final"] == e["label"]):
            raise SystemExit(f"QUICK EXEMPLAR {e['source_file']} no longer valid: {v['errors']}")
    path = f"results/imp_fewshot_exemplars_st_{cat}.json"
    json.dump({"exemplars": out, "category": cat,
               "source": quick["source"] + f"; addendum 3b adds {len(out) - len(quick['exemplars'])} templated exemplar(s) for {cat} from the same _02 files",
               "validated_with": "src/cyberdef/sc_cot.validate (current)"}, open(path, "w"), indent=1)
    print(path, [(o["source_file"][:48], o["label"], o["class"]) for o in out])


if __name__ == "__main__":
    main()
