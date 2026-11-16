"""#4 sink-centred backward slices with tree-sitter-c. Run with ~/venvs/sast/bin/python (has tree_sitter + tree_sitter_c):
  ~/venvs/sast/bin/python scripts/imp_slice.py primevul_matched|vs_holdout_matched|vs_nolinux_matched
Writes results/imp_slice_S_in.json (original pairing, code = slice or full fallback) and results/imp_slice_S_stats.json.
Then: .venv/bin/python scripts/imp_rematch.py results/imp_slice_S_in.json imp_slice_S   (re-measures length, re-pairs on slice length)."""
import json, sys
import tree_sitter_c
from tree_sitter import Language, Parser

LANG = Language(tree_sitter_c.language())
PARSER = Parser(LANG)
SINK_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
              "printf", "fprintf", "vprintf", "vfprintf", "syslog", "free", "realloc", "malloc", "calloc", "alloca", "read", "recv",
              "fread", "gets", "scanf", "sscanf", "fscanf", "bcopy", "wcscpy", "wcscat", "kfree", "kmalloc", "kzalloc", "krealloc",
              "copy_from_user", "copy_to_user", "g_free", "g_malloc", "av_free", "av_malloc"}
SIMPLE = {"expression_statement", "declaration", "return_statement", "goto_statement", "break_statement", "continue_statement"}
CONTROL = {"if_statement", "while_statement", "for_statement", "switch_statement", "do_statement"}
MAX_DEPTH = 3


def walk(n):
    yield n
    for c in n.children:
        yield from walk(c)


def idents(n):
    return {x.text.decode("utf8", "replace") for x in walk(n) if x.type == "identifier"}


def callee(call):
    f = call.child_by_field_name("function")
    return f.text.decode("utf8", "replace").split("->")[-1].split(".")[-1] if f is not None else ""


def is_sink(st):
    for x in walk(st):
        if x.type == "call_expression" and callee(x) in SINK_FUNCS:
            return True
        if x.type == "assignment_expression":
            lhs = x.child_by_field_name("left")
            if lhs is not None and any(y.type in ("subscript_expression", "pointer_expression") for y in walk(lhs)):
                return True
        if x.type in ("subscript_expression", "pointer_expression"):
            if any(y.type == "binary_expression" and y.text[:1] != b"" and (b"+" in y.text or b"-" in y.text) for y in walk(x)):
                return True            # pointer / index arithmetic
    return False


def defined(st):
    """identifiers this simple statement defines or may define (decl, assignment lhs, ++/--, &out-params)."""
    out = set()
    for x in walk(st):
        if x.type == "init_declarator" or x.type == "declarator":
            d = x.child_by_field_name("declarator") or x
            out |= idents(d) if x.type == "init_declarator" else set()
        if x.type == "assignment_expression":
            l = x.child_by_field_name("left")
            if l is not None:
                out |= idents(l)
        if x.type == "update_expression":
            out |= idents(x)
        if x.type == "pointer_expression" and x.text.startswith(b"&"):
            out |= idents(x)
        if x.type == "declaration":
            out |= {y.text.decode() for y in x.children if y.type == "identifier"}
    if st.type == "declaration":
        for x in walk(st):
            if x.type in ("identifier",):
                out.add(x.text.decode("utf8", "replace"))
    return out


def collect(node, ancestors, simples, controls):
    for c in node.children:
        if c.type in SIMPLE:
            simples.append((c, list(ancestors)))
            continue
        if c.type in CONTROL:
            controls.append(c)
            collect(c, ancestors + [c], simples, controls)
        elif c.type in ("compound_statement", "else_clause", "case_statement", "labeled_statement", "default_statement"):
            collect(c, ancestors + ([c] if c.type != "compound_statement" else []), simples, controls)
        else:
            collect(c, ancestors, simples, controls)


def header_rows(c):
    """rows of a control statement's header (up to, not including, its body)."""
    start = c.start_point[0]
    body = c.child_by_field_name("body") or c.child_by_field_name("consequence")
    if body is not None and body.type == "compound_statement":
        return range(start, body.start_point[0] + 1)
    cond = c.child_by_field_name("condition")
    return range(start, (cond.end_point[0] if cond is not None else start) + 1)


def slice_function(code):
    """returns (status, text)."""
    tree = PARSER.parse(code.encode("utf8", "replace"))
    root = tree.root_node
    fn = next((x for x in walk(root) if x.type == "function_definition"), None)
    if fn is None:
        return "fallback_parse_failure", code
    err = sum(x.end_byte - x.start_byte for x in walk(root) if x.type == "ERROR")
    if err > 0.10 * max(1, len(code.encode("utf8", "replace"))):     # amendment 1: tolerate local errors (macros, truncation, C++)
        return "fallback_parse_failure", code
    body = fn.child_by_field_name("body")
    if body is None:
        return "fallback_parse_failure", code
    simples, controls = [], []
    collect(body, [], simples, controls)
    sinks = [i for i, (s, _) in enumerate(simples) if is_sink(s)]
    if not sinks:
        return "fallback_no_sink", code
    keep = set(sinks)
    vars_ = set()
    for i in sinks:
        vars_ |= idents(simples[i][0])
    for _ in range(MAX_DEPTH):
        grew = False
        for i, (s, _) in enumerate(simples):
            if i in keep:
                continue
            if defined(s) & vars_:
                keep.add(i); vars_ |= idents(s); grew = True
        if not grew:
            break
    for i, (s_, anc) in enumerate(simples):                         # amendment 2: early-exit statements guarded by a condition over sink variables
        if i not in keep and s_.type in ("return_statement", "goto_statement", "break_statement", "continue_statement"):
            for a_ in anc:
                if a_.type in CONTROL:
                    cond = a_.child_by_field_name("condition")
                    if cond is not None and idents(cond) & vars_:
                        keep.add(i); break
    rows = set(range(fn.start_point[0], body.start_point[0] + 1))     # signature through the opening brace
    lines = code.split("\n")
    rows.add(body.end_point[0])
    for i in keep:
        s, anc = simples[i]
        rows |= set(range(s.start_point[0], s.end_point[0] + 1))
        for a in anc:                                                   # guards on the path + structural lines
            if a.type in CONTROL:
                rows |= set(header_rows(a))
                rows.add(a.end_point[0])
            elif a.type in ("else_clause", "case_statement", "labeled_statement", "default_statement"):
                rows.add(a.start_point[0])
        # braces closing the compound blocks containing this statement
        p = s.parent
        while p is not None and p.id != body.id:
            if p.type == "compound_statement":
                rows.add(p.end_point[0]); rows.add(p.start_point[0])
            p = p.parent
    out, prev = [], None
    for r in sorted(x for x in rows if 0 <= x < len(lines)):
        if prev is not None and r > prev + 1:
            out.append("\t/* ... */")
        out.append(lines[r]); prev = r
    return "sliced", "\n".join(out)


def main():
    S = sys.argv[1]
    srcf = "results/lenmatched_eval_cases.json" if S == "primevul_matched" else f"results/{S}_cases.json"
    d = json.load(open(srcf))
    st_cnt = {"sliced": 0, "fallback_parse_failure": 0, "fallback_no_sink": 0}
    shrink = []
    out = []
    for c in d["cases"]:
        status, text = slice_function(c["code"])
        st_cnt[status] += 1
        if status == "sliced":
            shrink.append(len(text) / max(1, len(c["code"])))
        out.append(dict(c, code=text, slice_status=status, orig_code_chars=len(c["code"])))
    bad, _ = slice_function("int f( { ]]] ;;")
    stats = {"set": S, "source": srcf, "n": len(out), "n_sliced": st_cnt["sliced"], "n_fallback_parse_failure": st_cnt["fallback_parse_failure"],
             "n_fallback_no_sink": st_cnt["fallback_no_sink"], "mean_slice_over_full_chars": round(sum(shrink) / max(1, len(shrink)), 4),
             "selftest_malformed_is_parse_failure": bad == "fallback_parse_failure",
             "by_label": {lab: {k: sum(1 for c in out if c["label"] == lab and c["slice_status"] == k) for k in st_cnt} for lab in ("VULNERABLE", "SAFE")}}
    json.dump({"cases": out, "pool": d.get("pool"), "split": d.get("split"), "seed": d.get("seed"),
               "note": "sink-centred slices; fallback to the full function on parse failure / no sink"}, open(f"results/imp_slice_{S}_in.json", "w"))
    json.dump(stats, open(f"results/imp_slice_{S}_stats.json", "w"), indent=1)
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
