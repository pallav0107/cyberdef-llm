"""Length edits for the trace bank C tag and the counterfactual arm: pad (dead-comment block ~50% longer), compress (comments + blank lines removed),
rename (declared locals/params -> v0, v1, ...). Semantics-preserving by construction; returns None when an edit is impossible (counted by the caller).
Needs tree_sitter + tree_sitter_c (box: ~/venvs/sast; Spark container: PYTHONPATH=/work/imp_pylib)."""
from __future__ import annotations
import re

_P = None


def _parser():
    global _P
    if _P is None:
        import tree_sitter_c
        from tree_sitter import Language, Parser
        _P = Parser(Language(tree_sitter_c.language()))
    return _P


def pad(code):
    line = "/* ---------- reviewed, no functional change ---------- */\n"
    k = max(1, round(0.5 * len(code) / len(line)))
    return line * k + code


def compress(code):
    c = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    c = re.sub(r"//[^\n]*", "", c)
    lines = [l.strip() for l in c.split("\n")]
    return "\n".join(l for l in lines if l)


def rename(code):
    b = code.encode("utf8", "replace")
    t = _parser().parse(b)
    root = t.root_node
    if root.has_error:
        return None
    names, protected = set(), set()

    def decl(n):
        if n.type == "identifier":
            names.add(n.text.decode())
        for ch in n.children:
            decl(ch)

    def walk(n):
        if n.type in ("parameter_declaration", "declaration"):
            for ch in n.children:
                if ch.type in ("pointer_declarator", "array_declarator", "identifier", "init_declarator", "parenthesized_declarator"):
                    decl(ch)
        if n.type == "call_expression":
            f = n.child_by_field_name("function")
            if f is not None and f.type == "identifier":
                protected.add(f.text.decode())
        for ch in n.children:
            walk(ch)

    walk(root)
    names = sorted(x for x in names if x not in protected)
    if not names:
        return None
    mp = {x: f"v{i}" for i, x in enumerate(names)}
    spans = []

    def w2(n):
        if n.type == "identifier" and n.text.decode() in mp:
            spans.append((n.start_byte, n.end_byte, mp[n.text.decode()]))
        for ch in n.children:
            w2(ch)

    w2(root)
    out, last = [], 0
    for s, e, new in sorted(spans):
        out.append(b[last:s].decode("utf8", "replace")); out.append(new); last = e
    out.append(b[last:].decode("utf8", "replace"))
    r = "".join(out)
    return None if _parser().parse(r.encode()).root_node.has_error else r


EDITS = {"pad": pad, "compress": compress, "rename": rename}


def apply_all(code):
    """{edit name: edited code} for the edits that are possible and actually change the text"""
    out = {}
    for k, f in EDITS.items():
        try:
            v = f(code)
        except Exception:
            v = None
        if v and v != code:
            out[k] = v
    return out
