"""Stage H step 2 (sast venv: needs tree_sitter + tree_sitter_c): build semantics-preserving length variants.
results/reason_H_bases.json -> results/reason_H_items.json. No dead-code insertion. Parse failures are skipped and counted."""
import json, re
import tree_sitter_c
from tree_sitter import Language, Parser

P = Parser(Language(tree_sitter_c.language()))
bases = json.load(open("results/reason_H_bases.json"))


def pad_comment(code, n):
    line = "/* ---------- reviewed, no functional change ---------- */\n"
    k = max(1, round(n / len(line)))
    return line * k + code


def pad_ws(code, n):
    out, added = [], 0
    for l in code.split("\n"):
        out.append(l)
        if added < n and l.strip():
            out.append("   "); added += 4
    extra = "\n" * max(0, n - added)
    return "\n".join(out) + extra


def compress(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)
    lines = [l.strip() for l in code.split("\n")]
    return "\n".join(l for l in lines if l)


def declared_names(code):
    b = code.encode()
    t = P.parse(b)
    if t.root_node.has_error:
        return None, None
    names = set()
    def walk(n):
        if n.type in ("parameter_declaration", "declaration"):
            def decl(m):
                if m.type == "identifier":
                    names.add(m.text.decode())
                for ch in m.children:
                    if n.type == "declaration" and ch.type == "init_declarator" or True:
                        decl(ch)
            for ch in n.children:
                if ch.type in ("pointer_declarator", "array_declarator", "identifier", "init_declarator", "function_declarator",
                               "parenthesized_declarator"):
                    # type_identifier / primitive types are different node types; only declarators carry `identifier`
                    decl(ch)
        for ch in n.children:
            walk(ch)
    walk(t.root_node)
    return t, names


def rename(code, mode):
    t, names = declared_names(code)
    if t is None or not names:
        return None
    b = code.encode()
    # never rename a name used as a called function or member
    protected = set()
    def walk(n):
        if n.type == "call_expression":
            f = n.child_by_field_name("function")
            if f is not None and f.type == "identifier":
                protected.add(f.text.decode())
        for ch in n.children:
            walk(ch)
    walk(t.root_node)
    names = sorted(x for x in names if x not in protected)
    if not names:
        return None
    mp = {x: (f"local_variable_value_{i}_for_processing" if mode == "long" else f"v{i}") for i, x in enumerate(names)}
    spans = []
    def w2(n):
        if n.type == "identifier" and n.text.decode() in mp:
            spans.append((n.start_byte, n.end_byte, mp[n.text.decode()]))
        for ch in n.children:
            w2(ch)
    w2(t.root_node)
    out, last = [], 0
    for s, e, new in sorted(spans):
        out.append(b[last:s].decode()); out.append(new); last = e
    out.append(b[last:].decode())
    r = "".join(out)
    return r if not P.parse(r.encode()).root_node.has_error else None


items, skipped = [], {}
for c in bases["length_bases"]:
    items.append(dict(key=f"len:{c['id']}:{c['label']}:orig", group="len", base=f"{c['id']}:{c['label']}", transform="orig",
                      label=c["label"], code=c["code"]))
    variants = {"pad_comment_500": pad_comment(c["code"], 500), "pad_comment_1500": pad_comment(c["code"], 1500),
                "pad_ws_1500": pad_ws(c["code"], 1500), "compress": compress(c["code"]),
                "rename_long": rename(c["code"], "long"), "rename_short": rename(c["code"], "short")}
    for k, v in variants.items():
        if v is None or v == c["code"]:
            skipped[k] = skipped.get(k, 0) + 1
            continue
        items.append(dict(key=f"len:{c['id']}:{c['label']}:{k}", group="len", base=f"{c['id']}:{c['label']}", transform=k,
                          label=c["label"], code=v))
for p in bases["pairs"]:
    items.append(dict(key=f"sem:{p['pair']}:v", group="sem", base=str(p["pair"]), transform="vuln", label="VULNERABLE", code=p["vuln_code"]))
    items.append(dict(key=f"sem:{p['pair']}:f", group="sem", base=str(p["pair"]), transform="fixed", label="SAFE", code=p["fixed_code"]))
json.dump(dict(items=items, skipped=skipped), open("results/reason_H_items.json", "w"))
print("[H variants] items", len(items), "skipped", skipped)
