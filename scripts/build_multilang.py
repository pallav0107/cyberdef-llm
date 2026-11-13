"""Build the multi-language (Java / Python / JS+TS) function-level data per EXPERIMENT_PLAN_MULTILANG.md.

Source: CrossVul v2.0 (Zenodo 10.5281/zenodo.4734050, CC BY 4.0): whole-file bad_/good_ pairs from
security-fix commits, with the commit URL. Functions are extracted with tree-sitter.
  vulnerable = function in the PRE-fix file whose (comment-stripped, whitespace-normalised) text is NOT
               present among the functions of the POST-fix file of the same pair (changed or deleted by the fix)
  safe       = function in the PRE-fix file whose text IS present unchanged in the post-fix file
               (same file, same commit, untouched by the fix)
Split by repository, seed 0, 80/10/10, global across languages. Dedup on benchdata.norm(code[:4000]).
Also builds owasp_java (test only) from a local clone of OWASP-Benchmark/BenchmarkJava.

Usage: build_multilang.py RAW_DIR OUT_DIR   (RAW_DIR has crossvul/x/dataset_final_sorted and owasp/)
"""
import collections, hashlib, json, os, random, re, sys
import importlib.metadata as im
import pyarrow as pa, pyarrow.parquet as pq
import tree_sitter as ts
import tree_sitter_java, tree_sitter_python, tree_sitter_javascript, tree_sitter_typescript

SEED = 0
MAXF = 20000          # max function chars kept
MINF, MINLINES = 40, 3
MAXLINE = 1000        # JS/TS files with a line longer than this are treated as minified and skipped
KEYLEN = 4000         # dedup key = norm(code[:KEYLEN]) (matches the model's input budget)
GROUP = {"java": "ml_java", "python": "ml_python", "js": "ml_js", "ts": "ml_js", "tsx": "ml_js"}
EXT = {".java": "java", ".py": "python", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
       ".ts": "ts", ".tsx": "tsx"}


def norm(code):
    return "".join((code or "").split())


LANGS = {"java": ts.Language(tree_sitter_java.language()),
         "python": ts.Language(tree_sitter_python.language()),
         "js": ts.Language(tree_sitter_javascript.language()),
         "ts": ts.Language(tree_sitter_typescript.language_typescript()),
         "tsx": ts.Language(tree_sitter_typescript.language_tsx())}
PARSERS = {k: ts.Parser(v) for k, v in LANGS.items()}
FUNC_VALUE = {"arrow_function", "function_expression", "function", "generator_function"}
STATS = collections.Counter()


def strip_comments(node, src):
    spans = []
    stack = [node]
    while stack:
        n = stack.pop()
        if "comment" in n.type:
            spans.append((n.start_byte, n.end_byte))
            continue
        stack.extend(n.children)
    spans.sort()
    out, pos = [], node.start_byte
    for a, b in spans:
        out.append(src[pos:a]); pos = b
    out.append(src[pos:node.end_byte])
    return b"".join(out).decode("utf8", "replace")


def name_of(n, src):
    nm = n.child_by_field_name("name") or n.child_by_field_name("left") or n.child_by_field_name("key")
    return src[nm.start_byte:nm.end_byte].decode("utf8", "replace") if nm else n.type


def extract(src, lang):
    """Return list of (name, text, comment_stripped_text) for outermost functions."""
    tree = PARSERS[lang].parse(src)
    out = []

    def keep(n, nm):
        # returns True if the node is consumed (do not descend); False -> descend (too large)
        txt = src[n.start_byte:n.end_byte].decode("utf8", "replace")
        if len(txt) > MAXF:
            return False
        if n.has_error:
            STATS["func_skipped_parse_error"] += 1
            return True
        if len(txt) < MINF or txt.count("\n") + 1 < MINLINES:
            STATS["func_skipped_tiny"] += 1
            return True
        out.append((nm, txt, strip_comments(n, src)))
        return True

    def visit(n):
        t = n.type
        cap = None
        if lang == "java":
            if t in ("method_declaration", "constructor_declaration") and n.child_by_field_name("body"):
                cap = n
        elif lang == "python":
            if t == "function_definition":
                cap = n
        else:
            if t in ("function_declaration", "generator_function_declaration", "method_definition"):
                cap = n
            elif t == "variable_declarator":
                v = n.child_by_field_name("value")
                if v is not None and v.type in FUNC_VALUE:
                    cap = n
            elif t == "assignment_expression":
                r = n.child_by_field_name("right")
                if r is not None and r.type in FUNC_VALUE:
                    cap = n
            elif t == "pair":
                v = n.child_by_field_name("value")
                if v is not None and v.type in FUNC_VALUE:
                    cap = n
        if cap is not None and keep(cap, name_of(cap, src)):
            return
        for c in n.children:
            visit(c)

    sys.setrecursionlimit(20000)
    visit(tree.root_node)
    return out


def repo_of(url):
    m = re.match(r"https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/", url)
    if m:
        return (m.group(1) + "/" + m.group(2)).lower()
    return url.split("/commit")[0].lower()


def build_crossvul(root):
    base = os.path.join(root, "crossvul", "x", "dataset_final_sorted")
    meta = json.load(open(os.path.join(base, "metadata.json")))
    where = {}
    for dp, _, fs in os.walk(base):
        for f in fs:
            if f.startswith(("bad_", "good_")):
                where.setdefault(f, []).append(os.path.join(dp, f))
    rows = []
    for e in meta:
        files = {f["database_name"]: f["original_name"] for f in e["files"]}
        for dn, orig in sorted(files.items()):
            if not dn.startswith("bad_"):
                continue
            gn = "good_" + dn[4:]
            lang = EXT.get(os.path.splitext(orig)[1].lower())
            if not lang or gn not in files:
                continue
            STATS["pairs_" + lang] += 1

            def pick(name):
                c = [p for p in where.get(name, []) if f"/{e['cwe']}/" in p.replace("\\", "/")]
                return (c or where.get(name, [None]))[0]
            pb, pg = pick(dn), pick(gn)
            if not pb or not pg:
                STATS["pair_missing_file"] += 1
                continue
            sb, sg = open(pb, "rb").read(), open(pg, "rb").read()
            if sb == sg:
                STATS["pair_identical"] += 1
                continue
            if lang in ("js", "ts", "tsx") and max((len(l) for l in sb.split(b"\n")), default=0) > MAXLINE:
                STATS["pair_skipped_minified"] += 1
                continue
            fb, fg = extract(sb, lang), extract(sg, lang)
            gkeys = {norm(x[2]) for x in fg}
            if not fb:
                STATS["pair_no_functions"] += 1
                continue
            for i, (nm, txt, stripped) in enumerate(fb):
                lab = 0 if norm(stripped) in gkeys else 1
                rows.append(dict(id=f"{lang}:{dn[4:]}:{i}", project=repo_of(e["url"]), commit_url=e["url"],
                                 cve=e["cve"], cwe=e["cwe"], path=orig, lang=lang, group=GROUP[lang],
                                 func_name=nm, code=txt, label=lab))
    return rows


def split_and_dedup(rows):
    log = {}
    byg = collections.defaultdict(list)
    for r in rows:
        byg[r["group"]].append(r)
    projects = sorted({r["project"] for r in rows})
    rng = random.Random(SEED)
    rng.shuffle(projects)
    n = len(projects)
    ntr, nva = int(round(n * 0.8)), int(round(n * 0.1))
    pmap = {p: ("train" if i < ntr else "validation" if i < ntr + nva else "test") for i, p in enumerate(projects)}
    log["projects_total"] = n
    log["projects_per_split"] = dict(collections.Counter(pmap.values()))
    out = {}
    for g, rs in sorted(byg.items()):
        L = {"rows_extracted": len(rs), "raw_vuln": sum(r["label"] for r in rs)}
        grp = collections.defaultdict(list)
        for r in rs:
            grp[norm(r["code"][:KEYLEN])].append(r)
        kept, conflict = [], 0
        for k, lst in grp.items():
            if len({r["label"] for r in lst}) > 1:
                conflict += len(lst)
                continue
            kept.append(lst)
        L["dropped_conflicting_label_dups"] = conflict
        order = {"test": 0, "validation": 1, "train": 2}
        final, cross, within = [], 0, 0
        for lst in kept:
            lst.sort(key=lambda r: r["id"])
            best = min(order[pmap[r["project"]]] for r in lst)
            seen_split = set()
            for r in lst:
                sp = pmap[r["project"]]
                if order[sp] != best:
                    cross += 1
                    continue
                if sp in seen_split:
                    within += 1
                    continue
                seen_split.add(sp)
                r["split"] = sp
                final.append(r)
        L["dropped_cross_split_dups"] = cross
        L["dropped_within_split_dups"] = within
        out[g] = final
        L["per_split"] = {s: dict(vuln=sum(1 for r in final if r["split"] == s and r["label"] == 1),
                                  safe=sum(1 for r in final if r["split"] == s and r["label"] == 0),
                                  projects=len({r["project"] for r in final if r["split"] == s}))
                          for s in ("train", "validation", "test")}
        L["per_lang"] = dict(collections.Counter(r["lang"] for r in final))
        log[g] = L
    return out, log


def write(rows, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = sorted(rows, key=lambda r: r["id"])
    cols = {k: [r[k] for r in rows] for k in rows[0]} if rows else {}
    pq.write_table(pa.table(cols), path, compression="zstd")


def build_owasp(root, out):
    d = os.path.join(root, "owasp")
    exp = {}
    for line in open(os.path.join(d, "expectedresults-1.2.csv"), encoding="utf8"):
        if line.startswith("#") or not line.strip():
            continue
        name, cat, real, cwe = line.strip().split(",")[:4]
        exp[name] = (cat, real.strip().lower() == "true", cwe)
    rows = []
    tdir = os.path.join(d, "src/main/java/org/owasp/benchmark/testcode")
    for name, (cat, real, cwe) in sorted(exp.items()):
        txt = open(os.path.join(tdir, name + ".java"), encoding="utf8").read()
        i = txt.find("package ")
        code = txt[i:] if txt.lstrip().startswith("/**") and i > 0 else txt   # strip GPL licence header
        rows.append(dict(id=name, category=cat, cwe=cwe, code=code, label=int(real)))
    write(rows, os.path.join(out, "owasp_java", "test.parquet"))
    return dict(tests=len(rows), vulnerable=sum(r["label"] for r in rows),
                safe=sum(1 - r["label"] for r in rows), categories=len({r["category"] for r in rows}),
                header_stripped=True)


def main(raw, out):
    rows = build_crossvul(raw)
    groups, log = split_and_dedup(rows)
    for g, rs in groups.items():
        for sp in ("train", "validation", "test"):
            write([{k: v for k, v in r.items() if k not in ("split", "group")} for r in rs if r["split"] == sp],
                  os.path.join(out, g, f"{sp}.parquet"))
    log["owasp_java"] = build_owasp(raw, out)
    log["extraction_stats"] = dict(STATS)
    log["params"] = dict(seed=SEED, max_function_chars=MAXF, min_function_chars=MINF, min_lines=MINLINES,
                         minified_line_len=MAXLINE, dedup_key=f"norm(code[:{KEYLEN}])", split="80/10/10 by project")
    log["versions"] = {m: im.version(m) for m in ("tree-sitter", "tree-sitter-java", "tree-sitter-python",
                                                  "tree-sitter-javascript", "tree-sitter-typescript", "pyarrow")}
    h = {}
    for dp, _, fs in os.walk(out):
        for f in sorted(fs):
            if f.endswith(".parquet"):
                p = os.path.join(dp, f)
                h[os.path.relpath(p, out).replace("\\", "/")] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    log["sha256"] = h
    json.dump(log, open(os.path.join(out, "manifest.json"), "w"), indent=1)
    print(json.dumps(log, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
