"""Label-leak removal for synthetic / benchmark-annotated training functions (Juliet pools J and J2, synthetic SQLi pool Q).
Juliet source carries the answer in its comments (header 'CWE: 121 Stack Based Buffer Overflow', 'FLAW' / 'FIX' markers, BadSource/GoodSource) and in identifiers (CWE121_..._01_bad, goodG2B, badSink).
clean_code(): (1) removes ALL C/C++ comments (string- and char-literal aware), (2) renames every identifier that embeds a CWE id or the words bad/good (case-insensitive, as a word part) to neutral names fn_0, fn_1, ... consistently inside the text,
(3) collapses runs of blank lines. Semantics are unchanged (execution verification always uses the ORIGINAL files by base name). leak_hits() lists what is still visible, for the acceptance check."""
import re

_TOK = re.compile(r"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|(/\*.*?\*/)|(//[^\n]*)""", re.S)
LEAK = re.compile(r"\bFIX\b|CWE\s*-?\d|FLAW|POTENTIAL|BadSource|GoodSource|BadSink|GoodSink|(?<![A-Za-z])(?:bad|good)(?:G2B|B2G|Sink|Source|\b)|_(?:bad|good)\b|goodG2B|goodB2G", re.I)
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
# addendum 3i: _BADWORD is case-insensitive, so its "(?![a-z])" also rejects an uppercase letter and camelCase names such as
# badStatic, dataBadBuffer, helperBad survived cleaning. _CAMEL is case-SENSITIVE: bad/good as a camelCase word part.
_CAMEL = re.compile(r"(?:(?<![A-Za-z])(?:bad|good)|(?:Bad|Good))(?=[A-Z0-9_]|$)|(?<![A-Za-z])(?:BAD|GOOD)(?![A-Za-z])")
_BADWORD = re.compile(r"(?:CWE\d+)|(?:(?<![A-Za-z])(?:bad|good)(?![a-z]))|_(?:bad|good)|(?:bad|good)(?:G2B|B2G|Sink|Source)|(?:Bad|Good)(?:G2B|B2G|Sink|Source)", re.I)


def strip_comments(code):
    code = re.sub(r"/\*(?:(?!\*/).)*$", "", code, flags=re.S)       # unterminated /* at a truncation point
    def rep(m):
        if m.group(1):
            return m.group(1)
        return "\n" * m.group(0).count("\n") if m.group(2) else ""
    return _TOK.sub(rep, code)


def drop_omit_blocks_markers(code):
    """remove the Juliet '#ifndef OMITBAD / OMITGOOD ... #endif' guard lines (the guard NAME states the label); the guarded code is kept"""
    out, stack = [], []
    for ln in code.split("\n"):
        t = ln.strip()
        if re.match(r"#\s*(ifndef|ifdef)\s+OMIT(BAD|GOOD)", t):
            stack.append(True); continue
        if re.match(r"#\s*(if|ifdef|ifndef)", t):
            stack.append(False)
        elif re.match(r"#\s*endif", t):
            if stack and stack.pop():
                continue
        out.append(ln)
    return "\n".join(out)


def clean_code(code):
    s = drop_omit_blocks_markers(strip_comments(code))
    names = {}
    base = max([int(x) for x in re.findall(r"\bfn_(\d+)\b", s)] + [-1]) + 1   # re-cleaning already-cleaned text: never reuse an fn_N

    def ren(m):
        w = m.group(0)
        if re.fullmatch(r"fn_\d+", w):
            return w
        if _BADWORD.search(w) or _CAMEL.search(w):
            return names.setdefault(w, f"fn_{base + len(names)}")
        return w
    # rename identifiers outside string/char literals
    out, last = [], 0
    for m in re.finditer(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', s):
        lit = re.sub(r"(?i)(?<![A-Za-z])(bad|good)(?:g2b|b2g|sink|source)?(?![a-z])", "msg", m.group(0))      # label words inside string literals
        out.append(_IDENT.sub(ren, s[last:m.start()])); out.append(lit); last = m.end()
    out.append(_IDENT.sub(ren, s[last:]))
    s = "".join(out)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s


def leak_hits(code):
    """what a model could still read: any comment, or a CWE/bad/good marker in identifiers or strings"""
    hits = []
    if _TOK.search(code) and any(m.group(2) or m.group(3) for m in _TOK.finditer(code)):
        hits.append("comment")
    for m in LEAK.finditer(strip_comments(code)):
        hits.append(m.group(0))
    for m in _IDENT.finditer(strip_comments(code)):     # 3i: camelCase bad/good identifiers (badStatic, dataBadBuffer)
        if _CAMEL.search(m.group(0)) and not re.fullmatch(r"fn_\d+", m.group(0)):
            hits.append(m.group(0))
    return hits
