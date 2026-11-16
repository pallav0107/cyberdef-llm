"""FIXED feed parser for SC-CoT witnesses (amendment 3b, written before any C-SC v2 witness is executed).
parse_feed(witness, code) -> {channel, env, files, argv, stdin, parsed}. First match wins:
 1 env   : how_to_feed mentions env / environment / getenv AND names a variable -> env[NAME] = payload
 2 file  : mentions file / path AND names a literal path -> files[path] = payload; argv=[path] if the program reads argv[1]
 3 argv  : mentions argv / command line / command-line / argument -> string values as arguments
 4 stdin : mentions stdin / standard input
 5 else  : UNPARSEABLE -> stdin fallback (counted, never dropped)
Payload: env/file use witness.values[NAME] when keyed by the variable name, else the first string value containing CANARY, else the first string value."""
import re

CHANNELS = ("stdin", "argv", "env", "file", "unparseable")
_ENV_NAME = [re.compile(r"\b([A-Z][A-Z0-9_]{1,})\s*="), re.compile(r"(?:variable|var|env(?:ironment)?)\s+[\"'`]?([A-Z][A-Z0-9_]{1,})"),
             re.compile(r"getenv\(\s*[\"']([A-Z][A-Z0-9_]*)")]
_PATH = re.compile(r"(/[\w.\-/]+|[\w\-]+\.(?:txt|dat|cfg|conf|ini|json|xml|log|csv|db))")


def _strings(vals):
    return [str(v) for v in vals.values() if isinstance(v, (str, int, float))] if isinstance(vals, dict) else []


def _payload(vals, name=None):
    if isinstance(vals, dict) and name and name in vals and vals[name] not in (None, ""):
        return str(vals[name])
    ss = _strings(vals)
    for x in ss:
        if "CANARY" in x:
            return x
    return ss[0] if ss else ""


def parse_feed(witness, code=""):
    vals = witness.get("values") if isinstance(witness, dict) else None
    how = str(witness.get("how_to_feed", "")) if isinstance(witness, dict) else ""
    low = how.lower()
    out = {"channel": "unparseable", "env": {}, "files": [], "argv": [], "stdin": "", "parsed": False, "file_path": None}
    if re.search(r"\benv(ironment)?\b", low) or "getenv" in low:
        names = []
        for rx in _ENV_NAME:
            names += rx.findall(how)
        names = [n for n in names if n not in ("ARGV", "STDIN", "NULL")]
        if names:
            out["channel"] = "env"; out["parsed"] = True
            for n in dict.fromkeys(names):
                out["env"][n] = _payload(vals, n)
            return out
    if re.search(r"\b(file|path|write|save|create|store|put|place)\b", low):
        m = _PATH.search(how)
        if m:
            path = m.group(1)
            out.update(channel="file", parsed=True, file_path=path, files=[(path, _payload(vals))])
            if "argv[1]" in code:
                out["argv"] = [path]
            return out
    if "argv" in low or "command line" in low or "command-line" in low or "argument" in low:
        out.update(channel="argv", parsed=True, argv=_strings(vals))
        return out
    if "stdin" in low or "standard input" in low:
        out.update(channel="stdin", parsed=True, stdin="\n".join(_strings(vals)) + "\n")
        return out
    out["stdin"] = "\n".join(_strings(vals)) + "\n"        # unparseable: fall back to stdin, counted by the caller
    return out
