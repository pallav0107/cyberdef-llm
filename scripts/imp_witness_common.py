"""Shared pieces for witness-generation SFT and eval, so the training prompt is byte-identical to the eval prompt."""
from __future__ import annotations
import hashlib, json, re

SYSTEM_W = ("You are a defensive security analyst. Given a C program and the weakness class it is suspected of, write ONE "
            "concrete input that makes the weakness actually happen when the program runs, so a sandboxed sanitizer or "
            "behaviour monitor can confirm it. Where an injected shell command, path, SQL fragment or format string goes, "
            "use the literal token CANARY. Reply with a single JSON object and nothing else.")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def user_prompt(code, cwe, oracle):
    return (f"Weakness class: CWE-{cwe} (monitor: {oracle})\n"
            "Input channels: argv (list of strings), stdin (string), env (object), files (list of [path, content]).\n"
            'Answer format: {"argv": [], "stdin": "", "env": {}, "files": []}\n\n'
            f"Program:\n```c\n{code}\n```")


def fold_of(cid, k):
    """deterministic, label-blind fold assignment"""
    return int(hashlib.sha1(cid.encode()).hexdigest(), 16) % k


def witness_json(w):
    return json.dumps({"argv": w.get("argv", []), "stdin": w.get("stdin", ""), "env": w.get("env", {}),
                       "files": w.get("files", [])}, ensure_ascii=False)


def normalize(d):
    argv = d.get("argv") or []
    if isinstance(argv, str):
        argv = [argv]
    argv = [str(a) for a in argv][:8] if isinstance(argv, list) else []
    stdin = d.get("stdin") or ""
    if not isinstance(stdin, str):
        stdin = json.dumps(stdin)
    env = d.get("env") or {}
    env = {str(k): str(v) for k, v in env.items() if _ENV_KEY.match(str(k))} if isinstance(env, dict) else {}
    files = []
    for f in (d.get("files") or [])[:4] if isinstance(d.get("files"), list) else []:
        if isinstance(f, (list, tuple)) and len(f) == 2:
            files.append([str(f[0]), str(f[1])])
        elif isinstance(f, dict) and "path" in f:
            files.append([str(f["path"]), str(f.get("content", ""))])
    return {"argv": argv, "stdin": stdin[:20000], "env": env, "files": files}


def parse_witness(text):
    """First balanced {...} that parses as a JSON object with at least one channel key -> normalized witness; else None."""
    s = text or ""
    for st in [i for i, ch in enumerate(s) if ch == "{"]:
        depth, ins, esc = 0, False, False
        for j in range(st, len(s)):
            ch = s[j]
            if ins:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    ins = False
                continue
            if ch == '"':
                ins = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        d = json.loads(s[st:j + 1])
                    except Exception:
                        break
                    if isinstance(d, dict) and any(k in d for k in ("argv", "stdin", "env", "files")):
                        return normalize(d)
                    break
    return None
