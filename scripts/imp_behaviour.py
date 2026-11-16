"""Behaviour-oracle judge + runner (spec v2). Runs the PLAIN (non-sanitizer) build of a program under the LD_PRELOAD shim scripts/imp_shim.c with a per-run token T substituted for the literal
CANARY in the payload, then judges four oracles from the shim log and the program output. The oracle never writes a payload: it only judges the one it is given.
Pure python; used inside the sandbox container (cwd with imp_shim.so).
SQLi payload convention: CANARY must stand as a BARE token in the injected SQL (for example  x' OR CANARY=CANARY -- ); inside a quoted literal it is not syntax."""
import os, re, secrets, subprocess, tempfile

META = (";", "|", "&", "`", "$(", "\\n")        # '\n' = newline as escaped by the shim log
HEX = r"(?:0x[0-9a-f]+|\(nil\))"


def _lines(log, kinds):
    for l in log:
        k, _, t = l.partition("\t")
        if k in kinds:
            yield k, t


def judge_cmd(log, T):
    for k, t in _lines(log, ("SYSTEM", "POPEN", "EXECSH")):
        i = t.find(T)
        if i >= 0 and any(m in t[max(0, i - 40):i] for m in META):
            return True
    return False


def judge_fmt(out, T):
    return re.search(re.escape(T) + HEX + r"(?:[^0-9a-zA-Z(]{0,3}" + HEX + r"){1,}", out) is not None


def judge_path(log, T):
    for k, t in _lines(log, ("OPEN", "DIR", "STAT")):
        if T in t and re.search(r"(^|/)\.\.(/|$)", t):
            return True
    return False


def unquoted_segments(sql):
    segs, cur, q, i = [], [], None, 0
    while i < len(sql):
        ch = sql[i]
        if q:
            if ch == "\\" and i + 1 < len(sql):
                i += 2
                continue
            if ch == q:
                if i + 1 < len(sql) and sql[i + 1] == q:
                    i += 2
                    continue
                q = None
            i += 1
            continue
        if ch in ("'", '"'):
            segs.append("".join(cur)); cur = []; q = ch
        else:
            cur.append(ch)
        i += 1
    segs.append("".join(cur))
    return segs


def judge_sql(log, T):
    return any(any(T in s for s in unquoted_segments(t)) for _, t in _lines(log, ("SQL",)))


def run_behaviour(binary, payload, argv=(), timeout=3, shim="/w/imp_shim.so", env_extra=None, files=None):
    """payload: bytes fed on stdin (and, via the AFL argv shim inside the program, as argv). CANARY -> per-run token."""
    T = "CNRY" + secrets.token_hex(4)
    data = payload.replace(b"CANARY", T.encode())
    fd, logp = tempfile.mkstemp(prefix="impbeh_", suffix=".log")
    os.close(fd)
    env = dict(os.environ, LD_PRELOAD=shim, IMP_LOG=logp, IMP_CANARY=T)
    for k, v in (env_extra or {}).items():           # extra feeding channels (Juliet-specific feed: env ADD, file /tmp/file.txt); CANARY substituted the same way
        env[k] = v.replace("CANARY", T)
    for path, content in (files or {}).items():
        with open(path, "wb") as fh:
            fh.write(content.replace(b"CANARY", T.encode()))
    try:
        r = subprocess.run([binary] + list(argv), input=data, capture_output=True, timeout=timeout, env=env)
        out = (r.stdout + r.stderr).decode("utf8", "replace")
        to = False
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"") + (e.stderr or b"")).decode("utf8", "replace")
        to = True
    log = open(logp, errors="replace").read().splitlines()
    os.unlink(logp)
    return {"T": T, "log": log[:200], "out": out[:20000], "timed_out": to,
            "verdicts": {"cmd_injection": judge_cmd(log, T), "format_string": judge_fmt(out, T), "path_traversal": judge_path(log, T), "sqli": judge_sql(log, T)}}


def classes(res):
    return [("beh:" + k, True) for k, v in res["verdicts"].items() if v]
