"""Multi-variant execution oracle per results/imp_castle_oracle_spec.json, implemented INDEPENDENTLY (own report parser written from the
spec text; only group_of from scripts/imp_oracle.py is shared). Variants: A (afl-clang-fast ASan+UBSan, assert, cpu_hang), A_leak (LSan,
same binary), B (clang -fsanitize=integer recover), C (clang TSan, separate container with seccomp=unconfined), D (gcc ASan+UBSan).
A program is CONFIRMED if ANY counted report fires under ANY variant. Sandbox per container: --network none, --memory 1g, --pids-limit 64,
uid 65534, --cap-drop ALL, no-new-privileges (C additionally seccomp=unconfined). Image = EXEC_IMAGE (default imp-castle-san:1)."""
from __future__ import annotations
import os, re, secrets, shlex, shutil, subprocess, sys, tempfile

IMAGE = os.environ.get("EXEC_IMAGE", "imp-castle-san:1")
_ID = None
MODE = {"v": "real"}          # selftest mutants: never | always
INC = "-I/AFLplusplus/utils/argv_fuzzing"


def image_id():
    global _ID
    if _ID is None:
        _ID = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True).stdout.strip()
    return IMAGE + "@" + _ID


def libs(code):
    m = [("sqlite3.h", "-lsqlite3"), ("openssl/", "-lssl -lcrypto"), ("curl/", "-lcurl"), ("mysql", "-lmysqlclient")]
    return "-lm -lpthread " + " ".join(l for h, l in m if h in code)


def _docker(d, script, extra=()):
    cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64", "--user", "65534:65534",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *extra, "-v", f"{d}:/w", "-e", "HOME=/tmp",
           "--entrypoint", "bash", IMAGE, "-c", script]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=240).returncode
    except subprocess.TimeoutExpired:
        subprocess.run("docker ps -q --filter ancestor=" + IMAGE + " | xargs -r docker kill", shell=True)
        return -9


def _run_snip(name, bin_, env, args):
    return (f'( export {env}; TIMEFORMAT="%U %S"; {{ time timeout 3 ./{bin_} {args} < in.txt > out.{name} 2> err.{name}; }} 2> t.{name}; '
            f'echo $? > rc.{name} )\n')


def _read(d, f):
    p = os.path.join(d, f)
    return open(p, errors="replace").read()[:60000] if os.path.exists(p) else ""


def parse(variant, err, rc, cpu):
    """counted report classes for one run, from the spec's confirmed_report_classes"""
    out = []
    if variant in ("A", "D"):
        m = re.search(r"ERROR: AddressSanitizer: ([A-Za-z0-9_\-]+)", err)
        if "attempting free on address which was not malloc" in err:
            out.append("asan:bad-free")
        elif m and m.group(1) not in ("allocation-size-too-big", "out-of-memory"):
            out.append("asan:" + m.group(1))
        if "requested allocation size" in err and "exceeds maximum" in err:
            pass                                                   # recorded, not counted
        if "runtime error:" in err:
            out.append("ubsan")
        if variant == "A":
            if re.search(r"Assertion .*failed", err):
                out.append("assert")
            if rc == 124 and cpu >= 2.0:
                out.append("cpu_hang")
    elif variant == "A_leak":
        if "LeakSanitizer: detected memory leaks" in err:
            out.append("lsan:leak")
    elif variant == "B":
        for t in re.findall(r"runtime error: ([^\n]+)", err):
            if "implicit conversion" in t:
                continue
            if "unsigned integer overflow" in t:
                out.append("int:unsigned-overflow")
            elif "signed integer overflow" in t:
                out.append("int:signed-overflow")
            elif "division by zero" in t:
                out.append("int:div0")
            elif "shift" in t:
                out.append("int:shift")
    elif variant == "C":
        if "WARNING: ThreadSanitizer: data race" in err:
            out.append("tsan:data-race")
    if MODE["v"] == "never":
        return []
    if MODE["v"] == "always":
        return ["forced"]
    return out


SHIM_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", "imp_shim.c")
META = [";", "|", "&", "`", "$(", "\\n"]          # shell metacharacters (an escaped newline in the shim log appears as backslash-n)


def _sql_bare(sql, t):
    """True if token t occurs in the SQL OUTSIDE a quoted literal (quote-aware: ' and \" with doubled-quote escapes)."""
    i, q = 0, None
    while i < len(sql):
        ch = sql[i]
        if q:
            if ch == q:
                if i + 1 < len(sql) and sql[i + 1] == q:
                    i += 2; continue
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif sql.startswith(t, i):
            return True
        i += 1
    return False


def judge_P(log, stdout, t):
    out = []
    for line in log.split("\n"):
        if "\t" not in line:
            continue
        kind, text = line.split("\t", 1)
        p = text.find(t)
        if p < 0:
            continue
        if kind in ("SYSTEM", "POPEN", "EXECSH"):
            window = text[max(0, p - 40):p]
            if any(m in window for m in META):
                out.append("beh:cmd_injection")
        elif kind in ("OPEN", "STAT", "DIR"):
            if ".." in text.split(t)[0].replace("\\", "/").split("/") or ".." in text.replace("\\", "/").split("/"):
                out.append("beh:path_traversal")
        elif kind == "SQL":
            if _sql_bare(text, t):
                out.append("beh:sqli")
    m = re.search(re.escape(t) + r"(?:[^0-9A-Za-z(]{0,2}(?:0x[0-9a-fA-F]+|\(nil\))){2,}", stdout)
    if m:
        out.append("beh:format_string")
    if MODE["v"] == "never":
        return []
    if MODE["v"] == "always":
        return ["forced"]
    return sorted(set(out))


def noncounted(variant, err):
    o = []
    if variant in ("A", "D"):
        m = re.search(r"ERROR: AddressSanitizer: ([A-Za-z0-9_\-]+)", err)
        if m and m.group(1) in ("allocation-size-too-big", "out-of-memory"):
            o.append("asan:" + m.group(1))
        if "requested allocation size" in err and "exceeds maximum" in err:
            o.append("asan:allocation-size-too-big")
    return o


ROUTING = {  # oracle -> predicate over counted+noncounted class strings, from oracle_routing in spec v2
    "asan": lambda c: c.startswith("asan:") and c not in ("asan:allocation-size-too-big", "asan:out-of-memory"),
    "ubsan": lambda c: c == "ubsan", "integer": lambda c: c.startswith("int:") or c == "ubsan",
    "lsan": lambda c: c == "lsan:leak", "tsan": lambda c: c == "tsan:data-race",
    "resource": lambda c: c in ("assert", "cpu_hang", "asan:stack-overflow", "asan:out-of-memory", "asan:allocation-size-too-big"),
    "cmd_injection": lambda c: c == "beh:cmd_injection", "path_traversal": lambda c: c == "beh:path_traversal",
    "sqli": lambda c: c == "beh:sqli", "format_string": lambda c: c == "beh:format_string", "none": lambda c: False}


def routed_confirmed(result, oracle):
    """confirmed by the CHOSEN oracle (spec v2 oracle_routing): any counted/recorded class of the routed predicate fired"""
    pred = ROUTING.get(oracle)
    if pred is None:
        return False
    if MODE["v"] == "always":
        return oracle != "none"
    if MODE["v"] == "never":
        return False
    return any(pred(c) for v in result["variants"].values() for c in (v["counted"] + v.get("noncounted", [])))


def analyze(code, argv=(), stdin="", env=None, files=None):
    """-> dict(variants={V: {compiled, counted:[...], rc, cpu}}, confirmed, classes)"""
    d = tempfile.mkdtemp(prefix="orc_"); os.chmod(d, 0o777)
    try:
        open(f"{d}/p.c", "w").write(code); open(f"{d}/in.txt", "w").write(stdin)
        for f in ("p.c", "in.txt"):
            os.chmod(f"{d}/{f}", 0o644)
        env = env or {}; files = files or []
        def header(sub):
            """export env vars and create files (inside the sandbox) with CANARY replaced by `sub` when given"""
            h = ""
            for k, v in env.items():
                v = v.replace("CANARY", sub) if sub else v
                h += f"export {k}={shlex.quote(v)}\n"
            for pth, content in files:
                content = content.replace("CANARY", sub) if sub else content
                h += (f"mkdir -p {shlex.quote(os.path.dirname(pth) or '.')} 2>/dev/null; printf '%s' {shlex.quote(content)} > {shlex.quote(pth)} 2>/dev/null"
                      f" || echo {shlex.quote(pth)} >> /w/filewrite.failed\n")
            return h
        L = libs(code); args = " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)
        has_can = ("CANARY" in stdin or any("CANARY" in a for a in argv) or any("CANARY" in v for v in env.values())
                   or any("CANARY" in c for _, c in files))
        T = "CNRY" + secrets.token_hex(4) if has_can else None
        if has_can:
            shutil.copy(SHIM_SRC, f"{d}/imp_shim.c"); os.chmod(f"{d}/imp_shim.c", 0o644)
            open(f"{d}/inP.txt", "w").write(stdin.replace("CANARY", T)); os.chmod(f"{d}/inP.txt", 0o644)
            argsP = " ".join("'" + a.replace("CANARY", T).replace("'", "'\\''") + "'" for a in argv)
        s1 = ("cd /w\n" + header(None) +
              f"AFL_USE_ASAN=1 AFL_USE_UBSAN=1 afl-clang-fast -w -O1 -g {INC} p.c -o pA {L} 2> ccA.err || echo 1 > ccfail.A\n"
              f"clang -w -O1 -g -fsanitize=integer -fsanitize-recover=all {INC} p.c -o pB {L} 2> ccB.err || echo 1 > ccfail.B\n"
              f"gcc -w -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined {INC} p.c -o pD {L} 2> ccD.err || echo 1 > ccfail.D\n")
        s1 += _run_snip("A", "pA", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=0:allocator_may_return_null=0 UBSAN_OPTIONS=print_stacktrace=0", args)
        s1 += _run_snip("Aleak", "pA", "ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:symbolize=0", args)
        s1 += _run_snip("B", "pB", "UBSAN_OPTIONS=print_stacktrace=0", args)
        s1 += _run_snip("D", "pD", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=0", args)
        if has_can:
            s1 += (header(T) + f"gcc -w -O0 -g {INC} p.c -o pP {L} 2> ccP.err || echo 1 > ccfail.P\n"
                   "gcc -shared -fPIC -O1 imp_shim.c -o imp_shim.so -ldl 2> ccS.err || echo 1 > ccfail.S\n"
                   f"( export IMP_LOG=/w/imp.log IMP_CANARY={T}; timeout 3 env LD_PRELOAD=/w/imp_shim.so ./pP {argsP} < inP.txt > out.P 2> err.P; echo $? > rc.P )\n")
        _docker(d, s1)
        s2 = ("cd /w\n" + header(None) + f"clang -w -O1 -g -fsanitize=thread {INC} p.c -o pC {L} 2> ccC.err || echo 1 > ccfail.C\n"
              + _run_snip("C", "pC", "TSAN_OPTIONS=exitcode=66:symbolize=0", args))
        _docker(d, s2, extra=["--security-opt", "seccomp=unconfined"])
        res = {}
        for v, name, ccf in (("A", "A", "A"), ("A_leak", "Aleak", "A"), ("B", "B", "B"), ("C", "C", "C"), ("D", "D", "D")):
            compiled = not os.path.exists(f"{d}/ccfail.{ccf}")
            rc = _read(d, f"rc.{name}").strip(); tt = re.findall(r"^(\d+\.\d+) (\d+\.\d+)$", _read(d, f"t.{name}"), re.M)
            cpu = float(tt[-1][0]) + float(tt[-1][1]) if tt else 0.0
            err = _read(d, f"err.{name}") if compiled else ""
            res[v] = {"compiled": compiled, "rc": int(rc) if rc.lstrip("-").isdigit() else None, "cpu": round(cpu, 2),
                      "counted": parse(v, err, int(rc) if rc.lstrip("-").isdigit() else None, cpu) if compiled else []}
        for v in ("A", "D"):
            res[v]["noncounted"] = noncounted(v, _read(d, "err.A" if v == "A" else "err.D")) if res[v]["compiled"] else []
        pc = not os.path.exists(f"{d}/ccfail.P") and not os.path.exists(f"{d}/ccfail.S")
        res["P"] = {"ran": has_can, "compiled": pc if has_can else None, "rc": None,
                    "counted": judge_P(_read(d, "imp.log"), _read(d, "out.P"), T) if (has_can and pc) else []}
        classes = sorted({c for v in res.values() for c in v["counted"]})
        return {"file_write_failed": os.path.exists(f"{d}/filewrite.failed"), "variants": res, "confirmed": bool(classes), "classes": classes, "any_compiled": any(bool(v["compiled"]) for v in res.values()),
                "image": image_id()}
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------- fail-first controls (acceptance/reasoning/check_D2.py)
OVER = ('#include <stdio.h>\n#include <string.h>\n'
        'int main(void){ char in[256], b[8]; if(!fgets(in,sizeof in,stdin)) return 0; strcpy(b,in); printf("%s\\n",b); return 0; }\n')
LEAK = '#include <stdlib.h>\nint main(void){ char *p = malloc(64); p[0] = 1; p = 0; return 0; }\n'
UWRAP = '#include <stdio.h>\nint main(void){ volatile unsigned x = 4294967295u; x = x + 1; printf("%u\\n", x); return 0; }\n'
RACE = ('#include <pthread.h>\n#include <stdio.h>\nint g = 0;\n'
        'void *f(void *a){ for (int i = 0; i < 200000; i++) g++; return 0; }\n'
        'int main(void){ pthread_t t1, t2; pthread_create(&t1, 0, f, 0); pthread_create(&t2, 0, f, 0); pthread_join(t1, 0); pthread_join(t2, 0); printf("%d\\n", g); return 0; }\n')
SPIN = 'int main(void){ volatile int x = 0; for(;;){ x++; } }\n'
ABORT = '#include <stdlib.h>\nint main(void){ abort(); }\n'
BENIGN = '#include <stdio.h>\nint main(void){ puts("hi"); return 0; }\n'
IMPLICIT = '#include <stdio.h>\nint main(void){ volatile int x = 300; unsigned char c = x; printf("%d\\n", c); return 0; }\n'


def selftest(mode):
    MODE["v"] = mode
    long_in = "A" * 100 + "\n"
    o = analyze(OVER, [], long_in); lk = analyze(LEAK); uw = analyze(UWRAP); rc = analyze(RACE); sp = analyze(SPIN)
    ab = analyze(ABORT); bn = analyze(BENIGN); im = analyze(IMPLICIT)
    cnt = lambda r, v: bool(r["variants"][v]["counted"])
    return {"overflow_confirmed_A_and_D": cnt(o, "A") and cnt(o, "D"),
            "leak_confirmed_only_via_A_leak": cnt(lk, "A_leak") and not cnt(lk, "A") and not cnt(lk, "D") and not cnt(lk, "B"),
            "unsigned_wrap_only_via_B": cnt(uw, "B") and not cnt(uw, "A") and not cnt(uw, "D"),
            "race_only_via_C": cnt(rc, "C") and not cnt(rc, "A") and not cnt(rc, "D"),
            "spin_is_cpu_hang": "cpu_hang" in sp["variants"]["A"]["counted"],
            "plain_abort_not_counted": not ab["confirmed"],
            "benign_nothing_fires": not bn["confirmed"],
            "implicit_conversion_not_counted": not cnt(im, "B") and not im["confirmed"]}


CMD_VULN = ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            'int main(void){ char in[200], cmd[400]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; snprintf(cmd,sizeof cmd,"echo %s",in); return system(cmd); }\n')
CMD_SAFE = ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <ctype.h>\n'
            'int main(void){ char in[200], o[200]; int k=0; if(!fgets(in,sizeof in,stdin)) return 0; for(char*p=in;*p;p++) if(isalnum((unsigned char)*p)) o[k++]=*p; o[k]=0;'
            ' char cmd[400]; snprintf(cmd,sizeof cmd,"echo %s",o); return system(cmd); }\n')
PATH_VULN = ('#include <stdio.h>\n#include <string.h>\n'
             'int main(void){ char in[200], path[400]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; snprintf(path,sizeof path,"/tmp/data/%s",in);'
             ' FILE*f=fopen(path,"r"); if(f) fclose(f); return 0; }\n')
PATH_SAFE = ('#include <stdio.h>\n#include <string.h>\n'
             'int main(void){ char in[200], path[400]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; char*q; while((q=strstr(in,".."))) memmove(q,q+2,strlen(q+2)+1);'
             ' snprintf(path,sizeof path,"/tmp/data/%s",in); FILE*f=fopen(path,"r"); if(f) fclose(f); return 0; }\n')
SQL_VULN = ('#include <stdio.h>\n#include <string.h>\n#include <sqlite3.h>\n'
            'int main(void){ char in[200], q[500]; sqlite3*db; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; sqlite3_open(":memory:",&db);'
            ' snprintf(q,sizeof q,"SELECT * FROM t WHERE name=\'%s\'",in); sqlite3_exec(db,q,0,0,0); sqlite3_close(db); return 0; }\n')
SQL_ESC = ('#include <stdio.h>\n#include <string.h>\n#include <sqlite3.h>\n'
           'int main(void){ char in[200], e[400], q[800]; int k=0; sqlite3*db; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0;'
           ' for(char*p=in;*p;p++){ if(*p==\'\\\'\') e[k++]=\'\\\'\'; e[k++]=*p; } e[k]=0; sqlite3_open(":memory:",&db);'
           ' snprintf(q,sizeof q,"SELECT * FROM t WHERE name=\'%s\'",e); sqlite3_exec(db,q,0,0,0); sqlite3_close(db); return 0; }\n')
SQL_PREP = ('#include <stdio.h>\n#include <string.h>\n#include <sqlite3.h>\n'
            'int main(void){ char in[200]; sqlite3*db; sqlite3_stmt*st; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; sqlite3_open(":memory:",&db);'
            ' sqlite3_prepare_v2(db,"SELECT * FROM t WHERE name=?",-1,&st,0); if(st){ sqlite3_bind_text(st,1,in,-1,SQLITE_TRANSIENT); sqlite3_finalize(st);} sqlite3_close(db); return 0; }\n')
FMT_VULN = ('#include <stdio.h>\n#include <string.h>\n'
            'int main(void){ char in[200]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; printf(in); printf("\\n"); return 0; }\n')
FMT_SAFE = ('#include <stdio.h>\n#include <string.h>\n'
            'int main(void){ char in[200]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; printf("%s",in); printf("\\n"); return 0; }\n')


ENV_CMD = ('#include <stdio.h>\n#include <stdlib.h>\n'
           'int main(void){ const char *q = getenv("QUERY"); if(!q) return 0; char cmd[400]; snprintf(cmd,sizeof cmd,"echo %s",q); return system(cmd); }\n')
FILE_CMD = ('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            'int main(void){ FILE*f=fopen("/tmp/payload.txt","r"); if(!f) return 0; char in[200]; if(!fgets(in,sizeof in,f)) return 0; fclose(f); in[strcspn(in,"\\n")]=0;'
            ' char cmd[400]; snprintf(cmd,sizeof cmd,"echo %s",in); return system(cmd); }\n')


def selftest2(mode):
    MODE["v"] = mode
    run = lambda code, stdin, argv=(): analyze(code, list(argv), stdin)
    cmd_in, path_in = "x; CANARY\n", "../../CANARY/x\n"
    sql_in, fmt_in = "x' OR CANARY=CANARY --\n", "CANARY%p.%p.%p.%p\n"
    ok = lambda r, o: routed_confirmed(r, o)
    r = {}
    r["cmd_vuln_confirmed"] = ok(run(CMD_VULN, cmd_in), "cmd_injection")
    r["cmd_safe_sanitised_not_confirmed"] = not ok(run(CMD_SAFE, cmd_in), "cmd_injection")
    r["path_vuln_confirmed"] = ok(run(PATH_VULN, path_in), "path_traversal")
    r["path_safe_dotdot_stripped_not_confirmed"] = not ok(run(PATH_SAFE, path_in), "path_traversal")
    r["sqli_vuln_confirmed"] = ok(run(SQL_VULN, sql_in), "sqli")
    r["sqli_safe_escaped_not_confirmed"] = not ok(run(SQL_ESC, sql_in), "sqli")
    r["sqli_safe_prepared_not_confirmed"] = not ok(run(SQL_PREP, sql_in), "sqli")
    r["fmt_vuln_confirmed"] = ok(run(FMT_VULN, fmt_in), "format_string")
    r["fmt_safe_literal_not_confirmed"] = not ok(run(FMT_SAFE, fmt_in), "format_string")
    b = [run(c, "hello\n") for c in (CMD_VULN, PATH_VULN, SQL_VULN, FMT_VULN)]
    r["benign_input_nothing_fires"] = all(not x["confirmed"] and not x["variants"]["P"]["ran"] for x in b)
    e = run(CMD_VULN, "")
    r["empty_input_variant_P_not_run"] = (not e["variants"]["P"]["ran"]) and not any(c.startswith("beh:") for c in e["classes"])
    w = run(CMD_VULN, cmd_in)
    r["wrong_oracle_routing_not_confirmed"] = not ok(w, "asan") and not ok(w, "sqli") and not ok(w, "none")
    from cyberdef.feed import parse_feed
    W = lambda how, vals=None: {"values": vals or {"QUERY": "x; CANARY"}, "how_to_feed": how}
    ev = analyze(ENV_CMD, [], "", env={"QUERY": "x; CANARY"})
    r["env_cmd_confirmed_via_env"] = ok(ev, "cmd_injection")
    r["env_cmd_not_confirmed_via_stdin"] = not ok(analyze(ENV_CMD, [], "x; CANARY\n"), "cmd_injection")
    fv = analyze(FILE_CMD, [], "", files=[("/tmp/payload.txt", "x; CANARY\n")])
    r["file_cmd_confirmed_via_file"] = ok(fv, "cmd_injection")
    chk = [("set environment variable QUERY to the payload", "env"), ("env QUERY=x; CANARY ./prog", "env"), ("getenv(\"QUERY\") reads it", "env"),
           ("write the payload to /tmp/payload.txt", "file"), ("pass as argv[1]", "argv"), ("command line argument", "argv"), ("send on stdin", "stdin"),
           ("standard input", "stdin"), ("somehow", "unparseable"), ("", "unparseable")]
    got = [parse_feed(W(h), "")["channel"] for h, _ in chk]
    r["feed_parser_channels_correct"] = got == [c for _, c in chk]
    u = parse_feed(W("somehow"), "")
    r["unparseable_feed_falls_back_to_stdin_and_is_counted"] = (u["channel"] == "unparseable" and not u["parsed"] and u["stdin"].strip() != "")
    if MODE["v"] == "never":
        r["feed_parser_channels_correct"] = False
    if MODE["v"] == "always":
        r["unparseable_feed_falls_back_to_stdin_and_is_counted"] = False
    return r


if __name__ == "__main__":
    import json
    if "--selftest2" in sys.argv:
        a = [x for x in sys.argv if x in ("never", "always")]
        print(json.dumps(selftest2(a[0] if a else "real"))); sys.exit(0)
    if "--selftest" in sys.argv:
        a = [x for x in sys.argv if x in ("never", "always")]
        print(json.dumps(selftest(a[0] if a else "real")))
