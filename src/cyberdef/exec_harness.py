"""Stage D execution harness: compile + run a C program in a sandbox and report whether a SANITIZER fired.

Sandbox (per run): docker run --rm --network none --memory 1g --pids-limit 64 --user 65534:65534 --cap-drop ALL
--security-opt no-new-privileges, image gcc:13, 10 s timeout inside the container, work dir mounted from a fresh temp dir.
Compile: gcc -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined (compilation also happens INSIDE the sandbox).
A run "has a sanitizer report" only if stderr contains an AddressSanitizer/UndefinedBehaviorSanitizer report line; a plain
abort()/nonzero exit/timeout does NOT count. confirm(): vuln program reports AND safe counterpart (same input) does not.

Witness -> input mapping (pre-registered): witness dict keys "argv" (list) and "stdin" (str) are used as given; otherwise all
scalar witness values are joined with newlines as stdin."""
from __future__ import annotations
import os, re, shutil, subprocess, tempfile

IMAGE = os.environ.get("EXEC_IMAGE", "gcc:13")   # amendment: derived image with dev headers may be used; recorded in every result
SAN_RE = re.compile(r"ERROR: AddressSanitizer|runtime error:|ERROR: UndefinedBehaviorSanitizer|SUMMARY: (Address|Undefined)Sanitizer")
CAP = 20000


def witness_to_input(w):
    if not isinstance(w, dict):
        return [], ""
    argv = [str(a) for a in w["argv"]] if isinstance(w.get("argv"), list) else []
    if isinstance(w.get("stdin"), str):
        return argv, w["stdin"]
    vals = [str(v) for k, v in w.items() if k != "argv" and isinstance(v, (str, int, float))]
    return argv, "\n".join(vals)


_IMG_ID = None


def image_id():
    """image name + content digest, recorded in every result"""
    global _IMG_ID
    if _IMG_ID is None:
        r = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True)
        _IMG_ID = r.stdout.strip() or "unknown"
    return IMAGE + "@" + _IMG_ID


def link_libs(code):
    """-l flags implied by the includes (needed once dev headers are present in the image)."""
    m = [("sqlite3.h", "-lsqlite3"), ("openssl/", "-lssl -lcrypto"), ("curl/", "-lcurl"), ("mysql/", "-lmysqlclient"),
         ("mysql.h", "-lmysqlclient"), ("zlib.h", "-lz"), ("pthread.h", "-lpthread")]
    return " ".join(l for h, l in m if h in code)


def run_c(code, argv=(), stdin="", timeout=10):
    """returns dict(compiled, sanitizer, kind, timed_out, exit, stderr_tail)"""
    d = tempfile.mkdtemp(prefix="exh_")
    os.chmod(d, 0o777)
    try:
        open(f"{d}/p.c", "w").write(code)
        open(f"{d}/in.txt", "w").write(stdin)
        for f in ("p.c", "in.txt"):
            os.chmod(f"{d}/{f}", 0o644)
        args = " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)
        inner = ("cd /w && gcc -O0 -g -w -fsanitize=address,undefined -fno-sanitize-recover=undefined p.c -o p -lm " + link_libs(code) + " "
                 "2> cc.err || { echo __COMPILE_FAIL__ >&2; cat cc.err >&2; exit 97; }; "
                 f"ASAN_OPTIONS=detect_leaks=0 timeout {timeout} ./p {args} < in.txt > out.txt 2> run.err; echo $? > rc.txt")
        cmd = ["docker", "run", "--rm", "--network", "none", "--memory", "1g", "--pids-limit", "64",
               "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "-v", f"{d}:/w", "-e", "HOME=/tmp", "--entrypoint", "sh", IMAGE, "-c", inner]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        except subprocess.TimeoutExpired:
            subprocess.run("docker ps -q --filter ancestor=gcc:13 | xargs -r docker kill", shell=True)
            return dict(compiled=True, sanitizer=False, kind="harness_timeout", timed_out=True, exit=None, stderr_tail="")
        if r.returncode == 97 or "__COMPILE_FAIL__" in r.stderr:
            return dict(compiled=False, sanitizer=False, kind="compile_fail", timed_out=False, exit=97,
                        stderr_tail=r.stderr[-300:])
        rc = open(f"{d}/rc.txt").read().strip() if os.path.exists(f"{d}/rc.txt") else "?"
        err = open(f"{d}/run.err", errors="replace").read()[:CAP] if os.path.exists(f"{d}/run.err") else ""
        san = bool(SAN_RE.search(err))
        kind = "asan" if "AddressSanitizer" in err else "ubsan" if "runtime error:" in err else ("none")
        so = open(f"{d}/out.txt", errors="replace").read()[:CAP] if os.path.exists(f"{d}/out.txt") else ""
        return dict(compiled=True, sanitizer=san, kind=kind, timed_out=(rc == "124"), exit=int(rc) if rc.lstrip("-").isdigit() else None,
                    stderr_tail=err[-300:], stdout_tail=so[-300:], image=image_id())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def confirm(vuln_code, safe_code, argv=(), stdin=""):
    v = run_c(vuln_code, argv, stdin)
    s = run_c(safe_code, argv, stdin)
    return dict(confirmed=bool(v["sanitizer"] and s["compiled"] and not s["sanitizer"]), vuln=v, safe=s)


# ---------------- fail-first controls (used by acceptance/reasoning/check_D.py) ----------------
VULN = r'''#include <stdio.h>
#include <string.h>
int main(void){ char in[256]; char b[8]; if(!fgets(in,sizeof in,stdin)) return 0; strcpy(b,in); printf("%s\n",b); return 0; }'''
SAFE = r'''#include <stdio.h>
#include <string.h>
int main(void){ char in[256]; char b[8]; if(!fgets(in,sizeof in,stdin)) return 0; strncpy(b,in,sizeof b-1); b[7]=0; printf("%s\n",b); return 0; }'''
ABORT = '#include <stdlib.h>\nint main(void){ abort(); }'
LOOPNET = r'''#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
int main(void){ int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(80);
 inet_pton(AF_INET,"1.1.1.1",&a.sin_addr); int c=connect(s,(struct sockaddr*)&a,sizeof a); printf("connect=%d\n",c); fflush(stdout); for(;;){} }'''


NETONLY = LOOPNET.replace("for(;;){} }", "return 0; }")


def selftest(mode="real"):
    """mode: real | always_true | always_false (mutants must FAIL the acceptance)"""
    import time
    global run_c
    orig = run_c
    if mode == "always_true":
        run_c = lambda *a, **k: dict(compiled=True, sanitizer=True, kind="asan", timed_out=False, exit=1, stderr_tail="")
    elif mode == "always_false":
        run_c = lambda *a, **k: dict(compiled=True, sanitizer=False, kind="none", timed_out=False, exit=0, stderr_tail="")
    try:
        long_in, short_in = "A" * 100 + "\n", "hi\n"
        out = {}
        out["c1_vuln_long_confirmed"] = confirm(VULN, SAFE, [], long_in)["confirmed"]
        out["c2_vuln_short_not_confirmed"] = not confirm(VULN, SAFE, [], short_in)["confirmed"]
        out["c3_identical_programs_not_confirmed"] = not confirm(VULN, VULN, [], long_in)["confirmed"]
        a = run_c(ABORT)
        out["c4a_plain_abort_not_sanitizer"] = not a["sanitizer"]
        t0 = time.time(); n = run_c(LOOPNET, timeout=3); dt = time.time() - t0
        out["c4b_loop_killed_and_no_network"] = bool(n["timed_out"]) and dt < 60 and not n["sanitizer"]
        nn = run_c(NETONLY)
        out["c4c_network_blocked"] = "connect=-1" in nn.get("stdout_tail", "")
        return out
    finally:
        run_c = orig


if __name__ == "__main__":
    import json, sys
    print(json.dumps(selftest(sys.argv[1] if len(sys.argv) > 1 else "real")))
