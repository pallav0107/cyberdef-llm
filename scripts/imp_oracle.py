"""ONE shared oracle spec for CASTLE execution (EXPERIMENT_PLAN_IMPROVE.md, oracle amendment): build variants, which report classes count as "confirmed", and the CWE grouping used for reporting.
  python3 scripts/imp_oracle.py --write-spec     -> results/imp_castle_oracle_spec.json
Pure python; imported by the in-container inners and by the host driver. Labels never enter this module."""
import json, re, sys

SPEC_VERSION = 2          # v1 = sanitizer variants A/A_leak/B/C/D + cpu_hang/assert; v2 adds variant P (behaviour oracles) and the chosen-oracle routing map
IMAGE = "imp-castle-san:1"
LIBS = "-lm -lpthread -lsqlite3 -lmysqlclient -lssl -lcrypto -lcurl"
INC = "-I/AFLplusplus/utils/argv_fuzzing"
VARIANTS = {
    "A": {"compiler": "afl-clang-fast (clang 20)", "flags": f"AFL_USE_ASAN=1 AFL_USE_UBSAN=1 -w -O1 -g {INC} p.c -o p {LIBS}",
          "run_env": "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=0:allocator_may_return_null=0 UBSAN_OPTIONS=print_stacktrace=0", "role": "ASan + UBSan(trap-free, abort); the AFL++ fuzzing build; also detects bad-free (CWE-761), UAF, overflows, stack overflow (recursion), assert aborts (text)"},
    "A_leak": {"compiler": "same binary as A", "flags": "(no rebuild)", "run_env": "ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:symbolize=0 (LeakSanitizer at exit)", "role": "memory leaks (CWE-401)"},
    "B": {"compiler": "clang 20", "flags": f"-w -O1 -g -fsanitize=integer -fsanitize-recover=all {INC} p.c -o pB {LIBS}", "run_env": "UBSAN_OPTIONS=print_stacktrace=0",
          "role": "signed AND unsigned integer overflow/wrap, divide by zero, shifts (CWE-190/191/369); recover mode so that noisy implicit-conversion reports do not mask a later genuine overflow"},
    "C": {"compiler": "clang 20", "flags": f"-w -O1 -g -fsanitize=thread {INC} p.c -o pC {LIBS}", "run_env": "TSAN_OPTIONS=exitcode=66:symbolize=0",
          "role": "data races (CWE-362); cannot be combined with ASan. Runs in a SEPARATE container with seccomp=unconfined (TSan needs personality(ADDR_NO_RANDOMIZE), blocked by Docker default seccomp) but still --network none, --cap-drop ALL, no-new-privileges, non-root, mem/pids caps"},
    "P": {"compiler": "gcc 13.3 (plain, NO sanitizer)", "flags": f"-w -O0 -g {INC} p.c -o pP {LIBS}; shim: gcc -shared -fPIC -O1 imp_shim.c -o imp_shim.so -ldl",
          "run_env": "LD_PRELOAD=imp_shim.so IMP_LOG=<file> IMP_CANARY=<T>; stdin = corpus input with the literal CANARY replaced by T = CNRY+8 hex per run",
          "role": "behaviour oracles cmd_injection / format_string / path_traversal / sqli; the shim logs and NEVER executes a command, opens a path or runs a query containing T; replayed only on corpus inputs that contain CANARY (the model or fuzzer supplies the payload)"},
    "D": {"compiler": "gcc 13.3", "flags": f"-w -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined {INC} p.c -o pD {LIBS}", "run_env": "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=0",
          "role": "the toolchain of the pipeline empty-input floor (gcc ASan+UBSan, signed checks); keeps the floor comparable"},
}
# report classes that COUNT as "confirmed" (per variant); everything else is recorded but not counted
COUNTED = {
    "A": ["asan:* except allocation-size-too-big / out-of-memory", "ubsan:* (every 'runtime error:')", "assert (glibc 'Assertion ... failed' abort)", "cpu_hang (timeout >= 3 s AND user+sys CPU >= 2.0 s: spinning, not sleeping/waiting)"],
    "A_leak": ["lsan:leak (LeakSanitizer: detected memory leaks)"],
    "B": ["signed integer overflow", "unsigned integer overflow", "division by zero", "shift (base/exponent)"],
    "C": ["tsan:data-race (WARNING: ThreadSanitizer: data race)"],
    "D": ["asan:* except allocation-size-too-big / out-of-memory", "ubsan:* (every 'runtime error:')"],
    "P": ["beh:cmd_injection: a shell-spawning call (system/popen/exec of sh -c) receives a command string containing T within 40 chars after a shell metacharacter (; | & ` $( newline)",
          "beh:format_string: program output contains T immediately followed by >= 2 hex-pointer items (0x.. or (nil)) i.e. %p/%x directives were interpreted",
          "beh:path_traversal: an open/fopen/stat/opendir/access path contains T and a '..' component",
          "beh:sqli: the SQL text given to sqlite3_exec/prepare or mysql_query/real_query/stmt_prepare contains T OUTSIDE a quoted literal (quote-aware tokeniser); CANARY must be a bare token in the payload, e.g.  x' OR CANARY=CANARY --"],
}
# chosen-oracle routing (SC-CoT v2 `oracle` field -> which report classes can verify a witness); cwe_oracle.CWE_ORACLE of the pipeline fixes CWE -> oracle
ORACLE_ROUTING = {
    "asan": {"variants": ["A", "D"], "classes": ["asan:* except allocation-size-too-big / out-of-memory"]},
    "ubsan": {"variants": ["A", "D"], "classes": ["ubsan:*"]},
    "integer": {"variants": ["B", "A", "D"], "classes": ["int:signed-overflow", "int:unsigned-overflow", "int:div0", "int:shift", "ubsan:*"]},
    "lsan": {"variants": ["A_leak"], "classes": ["lsan:leak"]},
    "tsan": {"variants": ["C"], "classes": ["tsan:data-race"]},
    "resource": {"variants": ["A"], "classes": ["assert", "asan:stack-overflow (runaway recursion)", "cpu_hang", "asan:out-of-memory", "asan:allocation-size-too-big (memory-limit detectors)"]},
    "cmd_injection": {"variants": ["P"], "classes": ["beh:cmd_injection"]}, "path_traversal": {"variants": ["P"], "classes": ["beh:path_traversal"]},
    "sqli": {"variants": ["P"], "classes": ["beh:sqli"]}, "format_string": {"variants": ["P"], "classes": ["beh:format_string"]},
    "none": {"variants": [], "classes": [], "note": "no runtime monitor; the trace must carry static_evidence {line, snippet}"},
}
TOKEN_CONVENTION = {"literal": "CANARY", "where": "inside a string value of the witness (witness.values), at the point where the injected command / path / query fragment / format directive goes",
                    "substitution": "the harness replaces every CANARY in the stdin bytes and argv of the replayed input by a fresh per-run token T = CNRY + 8 hex digits; the model never sees T",
                    "sqli": "CANARY must be a BARE token in the injected SQL (e.g. ' OR CANARY=CANARY --); inside a quoted literal it is not syntax and does not confirm",
                    "format_string": "a payload of the form CANARY%p.%p.%p.%p (T followed by directives); the oracle never uses %n", "path_traversal": "e.g. ../../CANARY/x : the path must reach an open/stat call still containing a '..' component",
                    "cmd_injection": "e.g. x; echo CANARY : T must land in a shell command string after a metacharacter", "who_writes_the_payload": "the model or the fuzzer; the oracle only judges"}
NOT_COUNTED = {"A": ["asan:allocation-size-too-big", "asan:out-of-memory"], "B": ["implicit-conversion / implicit-*", "any other UB text"], "C": ["lock-order-inversion", "thread leak", "other TSan warnings"]}
# CWE grouping for reporting, fixed BEFORE re-scoring (coordinator decision): (a) sanitizer-detectable, (b) crash-like-other (assert / recursion / loop), (c) non-crash classes
GROUP_A = [119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 190, 191, 194, 369, 415, 416, 457, 476, 590, 680, 761, 787, 788, 822, 824, 825, 908, 401, 362]
GROUP_B = [617, 674, 835]
SPEC = {"version": SPEC_VERSION, "oracle_routing": ORACLE_ROUTING, "token_convention": TOKEN_CONVENTION, "image": IMAGE, "variants": VARIANTS, "confirmed_report_classes": COUNTED, "recorded_but_not_counted": NOT_COUNTED,
        "program_level_rule": "a program is CONFIRMED if ANY counted report fires on ANY corpus input (seeds + AFL++ queue/crash inputs, <= 40 inputs) under ANY variant; time-to-first = min over firing inputs of its discovery time (seeds t=0)",
        "replay": {"timeout_s": 3, "stdin": "the corpus file; argv shim AFL_INIT_ARGV fed from stdin as in the fuzz harness", "floor_arm": "single empty-stdin input, no fuzzing, same variants"},
        "cwe_groups": {"a_sanitizer_detectable": GROUP_A, "b_crash_like_other": GROUP_B, "c_non_crash": "every other CWE id in CASTLE"},
        "known_limits": ["file/env inputs are not fed (20% of vulnerable programs, only ~2 sanitizer-class)", "CWE-835 and CWE-617 rely on the cpu_hang and assert oracles", "unsigned-wrap reports in variant B can fire on safe programs: reported as false positives per group"]}


def group_of(cid):
    c = int(cid.split("-")[1])
    return "a" if c in GROUP_A else "b" if c in GROUP_B else "c"


BENIGN_ASAN = ("allocation-size-too-big", "out-of-memory")


def classify(variant, err, timed_out=False, cpu_s=0.0):
    """-> list of (class, counted) for one replay. err = stderr text."""
    import os
    if os.environ.get("IMP_ORACLE_BROKEN") == "1":      # mutation switch for the fail-first control only
        return []
    out = []
    if variant in ("A", "D"):
        if "attempting free on address which was not malloc" in err:
            out.append(("asan:bad-free", True))
        else:
            m = re.search(r"ERROR: AddressSanitizer: ([A-Za-z0-9_\-]+)", err)
            if m:
                k = m.group(1)
                out.append(("asan:" + k, k not in BENIGN_ASAN))
        if "requested allocation size" in err and "exceeds maximum" in err:
            out.append(("asan:allocation-size-too-big", False))
        for t in re.findall(r"runtime error: ([^\n]+)", err):
            k = ("signed-overflow" if "signed integer overflow" in t else "div0" if "division by zero" in t else "shift" if "shift" in t else
                 "bounds" if "out of bounds" in t else "null" if "null pointer" in t else "other")
            out.append(("ubsan:" + k, True))
        if variant == "A":
            if re.search(r"Assertion [`'\"].*failed", err):
                out.append(("assert", True))
            if timed_out and cpu_s >= 2.0:
                out.append(("cpu_hang", True))
    elif variant == "A_leak":
        if "LeakSanitizer: detected memory leaks" in err:
            out.append(("lsan:leak", True))
    elif variant == "B":
        for t in re.findall(r"runtime error: ([^\n]+)", err):
            if "unsigned integer overflow" in t:
                out.append(("int:unsigned-overflow", True))
            elif "signed integer overflow" in t:
                out.append(("int:signed-overflow", True))
            elif "division by zero" in t:
                out.append(("int:div0", True))
            elif "shift" in t:
                out.append(("int:shift", True))
            elif "implicit conversion" in t:
                out.append(("int:implicit-conversion", False))
            else:
                out.append(("int:other", False))
    elif variant == "C":
        for m in re.findall(r"WARNING: ThreadSanitizer: ([a-z\- ]+)", err):
            out.append(("tsan:" + m.strip().replace(" ", "-"), m.strip() == "data race"))
    return out


if __name__ == "__main__":
    if "--write-spec" in sys.argv:
        json.dump(SPEC, open("results/imp_castle_oracle_spec.json", "w"), indent=1)
        print("wrote results/imp_castle_oracle_spec.json")
