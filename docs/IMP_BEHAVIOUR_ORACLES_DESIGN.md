# Behaviour oracles for non-crash CASTLE classes: DESIGN ONLY (not built; waits for owner OK)

Written 2026-11-14. Scope: where the headroom is. In the pipeline grouping the empty-input floor catches 1 of 34 class-(c) (non-crash) and 6 of 32 class-(b) (crash-like-other) vulnerable programs.
In the oracle-spec grouping used by results/imp_castle_oracle_spec.json the counts of VULNERABLE programs per CWE are: 22:4, 78:3, 89:5, 134:3, 253:4, 327:5, 522:4, 628:4, 770:4, 798:4, 843:5 (class c = 45 programs);
617:3, 674:4, 835:4 (class b = 11 programs, already covered by the assert / ASan stack-overflow / cpu_hang oracles of the spec: their yield is measured by the oracle re-scoring, not here).

General shape of every oracle below: (1) a CANARY the oracle itself plants (a token or file the program cannot know); (2) an observation point that does not trust the program's own output (LD_PRELOAD interposer or ptrace/strace in the sandbox);
(3) a PAYLOAD that must come from the model witness or the fuzzer, never from the oracle (the oracle only judges); (4) a verdict "attacker data crossed a security boundary".
Fail-first rule for each: a hand-written vulnerable program and its safe twin; the oracle must confirm the first, must NOT confirm the twin, and must NOT confirm the first with the interposer disabled (proves the detector is the interposer) and with a benign input.
Everything runs in the existing sandbox (docker, --network none, caps dropped, non-root). Input feeding is the current harness (stdin + argv shim); programs that take payload from files/env are out of reach, as measured.

## 1. Command injection (CWE-78)
- Observation: LD_PRELOAD shim interposing system(), popen(), execl*/execv*/execve (and a seccomp-notify or `strace -f -e trace=execve` fallback for raw syscalls). Logs argv of every spawn.
- Canary/payload: payload carries `;echo $((1337*7))` (or a `$(...)` form). Verdict TRUE iff (a) a shell (`/bin/sh -c ...`) was spawned with a string containing the payload AND (b) the number 9359, which is NOT present in the input, appears in the program stdout or spawn output (the shell evaluated attacker data).
- Covers: CWE-78, 3 vulnerable programs (argv/stdin fed). Possibly CWE-88-like cases if the benchmark had them (it does not).
- False-positive risk on safe programs: low. Safe twins use execv without a shell or whitelist/escape the argument, so (a) or (b) fails. Residual risk: a safe program that legitimately spawns a shell with a fixed command (no payload in the string) is not confirmed because the payload test in (a) fails.
- Build effort: about half a day (shim + two controls).

## 2. Path traversal (CWE-22)
- Observation: LD_PRELOAD interposer on open/openat/fopen/freopen/opendir/stat logging the path string BEFORE the call; plus a canary file planted at a path outside every directory the program mentions (e.g. /tmp/imp_canary/secret.txt with a random token).
- Payload: `../../../../tmp/imp_canary/secret.txt` style strings (from witness/fuzzer). Verdict TRUE iff an open() succeeds on a path whose realpath is the canary file AND the token is read back into the program output or the path argument contains an attacker-controlled `..` segment that survives into the open() call.
- Covers: CWE-22, 4 vulnerable programs (all four read the path from argv per the channel table). CWE-73-like only if present.
- False-positive risk: low to medium. Safe twins canonicalise and prefix-check (realpath + startswith) or strip `..`; the open on the canary never happens. Risk: programs that open some other fixed path outside their mount (e.g. /etc/passwd read by design) would look like traversal if the attacker token is not required: the rule therefore requires the open path to CONTAIN the attacker payload text.
- Build effort: about one day (interposer, canary tree, two controls, handling of relative cwd).

## 3. SQL injection (CWE-89)
- Observation: LD_PRELOAD interposer on sqlite3_exec / sqlite3_prepare_v2 / sqlite3_prepare_v3 and on mysql_query / mysql_real_query (with a stub mysql_real_connect that returns a dummy handle, since no server exists in the sandbox). Logs the SQL TEXT given to the library.
- Payload carries a unique canary inside a quote-breaking sequence, e.g. `x' OR 'CNRY'='CNRY`. Verdict TRUE iff the canary token appears OUTSIDE a quoted literal in the logged SQL (tokeniser honours '...' and "..." and doubled quotes), i.e. attacker data became syntax.
- Covers: CWE-89, 5 vulnerable programs (3 use argv+stdin, 2 env+stdin per the channel table; env-fed ones are NOT reachable today, so 3 now, 5 after env feeding).
- False-positive risk: low. Parameterised queries log `?`/`:name` and never contain the canary; escaped/quoted data keeps the canary inside a literal. Risk: ORM-like wrappers or programs that build SQL from constants only.
- Build effort: 1.5 to 2 days (sqlite + mysql stubs, SQL tokeniser, controls).

## 4. Format-string payloads (CWE-134)
- ASan/UBSan do not flag a benign format-string misuse; `%n` or `%s` on a bad pointer crashes and is already caught by variant A.
- Observation: program stdout/stderr. Payload `%p.%p.%p.%p` (and `%x.%x`) with a canary prefix `CNRY`. Verdict TRUE iff the output contains `CNRY` followed by hex-pointer-looking text (`0x...` or hex words) that was not in the input (the format string was interpreted).
- Covers: CWE-134, 3 vulnerable programs (argv fed).
- False-positive risk: low. Safe twins print the input with "%s", so the output echoes `%p.%p...` literally.
- Build effort: about half a day (two controls; the only subtlety is programs that echo input through a logging wrapper).

## 5. Resource exhaustion (CWE-770), optional
- Observation: malloc/calloc/realloc interposer logging requested sizes plus RLIMIT_AS=1 GiB. Payload = a very large number/length. Verdict TRUE iff a request >= 256 MiB derived from input (monotone in the payload) is issued or the program dies on RLIMIT_AS.
- Covers: 4 vulnerable programs. False-positive risk medium: safe twins that clamp sizes return early; programs allocating large fixed buffers by design would need a baseline run with a benign input to subtract.
- Effort: about 1 day.

## Not coverable by an execution oracle (26 of 45 class-(c) vulnerable programs)
CWE-253 (return-value check, 4), 327 (weak crypto, 5), 522 (credential handling, 4), 628 (argument mismatch, 4), 798 (hard-coded credentials, 4), 843 (type confusion, 5). They are static or semantic properties; a static rule set or an LLM-as-judge with a stated bar would be needed, and neither is an execution witness.

## Summary table
| Oracle | CWEs | Vulnerable programs verifiable | FP risk on safe | Effort |
|---|---|---|---|---|
| command injection | 78 | 3 | low | 0.5 d |
| path traversal | 22 | 4 | low-medium | 1 d |
| SQL injection | 89 | 3 now (5 with env feeding) | low | 1.5-2 d |
| format string | 134 | 3 | low | 0.5 d |
| resource exhaustion (optional) | 770 | 4 | medium | 1 d |
| total (without 770 / with 770) | | 13 / 17 of 45 class-(c) vulnerable programs | | about 4 / 5 days |

Ceiling note: even with all of these, 26 class-(c) vulnerable programs remain outside execution-based verification; the largest remaining gains over the spec baseline are therefore about 13 to 17 programs of 99 (13% to 17% of vulnerable programs).
