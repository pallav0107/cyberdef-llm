"""In-container fail-first controls for the behaviour oracles (spec v2). Compiles the shim and control programs (plain gcc), runs each with its payload / benign input / shim disabled,
prints one JSON object {control: {...}}. Run via acceptance/improve/check_beh.py. env IMP_BEH_BROKEN=1 disables the judges (mutant)."""
import json, os, subprocess, sys

sys.path.insert(0, "/w")
import imp_behaviour as B

H = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <sqlite3.h>\n"
RD = 'char in[200]; if(!fgets(in,sizeof in,stdin)) return 0; in[strcspn(in,"\\n")]=0; '
P = {}
P["cmd_vuln"] = H + "int main(){char c[300]; " + RD + 'snprintf(c,sizeof c,"ls %s",in); system(c); return 0;}'
P["cmd_safe_exec"] = H + "int main(){" + RD + 'char*a[]={"ls",in,0}; execv("/bin/ls",a); return 0;}'
P["cmd_safe_validate"] = H + "int main(){char c[300]; " + RD + 'for(char*p=in;*p;p++) if(!((*p>=97&&*p<=122)||(*p>=48&&*p<=57))){puts("bad");return 1;} snprintf(c,sizeof c,"ls %s",in); system(c); return 0;}'
P["fmt_vuln"] = H + "int main(){" + RD + "printf(in); return 0;}"
P["fmt_safe"] = H + "int main(){" + RD + 'printf("%s",in); return 0;}'
P["path_vuln"] = H + "int main(){char p[300]; " + RD + 'snprintf(p,sizeof p,"/var/data/%s",in); FILE*f=fopen(p,"r"); if(f) fclose(f); return 0;}'
P["path_safe_reject"] = H + "int main(){char p[300]; " + RD + 'if(strstr(in,"..")){puts("no");return 1;} snprintf(p,sizeof p,"/var/data/%s",in); FILE*f=fopen(p,"r"); if(f) fclose(f); return 0;}'
P["path_safe_realpath"] = H + "#include <limits.h>\nint main(){char p[300],r[PATH_MAX]; " + RD + (
    'snprintf(p,sizeof p,"/var/data/%s",in); if(!realpath(p,r)){puts("no");return 1;} if(strncmp(r,"/var/data/",10)){puts("no");return 1;} FILE*f=fopen(r,"r"); if(f) fclose(f); return 0;}')
P["sql_vuln"] = H + "int main(){char q[400]; sqlite3*db; " + RD + (
    'snprintf(q,sizeof q,"SELECT * FROM u WHERE n=%c%s%c",39,in,39); sqlite3_open(":memory:",&db); sqlite3_exec(db,q,0,0,0); return 0;}')
P["sql_safe_bind"] = H + "int main(){sqlite3*db; sqlite3_stmt*s; " + RD + (
    'sqlite3_open(":memory:",&db); sqlite3_prepare_v2(db,"SELECT * FROM u WHERE n=?",-1,&s,0); sqlite3_bind_text(s,1,in,-1,SQLITE_STATIC); return 0;}')
P["sql_safe_escape"] = H + "int main(){char e[400],q[500]; sqlite3*db; int j=0; " + RD + (
    'for(char*p=in;*p&&j<390;p++){ if(*p==39) e[j++]=39; e[j++]=*p; } e[j]=0; snprintf(q,sizeof q,"SELECT * FROM u WHERE n=%c%s%c",39,e,39); sqlite3_open(":memory:",&db); sqlite3_exec(db,q,0,0,0); return 0;}')
PAY = {"cmd": b"x; echo CANARY\n", "fmt": b"CANARY%p.%p.%p.%p\n", "path": b"../../CANARY/x\n", "sql": b"x' OR CANARY=CANARY --\n"}
BENIGN = b"hello\n"
CASES = [("cmd_vuln", "cmd", "cmd_injection", True), ("cmd_safe_exec", "cmd", "cmd_injection", False), ("cmd_safe_validate", "cmd", "cmd_injection", False),
         ("fmt_vuln", "fmt", "format_string", True), ("fmt_safe", "fmt", "format_string", False),
         ("path_vuln", "path", "path_traversal", True), ("path_safe_reject", "path", "path_traversal", False), ("path_safe_realpath", "path", "path_traversal", False),
         ("sql_vuln", "sql", "sqli", True), ("sql_safe_bind", "sql", "sqli", False), ("sql_safe_escape", "sql", "sqli", False)]
subprocess.run("gcc -shared -fPIC -O1 /w/imp_shim.c -o /w/imp_shim.so -ldl", shell=True, check=True)
if os.environ.get("IMP_BEH_BROKEN") == "1":
    for n in ("judge_cmd", "judge_fmt", "judge_path", "judge_sql"):
        setattr(B, n, lambda *a, **k: False)
res = {}
for name, pk, oracle, want in CASES:
    open(f"/w/{name}.c", "w").write(P[name])
    cc = subprocess.run(f"gcc -w -O0 /w/{name}.c -o /w/{name} -lsqlite3 -lm", shell=True, capture_output=True, text=True)
    if cc.returncode:
        res[name] = {"error": cc.stderr[-300:], "oracle": oracle, "want": want}
        continue
    r = B.run_behaviour(f"/w/{name}", PAY[pk])
    rb = B.run_behaviour(f"/w/{name}", BENIGN)
    r_off = B.run_behaviour(f"/w/{name}", PAY[pk], shim="/nonexistent.so")      # shim disabled: nothing can be observed
    res[name] = {"oracle": oracle, "want": want, "got": r["verdicts"][oracle], "benign_got": rb["verdicts"][oracle], "shim_off_got": r_off["verdicts"][oracle],
                 "other_oracles_fired": [k for k, v in r["verdicts"].items() if v and k != oracle], "log_sample": r["log"][:3], "out_sample": r["out"][:80]}
print(json.dumps(res))
