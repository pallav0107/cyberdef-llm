"""Stage D0 (exploratory, no model): compile+run every CASTLE program with EMPTY input in the sandbox."""
import json, sys
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, "src")
from cyberdef import exec_harness as eh
cases = json.load(open("results/xdata_castle_cases.json"))["cases"]
def one(c):
    r = eh.run_c(c["code"], [], "", timeout=5)
    return {"id": c["id"], "label": c["label"], "truncated": c["truncated"], **{k: r[k] for k in ("compiled", "sanitizer", "kind", "timed_out", "exit")}}
with ThreadPoolExecutor(4) as ex:
    per = list(ex.map(one, cases))
def stats(rows):
    n = len(rows)
    return {"n": n, "compiled": sum(r["compiled"] for r in rows), "timed_out": sum(r["timed_out"] for r in rows),
            "ran_to_exit": sum(r["compiled"] and not r["timed_out"] for r in rows), "sanitizer_fired_empty_input": sum(r["sanitizer"] for r in rows),
            "truncated_source": sum(r["truncated"] for r in rows)}
res = {"all": stats(per), "VULNERABLE": stats([r for r in per if r["label"] == "VULNERABLE"]),
       "SAFE": stats([r for r in per if r["label"] == "SAFE"]), "per_case": per}
json.dump(res, open("results/reason_D0_castle_preflight.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "per_case"}))
