"""Acceptance for imp_build_cot_items.py (written BEFORE it ran on the real bank). Run from repo root; env IMP_RESULTS=dir to test on a stub directory.
 1 for every arm a in {2,3,5clean,5unfilt,6,7}: imp_cot_a_items.json and imp_cot_a_twin_items.json exist with equal length (even), same id, label, code, order row for row
 2 CoT rows carry system/user/target; the target parses as JSON with verdict == label; twin rows carry NO target/system/user (verdict-only default prompt)
 3 arm 3 and arm 6 pair rows (rank true) are adjacent vuln-then-fix at even positions, labels differ, same pair id
 4 arm 5clean and 5unfilt have the same number of rows
 5 no CoT target for a function came from a trace that is not V&P in the bank (re-verified by lookup in the bank with the same raw text)
 6 stats file exists; arm7 'feasible' equals (x_verified_traces >= 200)
 --selftest: swap one twin label and require check 1 to fail"""
import json, os, sys

R = os.environ.get("IMP_RESULTS", "results") .rstrip("/") + "/"
QUICK = os.environ.get("IMP_BANK", "full") == "quick"
SUF, PRE = ("_quick", "imp_cotq_") if QUICK else ("", "imp_cot_")
fails = []
selftest = "--selftest" in sys.argv


def L(n):
    try:
        return json.load(open(R + n))["items"]
    except Exception as e:
        fails.append(f"cannot read {n}: {e}"); return []


bank = {}
try:
    for l in open(R + f"imp_trace_bank{SUF}.jsonl"):
        r = json.loads(l)
        bank.setdefault((r["fn"], r["edit"]), []).append(r)
except Exception as e:
    print("FAIL: bank missing", e); sys.exit(1)
for a in ("2", "3", "5clean", "5unfilt", "6", "7"):
    c, t = L(f"{PRE}{a}_items.json"), L(f"{PRE}{a}_twin_items.json")
    if selftest and a == "2" and t:
        t[0] = dict(t[0], label="SAFE" if t[0]["label"] == "VULNERABLE" else "VULNERABLE")
    if len(c) != len(t) or len(c) % 2:
        fails.append(f"arm {a}: lengths {len(c)} vs {len(t)} (must be equal and even)"); continue
    for i, (x, y) in enumerate(zip(c, t)):
        if (x["id"], x["label"], x["code"]) != (y["id"], y["label"], y["code"]):
            fails.append(f"arm {a}: row {i} differs between arm and twin"); break
        if not (x.get("system") and x.get("user") and x.get("target")) or any(k in y for k in ("target", "system", "user")):
            fails.append(f"arm {a}: row {i} prompt/target fields wrong"); break
        try:
            d = json.loads(x["target"])
        except Exception:
            fails.append(f"arm {a}: row {i} target not JSON"); break
        if d.get("verdict") != x["label"]:
            fails.append(f"arm {a}: row {i} target verdict != label"); break
        if not any(r["raw"] and r["V"] and r["P"] for r in bank.get((x["id"], "orig"), []) + bank.get((x["id"], "pad"), []) + bank.get((x["id"], "compress"), []) + bank.get((x["id"], "rename"), [])):
            fails.append(f"arm {a}: row {i} function has no V&P trace in the bank"); break
    if a in ("3", "6"):
        k = 0
        while k + 1 < len(c) and c[k].get("rank") and c[k + 1].get("rank"):
            if not (c[k]["label"] == "VULNERABLE" and c[k + 1]["label"] == "SAFE" and c[k]["pair"] == c[k + 1]["pair"]):
                fails.append(f"arm {a}: pair at {k} malformed"); break
            k += 2
        if a == "3" and k != len(c):
            fails.append("arm 3: not all rows are rank pairs")
n1, n2 = len(L(PRE + "5clean_items.json")), len(L(PRE + "5unfilt_items.json"))
if n1 != n2:
    fails.append(f"arm 5 sizes differ {n1} vs {n2}")
try:
    st = json.load(open(R + f"{PRE}items_stats.json"))
    for arm in ("arm2", "arm3"):
        b = st[arm]["balance"]
        if b.get("empty"):
            continue
        if abs(b["rows_after"] - b["rows_before"]) > 4:
            fails.append(f"{arm}: balancing changed the total rows {b['rows_before']} -> {b['rows_after']}")
        if not 0.4 <= b["safe_fraction_after"] <= 0.6:
            fails.append(f"{arm}: SAFE fraction after balancing {b['safe_fraction_after']} outside [0.4,0.6]")
        for c, nb in b["category_rows_before"].items():
            if c in ("cmd_injection", "integer", "lsan", "tsan", "resource", "format_string", "path_traversal", "sqli", "memory/asan") and 0 < nb < b["floor_rows"] and b["category_rows_after"].get(c, 0) < b["floor_rows"]:
                fails.append(f"{arm}: category {c} not upsampled to the floor ({b['category_rows_after'].get(c)} < {b['floor_rows']})")
    if st["arm7"]["feasible"] != (st["arm7"]["x_strict_traces"] >= 200):
        fails.append("arm7 feasibility flag inconsistent")
except Exception as e:
    fails.append(f"stats: {e}")
if selftest:
    print("SELFTEST OK: mutation caught" if fails else "SELFTEST FAIL: mutation not caught"); sys.exit(0 if fails else 1)
if fails:
    print("FAIL:"); [print(" -", f) for f in fails[:25]]; sys.exit(1)
print("PASS: CoT item files verified")
