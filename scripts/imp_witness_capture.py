#!/usr/bin/env python3
"""Execution-signal training set, Phase A: capture oracle-CONFIRMED (program, witness) pairs on the 198 CASTLE programs
WITHOUT fuzzing.

Candidate generation is LABEL-BLIND: it uses only the program text, the CWE in the file name (CASTLE-<cwe>-<n>.c, present
for SAFE and VULNERABLE alike) and the static input-channel detector (results/imp_castle_input_channels.json):
  - injection CWEs (78/22/89/134): the CANARY templates from exec_oracle.selftest2, fed on every detected channel, then
    minimised to a single channel when possible;
  - sanitizer CWEs (asan/integer/lsan/tsan/resource): empty input, then deterministic boundary inputs (long strings,
    integer edges);
  - oracle 'none': no candidate (no runtime monitor can confirm it).
A witness is kept only if exec_oracle routes it to the CWE's oracle AND a second, independent analyze() run reproduces it.
Labels are used ONLY to assign the training role and to score, never to choose candidates.

Outputs: data/witness_train.jsonl (one row per program, with role), results/witness_capture_report.json.
Resumable cache: results/witness_capture_cache.jsonl (rows tagged with CACHE_V; other versions are ignored).
Usage (repo root):  nice -n 19 python3 scripts/imp_witness_capture.py [--jobs 6] [--smoke 2] [--limit N]
"""
from __future__ import annotations
import argparse, json, os, re, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, "src")
from cyberdef import exec_oracle as EO
from cyberdef.cwe_oracle import CWE_ORACLE, INJECTION_ORACLES
from cyberdef.imp_common import auroc, hm_se, r4

CACHE_V = 1
CASES_F = "results/xdata_castle_cases.json"
CHAN_F = "results/imp_castle_input_channels.json"
FLOOR_F = "results/imp_2o_floor_b60.json"
CACHE_F = "results/witness_capture_cache.jsonl"
OUT_F = "data/witness_train.jsonl"
REPORT_F = "results/witness_capture_report.json"

TEMPLATE = {"cmd_injection": "x; CANARY\n", "path_traversal": "../../CANARY/x\n",
            "sqli": "x' OR CANARY=CANARY --\n", "format_string": "CANARY%p.%p.%p.%p\n"}
ENV_RE = re.compile(r'getenv\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)')
OPEN_RE = re.compile(r'(?:fopen|freopen|open|ifstream)\s*\(\s*"([^"%\n]+)"')
LONG, HUGE = "A" * 600, "A" * 5000
INT_EDGES = ["-1", "2147483647", "4294967296", "-2147483648", "99999"]


def cwe_of(cid):
    return int(cid.split("-")[1])


def wit(argv=(), stdin="", env=None, files=None):
    return {"argv": list(argv), "stdin": stdin, "env": dict(env or {}), "files": [list(f) for f in (files or [])]}


def run(code, w, oracle):
    r = EO.analyze(code, argv=tuple(w["argv"]), stdin=w["stdin"], env=(w["env"] or None),
                   files=([tuple(f) for f in w["files"]] or None))
    return EO.routed_confirmed(r, oracle), r


def injection_candidates(code, oracle, ch):
    t = TEMPLATE[oracle]
    a = t.rstrip("\n")
    envs = {n: a for n in sorted(set(ENV_RE.findall(code)))} if "env" in ch else {}
    files = [(p, t) for p in sorted(set(OPEN_RE.findall(code)))[:3]] if "file" in ch else []
    combined = [("template_all", wit([a] if "argv" in ch else [], t, envs, files))]
    if "argv" in ch:
        combined.append(("template_all_argv2", wit([a, a], t, envs, files)))
    singles = [("template_stdin", wit((), t))]
    if "argv" in ch:
        singles += [("template_argv", wit([a], "")), ("template_argv2", wit([a, a], ""))]
    singles += [("template_env", wit((), "", {n: v})) for n, v in envs.items()]
    singles += [("template_file", wit((), "", None, [f])) for f in files]
    return combined, singles


def sanitizer_candidates(oracle, ch):
    out = [("empty", wit()), ("long_stdin", wit((), LONG + "\n")), ("huge_stdin", wit((), HUGE + "\n"))]
    if oracle in ("asan", "integer"):
        out += [("int_stdin", wit((), e + "\n")) for e in INT_EDGES]
    if "argv" in ch:
        out += [("long_argv", wit([LONG], "")), ("huge_argv", wit([HUGE], ""))]
        if oracle in ("asan", "integer"):
            out += [("int_argv", wit([e], "")) for e in INT_EDGES[:3]]
    return out


def one(c, ch_map):
    cid, code = c["id"], c["code"]
    cwe = cwe_of(cid)
    oracle = CWE_ORACLE.get(cwe, "none")
    ch = ch_map.get(cid, {}).get("channels") or ["stdin"]
    row = {"v": CACHE_V, "id": cid, "label": c["label"], "cwe": cwe, "oracle": oracle,
           "truncated": bool(c.get("truncated")), "channels": ch, "compiled": None,
           "confirmed": False, "reproduced": False, "witness": None, "source": None,
           "confirmed_classes": [], "any_class_hit": False, "n_tried": 0}
    if oracle == "none":
        row["source"] = "no_runtime_oracle"
        return row
    chosen = None

    def attempt(w):
        ok, r = run(code, w, oracle)
        row["n_tried"] += 1
        if row["compiled"] is None:
            row["compiled"] = bool(r.get("any_compiled"))
        row["any_class_hit"] = row["any_class_hit"] or bool(r.get("confirmed"))
        return ok, r

    if oracle in INJECTION_ORACLES:
        combined, singles = injection_candidates(code, oracle, ch)
        for src, w in combined:
            ok, r = attempt(w)
            if ok:
                chosen = (src, w, r)
                break
            if not row["compiled"]:
                break
        if chosen:                                   # minimise to a single channel if one suffices
            for src, w in singles:
                ok, r = attempt(w)
                if ok:
                    chosen = (src, w, r)
                    break
    else:
        for src, w in sanitizer_candidates(oracle, ch):
            ok, r = attempt(w)
            if ok:
                chosen = (src, w, r)
                break
            if not row["compiled"]:                  # does not compile: no input can help
                break
    if chosen:
        src, w, r = chosen
        ok2, r2 = attempt(w)                         # independent re-run: keep only reproducible witnesses
        row.update(confirmed=True, reproduced=bool(ok2), witness=w, source=src,
                   confirmed_classes=sorted(set(r.get("classes", []))))
    return row


def pick_smoke(cases, k):
    seen, out = {}, []
    for c in cases:                                  # label-blind: first k programs per oracle class, file order
        o = CWE_ORACLE.get(cwe_of(c["id"]), "none")
        if seen.get(o, 0) < k:
            seen[o] = seen.get(o, 0) + 1
            out.append(c)
    return out


def role(r):
    if r.get("error"):
        return "error"
    if r["label"] == "VULNERABLE":
        return "positive" if (r["confirmed"] and r["reproduced"]) else "vulnerable_no_witness"
    return "safe_false_positive" if r["confirmed"] else "negative"


def score_auc(rows, key):
    s = [1.0 if key(r) else 0.0 for r in rows]
    y = [1 if r["label"] == "VULNERABLE" else 0 for r in rows]
    a = auroc(s, y)
    n1 = sum(y)
    return {"auroc": r4(a), "se_hm": r4(hm_se(a, n1, len(y) - n1)) if a is not None else None,
            "tpr": r4(sum(1 for i in range(len(y)) if y[i] and s[i]) / max(1, n1)),
            "fpr": r4(sum(1 for i in range(len(y)) if not y[i] and s[i]) / max(1, len(y) - n1)), "n": len(y)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--smoke", type=int, default=0, help="only the first K programs per oracle class (label-blind)")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    cases = json.load(open(CASES_F))["cases"]
    if a.smoke:
        cases = pick_smoke(cases, a.smoke)
    if a.limit:
        cases = cases[:a.limit]
    ch_map = {p["id"]: p for p in json.load(open(CHAN_F))["per_case"]}

    done = {}
    if os.path.exists(CACHE_F):
        for line in open(CACHE_F):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("v") == CACHE_V and not r.get("error"):
                done[r["id"]] = r
    todo = [c for c in cases if c["id"] not in done]
    t0 = time.time()
    print(f"[capture] {len(cases)} programs, {len(cases) - len(todo)} cached, {len(todo)} to run, jobs={a.jobs}, "
          f"image={EO.image_id()}", flush=True)
    lock = threading.Lock()
    finished = [0]

    def work(c):
        try:
            r = one(c, ch_map)
        except Exception as e:                       # recorded, never silently dropped
            r = {"v": CACHE_V, "id": c["id"], "label": c["label"], "error": f"{type(e).__name__}: {e}"[:300]}
        with lock:
            with open(CACHE_F, "a") as fh:
                fh.write(json.dumps(r) + "\n")
            done[c["id"]] = r
            finished[0] += 1
            if finished[0] % 10 == 0 or finished[0] == len(todo):
                print(f"[capture] {finished[0]}/{len(todo)} run, {time.time() - t0:.0f}s", flush=True)
        return r

    with ThreadPoolExecutor(a.jobs) as ex:
        list(ex.map(work, todo))

    rows = [done[c["id"]] for c in cases]
    code_by = {c["id"]: c["code"] for c in cases}
    os.makedirs("data", exist_ok=True)
    out_f = OUT_F if not (a.smoke or a.limit) else OUT_F.replace(".jsonl", "_smoke.jsonl")
    with open(out_f, "w") as fh:
        for r in rows:
            o = dict(r)
            o["role"] = role(r)
            o["code"] = code_by[r["id"]]
            fh.write(json.dumps(o) + "\n")

    ok_rows = [r for r in rows if not r.get("error")]
    by_role, by_oracle = {}, {}
    for r in ok_rows:
        by_role[role(r)] = by_role.get(role(r), 0) + 1
        b = by_oracle.setdefault(r["oracle"], {"vuln": 0, "vuln_confirmed": 0, "safe": 0, "safe_confirmed": 0})
        k = "vuln" if r["label"] == "VULNERABLE" else "safe"
        b[k] += 1
        b[k + "_confirmed"] += int(bool(r["confirmed"] and r["reproduced"]))
    src_counts = {}
    for r in ok_rows:
        if r["confirmed"] and r["reproduced"]:
            src_counts[r["source"]] = src_counts.get(r["source"], 0) + 1

    floor = None
    if os.path.exists(FLOOR_F) and not (a.smoke or a.limit):
        fpc = {p["id"]: p for p in json.load(open(FLOOR_F))["per_case"]}
        frows = [{"label": r["label"], "hit": bool(fpc.get(r["id"], {}).get("confirmed"))} for r in ok_rows]
        floor = score_auc(frows, lambda r: r["hit"])

    report = {
        "experiment": "witness_capture_phaseA", "cache_v": CACHE_V, "image": EO.image_id(),
        "n": len(rows), "errors": len(rows) - len(ok_rows), "seconds": round(time.time() - t0, 1),
        "smoke": a.smoke, "limit": a.limit, "roles": by_role, "per_oracle": by_oracle,
        "positive_witness_sources": src_counts,
        "detector_deterministic_witness_routed": score_auc(ok_rows, lambda r: r["confirmed"] and r["reproduced"]),
        "detector_any_class_hit": score_auc(ok_rows, lambda r: r["any_class_hit"]),
        "floor_same_cases_confirmed": floor,
        "notes": [
            "Phase A only: no fuzzing. Candidates are label-blind but CWE-informed (CWE from the CASTLE file name, "
            "present for SAFE and VULNERABLE programs alike).",
            "A NO-MODEL baseline: if detector_deterministic_witness_routed beats the floor, it raises the bar a trained "
            "witness generator must beat; it is not a result for any model.",
            "oracle 'none' programs cannot be execution-confirmed and score 0 by construction.",
            "Training roles: positive = VULNERABLE + reproduced oracle-confirmed witness; negative = SAFE + nothing "
            "confirmed; safe_false_positive and vulnerable_no_witness are kept but must not be trained as positives."],
        "outputs": {"train": out_f, "cache": CACHE_F},
    }
    rep_f = REPORT_F if not (a.smoke or a.limit) else REPORT_F.replace(".json", "_smoke.json")
    json.dump(report, open(rep_f, "w"), indent=2)
    print(json.dumps({k: report[k] for k in ("n", "errors", "seconds", "roles", "positive_witness_sources",
                                             "detector_deterministic_witness_routed", "floor_same_cases_confirmed")},
                     indent=1), flush=True)


if __name__ == "__main__":
    main()
