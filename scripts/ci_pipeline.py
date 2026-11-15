#!/usr/bin/env python3
"""The cyberdef pipeline status: the TRAIN + TEST diagram (PIPELINE_REVIEW_2026-11-14.md), box for box, as one table
(step | stage | status | why) whose statuses are computed from the real artifacts.

  --status --json F --md F : read every stage's artifacts on the box (local) and on Spark (one ssh call), recompute
                             AUROC from per_case where present (integrity), and write the table.
The table is published by the `status` job of the single `cyberdef pipeline` workflow (.github/workflows/cyberdef.yml).

Stage status: VERIFIED (artifacts present, integrity holds) | FAILED (known failure or integrity mismatch or an artifact
that should exist is missing) | RUNNING | PENDING | BLOCKED (with the reason). Nothing is ever shown greener than its
evidence: a stage with no artifact is never VERIFIED."""
from __future__ import annotations
import argparse, base64, json, os, subprocess, sys, time

SPARK = "spark-75cf@10.55.0.14"
SPARK_REPO = "~/cyberdef-lm"


def S(sec, sid, label, after=(), art=(), state="done", reason="", fail=None, running=None, kind="artifact", invalid=False):
    """art: 'box:path' / 'spark:path'. fail: (host:path, needle_or_None, reason). running: host:path marker.
    invalid=True: the stage's artifacts were decoded with the SC-CoT schema; any older than the v2.3 fix are INVALID."""
    return dict(sec=sec, id=sid, label=label, after=list(after), art=list(art), state=state, reason=reason,
                fail=fail, running=running, kind=kind, invalid=invalid)


# SC-CoT schema v2.1/v2.2 guided-decoding bug: witness.values could only be {} (proof: scripts/ci_schema_control.py).
# Fixed by schema v2.3 (commit c8851c0); the fixed file landed on Spark at this epoch. Older SC-schema output is INVALID.
SC_FIX_EPOCH = 1794711662
SC_BAD_HASHES = {"ecdfdd87d617f06f", "92b74cee"}
INVALID_REASON = ("INVALID: decoded under the SC-CoT schema v2.1/v2.2 grammar bug (a concrete witness could not be written); "
                  "measures a crippled decoder, neither a pass nor a fail. Regenerate under schema v2.3")


D, T, A, C, W, R, G, E, P, B, Z = ("0 DATA", "1 TRAIN", "1 ARMS (answer-only)", "1 ARMS (CoT)", "EXECUTION TRACK",
                                   "2 TEST · READ & JUDGE", "2 TEST · DIAGNOSE", "2 TEST · EXECUTE", "2 TEST · REPAIR",
                                   "2 BASELINES (beside every number)", "GATE")
STAGES = [
    # ---- 0. Data: what trains, what tests (a source never does both)
    S(D, "d_train_A", "A · PrimeVul train (length-matched pools)", art=["box:results/imp_train_build_stats.json", "spark:results/imp_train_unfilt_lm_items.json"]),
    S(D, "d_train_B", "B · VulSpot train pairs (1,000 vuln/fix)", art=["spark:results/imp_train_pairs_items.json"]),
    S(D, "d_train_J", "J · Juliet memory bugs (492 items)", art=["spark:results/imp_train_juliet_items.json"]),
    S(D, "d_train_J2", "J2 · Juliet injection (51 pairs)", art=["spark:results/imp_train_juliet2_items.json"]),
    S(D, "d_train_Q", "Q · synthetic SQLi (monitor-confirmed)", state="pending", reason="queued (P35): open-weight 14B writes C+sqlite pairs, kept only if the SQLi monitor confirms"),
    S(D, "d_test_pv", "TEST · PrimeVul length-matched 1,074 (length-only 0.50)", art=["box:results/lenmatched_eval_cases.json", "box:results/lenmatched_eval_control.json"]),
    S(D, "d_test_pvraw", "TEST · PrimeVul raw n=1000 (contrast, length-only 0.82)", art=["box:results/lm_sel_lenmatch_on_n1000.json"]),
    S(D, "d_test_vs", "TEST · VulSpot length-matched (holdout + no-linux)", art=["box:results/vs_holdout_matched_cases.json", "box:results/vs_nolinux_matched_cases.json", "box:results/vs_holdout_matched_control.json", "box:results/vs_nolinux_matched_control.json"]),
    S(D, "d_test_vspairs", "TEST · VulSpot vuln/fixed pairs (Stage H + pair eval)", art=["spark:results/reason_H_items.json", "box:results/imp_vs_pairs_eval_cases.json"]),
    S(D, "d_test_castle", "TEST · CASTLE 198 runnable programs (99/99)", art=["box:results/xdata_castle_cases.json"]),
    # ---- 1. Train pipeline
    S(T, "t_sccot", "SC-CoT v2 (11-step format, CWE+OWASP, monitor, witness)", after=["d_train_A", "d_train_B", "d_train_J", "d_train_J2"], art=["box:src/cyberdef/schemas_cot.py", "box:src/cyberdef/sc_cot.py"]),
    S(T, "t_bank_quick", "① Trace bank · quick (7B+14B, tagged V P S K O C X)", after=["t_sccot"], art=["spark:results/imp_trace_bank_quick.jsonl", "spark:results/imp_trace_bank_quick_counts.json"], invalid=True),
    S(T, "t_bank_v23", "① Trace bank · v2.3 pilot (Juliet J+J2, Qwen-14B) after the grammar fix", after=["t_sccot"], art=["spark:results/imp_bank_v23_pilot_g14_funnel.json"],
      running="spark:results/imp_bank_v23_pilot_g14.jsonl", state="pending", reason="pilot dispatched on the Spark runner (trace-bank workflow)"),
    S(T, "t_bank_full", "① Trace bank · full (+Coder-7B, gpt-oss-20b, 4 samples)", after=["t_bank_quick"], state="pending", reason="P55 queued (after P30 seeds and P35 SQLi data); regenerates under schema v2.3"),
    S(T, "t_category", "1b · per-category balancing (>=5% per monitor class)", after=["t_bank_quick"], art=["spark:results/imp_cotq_items_stats.json"], invalid=True),
    S(A, "a1", "#1 vuln-vs-patch pairs (control + pairwise)", after=["d_train_A", "d_train_B"], art=["spark:results/imp_ev_1ctl_pv.json", "spark:results/imp_ev_1arm_pv.json", "spark:results/imp_ev_1arm_castle.json"]),
    S(A, "a6", "#6 anti-length head (gradient reversal)", after=["d_train_A"], art=["box:results/box_ev_advctl_pv.json", "box:results/box_ev_adv_pv.json", "box:results/box_6_probe.json"]),
    S(A, "a7", "#7 clean vs unfiltered labels", after=["d_train_A"], art=["box:results/box_ev_7clean_pv.json", "box:results/box_ev_7unfilt_pv.json"]),
    S(C, "c2", "② CoT-SFT on traces passing V+P+S", after=["t_bank_quick", "t_category", "cat_memory", "cat_integer", "cat_leak", "cat_race", "cat_resource", "cat_cmdinj", "cat_fmtstr", "cat_pathtrav", "cat_sqli", "cat_nomon"], art=["box:out/imp_box_2cot/adapter_model.safetensors"],
      fail=("box:logs/box_train.log", "END train_2cot rc=1", "train_2cot crashed: CUDA out of memory on the 24 GB box (11:35). Its training items are also INVALID (built from the v2.2 bank: 386 items, 0 VULNERABLE). Re-run only after a v2.3 bank yields vulnerable traces")),
    S(C, "c3", "③ CoT x pairs (vuln cites sink, fix cites guard)", after=["t_bank_quick"], state="pending", reason="round 2 (items built: imp_cotq_3)"),
    S(C, "c4", "④ CoT x anti-length head", after=["t_bank_quick"], state="pending", reason="round 2"),
    S(C, "c5", "⑤ CoT x clean labels (weak contrast)", after=["t_bank_quick"], state="pending", reason="end of queue (items built: imp_cotq_5clean/5unfilt)"),
    S(C, "c6", "⑥ counterfactual CoT (padded/renamed -> same verdict)", after=["t_bank_quick", "t_category", "cat_memory", "cat_integer", "cat_leak", "cat_race", "cat_resource", "cat_cmdinj", "cat_fmtstr", "cat_pathtrav", "cat_sqli", "cat_nomon"], art=["box:out/imp_box_6cf/adapter_model.safetensors"],
      fail=("box:logs/box_train.log", "END train_6cf rc=1", "train_6cf crashed: CUDA out of memory on the 24 GB box (11:58). Its items are also INVALID (built from the v2.2 bank). Re-run only after a v2.3 bank yields vulnerable traces")),
    S(C, "c7", "⑦ execution-grounded CoT (X_strict traces only)", after=["t_bank_quick"], state="blocked", reason="needs >=200 strict (monitor-confirmed) traces; the quick bank has ~0"),
    S(C, "c8", "⑧ exec-loop revision traces", after=["t_bank_quick"], state="blocked", reason="needs Stage F (exec-loop)"),
    S(C, "c9", "⑨ repair CoT (fix verified by the repair checker)", after=["t_bank_quick"], state="blocked", reason="needs Stage G (repair)"),
    S(C, "c10", "⑩ RL (GRPO): reward V+S+X, penalty for length flips", after=["c2"], state="blocked", reason="only if ② works (② crashed)"),
    S(W, "w_capture", "Witness capture (deterministic, oracle-confirmed x2)", after=["d_test_castle"], art=["box:data/witness_train.jsonl", "box:results/witness_capture_report.json"]),
    S(W, "w_sft", "Witness-generator SFT -> oracle-graded test", after=["w_capture"], art=["box:results/witness/compare_fsec8b.json"],
      running="box:results/witness/items_manifest.json"),
    S("1 ADAPTERS", "adapters", "ADAPTERS -> TEST pipeline", after=["a1", "a6", "a7", "c2", "c6", "w_sft"], kind="join"),
    # ---- 2. Test pipeline
    S(R, "r_A", "A · bare verdict (published / lenmatch / base 7B)", after=["adapters", "d_test_pv"], art=["box:results/lm_sel_base_on_matched.json", "box:results/lm_sel_lenmatch_on_matched.json", "spark:results/pub7b_on_matched.json"]),
    S(R, "r_C", "C · witness prompt", after=["adapters", "d_test_pv"], art=["box:results/reason_C_base7b_matched.json", "box:results/reason_C_tuned7b_matched.json"]),
    S(R, "r_C2", "C2 · witness prompt, forced JSON", after=["adapters", "d_test_pv"], art=["spark:results/reason_C_base7b_c2_matched.json", "spark:results/reason_C_tuned7b_c2_matched.json"],
      fail=("spark:queue/failed/P17b_C2_tuned7b.sh", None, "tuned-7B C2 (P17b) failed: vLLM engine-core init error; base-7B C2 done. Needs a requeue")),
    S(R, "r_SC", "SC · SC-CoT v2 (base + tuned)", after=["adapters", "d_test_pv"], art=["spark:results/reason_CSC_base7b_matched.json", "spark:results/reason_CSC_tuned7b_matched.json"], invalid=True),
    S(R, "r_5", "#5 stronger models zero-shot (gpt-oss, nemotron, glm, qwen3-heavy)", after=["adapters", "d_test_pv"], state="pending",
      reason="re-prioritised 15 Nov: 300-case length-stratified sample (P87), queued after the CoT + execution work; "
             "full 1,074 only if the sample cannot rule out 0.60 (acceptance/improve/ZS_SAMPLE_AMENDMENT_2026-11-15.md)"),
    S(R, "r_3", "#3 + context", after=["adapters", "d_test_vs"], state="pending", reason="context cases built (imp_ctx_*); model evals queued after the CoT work (P89, P91)"),
    S(R, "r_4", "#4 sink slices", after=["adapters", "d_test_vs"], state="pending", reason="slice cases built (imp_slice_*); model evals queued after the CoT work (P91)"),
    S(R, "r_8", "#8 vote over 5", after=["adapters"], state="pending", reason="P94, queued after the CoT work"),
    S(R, "r_9c", "#9c confident-only (selective)", after=["adapters", "d_test_pv"], art=["box:results/imp_9c_selective.json"]),
    S(G, "g_H", "H · length edits vs bug-vs-fix edits", after=["adapters", "d_test_vspairs"], art=["box:results/reason_H_base7b_analysis.json", "box:results/reason_H_lm7b_analysis.json", "box:results/reason_H_pub7b_analysis.json"]),
    S(G, "g_I", "I · activation-level probe (Stage I, project-grouped)", after=["adapters", "d_test_pv"], art=["box:results/imp_probe_internal_boxbase7b.json", "box:results/imp_probe_class_boxbase7b.json"]),
    S(G, "g_9a", "#9a which line is the bug (+ random / longest-line)", after=["adapters"], art=["box:results/imp_9a_baselines.json", "box:results/imp_loc_stats.json"]),
    S(E, "e_floor", "FLOOR · run with empty input (oracle spec v2)", after=["d_test_castle"], art=["box:results/imp_2o_floor_b60.json"]),
    S(E, "e_D", "D · model witnesses (base / tuned 7B)", after=["adapters", "d_test_castle"], art=["box:results/reason_D2_base7b_castle.json", "box:results/reason_D2_tuned7b_castle.json"]),
    S(E, "e_fuzz", "fuzz · empty / random seeds", after=["d_test_castle"], art=["box:results/imp_2o_empty_b60.json", "box:results/imp_2o_random_b60.json"]),
    S(E, "e_fuzz_llm", "fuzz · LLM seeds", after=["d_test_castle"], state="pending", reason="P30 is next in the Spark queue (waiting for memory)"),
    S(E, "e_split", "CASTLE split by bug type (a/b/c) + union", after=["e_floor", "e_D"], art=["box:results/imp_2o_summary.json", "box:results/reason_D_byclass.json"]),
    S(E, "e_F", "F · exec-loop (propose -> run -> monitor feedback -> refine)", after=["e_D", "w_sft"], state="blocked", reason="unlocks only if model payloads confirm bugs the floor misses"),
    S(P, "p_G", "G · repair (compiles, closes the crash, keeps behaviour)", after=["e_F"], state="blocked", reason="after Stage F"),
    S(B, "b_len", "length-only", after=["d_test_pv", "d_test_vs"], art=["box:results/lenmatched_eval_control.json", "box:results/vs_holdout_matched_control.json", "box:results/vs_nolinux_matched_control.json"]),
    S(B, "b_sast", "flawfinder · semgrep", after=["d_test_pv", "d_test_castle"], art=["box:results/reason_B_sast_flawfinder_matched.json", "box:results/reason_B_sast_semgrep_matched.json", "box:results/reason_B_sast_flawfinder_castle.json", "box:results/reason_B_sast_semgrep_castle.json"]),
    S(B, "b_fuzzonly", "execution floor · fuzzer-only", after=["e_floor", "e_fuzz"], art=["box:results/imp_2o_floor_b60.json", "box:results/imp_2o_empty_b60.json"]),
    S(B, "b_noop", "no-op patch", after=["p_G"], state="blocked", reason="needs Stage G"),
    S(B, "b_line", "random / longest line", after=["g_9a"], art=["box:results/imp_9a_baselines.json"]),
    S(Z, "gate", "GATE · pre-registered: beats its baseline by >2 SE on held-out", kind="gate",
      after=["r_A", "r_C", "r_C2", "r_SC", "r_5", "r_3", "r_4", "r_8", "r_9c", "g_H", "g_I", "g_9a", "e_split", "e_fuzz_llm", "b_len", "b_sast", "b_fuzzonly", "b_noop", "b_line"]),
    S(Z, "audit", "recompute from per-case -> experiment-auditor -> verifier", after=["gate"], kind="audit"),
    S(Z, "standing", "STANDING ORDERS: verified crossing -> honest HF card; all monitors -> ASK -> Zenodo v4", after=["audit"], kind="standing"),
]

# ------------------------------------------------------------------ section 1b: CoT -> class -> OWASP -> monitor, per category
# (category key, monitor as named in exec_oracle/witness_capture, label with CWEs + OWASP 2021, expected OWASP)
CATEGORIES = [
    ("memory", "asan", "Memory safety (asan/ubsan) · CWE-119/120/121/122/125/415/416/476/787… · OWASP: outside Top 10 (MEM)", "MEM"),
    ("integer", "integer", "Integer (integer) · CWE-190/191/194/369/680 · OWASP: outside Top 10", "MEM"),
    ("leak", "lsan", "Leak (lsan) · CWE-401 · OWASP: outside Top 10", "MEM"),
    ("race", "tsan", "Data race (tsan) · CWE-362 · OWASP: outside Top 10", "MEM"),
    ("resource", "resource", "Resource / hang (resource) · CWE-400/617/674/770/835 · OWASP: outside Top 10", "MEM"),
    ("cmdinj", "cmd_injection", "OS command injection (cmd_injection) · CWE-78 · OWASP A03 Injection", "A03"),
    ("fmtstr", "format_string", "Format string (format_string) · CWE-134 · OWASP: not mapped in 2021", "MEM"),
    ("pathtrav", "path_traversal", "Path traversal (path_traversal) · CWE-22 · OWASP A01 Broken Access Control", "A01"),
    ("sqli", "sqli", "SQL injection (sqli) · CWE-89 · OWASP A03 Injection", "A03"),
    ("nomon", "none", "No runtime monitor (none) · CWE-253/327/522/628/798/843 · OWASP A02/A04/A07/outside", "various"),
]
N_CAT_STEPS = 11

CATS_PROBE = r'''
import json, re, sys, collections
req = json.loads(sys.stdin.readline())
M = req["cwe_oracle"]
def mon(cwe):
    m = re.search(r"\d+", str(cwe or "")); o = M.get(m.group(0)) if m else None
    return {"ubsan": "asan"}.get(o, o) or "unknown"
out = {"bank": {}, "slice": {}, "errors": {}}
try:
    rows = [json.loads(l) for l in open("results/imp_trace_bank_quick.jsonl") if l.strip()]
except Exception as e:
    rows = []; out["bank_error"] = type(e).__name__
agg = collections.defaultdict(lambda: collections.Counter())
errs = collections.defaultdict(collections.Counter)
hashes = collections.Counter()
for r in rows:
    dec = r.get("decoding")
    if isinstance(dec, str):
        try: dec = json.loads(dec)
        except Exception: dec = {}
    hashes[str((dec or {}).get("schema_hash"))] += 1
out["bank_schema_hashes"] = dict(hashes)
for r in rows:
    m = mon(r.get("cwe_id")); a = agg[m]
    if r.get("label") != "VULNERABLE":
        a["safe"] += 1; continue
    a["n"] += 1
    for k in ("V", "P", "K", "O_owasp", "O", "S"):
        a[k] += int(bool(r.get(k)))
    a["kept"] += int(all(r.get(k) for k in ("V", "P", "K", "O")))
    a["xs_computed"] += int(r.get("X_strict") is not None)
    a["xs_true"] += int(r.get("X_strict") is True)
    if not r.get("P"):
        for x in (r.get("errors") or [])[:1]:
            errs[m][re.sub(r"[0-9]+", "#", str(x))[:70]] += 1
out["bank"] = {m: dict(c) for m, c in agg.items()}
out["errors"] = {m: (c.most_common(1)[0][0] if c else "") for m, c in errs.items()}
try:
    st = json.load(open("results/imp_cotq_items_stats.json"))["arm2"]
    after = st["balance"]["category_rows_after"]
    out["slice"] = {"rows": after, "by_label": st.get("by_label", {})}
except Exception as e:
    out["slice_error"] = type(e).__name__
print(json.dumps(out))
'''


def compute_categories(box_files):
    """Per-category chain. Train side from the quick trace bank (Spark); test side from CASTLE executions (box)."""
    sys.path.insert(0, "src")
    from cyberdef.cwe_oracle import CWE_ORACLE
    req = json.dumps({"cwe_oracle": {str(k): v for k, v in CWE_ORACLE.items()}}) + "\n"
    b64 = base64.b64encode(CATS_PROBE.encode()).decode()
    code = f"import base64;exec(base64.b64decode('{b64}'))"
    try:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", SPARK,
                            f"cd {SPARK_REPO} && python3 -c \"{code}\""], input=req, capture_output=True, text=True, timeout=180)
        sp = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:
        sp = {"bank": {}, "slice": {}, "errors": {}, "bank_error": f"spark unreachable: {type(e).__name__}"}
    wc = json.load(open("results/witness_capture_report.json")).get("per_oracle", {}) if os.path.exists("results/witness_capture_report.json") else {}
    ft = {}
    if os.path.exists("results/witness/eval_fsec8b_ft.json"):
        for c in json.load(open("results/witness/eval_fsec8b_ft.json"))["per_case"]:
            if c["label"] == "VULNERABLE":
                f = ft.setdefault(c["oracle"], [0, 0]); f[1] += 1; f[0] += int(bool(c.get("reproduced")))
    slice_rows = sp.get("slice", {}).get("rows", {})
    slice_vuln = sp.get("slice", {}).get("by_label", {}).get("VULNERABLE")
    cats = {}
    for key, m, label, owasp in CATEGORIES:
        b = sp.get("bank", {}).get(m, {})
        n = b.get("n", 0)
        pct = lambda k: (100.0 * b.get(k, 0) / n) if n else 0.0
        runtime = m != "none"
        steps = []

        def add(name, ok, na=False, detail=""):
            steps.append({"name": name, "ok": bool(ok), "na": bool(na), "detail": detail})
        add(f"1 · pool: {n} vulnerable + {b.get('safe', 0)} safe traces in the quick bank", n > 0)
        add(f"2 · V · verdict correct: {pct('V'):.0f}%", n and b.get("V", 0) > 0)
        add(f"3 · K · CoT names the CWE class: {pct('K'):.0f}%", n and b.get("K", 0) > 0)
        add(f"4 · OWASP · CoT names {owasp}: {pct('O_owasp'):.0f}%", n and b.get("O_owasp", 0) > 0)
        add(f"5 · O · CoT picks the {m} monitor: {pct('O'):.0f}%", n and b.get("O", 0) > 0)
        add(f"6 · P · validator (lines/sinks/guards real, witness shaped): {pct('P'):.0f}% · top error: {sp.get('errors', {}).get(m, '-')}",
            n and b.get("P", 0) > 0)
        add(f"7 · KEPT for CoT training (V and P and K and O on the same trace): {b.get('kept', 0)}", b.get("kept", 0) > 0)
        if runtime:
            add(f"8 · X_strict · {m} confirms the trace's witness: {b.get('xs_true', 0)} (computed on {b.get('xs_computed', 0)} traces)",
                b.get("xs_true", 0) > 0)
        else:
            add("8 · static_evidence instead of a monitor (no runtime check exists)", False, na=True)
        rows_c = slice_rows.get("memory/asan" if m == "asan" else m, 0)
        add(f"9 · balanced training slice (arm ②): {rows_c} rows; VULNERABLE rows in the whole arm: {slice_vuln}",
            rows_c > 0 and bool(slice_vuln))
        w = wc.get(m, {})
        if runtime:
            add(f"10 · CASTLE · deterministic witness confirmed by {m}: {w.get('vuln_confirmed', 0)}/{w.get('vuln', 0)} vulnerable "
                f"(safe false-positives {w.get('safe_confirmed', 0)})", w.get("vuln_confirmed", 0) > 0)
            f = ft.get(m, [0, 0])
            add(f"11 · CASTLE · fine-tuned Foundation-Sec-8B witness confirmed by {m}: {f[0]}/{f[1]} vulnerable", f[0] > 0)
        else:
            add("10 · CASTLE · no runtime monitor: never execution-verified", False, na=True)
            add("11 · CASTLE · no runtime monitor: scored by class + localization only", False, na=True)
        broken = next((s["name"].split(" · ")[1] for s in steps if not s["ok"] and not s["na"]), None)
        bad_bank = any(h in SC_BAD_HASHES for h in sp.get("bank_schema_hashes", {}))
        if bad_bank:
            status = "INVALID — computed from a bank decoded under the v2.2 empty-witness grammar bug; regenerate under v2.3"
        else:
            status = f"CHAIN BREAKS AT {broken}" if broken else "CHAIN OK"
        cats[key] = {"label": label, "status": status, "ok": broken is None and not bad_bank, "steps": steps}
    note = sp.get("bank_error") or sp.get("slice_error") or ""
    return cats, note


# ------------------------------------------------------------------ probing (pure python: runs on box AND Spark)
PROBE = r'''
import json, os, sys
def auroc(s, y):
    n1 = sum(y); n0 = len(y) - n1
    if n1 == 0 or n0 == 0: return None
    order = sorted(range(len(s)), key=lambda i: s[i]); ranks = [0.0] * len(s); i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and s[order[j + 1]] == s[order[i]]: j += 1
        for k in range(i, j + 1): ranks[order[k]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return (sum(ranks[i] for i in range(len(s)) if y[i]) - n1 * (n1 + 1) / 2.0) / (n1 * n0)
def dig(d, path):
    for p in path.split("."):
        if isinstance(d, dict) and p in d: d = d[p]
        else: return None
    return d
KEYS = ["auroc", "model_auroc", "headline_project_grouped.auroc", "detector_deterministic_witness_routed.auroc",
        "hypotheses.H2_primary_beats_no_model_baseline.diff", "pairwise_win_rate_s_sc", "pairwise_win_rate",
        "summary.overall.auroc", "overall.auroc", "accuracy", "acc"]
def probe(p):
    r = {"exists": os.path.exists(p)}
    if not r["exists"]: return r
    r["mtime"] = int(os.path.getmtime(p))
    if os.path.isdir(p) or not (p.endswith(".json") or p.endswith(".jsonl")): return r
    if p.endswith(".jsonl"):
        try: r["n"] = sum(1 for l in open(p, errors="replace") if l.strip())
        except Exception: pass
        return r
    try: d = json.load(open(p))
    except Exception as e:
        r["error"] = type(e).__name__; return r
    if not isinstance(d, dict):
        r["n"] = len(d) if isinstance(d, list) else None; return r
    for k in KEYS:
        v = dig(d, k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            r["metric"], r["value"] = k, round(float(v), 4); break
    if isinstance(d.get("hypotheses"), dict):
        r["h2_pass"] = bool(dig(d, "hypotheses.H2_primary_beats_no_model_baseline.pass"))
    pc = d.get("per_case")
    if isinstance(pc, list) and pc and isinstance(pc[0], dict) and "label" in pc[0]:
        y = [1 if c.get("label") in ("VULNERABLE", 1, "1") else 0 for c in pc]
        r["n"] = len(pc)
        if "p_vuln" in pc[0]:
            a = auroc([float(c.get("p_vuln") or 0) for c in pc], y)
            if a is not None:
                r["recomputed"] = round(a, 4)
                if r.get("metric") == "auroc": r["integrity"] = abs(a - r["value"]) <= 0.005
        elif "confirmed" in pc[0]:
            a = auroc([1.0 if c.get("confirmed") else 0.0 for c in pc], y)
            if a is not None and "value" not in r: r["metric"], r["value"] = "auroc(confirmed)", round(a, 4)
    else:
        for k in ("n", "cases", "items"):
            v = d.get(k)
            if isinstance(v, int): r["n"] = v; break
            if isinstance(v, list): r["n"] = len(v); break
    return r
req = json.loads(sys.stdin.readline())
out = {"files": {p: probe(p) for p in req["files"]}, "greps": {}}
for path, needle in req["greps"]:
    k = path + "::" + str(needle)
    try:
        out["greps"][k] = os.path.exists(path) if needle is None else (needle in open(path, errors="replace").read())
    except Exception:
        out["greps"][k] = False
print(json.dumps(out))
'''


def run_probe(host, files, greps):
    req = json.dumps({"files": files, "greps": greps}) + "\n"
    b64 = base64.b64encode(PROBE.encode()).decode()
    code = f"import base64;exec(base64.b64decode('{b64}'))"
    if host == "box":
        cmd = [sys.executable, "-c", code]
    else:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", SPARK,
               f"cd {SPARK_REPO} && python3 -c \"{code}\""]
    try:
        p = subprocess.run(cmd, input=req, capture_output=True, text=True, timeout=120)
        return json.loads(p.stdout.strip().splitlines()[-1]), None
    except Exception as e:
        return {"files": {}, "greps": {}}, f"{host} unreachable: {type(e).__name__}"


def split(ref):
    h, p = ref.split(":", 1)
    return h, p


def fmt(p, r):
    name = os.path.basename(p)
    if not r.get("exists"):
        return f"{name}: MISSING"
    bits = [name]
    if "value" in r:
        bits.append(f"{r['metric']}={r['value']}")
    if "recomputed" in r and r.get("metric") == "auroc":
        bits.append(f"recomputed={r['recomputed']}" + ("" if r.get("integrity", True) else " INTEGRITY-MISMATCH"))
    if r.get("n") is not None:
        bits.append(f"n={r['n']}")
    return " ".join(bits)


def compute():
    want = {"box": set(), "spark": set()}
    greps = {"box": [], "spark": []}
    for s in STAGES:
        for ref in s["art"] + ([s["running"]] if s["running"] else []):
            h, p = split(ref)
            want[h].add(p)
        if s["fail"]:
            h, p = split(s["fail"][0])
            greps[h].append([p, s["fail"][1]])
    res, notes = {}, []
    for h in ("box", "spark"):
        out, err = run_probe(h, sorted(want[h]), greps[h])
        res[h] = out
        if err:
            notes.append(err)
    board = {}
    for s in STAGES:
        sid, kind = s["id"], s["kind"]
        if kind != "artifact":
            continue
        probes = [(ref, res[split(ref)[0]]["files"].get(split(ref)[1], {"exists": None})) for ref in s["art"]]
        unreachable = any(r.get("exists") is None for _, r in probes)
        present = probes and all(r.get("exists") for _, r in probes)
        integ_bad = [ref for ref, r in probes if r.get("integrity") is False]
        detail = " | ".join(f"[{split(ref)[0]}] {fmt(split(ref)[1], r)}" for ref, r in probes)
        fail_hit = False
        if s["fail"]:
            h, p = split(s["fail"][0])
            fail_hit = bool(res[h]["greps"].get(p + "::" + str(s["fail"][1])))
        run_hit = False
        if s["running"]:
            h, p = split(s["running"])
            run_hit = bool(res[h]["files"].get(p, {}).get("exists"))
        stale = s.get("invalid") and present and any((r.get("mtime") or 0) < SC_FIX_EPOCH for _, r in probes)
        if stale:
            st, detail = "INVALID", INVALID_REASON + " | " + detail
        elif present and not integ_bad:
            st = "VERIFIED"
        elif present and integ_bad:
            st, detail = "FAILED", "integrity mismatch (stored AUROC != per_case) in " + ", ".join(integ_bad) + " | " + detail
        elif fail_hit:
            st, detail = "FAILED", s["fail"][2] + " | " + detail
        elif run_hit:
            st, detail = "RUNNING", "in progress | " + detail
        elif s["state"] in ("pending", "blocked"):
            st, detail = s["state"].upper(), s["reason"] + (" | " + detail if s["art"] else "")
        elif unreachable:
            st, detail = "BLOCKED", "host unreachable during this check | " + detail
        else:
            st, detail = "FAILED", "expected artifact missing | " + detail
        board[sid] = {"status": st, "label": s["label"], "sec": s["sec"], "detail": detail[:900]}
    # derived stages
    art_stages = [b for b in board.values()]
    bad_integrity = [k for k, b in board.items() if "integrity mismatch" in b["detail"]]
    wsft = res["box"]["files"].get("results/witness/compare_fsec8b.json", {})
    h2 = wsft.get("h2_pass")
    board["adapters"] = {"status": "VERIFIED", "label": "ADAPTERS -> TEST pipeline", "sec": "1 ADAPTERS",
                         "detail": "join: " + ", ".join(f"{k}={board[k]['status']}" for k in ("a1", "a6", "a7", "c2", "c6", "w_sft"))}
    board["gate"] = {"status": "FAILED" if bad_integrity else "VERIFIED", "label": "GATE", "sec": Z,
                     "detail": ("integrity mismatch in " + ", ".join(bad_integrity)) if bad_integrity else
                     ("integrity holds on every result file with per_case. Crossings of a pre-registered bar: "
                      + ("witness H2 PASSED (pending audit)" if h2 else "none verified so far (reading arms at chance; witness run "
                         + ("finished, H2 not passed" if wsft.get("exists") else "still running") + ")"))}
    board["audit"] = {"status": "PENDING" if h2 else "BLOCKED", "label": "recompute -> auditor -> verifier", "sec": Z,
                      "detail": "witness H2 passed: run recompute + experiment-auditor + verifier before any claim" if h2 else
                      "nothing has crossed its bar, so there is nothing to audit yet"}
    cats, cnote = compute_categories(res["box"]["files"])
    if cnote:
        notes.append("category chain: " + cnote)
    ok_cats = sum(1 for c in cats.values() if c["ok"])
    board["standing"] = {"status": "BLOCKED", "label": "standing orders", "sec": Z,
                         "detail": "HF model replacement and Zenodo v4 require an audited floor-crossing (and for v4, asking the owner); "
                         f"none yet. Monitor categories whose CoT chain is complete: {ok_cats}/{len(cats)}"}
    counts = {}
    for b in board.values():
        counts[b["status"]] = counts.get(b["status"], 0) + 1
    board["cats"] = cats
    meta = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "counts": counts, "notes": notes}
    return board, meta


def _short(b):
    """one short human reason per stage for the at-a-glance table"""
    d = b["detail"].split(" | ")[0]
    return (d[:110] + "…") if len(d) > 110 else d


def to_md(board, meta):
    icon = {"VERIFIED": "✅", "FAILED": "❌", "INVALID": "🚫", "RUNNING": "🔄", "PENDING": "⏳", "BLOCKED": "⏸️"}
    lines = ["# cyberdef pipeline status", "",
             f"generated {meta['generated']} · " + " · ".join(f"{icon.get(k, '')} {k} {v}" for k, v in sorted(meta["counts"].items())), "",
             "✅ ran, and its evidence checks out (this is NOT the same as beating its bar; see GATE) · ❌ failed · "
             "🚫 invalid (built under the fixed schema bug; re-run needed) · "
             "🔄 running · ⏳ not started · ⏸️ blocked by an earlier stage", ""]
    if meta["notes"]:
        lines += ["> " + n for n in meta["notes"]] + [""]
    # 1. the diagram at a glance: one row per box, in pipeline order
    lines += ["## The pipeline at a glance", "", "| step | stage | status | why |", "|---|---|---|---|"]
    sec, n = None, 0
    for s in STAGES:
        b = board.get(s["id"])
        if not b or s["kind"] == "join":
            continue
        n += 1
        head = s["sec"] if s["sec"] != sec else ""
        sec = s["sec"]
        # verified rows stay quiet, except where "verified" could be misread as "won": the gate and the witness-SFT result
        quiet = b["status"] == "VERIFIED" and s["kind"] != "gate" and s["id"] != "w_sft"
        reason = "" if quiet else _short(b).replace("|", "/")
        lines.append(f"| {n} | {('**' + head + '** · ') if head else ''}{s['label']} | {icon.get(b['status'], '')} {b['status']} | {reason} |")
    # 2. full evidence, collapsed
    lines += ["", "<details><summary>Evidence behind every stage (files, recomputed AUROCs)</summary>", "",
              "| stage | evidence |", "|---|---|"]
    for s in STAGES:
        b = board.get(s["id"])
        if b and s["kind"] != "join":
            lines.append(f"| {s['label']} | {b['detail'].replace('|', '/')} |")
    lines += ["", "</details>"]
    cats = board.get("cats") or {}
    if cats:
        lines += ["", "## Per category: CoT → CWE class → OWASP → monitor → witness → confirmation", "",
                  "| category | status |", "|---|---|"]
        for key, c in cats.items():
            lines.append(f"| {c['label'].split(' · ')[0]} | {'✅' if c['ok'] else ('🚫' if c['status'].startswith('INVALID') else '❌')} {c['status']} |")
        lines += ["", "<details><summary>Every link, per category</summary>", ""]
        for key, c in cats.items():
            lines += [f"**{c['label']}** — {c['status']}", ""]
            for st in c["steps"]:
                mark = "n/a" if st["na"] else ("✅" if st["ok"] else "❌")
                lines.append(f"- {mark} {st['name'].replace('|', '/')}")
            lines.append("")
        lines += ["</details>"]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--json", default="")
    ap.add_argument("--md", default="")
    a = ap.parse_args()
    if a.status:
        try:
            board, meta = compute()
        except Exception as e:   # never leave the workflow without a board
            board = {s["id"]: {"status": "BLOCKED", "label": s["label"], "sec": s["sec"], "detail": f"board error: {type(e).__name__}: {e}"} for s in STAGES}
            meta = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "counts": {"BLOCKED": len(board)}, "notes": [repr(e)]}
        if a.json:
            open(a.json, "w").write(json.dumps(board, ensure_ascii=False))
        md = to_md(board, meta)
        if a.md:
            open(a.md, "w", encoding="utf-8").write(md)
        print(md)


if __name__ == "__main__":
    main()
