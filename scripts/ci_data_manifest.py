#!/usr/bin/env python3
"""Integrity manifest for the canonical datasets every cyberdef result depends on.

  --write : record sha256, size and case count of each canonical file into data/DATA_MANIFEST.json (commit it)
  --check : recompute and compare; exit 1 if any file is missing or changed (a silently edited eval set is caught)
  --selftest : prove --check can fail: corrupt a temporary copy and confirm the mismatch is detected

Only hashes and counts are recorded, never the data itself, so the manifest is safe to publish."""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, tempfile, time

MANIFEST = "data/DATA_MANIFEST.json"
CANONICAL = [
    ("results/lenmatched_eval_cases.json", "PrimeVul TEST, length-matched (537 pairs) - primary reading eval set"),
    ("results/vs_holdout_matched_cases.json", "VulSpot project-holdout, length-matched"),
    ("results/vs_nolinux_matched_cases.json", "VulSpot chrono test (no linux), length-matched"),
    ("results/xdata_castle_cases.json", "CASTLE 198 executable programs (99/99)"),
    ("results/imp_castle_input_channels.json", "static input-channel detector output for CASTLE"),
    ("results/imp_2o_floor_b60.json", "fuzzer floor on CASTLE (execution baseline)"),
    ("data/witness_train.jsonl", "oracle-confirmed witness set (Phase-A capture)"),
    ("results/j3_heldout_cases.json", "J3 held-out (2b), 840 pairs, cleaned 3g+3i; DESCRIPTIVE: function count gives the label (3i)"),
    ("results/j3_heldout_matched_cases.json", "J3 matched (2c), cleaned 3g+3i; DESCRIPTIVE: function count alone scores 0.975 (3i)"),
    ("results/j3s_heldout_matched_cases.json", "J3s (3i): structure- and length-matched; primary test for format string (CWE-134)"),
    ("results/j4_heldout_matched_cases.json", "J4b matched (3e), cleaned 3g+3i; DESCRIPTIVE: function count alone scores 0.956 (3i)"),
    ("results/vsp_t_cases.json", "VSP-T (3680322): 388 real-world before/after fix pairs, 159 projects; primary test of VSP_SFT_R1_PREREG"),
    ("results/vsp_sft_items.json", "VSP-SFT training items (VulSpot train-split fix pairs; check_vsp_items.py ALL PASS)"),
    ("results/vsp_dev_cases.json", "VSP-DEV: 64 held-out round-1 projects, 316 pairs; pilot-only test set (never VSP-T)"),
    ("results/vsp_pilot_k1_items.json", "VSP pilot K1 training items: round 1 minus dev projects and dev near-duplicates"),
    ("results/vsp_pilot_k2_items.json", "VSP pilot K2 training items: K1 + 300 linux V-longer pairs"),
    ("results/vsp_sft_k2_items.json", "VSP-SFT K2 final training items: round 1 + the same 300 linux V-longer pairs"),
    ("results/vsp_dev2_cases.json", "VSP-DEV2 (cycle 2): 64 remaining non-linux round-1 B-holding projects + test-split supplement, 505 pairs; K4 pilots only (never VSP-T)"),
    ("results/vsp_probe_cases.json", "VSP linux held-out probe: 150 A + 150 B val-split linux pairs; NOT project-disjoint; descriptive, outside the gate"),
    ("results/vsp_pilot_k4_items.json", "VSP pilot K4a training items: round 1 minus dev2 projects/near-duplicates + 308 linux B and 308 linux A pairs"),
    ("results/vsp_pilot_k4b_items.json", "VSP pilot K4b training items: the K4a items with a two-line VERDICT / SITE target"),
    ("results/vsp_sft_k4b_items.json", "VSP-SFT K4b final training items (attempt 5): the K4 final items with a two-line VERDICT / SITE target"),
    ("results/vsp_sft_k4_items.json", "VSP-SFT K4 final training items: round 1 (dev2 folded back) minus dev2-supplement near-duplicates + the K4 linux extras"),
    ("results/vsp_dev3_cases.json", "VSP-DEV3 (attempt 6): confirmation fold, 122 non-linux non-dev2 projects of the K4b final file, 400 pairs; d3 pilots and base models only (never VSP-T)"),
    ("results/vsp_pilot_k4b_d3_items.json", "VSP pilot D3 training items (attempt 6): K4b final items minus every dev3 project and dev3 near-duplicates, two-line VERDICT / SITE target"),
    ("results/j4s_heldout_matched_cases.json", "J4s (3i): structure- and length-matched, execution-verified; primary test for memory, integer, leak"),
    ("results/q_heldout_cases.json", "SQLi held-out, 44 oracle-verified pairs never in any pool (3g: cleaned, re-verified): primary test for SQL injection"),
    ("results/imp_fewshot_exemplars.json", "few-shot exemplars templated from Juliet _02 ground truth (quick bank; no model)"),
    ("results/imp_fewshot_exemplars_st_cmd_injection.json", "addendum 3b: quick exemplars + templated SAFE command-injection exemplar"),
    ("results/imp_fewshot_exemplars_st_path_traversal.json", "addendum 3c: quick exemplars + templated VULNERABLE and SAFE path-traversal exemplars"),
    ("results/imp_fewshot_exemplars_st_sqli.json", "addendum 3d: quick exemplars + templated VULNERABLE and SAFE SQL-injection exemplars"),
    ("results/imp_fewshot_exemplars_st_format_string.json", "addendum 3f: quick exemplars + templated VULNERABLE and SAFE format-string exemplars"),
    ("results/imp_fewshot_exemplars_st_integer.json", "addendum 3e: quick exemplars + templated VULNERABLE and SAFE integer exemplars"),
    ("results/imp_fewshot_exemplars_st_leak.json", "addendum 3e: quick exemplars + templated VULNERABLE and SAFE leak exemplars"),
    # CoT item files are NOT canonical: they are rebuilt from each trace-bank build and pinned per build by the sha256s
    # in results/imp_cotq_BUILD_OK.json, which the Dataset step checks on both machines. (Until 15 Nov this list pinned
    # the v2.2 items, built under the SC-CoT grammar bug: INVALID, and the reason --check failed once they were rebuilt.)
]


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def count(p):
    try:
        if p.endswith(".jsonl"):
            return sum(1 for l in open(p) if l.strip())
        d = json.load(open(p))
        for k in ("cases", "items", "per_case"):
            if isinstance(d, dict) and isinstance(d.get(k), list):
                return len(d[k])
        return len(d) if isinstance(d, list) else None
    except Exception:
        return None


def entry(p):
    return {"sha256": sha256(p), "bytes": os.path.getsize(p), "n": count(p)}


def check(manifest, root="."):
    m = json.load(open(manifest))
    bad = []
    for rel, rec in m["files"].items():
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            bad.append(f"MISSING {rel}")
        elif sha256(p) != rec["sha256"]:
            bad.append(f"CHANGED {rel} (n {rec['n']} -> {count(p)})")
    return bad


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    g.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.write:
        files = {rel: {**entry(rel), "what": what} for rel, what in CANONICAL if os.path.exists(rel)}
        missing = [rel for rel, _ in CANONICAL if not os.path.exists(rel)]
        os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
        json.dump({"written": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "files": files, "missing_at_write": missing},
                  open(MANIFEST, "w"), indent=2)
        print(f"wrote {MANIFEST}: {len(files)} files" + (f"; missing: {missing}" if missing else ""))
        return
    if a.check:
        bad = check(MANIFEST)
        for b in bad:
            print("::error::" + b)
        print("data integrity: " + ("OK, all canonical files match the manifest" if not bad else f"{len(bad)} problem(s)"))
        sys.exit(1 if bad else 0)
    # selftest: a corrupted copy must be caught, an intact copy must pass
    m = json.load(open(MANIFEST))
    rel = next(iter(m["files"]))
    with tempfile.TemporaryDirectory() as td:
        for r in m["files"]:
            os.makedirs(os.path.join(td, os.path.dirname(r)), exist_ok=True)
            shutil.copy(r, os.path.join(td, r))
        intact = check(MANIFEST, td)
        with open(os.path.join(td, rel), "ab") as f:
            f.write(b" ")
        corrupted = check(MANIFEST, td)
    ok = (not intact) and any(rel in b for b in corrupted)
    print(f"selftest: intact copy -> {intact or 'OK'}; one appended byte in {rel} -> {corrupted}")
    print("data manifest selftest " + ("PASS" if ok else "FAIL"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
