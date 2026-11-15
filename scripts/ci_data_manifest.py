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
    ("results/imp_cotq_2_items.json", "CoT arm 2 training items"),
    ("results/imp_cotq_2_twin_items.json", "CoT arm 2 verdict-only twin items"),
    ("results/imp_cotq_6_items.json", "CoT arm 6 (counterfactual) training items"),
    ("results/imp_cotq_6_twin_items.json", "CoT arm 6 verdict-only twin items"),
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
