#!/usr/bin/env python3
"""Emit a provenance record for a cyberdef CI train/eval run. This is the artefact that turns
the actionledger 'not under git / undisclosed gates' finding into a reproducible claim: it ties
a result to an exact commit, runner, input set, pinned environment, and quantization mode.

No third-party deps. Reads GitHub-Actions env vars when present; degrades gracefully off-CI.
"""
from __future__ import annotations
import argparse, hashlib, json, os, subprocess, time


def sh(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""


def sha256(path, cap=64 * 1024 * 1024):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
                cap -= len(b)
                if cap <= 0:
                    return h.hexdigest() + "+truncated"
        return h.hexdigest()
    except Exception:
        return None


def mode_from_train_log(out_tag):
    p = f"out/imp_{out_tag}_imp_train_log.json"
    if not os.path.exists(p):
        return None
    try:
        return json.load(open(p)).get("flags", {}).get("mode")  # may be absent; trainer prints mode to stdout
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=["train", "eval"])
    ap.add_argument("--out-tag", default="")
    ap.add_argument("--result", default="", help="eval: result json to hash + record")
    ap.add_argument("--lane", default="")
    ap.add_argument("--inputs", default="", help="k=v;k=v recorded verbatim")
    ap.add_argument("--env-drift", default="", help="path to a diff vs constraints.txt (recorded if non-empty)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    drift = ""
    if a.env_drift and os.path.exists(a.env_drift):
        drift = open(a.env_drift).read()[:8000]

    rec = {
        "kind": a.kind,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "git": {
            "sha": os.environ.get("GITHUB_SHA") or sh("git", "rev-parse", "HEAD"),
            "ref": os.environ.get("GITHUB_REF") or sh("git", "rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(sh("git", "status", "--porcelain")),
        },
        "ci": {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "actor": os.environ.get("GITHUB_ACTOR"),
        },
        "runner": {
            "lane": a.lane,
            "name": os.environ.get("RUNNER_NAME"),
            "os": os.environ.get("RUNNER_OS") or sh("uname", "-sm"),
        },
        "inputs": dict(kv.split("=", 1) for kv in a.inputs.split(";") if "=" in kv),
        "constraints_sha256": sha256("constraints.txt"),
        "env_drift_vs_constraints": drift or "none",
        "python": sh("python3", "--version"),
    }
    if a.kind == "train" and a.out_tag:
        rec["out_tag"] = a.out_tag
        rec["adapter_present"] = os.path.exists(f"out/imp_{a.out_tag}/adapter_model.safetensors")
        rec["train_mode"] = mode_from_train_log(a.out_tag)
    if a.kind == "eval" and a.result:
        rec["result_file"] = a.result
        rec["result_sha256"] = sha256(a.result)
        try:
            d = json.load(open(a.result))
            rec["result_headline"] = {k: d.get(k) for k in ("auroc", "accuracy", "n", "model", "adapter", "cases_file")}
            cf = d.get("cases_file")
            if cf:
                rec["cases_file_sha256"] = sha256(cf)
        except Exception:
            pass

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rec, open(a.out, "w"), indent=2)
    print(json.dumps(rec, indent=2))


if __name__ == "__main__":
    main()
