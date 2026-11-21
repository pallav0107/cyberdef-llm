"""Acceptance checker for the K4b diff-site targets (spec C7).

Usage:
  .venv/bin/python acceptance/improve/check_site_targets.py ITEMS.json [--k4a F] [--tokenizer NAME]

ITEMS.json = results/vsp_pilot_k4b_items.json: {"items": [...]} in pair-adjacent order, each item carrying the
training target in the "target" field (the field scripts/imp_train.py build_examples reads).

Checks (one PASS/FAIL line each; exit 0 only if all pass):
  FILES               items file present (and, if --k4a is given or the default exists, the K4a pilot).
  TARGET_SHAPE        every target is exactly two lines: "VERDICT: <label>" (label = the item label) then a line
                      starting "SITE: ".
  SITE_VERBATIM       the SITE text is a verbatim line of that item code (exact, or equal after strip()).
  SITE_DIFFLIB        the SITE text equals an independent difflib recomputation. Rule (plan, K4b): diff the vulnerable
                      and the fixed code line by line; if this side has a changed line, the first such line; else
                      (pure insert / delete on the other side) the line after the first edit point, or, if none, the
                      last line before it. Accepted variants (spec silent): split("\n") or splitlines(), autojunk
                      False or True, exact or strip()-equal match.
  SAME_AS_K4A         K4b has the same items (id, code, label, pair, project) as the K4a pilot: one change only.
  SLOT_TWO_LINE       scripts/imp_train.py verdict_slot returns an index >= 0 and two distinct token ids for every
                      target, equal to the slot of the one-line target "VERDICT: <label>" (the SITE suffix is never
                      scored; this is the trap where a two-line target silently returned (-1, 0, 0)).
  SLOT_SYNTHETIC      two-line targets whose SITE text mentions VULNERABLE / SAFE / VERDICT give the same slot as the
                      one-line target.
  SLOT_REGRESSION     one-line targets and the JSON-style target still resolve (index >= 0), the slot tokens decode to a
                      prefix of VULNERABLE / SAFE, and a target with no verdict is still (-1, 0, 0).
The tokenizer is the one check_train_slots.py uses (local HF cache). A missing file or tokenizer is a FAIL.
"""
from __future__ import annotations

import argparse
import difflib
import importlib.util
import os
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOKENIZER = "Qwen/Qwen2.5-7B-Instruct"
DEFAULT_K4A = "results/vsp_pilot_k4_items.json"
RESULTS = []


def load_items(path):
    return json.load(open(path, encoding="utf-8"))["items"]


def pair_map(items):
    out = {}
    for it in items:
        out.setdefault(it["pair"], {})["V" if it["label"] == "VULNERABLE" else "S"] = it
    return out


def parse_target(it):
    """(label line, site text or None, number of lines)."""
    t = it.get("target")
    if not isinstance(t, str):
        return None, None, 0
    lines = t.split("\n")
    site = lines[1][len("SITE: "):] if len(lines) > 1 and lines[1].startswith("SITE: ") else None
    return lines[0], site, len(lines)


def site_candidates(vcode, scode, side):
    out = set()
    for split in (lambda s: s.split("\n"), lambda s: s.splitlines()):
        a, b = split(vcode), split(scode)
        for autojunk in (False, True):
            ops = [o for o in difflib.SequenceMatcher(None, a, b, autojunk=autojunk).get_opcodes() if o[0] != "equal"]
            if not ops:
                continue
            mine = a if side == "V" else b
            line = None
            for _tag, i1, i2, j1, j2 in ops:
                lo, hi = (i1, i2) if side == "V" else (j1, j2)
                if hi > lo:
                    line = mine[lo]
                    break
            if line is None:
                lo = ops[0][1] if side == "V" else ops[0][3]
                line = "" if not mine else (mine[lo] if lo < len(mine) else mine[lo - 1])
            out.add(line)
    return out


def check_files(ctx):
    missing = [p for p in (ctx["items_path"],) if not Path(p).is_file()]
    return not missing, "items file present" if not missing else "target not built yet: " + ", ".join(missing)


def check_shape(ctx):
    bad = []
    for it in ctx["items"]:
        head, site, n = parse_target(it)
        if n != 2 or head != "VERDICT: " + it["label"] or site is None:
            bad.append(f"{it['id']}: {n} lines, head {head!r}")
    return not bad, f"{len(ctx['items'])} items, {len(bad)} malformed targets {bad[:3]}"


def check_verbatim(ctx):
    bad = []
    for it in ctx["items"]:
        _, site, n = parse_target(it)
        lines = it["code"].split("\n")
        if site is None or not (site in lines or site.strip() in {ln.strip() for ln in lines}):
            bad.append(it["id"])
    return not bad, f"{len(bad)} items whose SITE is not a verbatim line of their code {bad[:3]}"


def check_difflib(ctx):
    bad = []
    for pair, p in pair_map(ctx["items"]).items():
        if "V" not in p or "S" not in p:
            bad.append(f"{pair}: incomplete pair")
            continue
        for side in "VS":
            _, site, _n = parse_target(p[side])
            cands = site_candidates(p["V"]["code"], p["S"]["code"], side)
            stripped = {c.strip() for c in cands}
            if site is None or not (site in cands or site.strip() in stripped):
                bad.append(f"{pair}:{side}")
    return not bad, f"{len(bad)} items whose SITE differs from the difflib recomputation {bad[:4]}"


def check_same_as_k4a(ctx):
    path = ctx["k4a_path"]
    if not path or not Path(path).is_file():
        return False, f"target not built yet: {path}"
    keys = ("id", "code", "label", "pair", "project")
    a = [tuple(i[k] for k in keys) for i in load_items(path)]
    b = [tuple(i[k] for k in keys) for i in ctx["items"]]
    return a == b, f"K4a pilot {len(a)} items, K4b {len(b)} items, identical in id/code/label/pair/project/order: {a == b}"


def get_train_module():
    sys.path.insert(0, str(ROOT / "src"))
    sys.path.insert(0, str(ROOT / "scripts"))
    script = os.environ.get("SITE_TRAIN_SCRIPT", str(ROOT / "scripts/imp_train.py"))   # env: checker self-test only
    spec = importlib.util.spec_from_file_location("imp_train", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def slot(ctx, target):
    return ctx["mod"].verdict_slot(ctx["tok"], target)


def check_slot_two_line(ctx):
    bad, memo = [], {}
    for it in ctx["items"]:
        lab = it["label"]
        if lab not in memo:
            memo[lab] = slot(ctx, "VERDICT: " + lab)
        got = slot(ctx, it["target"]) if isinstance(it.get("target"), str) else (-1, 0, 0)
        if got[0] < 0 or got[1] == got[2] or got != memo[lab]:
            bad.append(f"{it['id']}: {got} vs one-line {memo[lab]}")
    return not bad, f"{len(ctx['items'])} targets, {len(bad)} with a slot that is missing or differs {bad[:3]}"


def check_slot_synthetic(ctx):
    bad = []
    sites = ["if (ret == SAFE) return VULNERABLE;", "VERDICT: SAFE", "x = VULNERABLE_FLAG;", "", "  return 0;"]
    for lab in ("VULNERABLE", "SAFE"):
        one = slot(ctx, "VERDICT: " + lab)
        for s in sites:
            got = slot(ctx, "VERDICT: " + lab + "\nSITE: " + s)
            if got[0] < 0 or got != one:
                bad.append(f"{lab} + {s!r}: {got} vs {one}")
    return not bad, f"{len(bad)} synthetic two-line targets with a wrong slot {bad[:3]}"


def check_slot_regression(ctx):
    tok, bad = ctx["tok"], []
    for lab in ("VULNERABLE", "SAFE"):
        vd, tv, ts = slot(ctx, "VERDICT: " + lab)
        dv, ds = tok.decode([tv]).strip().upper(), tok.decode([ts]).strip().upper()
        if vd < 0 or not dv or not ds or not "VULNERABLE".startswith(dv) or not "SAFE".startswith(ds):
            bad.append(f"one-line {lab}: slot {vd} {dv!r} {ds!r}")
        js = json.dumps({"a": [1], "verdict": lab, "cwe": ""}, indent=1)
        if slot(ctx, js)[0] < 0:
            bad.append(f"JSON-style {lab}: slot -1")
    if slot(ctx, "no verdict here") != (-1, 0, 0):
        bad.append("a target with no verdict no longer returns (-1, 0, 0)")
    return not bad, "one-line, JSON-style and no-verdict targets behave as before" if not bad else "; ".join(bad)


CHECKS = [("FILES", check_files), ("TARGET_SHAPE", check_shape), ("SITE_VERBATIM", check_verbatim),
          ("SITE_DIFFLIB", check_difflib), ("SAME_AS_K4A", check_same_as_k4a), ("SLOT_TWO_LINE", check_slot_two_line),
          ("SLOT_SYNTHETIC", check_slot_synthetic), ("SLOT_REGRESSION", check_slot_regression)]
NEEDS_TOKENIZER = {"SLOT_TWO_LINE", "SLOT_SYNTHETIC", "SLOT_REGRESSION"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("items")
    ap.add_argument("--k4a", default=str(ROOT / DEFAULT_K4A))
    ap.add_argument("--tokenizer", default=TOKENIZER)
    a = ap.parse_args(argv)
    ctx = {"items_path": a.items, "k4a_path": a.k4a, "items": []}
    if Path(a.items).is_file():
        try:
            ctx["items"] = load_items(a.items)
        except (ValueError, KeyError) as exc:
            print(f"FAIL FILES - cannot read {a.items}: {type(exc).__name__}: {exc}")
    tok_err = ""
    try:
        from transformers import AutoTokenizer
        ctx["tok"] = AutoTokenizer.from_pretrained(a.tokenizer)
        ctx["mod"] = get_train_module()
    except Exception as exc:  # noqa: BLE001
        tok_err = f"tokenizer or scripts/imp_train.py unavailable: {type(exc).__name__}: {exc}"
    failed = 0
    for name, fn in CHECKS:
        try:
            if not ctx["items"] and name != "FILES":
                ok, detail = False, "target not built yet: " + a.items
            elif name in NEEDS_TOKENIZER and tok_err:
                ok, detail = False, tok_err
            else:
                ok, detail = fn(ctx)
        except Exception as exc:  # noqa: BLE001  a malformed item is a FAIL, never a crash
            ok, detail = False, type(exc).__name__ + ": " + str(exc)
        print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
        failed += 0 if ok else 1
    print("RESULT: " + ("FAIL" if failed else "PASS") + f" ({failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
