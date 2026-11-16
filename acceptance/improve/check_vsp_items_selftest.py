"""Self-test for check_vsp_items.py: each code fires on a planted defect; a clean set built from
REAL train rows (parquet) stays quiet. Prints ALL PASS on success.

Clean set: real train V/S pairs, non-VSP-T projects, stripped length < 4000, text built with the
builder stripper (scripts/imp_build_vsp.py), then hill-climbed (selection only, labels untouched)
until the five band AUROCs sit inside [0.45, 0.55].
"""
from __future__ import annotations

import copy
import importlib.util
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_vsp as cv  # noqa: E402
import check_vsp_items as ci  # noqa: E402

ROOT = cv.ROOT
SEED, N_PAIRS, PER_PROJECT, MAX_DEV, MIN_SHAPE_PROJECTS = 7, 660, 4, 0.03, 170
FAILS = []


def builder_stripper():
    spec = importlib.util.spec_from_file_location("imp_build_vsp", ROOT / "scripts/imp_build_vsp.py")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "src"))
    spec.loader.exec_module(mod)
    return mod.strip_comments


def eligible_pairs(ctx, strip):
    """Real train pairs: both rows in train, project not in VSP-T, short, distinct, hash-clean."""
    df, train = ctx.rows, ctx.train
    tprojects, thashes = ctx.test
    bodies, proj = df.func_body.tolist(), df.project.tolist()
    v = df[df.is_vulnerable & df.fixed_func_idx.notna() & df.idx.isin(train)]
    out = []
    for i, fx in zip(v.idx.tolist(), v.fixed_func_idx.astype(int).tolist()):
        if fx not in train or proj[i] in tprojects:
            continue
        a, b = strip(bodies[i]), strip(bodies[fx])
        short = len(a) < cv.TRUNC_LEN and len(b) < cv.TRUNC_LEN
        if short and ci.squash(a) != ci.squash(b) and not {cv.norm_hash(a), cv.norm_hash(b)} & thashes:
            out.append((i, fx, proj[i], a, b))
    return out


def pair_items(n, rec):
    i, fx, project, a, b = rec
    return [{"id": f"v{n}", "code": a, "code_chars": len(a), "label": "VULNERABLE", "pair": n,
             "project": project, "src_idx": i},
            {"id": f"s{n}", "code": b, "code_chars": len(b), "label": "SAFE", "pair": n,
             "project": project, "src_idx": fx}]


def feature_arrays(recs):
    """Per-pair band features of the V side and the S side."""
    keys = ["chars", "lines", "if", "static", "comments"]
    fv = np.array([[cv.band_features(r[3])[k] for k in keys] for r in recs], dtype=float)
    fs = np.array([[cv.band_features(r[4])[k] for k in keys] for r in recs], dtype=float)
    return fv, fs


def dev(fv, fs, sel):
    """Largest |AUROC-0.5| over the band features for the selected pairs."""
    worst = 0.0
    for k in range(fv.shape[1]):
        x = np.concatenate([fv[sel, k], fs[sel, k]])
        r = pd.Series(x).rank().to_numpy()
        n = len(sel)
        a = (r[:n].sum() - n * (n + 1) / 2) / (n * n)
        worst = max(worst, abs(a - 0.5))
    return worst


def pick_balanced(recs, rng):
    """Up to PER_PROJECT random pairs from every project, shuffled, first N_PAIRS kept."""
    by = {}
    for n, r in enumerate(recs):
        by.setdefault(r[2], []).append(n)
    pool = [n for p in by for n in rng.sample(by[p], min(PER_PROJECT, len(by[p])))]
    rng.shuffle(pool)
    return pool[:N_PAIRS], pool[N_PAIRS:]


def shape_ok(recs, sel):
    counts = {}
    for n in sel:
        counts[recs[n][2]] = counts.get(recs[n][2], 0) + 1
    return len(counts) >= MIN_SHAPE_PROJECTS and max(counts.values()) <= PER_PROJECT + 2


def climb(recs, sel, spare, rng, steps=20000):
    fv, fs = feature_arrays(recs)
    best = dev(fv, fs, sel)
    for _ in range(steps):
        if best <= MAX_DEV:
            break
        pos, k = rng.randrange(len(sel)), rng.randrange(len(spare))
        trial = sel[:pos] + [spare[k]] + sel[pos + 1:]
        d = dev(fv, fs, trial)
        if d < best and shape_ok(recs, trial):
            spare[k], sel, best = sel[pos], trial, d
    return sel, best


def clean_items(ctx):
    strip = builder_stripper()
    recs = eligible_pairs(ctx, strip)
    rng = random.Random(SEED)
    sel, spare = pick_balanced(recs, rng)
    sel, best = climb(recs, sel, spare, rng)
    items = [x for n, k in enumerate(sel) for x in pair_items(n, recs[k])]
    return items, best, recs


def run(items, ctx):
    return {c: f for c, (f, _) in ci.run_all(items, ctx).items()}


def expect(name, items, ctx, codes):
    fired = run(items, ctx)
    ok = all(fired[c] for c in codes)
    print(f"  {'ok  ' if ok else 'FAIL'} {name}: fired={[c for c in ci.CODES if fired[c]]} expected={codes}")
    if not ok:
        FAILS.append(name)


def vitems(items):
    return [x for x in items if x["label"] == "VULNERABLE"]


def mutate(items, fn):
    out = copy.deepcopy(items)
    fn(out)
    return out


def p_pairs(items):
    items[1]["code"] = items[0]["code"]


def p_pairs_missing(items):
    del items[1]


def p_length(items):
    items[0]["code"] += "\n" + "/" * cv.TRUNC_LEN


def p_train_split(items):
    items[0]["src_idx"] = json.load(open(cv.SPLITS))["test"][0]


def p_label_v(items):
    items[1]["src_idx"], items[0]["src_idx"] = items[0]["src_idx"], items[1]["src_idx"]


def p_label_s(items):
    items[1]["src_idx"] = items[3]["src_idx"]


def p_text(items):
    for x in items[:60]:
        x["code"] += "\nint planted_defect;"


def p_overlap_project(items, ctx):
    items[0]["project"] = sorted(ctx.test[0])[0]


def p_overlap_hash(items):
    case = json.load(open(ci.TEST_CASES, encoding="utf-8"))["cases"][0]
    items[0]["code"] = case["code"]


def p_cap(items):
    for x in items[:2 * (ci.MAX_PAIRS_PER_PROJECT + 1)]:
        x["project"] = "one_big_project"


def p_floor_pairs(items):
    del items[200:]


def p_floor_projects(items):
    for x in items:
        x["project"] = f"p{x['pair'] % 100}"


def band_padders():
    """Each pads only one side so one band feature separates the labels."""
    return {
        "chars": lambda i: [x.update(code=x["code"] + " " * 600) for x in vitems(i)],
        "lines": lambda i: [x.update(code=x["code"] + "\n" * 30) for x in vitems(i)],
        "if": lambda i: [x.update(code=x["code"] + "\nif (0) {}" * 6) for x in vitems(i)],
        "static": lambda i: [x.update(code=x["code"] + "\nstatic int z;" * 6) for x in vitems(i)],
        "comments": lambda i: [x.update(code=x["code"] + " // fix") for x in i if x["label"] == "SAFE"],
    }


def test_bands(clean, ctx):
    for feat, fn in band_padders().items():
        items = mutate(clean, fn)
        fired, msg = ci.check_bands(items, ctx)
        ok = fired and f"{feat}=" in msg and feat in msg.split("out=")[1]
        print(f"  {'ok  ' if ok else 'FAIL'} BANDS/{feat}: {msg}")
        if not ok:
            FAILS.append("BANDS/" + feat)


def test_stripper():
    cases = {
        "a // c\nb": "a  \nb", 'x = "//not";': 'x = "//not";',
        "c = 34; /* z */ d": "c = 34;   d", "q = '\"'; // t": "q = '\"';  ",
        "n = 1'000; // t": "n = 1'000;  ", "a /* un": "a  ",
    }
    for src, want in cases.items():
        ok = ci.squash(ci.strip_comments(src)) == ci.squash(want)
        print(f"  {'ok  ' if ok else 'FAIL'} stripper {src!r}")
        if not ok:
            FAILS.append("stripper " + src)


def test_quiet_variants(clean, ctx):
    """Whitespace-only reformatting must not fire TEXT_SOURCE; an empty file must fire everything."""
    spaced = mutate(clean, lambda i: [x.update(code=x["code"].replace("\n", "\n\n")) for x in i])
    ok = not ci.check_text_source(spaced, ctx)[0]
    print(f"  {'ok  ' if ok else 'FAIL'} whitespace-only change keeps TEXT_SOURCE quiet")
    empty = ci.run_all([], ctx)
    ok2 = all(f for f, _ in empty.values())
    print(f"  {'ok  ' if ok2 else 'FAIL'} empty items refuse every code")
    FAILS.extend([] if ok and ok2 else ["variants"])


def cli(args, items=None):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"items": items or [], "note": "", "stats": {}}, fh)
    cmd = [sys.executable, str(HERE / "check_vsp_items.py"), fh.name] + args
    return subprocess.run(cmd, capture_output=True, text=True).returncode


def test_cli(clean):
    checks = [("clean file exit 0", cli([], clean), 0),
              ("clean + --expect-refuse BANDS exit 1", cli(["--expect-refuse", "BANDS"], clean), 1),
              ("floor-cut + --expect-refuse FLOOR exit 0", cli(["--expect-refuse", "FLOOR"], clean[:200]), 0),
              ("clean without expect, floor-cut exit 1", cli([], clean[:200]), 1),
              ("unreadable file exit 2", subprocess.run([sys.executable, str(HERE / "check_vsp_items.py"),
                                                         "/nonexistent.json"], capture_output=True).returncode, 2)]
    for name, got, want in checks:
        print(f"  {'ok  ' if got == want else 'FAIL'} {name} (exit {got})")
        if got != want:
            FAILS.append(name)


def main():
    ctx = ci.Ctx()
    clean, best, recs = clean_items(ctx)
    print(f"real eligible train pairs: {len(recs)}; clean set: {len(clean) // 2} pairs, "
          f"{len({x['project'] for x in clean})} projects, max band dev {best:.4f}")
    print("clean set must be quiet:")
    quiet = ci.run_all(clean, ctx)
    for c, (f, msg) in quiet.items():
        print(f"  {'FAIL' if f else 'ok  '} {c}: {msg}")
        if f:
            FAILS.append("clean/" + c)
    print("planted defects:")
    for name, fn, codes in [("identical V/S", p_pairs, ["PAIRS"]), ("missing S", p_pairs_missing, ["PAIRS"]),
                            ("long code", p_length, ["LENGTH"]), ("test-split src_idx", p_train_split, ["TRAIN_SPLIT"]),
                            ("V src not vulnerable", p_label_v, ["LABEL_SOURCE"]),
                            ("S src not fixed twin", p_label_s, ["LABEL_SOURCE"]),
                            ("text edited", p_text, ["TEXT_SOURCE"]), ("test hash", p_overlap_hash, ["TEST_OVERLAP"]),
                            ("project cap", p_cap, ["PROJECT_CAP"]), ("few pairs", p_floor_pairs, ["FLOOR"]),
                            ("few projects", p_floor_projects, ["FLOOR"])]:
        expect(name, mutate(clean, fn), ctx, codes)
    expect("test project", mutate(clean, lambda i: p_overlap_project(i, ctx)), ctx, ["TEST_OVERLAP"])
    test_bands(clean, ctx)
    test_stripper()
    test_quiet_variants(clean, ctx)
    test_cli(clean)
    print("ALL PASS" if not FAILS else f"FAILED: {FAILS}")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
