"""Self-test for check_vsp.py: each code fires on a planted defect, clean set stays quiet."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check_vsp as cv  # noqa: E402

N_PAIRS = 320


def make_pair(i, project):
    """V and S differ; the longer one alternates between V and S so no size feature separates."""
    small = "void f(void) {\n" + "".join(f"  stmt_{i}_{j}(x);\n" for j in range(3 + i % 5)) + "  return 0;\n}"
    big = small.replace("  return 0;", "  int pad;\n  int pad2;\n  return 0;")
    v, s = (big, small) if i % 2 == 0 else (small, big)
    return [
        {"id": f"v{i}", "code": v, "label": "VULNERABLE", "pair": i, "project": project, "truncated": False},
        {"id": f"s{i}", "code": s, "label": "SAFE", "pair": i, "project": project, "truncated": False},
    ]


def clean_set():
    cases = []
    for i in range(N_PAIRS):
        cases += make_pair(i, f"synproj{i // 2}")
    return cases


def v_of(cases, i):
    return next(c for c in cases if c["pair"] == i and c["label"] == "VULNERABLE")


def s_of(cases, i):
    return next(c for c in cases if c["pair"] == i and c["label"] == "SAFE")


def plant_identical(c):
    s_of(c, 0)["code"] = v_of(c, 0)["code"]


def plant_trunc_flag(c):
    v_of(c, 0)["truncated"] = True


def plant_trunc_len(c):
    v_of(c, 1)["code"] += "\n" + "/" * 4000


def plant_incomplete(c):
    c.remove(s_of(c, 0))


def plant_cap(c):
    for x in c:
        if x["pair"] < 11:
            x["project"] = "capproj"


def plant_balance(c):
    v_of(c, 0)["project"] = "elsewhere"


def plant_train_project(c, train):
    name = sorted(train[0])[0]
    for x in c:
        if x["pair"] == 0:
            x["project"] = name


def plant_train_code(c, train):
    v_of(c, 0)["code"] = train_body()


def plant_bands(c):
    for x in c:
        if x["label"] == "VULNERABLE":
            x["code"] += "\n" + "\n".join(f"  extra_{x['pair']}_{k};" for k in range(30))


def plant_line_scan(c):
    for x in c:
        tail = "/* tail_v */" if x["label"] == "VULNERABLE" else "/* %06d */" % x["pair"]
        x["code"] = x["code"][:-1] + tail + "\n}"


def plant_small(c):
    c[:] = [x for x in c if x["pair"] < 50]


def train_body():
    """A real train-split function body, with doubled spaces to exercise normalisation."""
    import pandas as pd
    idx = set(json.load(open(cv.SPLITS))["train"])
    df = pd.read_parquet(cv.PARQUET, columns=["idx", "func_body"])
    body = df[df["idx"].isin(idx)]["func_body"].iloc[5]
    return body.replace(" ", "  ")


def fired(cases, train):
    return {k for k, (f, _) in cv.run_all(cases, train).items() if f}


def run_plain(base, train):
    plain = {
        "IDENTICAL_PAIRS": plant_identical, "TRUNCATED": plant_trunc_flag,
        "PAIR_INCOMPLETE": plant_incomplete, "PROJECT_CAP": plant_cap,
        "PROJECT_BALANCE": plant_balance, "BANDS": plant_bands,
        "LINE_SCAN": plant_line_scan, "TOO_SMALL": plant_small,
    }
    for code, fn in plain.items():
        c = copy.deepcopy(base)
        fn(c)
        got = fired(c, train)
        assert code in got, f"{code} did not fire (fired: {got})"
        print(f"ok {code} (fired: {sorted(got)})")


def run_special(base, train):
    c = copy.deepcopy(base)
    plant_trunc_len(c)
    assert "TRUNCATED" in fired(c, train), "TRUNCATED len>=4000 did not fire"
    for fn in (plant_train_project, plant_train_code):
        c = copy.deepcopy(base)
        fn(c, train)
        assert "TRAIN_OVERLAP" in fired(c, train), f"TRAIN_OVERLAP not fired by {fn.__name__}"
    only = copy.deepcopy(base)
    plant_line_scan(only)
    assert fired(only, train) == {"LINE_SCAN"}, "tail-line plant should fire LINE_SCAN alone"


def run_comments(base, train):
    """a fix comment on SAFE texts only (an equal-length statement on VULNERABLE texts) must fire BANDS"""
    c = copy.deepcopy(base)
    for x in c:
        add = "\n// check len\n" if x["label"] == "SAFE" else "\nint _pad_x;\n"
        x["code"] = x["code"].replace("\n", add, 1)
    got = fired(c, train)
    assert "BANDS" in got, f"comment plant should fire BANDS, fired: {got}"
    print(f"ok BANDS comments plant (fired: {sorted(got)})")


def run_cli():
    py, script = sys.executable, str(HERE / "check_vsp.py")
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "clean.json"
        p.write_text(json.dumps({"cases": clean_set()}))
        r = subprocess.run([py, script, str(p)], capture_output=True, text=True)
        assert r.returncode == 0, f"CLI on clean set exit {r.returncode}: {r.stdout}{r.stderr}"
        r = subprocess.run([py, script, str(p), "--expect-refuse", "BANDS"], capture_output=True, text=True)
        assert r.returncode == 1, "expect-refuse on a clean set must exit non-zero"
        r = subprocess.run([py, script, str(Path(d) / "nope.json")], capture_output=True, text=True)
        assert r.returncode == 2, "missing file must exit 2"


def main():
    train = cv.load_train()
    base = clean_set()
    quiet = fired(base, train)
    assert not quiet, f"clean set should be quiet, fired: {quiet}"
    print("ok clean set quiet")
    run_plain(base, train)
    run_special(base, train)
    run_comments(base, train)
    run_cli()
    print("ALL PASS")


if __name__ == "__main__":
    main()
