"""Acceptance checker for the attempt-6 data manifest and hygiene registration (criterion C6 of cyberdef-a6-tooling).

Usage:
  .venv/bin/python acceptance/improve/check_a6_manifest.py

Checks (one PASS/FAIL line each; exit 0 only if all pass). Exit codes alone are weak here: today ci_data_manifest --check and
ci_data_hygiene --check already exit 0 on the old files, so every check also reads the output or the data:
  FILES_PRESENT     results/vsp_dev3_cases.json (800 cases) and results/vsp_pilot_k4b_d3_items.json exist.
  MANIFEST_ENTRIES  both files are in ci_data_manifest.CANONICAL and in data/DATA_MANIFEST.json with the right sha256,
                    byte size, n (800 and the item count of the file) and a non-empty what.
  MANIFEST_CHECK    scripts/ci_data_manifest.py --check exits 0 and reports the files match.
  HYGIENE_CHECK     scripts/ci_data_hygiene.py --check exits 0 and prints "test vspdev3: 800 cases; label text in 0; shared
                    with a training pool: 0" (dev3 is a registered test set that was really checked) and the vspt line (776
                    cases, 0 shared) is still there.
  HYGIENE_SCOPE     ci_data_hygiene.SCOPED_POOLS["vspdev3"] contains the d3 pilot file (dev3 is carved from the final file,
                    so only the d3 pilot is its training pool; unscoped it would collide with every final).
  HYGIENE_ITEMS     scripts/ci_data_hygiene.py --items results/vsp_pilot_k4b_d3_items.json exits 0 and reports its item count.
  VSPT_DISJOINT     recomputed here: 0 whitespace-normalised code hashes and 0 projects shared between the VSP-T cases and
                    the d3 pilot file, and between the VSP-T cases and the dev3 cases.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEV3, D3 = "results/vsp_dev3_cases.json", "results/vsp_pilot_k4b_d3_items.json"
VSPT = "results/vsp_t_cases.json"


def sh(*cmd):
    p = subprocess.run(list(cmd), cwd=ROOT, capture_output=True, text=True, timeout=600)
    return p.returncode, p.stdout + p.stderr


def rows(rel):
    d = json.load(open(ROOT / rel, encoding="utf-8"))
    return next(d[k] for k in ("cases", "items") if k in d)


def h(code):
    return hashlib.sha256(" ".join(code.split()).encode()).hexdigest()


def check_files():
    miss = [f for f in (DEV3, D3) if not (ROOT / f).is_file()]
    if miss:
        return False, f"target not built yet: {miss}"
    return len(rows(DEV3)) == 800, f"dev3 has {len(rows(DEV3))} cases (spec 800); d3 pilot has {len(rows(D3))} items"


def check_manifest_entries():
    sys.path.insert(0, str(ROOT / "scripts"))
    import ci_data_manifest as dm
    man = json.load(open(ROOT / "data/DATA_MANIFEST.json", encoding="utf-8"))["files"]
    canon = {p for p, _ in dm.CANONICAL}
    bad = []
    for f in (DEV3, D3):
        e = man.get(f)
        if f not in canon:
            bad.append(f"{f}: not in CANONICAL")
        if not e:
            bad.append(f"{f}: not in DATA_MANIFEST.json")
            continue
        p = ROOT / f
        want_n = 800 if f == DEV3 else len(rows(f))
        if e["sha256"] != hashlib.sha256(p.read_bytes()).hexdigest() or e["bytes"] != p.stat().st_size \
                or e["n"] != want_n or not e.get("what"):
            bad.append(f"{f}: sha256 / bytes / n (want {want_n}) / what does not match")
    return not bad, f"problems {bad[:4]}"


def check_manifest_cmd():
    code, out = sh(sys.executable, "scripts/ci_data_manifest.py", "--check")
    return code == 0 and "match the manifest" in out, f"exit {code}; {out.strip()[-120:]}"


def check_hygiene_cmd():
    code, out = sh(sys.executable, "scripts/ci_data_hygiene.py", "--check")
    want3 = re.search(r"test vspdev3: 800 cases; label text in 0; shared with a training pool: 0", out)
    wantt = re.search(r"test vspt: 776 cases; label text in 0; shared with a training pool: 0", out)
    return code == 0 and bool(want3) and bool(wantt), f"exit {code}; vspdev3 line {bool(want3)}; vspt line {bool(wantt)}; {out.strip()[-100:]}"


def check_hygiene_scope():
    code = "import sys; sys.path.insert(0, 'scripts'); import ci_data_hygiene as h; print(repr(h.SCOPED_POOLS.get('vspdev3')))"
    rc, out = sh(sys.executable, "-c", code)
    return rc == 0 and D3 in out, f"SCOPED_POOLS['vspdev3'] = {out.strip()[-160:]}"


def check_hygiene_items():
    n = len(rows(D3))
    code, out = sh(sys.executable, "scripts/ci_data_hygiene.py", "--items", D3)
    return code == 0 and f"{n} items" in out, f"exit {code}; {out.strip()[-140:]}"


def check_vspt_disjoint():
    vt = rows(VSPT)
    th, tp = {h(c["code"]) for c in vt}, {c["project"] for c in vt}
    out = []
    bad = False
    for f in (D3, DEV3):
        xs = rows(f)
        hh = sum(1 for x in xs if h(x["code"]) in th)
        pp = sorted({x["project"] for x in xs} & tp)
        bad |= bool(hh or pp)
        out.append(f"{Path(f).name}: {hh} shared code hashes, {len(pp)} shared projects {pp[:2]}")
    return not bad, "; ".join(out)


CHECKS = [("FILES_PRESENT", check_files), ("MANIFEST_ENTRIES", check_manifest_entries),
          ("MANIFEST_CHECK", check_manifest_cmd), ("HYGIENE_CHECK", check_hygiene_cmd),
          ("HYGIENE_SCOPE", check_hygiene_scope), ("HYGIENE_ITEMS", check_hygiene_items),
          ("VSPT_DISJOINT", check_vspt_disjoint)]


def main():
    failed = 0
    for name, fn in CHECKS:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001  a missing file is a FAIL, never a crash
            ok, detail = False, type(exc).__name__ + ": " + str(exc)
        print(("PASS " if ok else "FAIL ") + name + " - " + detail, flush=True)
        failed += 0 if ok else 1
    print("RESULT: " + ("FAIL" if failed else "PASS") + f" ({failed} failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
