"""Benchmark dataset registry. One place that knows each recognized dataset's HF id, split
names, and which fields hold the code and the vulnerable/safe label. Lets the same training
and eval code target Devign (CodeXGLUE) or PrimeVul without per-dataset forks.

All sampling is balanced + seeded so accuracy has a 50% chance floor, and the training-item
builder drops any train function whose whitespace-normalised text also appears in val/test
(leakage guard) -- essential for PrimeVul, which has near-duplicate functions across splits.
"""
from __future__ import annotations
import glob
import os
import random
from datasets import load_dataset

# DiverseVul ships as plain parquet splits in its HF snapshot, so it loads from the local cache
# directly (load_dataset by repo id needs a Hub round-trip and fails under HF_HUB_OFFLINE=1).
# The glob matches whatever snapshot revision is cached; if nothing matches we fall back to the
# Hub id. This is the ONLY dataset wired for offline parquet because it is used purely as an
# unseen cross-dataset TEST set (train on PrimeVul -> test on DiverseVul) to measure transfer.
_HF_HUB = os.path.expanduser("~/.cache/huggingface/hub")
_DV = f"{_HF_HUB}/datasets--bstee615--diversevul/snapshots/*/data"

# Independent transfer sets (plan step E), all loaded from local files so they work offline.
_RV = f"{_HF_HUB}/datasets--claudios--ReVeal/snapshots/*/data"
_D2A = f"{_HF_HUB}/datasets--claudios--D2A/snapshots/*/function"
_CASTLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "castle",
                       "datasets", "CASTLE-C250.json")

# Multi-language extension (EXPERIMENT_PLAN_MULTILANG.md): function-level Java / Python / JS+TS data
# derived from CrossVul v2.0 and an OWASP Benchmark test set, built offline by scripts/build_multilang.py
# into data/multilang/out/<name>/<split>.parquet. See data/MULTILANG_DATA.md.
_ML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "multilang", "out")


def _ml(name, splits):
    return dict(hf=f"local:multilang/{name}", splits={s: s for s in splits}, func="code", label="label",
                id="id", parquet={s: f"{_ML}/{name}/{s}.parquet" for s in splits})


BENCHES = {
    "devign": dict(hf="google/code_x_glue_cc_defect_detection",
                   splits=dict(train="train", validation="validation", test="test"),
                   func="func", label="target"),
    "primevul": dict(hf="colin/PrimeVul",
                     splits=dict(train="train", validation="validation", test="test"),
                     func="func", label="target"),
    "diversevul": dict(hf="bstee615/diversevul",
                       splits=dict(train="train", validation="validation", test="test"),
                       func="func", label="target",
                       parquet=dict(train=f"{_DV}/train-*.parquet",
                                    validation=f"{_DV}/validation-*.parquet",
                                    test=f"{_DV}/test-*.parquet")),
    # ReVeal (Chromium + Debian, patch-diff labels). Columns: hash, project, size, label,
    # functionSource.
    "reveal": dict(hf="claudios/ReVeal",
                   splits=dict(train="train", validation="validation", test="test"),
                   func="functionSource", label="label", id="hash",
                   parquet=dict(train=f"{_RV}/train-*.parquet",
                                validation=f"{_RV}/validation-*.parquet",
                                test=f"{_RV}/test-*.parquet")),
    # D2A `function` subset (Infer differential labels). Columns: id, label, code. Its official
    # test split is UNLABELLED (all -1), so the labelled evaluation split is "validation" = the
    # official `dev` file (596 rows); "train" is labelled too but is not used for evaluation.
    "d2a": dict(hf="claudios/D2A",
                splits=dict(train="train", validation="dev", test="test"),
                func="code", label="label", id="id",
                parquet=dict(train=f"{_D2A}/train-*.parquet",
                             validation=f"{_D2A}/dev-*.parquet",
                             test=f"{_D2A}/test-*.parquet")),
    # CASTLE C250: 250 hand-written C programs, per-program boolean `vulnerable` (150 vulnerable /
    # 100 non-vulnerable). Local JSON (git clone of CASTLE-Benchmark into data/castle/).
    "castle": dict(hf="CASTLE-Benchmark/CASTLE-Benchmark",
                   splits=dict(test="test"), func="code", label="vulnerable", id="name",
                   local_json=_CASTLE, json_key="tests"),
    "ml_java": _ml("ml_java", ("train", "validation", "test")),
    "ml_python": _ml("ml_python", ("train", "validation", "test")),
    "ml_js": _ml("ml_js", ("train", "validation", "test")),      # JavaScript + TypeScript together
    "owasp_java": _ml("owasp_java", ("test",)),                  # OWASP Benchmark v1.2, test only
}


def spec(name):
    if name not in BENCHES:
        raise SystemExit(f"unknown dataset '{name}'; choices: {list(BENCHES)}")
    return BENCHES[name]


def _load_split(sp, split, streaming=False):
    """Load one split, preferring cached local parquet (offline-safe) when the registry entry
    declares a parquet glob and files exist; otherwise load from the Hub id as before."""
    if sp.get("local_json"):
        import json
        path = os.path.normpath(sp["local_json"])
        if not os.path.exists(path):
            raise SystemExit(f"local dataset file missing: {path}")
        return json.load(open(path))[sp["json_key"]]
    pq = sp.get("parquet")
    if pq and split in pq:
        files = sorted(glob.glob(pq[split]))
        if files:
            # data_files as a list is always exposed under the "train" split name by datasets.
            return load_dataset("parquet", data_files=files, split="train", streaming=streaming)
    return load_dataset(sp["hf"], split=sp["splits"][split], streaming=streaming)


def _is_vuln(v) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "vulnerable", "yes")
    return bool(v)


def norm(code: str) -> str:
    return "".join((code or "").split())


def _row_code(r, sp):
    return r[sp["func"]] or ""


def _mk(r, sp, max_chars):
    code = _row_code(r, sp)
    rid = r.get(sp["id"]) if sp.get("id") else r.get("idx", r.get("id", ""))
    return dict(id=str(rid),
                code=code[:max_chars], code_chars=len(code),
                truncated=len(code) > max_chars,
                label="VULNERABLE" if _is_vuln(r[sp["label"]]) else "SAFE")


def balanced_sample(name, split, n_per_class, seed, max_chars, cap_to_pool=False):
    """Balanced n_per_class vulnerable + n_per_class safe from the named split. With cap_to_pool=True
    (opt-in; default behaviour unchanged) n is reduced to the smaller class so the sample stays balanced
    when a pool is short (e.g. held-out-project test of the multi-language sets)."""
    sp = spec(name)
    ds = _load_split(sp, split)
    vuln, safe = [], []
    for r in ds:
        (vuln if _is_vuln(r[sp["label"]]) else safe).append(r)
    rng = random.Random(seed)
    rng.shuffle(vuln); rng.shuffle(safe)
    if cap_to_pool:
        n_per_class = min(n_per_class, len(vuln), len(safe))
    rows = vuln[:n_per_class] + safe[:n_per_class]
    rng.shuffle(rows)
    return [_mk(r, sp, max_chars) for r in rows], dict(n_vuln=len(vuln), n_safe=len(safe))


def train_items(name, n_per_class, seed, max_chars, stream_cap=200000):
    """Balanced training items from the TRAIN split, with any function duplicated in val/test
    removed (leakage guard) plus intra-train dedup. The train split is STREAMED (not fully
    downloaded): on a flaky link we only need the prefix that yields the balanced sample, so we
    stop as soon as both buckets are full. Selection is therefore stream-order (not globally
    shuffled) -- an acceptable training-data bias; the TEST metric uses a balanced random
    sample and is unaffected. val/test are loaded normally (smaller) for the forbid set."""
    sp = spec(name)
    forbid = set()
    for s in ("validation", "test"):
        for r in _load_split(sp, s):
            forbid.add(norm(_row_code(r, sp)))
    ds = _load_split(sp, "train", streaming=True)
    vuln, safe, seen, dropped, scanned = [], [], set(), 0, 0
    for r in ds:
        scanned += 1
        if scanned > stream_cap:
            break
        h = norm(_row_code(r, sp))
        if h in forbid or h in seen:
            dropped += 1
            continue
        seen.add(h)
        bucket = vuln if _is_vuln(r[sp["label"]]) else safe
        if len(bucket) < n_per_class:
            bucket.append(_mk(r, sp, max_chars))
        if len(vuln) >= n_per_class and len(safe) >= n_per_class:
            break
    items = vuln + safe
    random.Random(seed).shuffle(items)
    return items, dict(n_vuln=len(vuln), n_safe=len(safe), dropped=dropped,
                       scanned=scanned, forbid=len(forbid))


def train_items_multi(names, seed, max_chars, stream_cap=200000):
    """Multi-language training items (EXPERIMENT_PLAN_MULTILANG.md). For each dataset in `names`: run
    train_items() with its own leakage guard (val/test of THAT dataset) taking every available
    vulnerable function, then keep an equal number of safe ones (random, seeded). Concatenate and
    shuffle with the seed. Single-dataset callers keep using train_items(); this is additive."""
    items, per = [], {}
    for name in names:
        got, st = train_items(name, 10 ** 9, seed, max_chars, stream_cap)
        vuln = [x for x in got if x["label"] == "VULNERABLE"]
        safe = [x for x in got if x["label"] != "VULNERABLE"]
        random.Random(f"{seed}:{name}").shuffle(safe)
        safe = safe[:len(vuln)]
        items += vuln + safe
        per[name] = dict(st, n_vuln_used=len(vuln), n_safe_used=len(safe))
    random.Random(seed).shuffle(items)
    return items, dict(per_dataset=per, total=len(items))
