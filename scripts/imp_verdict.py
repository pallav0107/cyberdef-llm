#!/usr/bin/env python3
"""Pre-registered verdict analysis for the imp_* improvement experiments.

Implements addendum 3k M4 and 3l (round verdict) and the TWIN_REPLICATION
pre-registration of acceptance/improve/TWIN_REPLICATION_PREREG_2026-11-16.md
(twinrep verdict). Pure analysis over existing result JSON files: no models are
run, nothing is fetched. The acceptance contract is acceptance/improve/check_verdict.py.

Round: the adapter must beat base, twin and the length / function_count /
static_count baselines by more than 2 combined SE each. Twinrep: the twin must
beat its untrained base (and its length baseline) per set, Holm-corrected over
sets, with seed replications not contradicting the effect.

Round extensions for the supervised real-world round: --twin is optional (two
arms: adapter vs base), --baselines NAME,NAME,... selects the baseline set
(length, function_count, static_count, lines, if_count, comments; default: the
pre-registered three), and --within-cluster adds a pair-weighted within-cluster
AUROC veto: verdict = PASS only if everything required today passes AND the
within-cluster delta (adapter - base) is positive. With --cluster-bootstrap the
within delta also gets a descriptive cluster-resample SE ("se_cluster").

With --cluster-bootstrap (pre-registration FORMAT_R1B, section 5) an additional
cluster-level paired bootstrap (10,000 resamples, seed 0) is computed: cluster
= Juliet source file without its flow suffix _NN[a-z].c/.cpp, so a real-world
V/S pair is one cluster. Round then requires every comparison to pass under
both schemes; twinrep reports it as a per-set sensitivity check only.

With --cluster-by FIELD (part (B) of the VSP-T brief, /tmp/brief_vsp.txt) the
cluster of a case is that case's FIELD value from the cases file (e.g.
--cluster-by project for real-world sets); a case missing the field is
refused. Without the flag clustering is exactly as described above.

  python3 scripts/imp_verdict.py round --cases C.json --adapter F F F --base F F F \
      [--twin F] [--baselines NAME,NAME,...] [--cross NAME=F,F,F ...] \
      [--cluster-bootstrap] [--cluster-by FIELD] [--within-cluster] --out O.json
  python3 scripts/imp_verdict.py twinrep --set NAME CASES BASE TWIN0 [S1 S2 S3] \
      [--set ...] [--cluster-bootstrap] [--cluster-by FIELD] --out O.json
  python3 scripts/imp_verdict.py --selftest
"""
from __future__ import annotations
import hashlib, json, math, os, random, re, sys, tempfile

import numpy as np

sys.dont_write_bytecode = True  # importing the two helpers below must not touch the tree
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "src"), os.path.join(ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cyberdef.imp_common import auroc, hm_se  # noqa: E402
# imp_build_structure_matched only defines functions/regexes at module level (main is
# __main__-guarded), so importing nfun has no side effects.
from imp_build_structure_matched import nfun  # noqa: E402

B = 10000          # paired bootstrap resamples (fixed by the pre-registrations)
SEL_PREFIX = "logprob-scored"
BASELINES = ("length", "function_count", "static_count", "lines", "if_count", "comments")
DEFAULT_BASELINES = ("length", "function_count", "static_count")
USAGE = "usage: imp_verdict.py round|twinrep [--cluster-bootstrap] [--within-cluster] ... | imp_verdict.py --selftest"


class Refused(Exception):
    """Fatal input problem: message goes to stderr, exit code 2, no output file."""


# ---------------------------------------------------------------- loading

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_cases(path):
    cases = load_json(path)["cases"]
    keys = [(c["id"], c["label"]) for c in cases]
    if len(set(keys)) != len(keys):
        raise Refused("%s: duplicate (id,label) keys" % path)
    return cases, keys


def load_result(path, keys):
    d = load_json(path)
    pc = d.get("per_case")
    if not isinstance(pc, list):
        raise Refused("%s: no per_case list" % path)
    got = {(r["id"], r["label"]): float(r["p_vuln"]) for r in pc}
    if len(got) != len(pc):
        raise Refused("%s: %d duplicated (id, label) rows" % (path, len(pc) - len(got)))
    want = set(keys)
    if set(got) != want:
        raise Refused("%s: key mismatch: missing %d (e.g. %s), extra %d (e.g. %s)"
                      % (path, len(want - set(got)), sorted(want - set(got))[:3],
                         len(set(got) - want), sorted(set(got) - want)[:3]))
    return str(d.get("method", "")), [got[k] for k in keys]


def load_model(name, paths, keys):
    if not paths:
        raise Refused("%s: no result files given" % name)
    methods, runs = [], []
    for p in paths:
        m, s = load_result(p, keys)
        methods.append(m)
        runs.append(s)
    if len(set(methods)) != 1:
        raise Refused("%s: mixed methods %s" % (name, sorted(set(methods))))
    det = methods[0].startswith(SEL_PREFIX)
    if not det and len(paths) < 3:
        raise Refused("%s: CoT-scored model needs K >= 3 files, got %d" % (name, len(paths)))
    return {"det": det, "runs": runs}


# ---------------------------------------------------------------- model stats

def labels(keys):
    return [1 if k[1] == "VULNERABLE" else 0 for k in keys]


def split_idx(y):
    return [i for i, t in enumerate(y) if t == 1], [i for i, t in enumerate(y) if t == 0]


def stdev1(xs):
    m = sum(xs) / len(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def balanced_accuracy(scores, y):
    n1 = n0 = c1 = c0 = 0
    for s, t in zip(scores, y):
        if t == 1:
            n1 += 1
            c1 += s >= 0.5
        else:
            n0 += 1
            c0 += s >= 0.5
    return 0.5 * (c1 / n1 + 1.0 - c0 / n0)


def model_stats(runs, y, n1, n0):
    k = len(runs)
    mean = [sum(col) / k for col in zip(*runs)]
    a = auroc(mean, y)
    sr = [auroc(r, y) for r in runs]
    sd = 0.0 if (k < 2 or max(sr) == min(sr)) else stdev1(sr) / math.sqrt(k)
    return {"k": k, "auroc": a, "hm_se": hm_se(a, n1, n0),
            "single_run_auroc": sr, "sd_decode": sd,
            "balanced_accuracy": balanced_accuracy(mean, y)}, mean


# ---------------------------------------------------------------- paired bootstrap

def boot_draws(n1, n0, b=B, seed=0):
    rng = np.random.default_rng(seed)
    return rng.integers(0, n1, (b, n1)), rng.integers(0, n0, (b, n0))


def boot_scores(scores, pos, neg, d1, d0):
    sp = np.array([scores[i] for i in pos], dtype=float)
    sn = np.array([scores[i] for i in neg], dtype=float)
    return np.concatenate((sp[d1], sn[d0]), axis=1)


def auroc_rows(rows, n1):
    """AUROC per row of rows (R, n); the first n1 columns hold positives.

    Tie-averaged ranks, exactly matching cyberdef.imp_common.auroc."""
    n = rows.shape[1]
    order = np.argsort(rows, axis=1, kind="stable")
    sv = np.take_along_axis(rows, order, axis=1)
    diff = np.ones((rows.shape[0], n), dtype=bool)
    diff[:, 1:] = sv[:, 1:] != sv[:, :-1]
    idx = np.arange(n)[None, :]
    start = np.maximum.accumulate(np.where(diff, idx, 0), axis=1)
    ns = np.where(diff, idx, n)                      # next group start per position
    minacc = np.minimum.accumulate(ns[:, ::-1], axis=1)[:, ::-1]
    end = np.concatenate([np.maximum(minacc[:, 1:], idx[:, 1:]), np.full((rows.shape[0], 1), n)], axis=1) - 1
    avg1 = (start + end) / 2.0 + 1.0                 # 1-based tie-averaged rank
    ranks = np.empty_like(rows)
    np.put_along_axis(ranks, order, avg1, axis=1)
    n0 = n - n1
    return (ranks[:, :n1].sum(axis=1) - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def check_vec(scores, y, pos, neg):
    rows = np.asarray([[float(scores[i]) for i in pos] + [float(scores[i]) for i in neg]])
    ref = auroc([float(s) for s in scores], y)
    if ref is None:
        return
    v = float(auroc_rows(rows, len(pos))[0])
    assert abs(v - ref) < 1e-12, "vectorised AUROC %r != imp_common.auroc %r" % (v, ref)


def paired_delta_b(arm, oth, pos, neg, d1, d0):
    n1 = len(pos)
    am = auroc_rows(boot_scores(arm, pos, neg, d1, d0), n1)
    om = auroc_rows(boot_scores(oth, pos, neg, d1, d0), n1)
    return am - om


# ---------------------------------------------------------------- cluster bootstrap

CLUS_RE = re.compile(r"_\d+[a-z]?\.(c|cpp)$")


def cluster_key(cid):
    """Cluster of a case id: Juliet file without its flow suffix, else the id
    with a trailing :V/:S stripped (a real-world pair is one cluster)."""
    parts = cid.split(":")
    if len(parts) >= 3 and CLUS_RE.search(parts[1]):
        return CLUS_RE.sub("", parts[1])
    return re.sub(r":[VS]$", "", cid)


def cluster_by_ids(cases, field):
    """Per-case cluster ids from a case field (--cluster-by FIELD); the whole
    run is refused if any case lacks the field."""
    if any(field not in c for c in cases):
        raise Refused("--cluster-by %s: a case lacks the %r field" % (field, field))
    return [str(c[field]) for c in cases]


def cluster_setup(keys, cid=None):
    """Group case indices by cluster; per cluster the (pos, neg) index arrays.
    cid: optional per-case cluster ids (--cluster-by FIELD), else the id-based
    cluster_key."""
    groups = {}
    for i, k in enumerate(keys):
        ck = cid[i] if cid is not None else cluster_key(k[0])
        groups.setdefault(ck, []).append(i)
    idx, lab = [], []
    for v in groups.values():
        yy = np.array([1 if keys[i][1] == "VULNERABLE" else 0 for i in v])
        ii = np.array(v, dtype=int)
        idx.append(ii)
        lab.append((ii[yy == 1], ii[yy == 0]))
    return idx, lab


def cluster_plan(idx, lab, b=B, seed=0):
    """The B cluster resamples (shared by every comparison): n_cl draws with
    replacement each, keeping every case of a drawn cluster with multiplicity.
    valid marks resamples that contain both labels."""
    rng = np.random.default_rng(seed)
    draws = rng.integers(0, len(idx), (b, len(idx)))
    n1c = np.array([len(p) for p, _ in lab])
    nc = n1c + np.array([len(n) for _, n in lab])
    n1b, nb = n1c[draws].sum(axis=1), nc[draws].sum(axis=1)
    return draws, (n1b > 0) & (n1b < nb)


def cluster_auroc(scores, lab, dr):
    pos = np.concatenate([lab[d][0] for d in dr])
    neg = np.concatenate([lab[d][1] for d in dr])
    row = np.concatenate((scores[pos], scores[neg]))
    return auroc_rows(row[None, :], len(pos))[0]


def cluster_se(arm, oth, lab, draws, valid):
    """Cluster bootstrap SE of auroc(arm) - auroc(oth); same draws both arms."""
    arm, oth = np.asarray(arm, float), np.asarray(oth, float)
    d = [cluster_auroc(arm, lab, dr) - cluster_auroc(oth, lab, dr)
         for dr, ok in zip(draws, valid) if ok]
    return float(np.std(d, ddof=1))


# ---------------------------------------------------------------- within-cluster

def within_auroc(scores, lab):
    """Pair-weighted within-cluster AUROC: sum_c n1_c * n0_c * AUROC_c over
    clusters with both labels, divided by the sum of n1_c * n0_c.

    lab: per-cluster (pos, neg) case-index arrays (cluster_setup). Also
    returns how many clusters had both labels."""
    num = den = 0.0
    used = 0
    for p, n in lab:
        n1c, n0c = len(p), len(n)
        if n1c and n0c:
            s = [float(scores[i]) for i in list(p) + list(n)]
            w = float(n1c * n0c)
            num += w * auroc(s, [1] * n1c + [0] * n0c)
            den += w
            used += 1
    return (num / den if den else None), used


def within_se_cluster(arm, oth, lab, draws, valid):
    """Std (ddof=1) of the within-cluster delta (arm - oth) over the existing
    cluster resample plan; descriptive, does not enter the within pass."""
    ds = []
    for dr, ok in zip(draws, valid):
        if not ok:
            continue
        sub = [lab[d] for d in dr]
        wa, ua = within_auroc(arm, sub)
        wo, _ = within_auroc(oth, sub)
        if ua:
            ds.append(wa - wo)
    return float(np.std(ds, ddof=1))


def comparison(arm, oth, y, pos, neg, d1, d0, hm_arm, hm_oth, sd_arm, sd_oth,
               negate=False, cb=None):
    """Paired comparison of arm vs other; delta = auroc(arm) - auroc(other).

    negate: score `oth` is negated (baseline whose direction is fixed by its
    full-sample auroc). The bootstrap reuses the same index draws for both arms.
    cb: (lab, draws, valid) cluster resample plan; adds the cluster keys."""
    oth = [-v for v in oth] if negate else [float(v) for v in oth]
    arm = [float(v) for v in arm]
    check_vec(arm, y, pos, neg)
    check_vec(oth, y, pos, neg)
    delta = auroc(arm, y) - auroc(oth, y)
    se_boot = float(np.std(paired_delta_b(arm, oth, pos, neg, d1, d0), ddof=1))
    sd = math.sqrt(sd_arm * sd_arm + sd_oth * sd_oth)
    se_comb = math.sqrt(se_boot * se_boot + sd * sd)
    den = None
    if hm_arm is not None and hm_oth is not None:
        den = math.sqrt(hm_arm * hm_arm + hm_oth * hm_oth)
    hm_ds = delta / den if den else None
    out = {"delta": delta, "se_boot": se_boot, "sd_decode": sd, "se_comb": se_comb,
           "pass": bool(delta > 2 * se_comb), "hm_delta_over_se": hm_ds}
    if cb is not None:
        lab, draws, valid = cb
        se_c = cluster_se(arm, oth, lab, draws, valid)
        se_cc = math.sqrt(se_c * se_c + sd * sd)
        out.update(se_boot_cluster=se_c, se_comb_cluster=se_cc,
                   pass_cluster=bool(delta > 2 * se_cc))
    return out


# ---------------------------------------------------------------- baselines / io

def baseline_scores(codes, kind):
    if kind == "length":
        return [float(len(c)) for c in codes]
    if kind == "function_count":
        return [float(nfun(c)) for c in codes]
    if kind == "static_count":
        return [float(len(re.findall(r"\bstatic\b", c))) for c in codes]
    if kind == "lines":
        return [float(c.count("\n") + 1) for c in codes]
    if kind == "if_count":
        return [float(len(re.findall(r"\bif\b", c))) for c in codes]
    if kind == "comments":
        return [float(len(re.findall(r"/\*|(?<![:\\])//", c))) for c in codes]
    raise Refused("unknown baseline %r (choose from %s)" % (kind, ",".join(BASELINES)))


def baseline_kinds(o):
    """The --baselines set (default: the pre-registered three)."""
    raw = o.get("baselines")
    if raw is None:
        return list(DEFAULT_BASELINES)
    kinds = [k for k in raw.split(",") if k]
    bad = [k for k in kinds if k not in BASELINES]
    if bad or not kinds:
        raise Refused("unknown --baselines %s (choose from %s)"
                      % (",".join(bad) or raw, ",".join(BASELINES)))
    return kinds


def write_out(path, payload, inputs):
    payload["inputs"] = {os.path.abspath(p): sha256_of(p) for p in inputs}
    payload["script_sha256"] = sha256_of(os.path.abspath(__file__))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1, sort_keys=True)


def sha256_of(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def parse_opts(argv, multi):
    """Parse `--flag v v --flag2 v` style argv; multi flags take >= 0 values and each
    occurrence appends its value list, other flags take exactly one value."""
    opts = {}
    i = 0
    while i < len(argv):
        t = argv[i]
        if not t.startswith("--"):
            raise Refused("unexpected argument: %r" % t)
        key, i = t[2:], i + 1
        vals = []
        while i < len(argv) and not argv[i].startswith("--"):
            vals.append(argv[i])
            i += 1
        if key in multi:
            opts.setdefault(key, []).append(vals)
        else:
            if len(vals) != 1:
                raise Refused("--%s needs exactly one value" % key)
            opts[key] = vals[0]
    return opts


def flat(opts, key):
    return [v for group in opts.get(key, []) for v in group]


def take_flag(argv, flag):
    """Remove every occurrence of a valueless flag; report whether it was given."""
    return [a for a in argv if a != flag], flag in argv


# ---------------------------------------------------------------- round mode

def run_round(argv):
    argv, clus = take_flag(argv, "--cluster-bootstrap")
    argv, within = take_flag(argv, "--within-cluster")
    o = parse_opts(argv, {"adapter", "base", "twin", "cross"})
    for req in ("cases", "out"):
        if req not in o:
            raise Refused("round: missing --" + req)
    for req in ("adapter", "base"):
        if not flat(o, req):
            raise Refused("round: missing --" + req)
    cases, keys = load_cases(o["cases"])
    y = labels(keys)
    pos, neg = split_idx(y)
    n1, n0 = len(pos), len(neg)
    d1, d0 = boot_draws(n1, n0)
    cb, idx, lab = None, None, None
    if clus or within:
        cid = cluster_by_ids(cases, o["cluster-by"]) if o.get("cluster-by") else None
        idx, lab = cluster_setup(keys, cid)
        if clus:
            draws, valid = cluster_plan(idx, lab)
            cb = (lab, draws, valid)
    arms = ["adapter", "base"] + (["twin"] if flat(o, "twin") else [])
    models, means, sds, hms = {}, {}, {}, {}
    for name in arms:
        st, mean = model_stats(load_model(name, flat(o, name), keys)["runs"], y, n1, n0)
        models[name] = st
        means[name], sds[name], hms[name] = mean, st["sd_decode"], st["hm_se"]
        check_vec(mean, y, pos, neg)
    comparisons, cmp_keys = {}, []
    for name in ("base", "twin"):
        if name not in models:
            continue
        comparisons[name] = comparison(means["adapter"], means[name], y, pos, neg,
                                       d1, d0, hms["adapter"], hms[name],
                                       sds["adapter"], sds[name], cb=cb)
        cmp_keys.append(name)
    codes = [c["code"] for c in cases]
    baselines = {}
    for kind in baseline_kinds(o):
        bs = baseline_scores(codes, kind)
        a = auroc(bs, y)
        baselines[kind] = {"auroc": a, "auroc_best_direction": max(a, 1 - a)}
        neg_k = a < 0.5
        hm_o = hm_se(1 - a if neg_k else a, n1, n0)
        comparisons[kind] = comparison(means["adapter"], bs, y, pos, neg, d1, d0,
                                       hms["adapter"], hm_o, sds["adapter"], 0.0,
                                       negate=neg_k, cb=cb)
        cmp_keys.append(kind)
    cues = {"pct_s_count": {"auroc": auroc([float(c.count("%s")) for c in codes], y)}}
    cross = {}
    inputs = [o["cases"]] + flat(o, "adapter") + flat(o, "base") + flat(o, "twin")
    for spec in o.get("cross", []):
        name, _, fs = spec[0].partition("=")
        fs = [f for f in fs.split(",") if f]
        st, mean = model_stats(load_model(name, fs, keys)["runs"], y, n1, n0)
        cross[name] = {"model": st,
                       "comparison": comparison(means["adapter"], mean, y, pos, neg,
                                                d1, d0, hms["adapter"], st["hm_se"],
                                                sds["adapter"], st["sd_decode"],
                                                cb=cb)}
        inputs += fs
    payload = {"mode": "round", "n": len(keys), "n_vuln": n1,
               "models": models, "comparisons": comparisons,
               "baselines": baselines, "cues": cues, "cross": cross}
    verdict = "PASS" if all(comparisons[k]["pass"] for k in cmp_keys) else "FAIL"
    payload["verdict"] = verdict
    if clus:
        v_cluster = "PASS" if all(comparisons[k]["pass_cluster"] for k in cmp_keys) else "FAIL"
        payload.update(n_clusters=len(idx),
                       cluster_resamples_used=int(np.count_nonzero(valid)),
                       verdict_case=verdict, verdict_cluster=v_cluster,
                       verdict="PASS" if (verdict == "PASS" and v_cluster == "PASS") else "FAIL")
    if within:
        wd = within_block(means["adapter"], means["base"], lab, cb)
        payload["within"] = wd
        payload["verdict_within"] = "PASS" if wd["pass"] else "FAIL"
        if not wd["pass"]:
            payload["verdict"] = "FAIL"
    write_out(o["out"], payload, inputs)


def within_block(arm, oth, lab, cb):
    """The --within-cluster block: pair-weighted within-cluster AUROC of each
    arm, the adapter-minus-base delta, its pass (delta > 0) and, with
    --cluster-bootstrap, the cluster-resample SE of the delta."""
    wa, used = within_auroc(arm, lab)
    wo, _ = within_auroc(oth, lab)
    out = {"adapter": wa, "base": wo, "delta": wa - wo,
           "pass": bool(wa - wo > 0), "clusters_used": used}
    if cb is not None:
        clab, draws, valid = cb
        out["se_cluster"] = within_se_cluster(arm, oth, clab, draws, valid)
    return out


# ---------------------------------------------------------------- twinrep mode

def zscore(delta, se):
    if se > 0:
        return delta / se
    return math.inf if delta > 0 else (-math.inf if delta < 0 else 0.0)


def twin_set(vals, clus=False, by=None):
    if len(vals) < 4:
        raise Refused("--set needs NAME CASES BASE TWIN0 [SEED1 SEED2 SEED3]")
    name, cpath, bpath, t0path, seed_paths = vals[0], vals[1], vals[2], vals[3], vals[4:]
    cases, keys = load_cases(cpath)
    y = labels(keys)
    pos, neg = split_idx(y)
    n1, n0 = len(pos), len(neg)
    d1, d0 = boot_draws(n1, n0)
    _, bsc = load_result(bpath, keys)
    _, t0sc = load_result(t0path, keys)
    seeds = [load_result(p, keys)[1] for p in seed_paths]
    a_base, a_t0 = auroc(bsc, y), auroc(t0sc, y)
    hm_base, hm_t0 = hm_se(a_base, n1, n0), hm_se(a_t0, n1, n0)
    cmp_tb = comparison(t0sc, bsc, y, pos, neg, d1, d0, hm_t0, hm_base, 0.0, 0.0)
    db = paired_delta_b(t0sc, bsc, pos, neg, d1, d0)
    p_one = (int(np.count_nonzero(db <= 0.0)) + 1) / (B + 1)
    seed_deltas, seed_se = {}, {}
    for i, sc in enumerate([t0sc] + seeds):
        c = comparison(sc, bsc, y, pos, neg, d1, d0,
                       hm_se(auroc(sc, y), n1, n0), hm_base, 0.0, 0.0)
        seed_deltas[str(i)], seed_se[str(i)] = c["delta"], c["se_boot"]
    mean_seed = sum(seed_deltas.values()) / len(seed_deltas)
    min_z = min(zscore(seed_deltas[k], seed_se[k]) for k in seed_deltas)
    ls = [float(len(c["code"])) for c in cases]
    a_len = auroc(ls, y)
    neg_l = a_len < 0.5
    cmp_len = comparison(t0sc, ls, y, pos, neg, d1, d0, hm_t0,
                         hm_se(1 - a_len if neg_l else a_len, n1, n0), 0.0, 0.0,
                         negate=neg_l)
    sdict = {"n": len(keys), "n_vuln": n1,
             "base_auroc": a_base, "twin0_auroc": a_t0,
             "delta": cmp_tb["delta"], "se_boot": cmp_tb["se_boot"],
             "p_one_sided": p_one, "hm_delta_over_se": cmp_tb["hm_delta_over_se"],
             "seed_deltas": seed_deltas, "seed_se": seed_se,
             "mean_seed_delta": mean_seed, "min_seed_z": min_z,
             "length_auroc": a_len, "length_best": max(a_len, 1 - a_len),
             "twin_minus_length": cmp_len["delta"], "se_length": cmp_len["se_boot"],
             "pass_twin_vs_base": bool(cmp_tb["delta"] > 2 * cmp_tb["se_boot"]),
             "pass_length": bool(cmp_len["delta"] > 2 * cmp_len["se_boot"])}
    if clus:
        cid = cluster_by_ids(cases, by) if by else None
        idx, lab = cluster_setup(keys, cid)
        draws, valid = cluster_plan(idx, lab)
        se_c = cluster_se(t0sc, bsc, lab, draws, valid)
        sdict.update(n_clusters=len(idx), se_boot_cluster=se_c,
                     pass_twin_vs_base_cluster=bool(cmp_tb["delta"] > 2 * se_c))
    return name, sdict, [cpath, bpath, t0path] + seed_paths


def seeds_ok(sets):
    for nm, s in sets.items():
        if len(s["seed_deltas"]) != 4:   # TWIN_REPLICATION: seeds 0-3 (seed 0 plus seed files 1, 2, 3)
            return False, ["set %s: %d of seeds 0-3 given; the pre-registered seed bar needs all four" % (nm, len(s["seed_deltas"]))]
    reasons = []
    for nm, s in sets.items():
        if not s["mean_seed_delta"] > 0:
            reasons.append("set %s: mean_seed_delta <= 0" % nm)
        for k in sorted(s["seed_deltas"], key=int):
            if s["seed_deltas"][k] < -2 * s["seed_se"][k]:
                reasons.append("set %s seed %s: delta < -2*se" % (nm, k))
    return (not reasons), reasons


def run_twinrep(argv):
    argv, clus = take_flag(argv, "--cluster-bootstrap")
    o = parse_opts(argv, {"set"})
    if "out" not in o:
        raise Refused("twinrep: missing --out")
    specs = o.get("set", [])
    if not specs:
        raise Refused("twinrep: no --set given")
    sets, inputs = {}, []
    for vals in specs:
        nm, sdict, files = twin_set(vals, clus, o.get("cluster-by"))
        sets[nm], inputs = sdict, inputs + files
    m = len(sets)
    p_sorted = sorted(s["p_one_sided"] for s in sets.values())
    holm = {"p_sorted": p_sorted,
            "pass": bool(all(p_sorted[i] < 0.05 / (m - i) for i in range(m)))}
    pass_seeds, reasons = seeds_ok(sets)
    for nm, s in sets.items():
        if not s["pass_twin_vs_base"]:
            reasons.append("set %s: pass_twin_vs_base failed" % nm)
        if not s["pass_length"]:
            reasons.append("set %s: pass_length failed" % nm)
    if not holm["pass"]:
        reasons.append("holm failed")
    if not pass_seeds and not any("seed" in r for r in reasons):
        reasons.append("pass_seeds failed")
    sets_ok = all(s["pass_twin_vs_base"] and s["pass_length"] for s in sets.values())
    verdict = "SUPPORTED" if (sets_ok and holm["pass"] and pass_seeds) else "NOT SUPPORTED"
    write_out(o["out"], {"mode": "twinrep", "n_sets": m, "sets": sets, "holm": holm,
                         "pass_seeds": pass_seeds, "reasons": reasons,
                         "verdict": verdict}, inputs)


# ---------------------------------------------------------------- selftest

SEL = SEL_PREFIX + " verdict (selftest)"
COT = "vLLM SC-CoT (selftest)"


def _st_cases(t):
    cs = []
    for i in range(80):
        lab = "VULNERABLE" if i < 40 else "SAFE"
        cs.append({"id": "c%d" % i, "code": "int fn_1(void) {\n" + ("x;" * (i % 23)) + "\n}\n",
                   "label": lab, "cwe": "CWE000", "pair": "p%d" % (i % 40)})
    p = os.path.join(t, "cases.json")
    json.dump({"cases": cs}, open(p, "w"))
    return p, [(c["id"], c["label"]) for c in cs]


def _st_scores(rng, keys, sig, noise):
    out = []
    for _, lab in keys:
        v = 0.5 + (sig if lab == "VULNERABLE" else -sig) + rng.uniform(-noise, noise)
        out.append(min(1.0, max(0.0, v)))
    return out


def _st_result(path, keys, scores, method=SEL):
    json.dump({"method": method,
               "per_case": [{"id": k[0], "label": k[1], "p_vuln": s}
                            for k, s in zip(keys, scores)]}, open(path, "w"))
    return path


def selftest():
    t = tempfile.mkdtemp(prefix="imp_verdict_selftest_")
    rng = random.Random(0)
    cp, keys = _st_cases(t)
    res = lambda tag, sc, method=SEL: _st_result(os.path.join(t, tag + ".json"), keys, sc, method)
    try:
        out1 = os.path.join(t, "o1.json")
        same = _st_scores(rng, keys, 0.0, 0.2)
        run_round(["--cases", cp, "--adapter", res("s1a", same), "--base", res("s1b", same),
                   "--twin", res("s1t", same), "--out", out1])
        d = json.load(open(out1))
        assert d["verdict"] == "FAIL", d["verdict"]
        assert d["comparisons"]["base"]["delta"] == 0.0
        assert d["comparisons"]["base"]["se_boot"] == 0.0
        assert d["comparisons"]["twin"]["delta"] == 0.0

        out2 = os.path.join(t, "o2.json")
        run_round(["--cases", cp, "--adapter"] + [res("s2a%d" % i, _st_scores(rng, keys, 0.3, 0.1), COT)
                                                  for i in range(3)]
                  + ["--base"] + [res("s2b%d" % i, _st_scores(rng, keys, 0.0, 0.2), COT) for i in range(3)]
                  + ["--twin", res("s2t", _st_scores(rng, keys, 0.0, 0.2)), "--out", out2])
        assert json.load(open(out2))["verdict"] == "PASS"

        mid = _st_scores(rng, keys, 0.15, 0.1)
        e = [rng.uniform(-0.2, 0.2) for _ in keys]
        noise = [[m + x for m, x in zip(mid, e)],
                 [m - x for m, x in zip(mid, e)], mid]
        bse = [_st_scores(rng, keys, 0.0, 0.2) for _ in range(3)]
        outs = []
        for tag, runs in (("ctl", [mid] * 3), ("noi", noise)):
            out = os.path.join(t, "o3%s.json" % tag)
            run_round(["--cases", cp, "--adapter"] + [res("%s%d" % (tag, i), r, COT) for i, r in enumerate(runs)]
                      + ["--base"] + [res("%sb%d" % (tag, i), b, COT) for i, b in enumerate(bse)]
                      + ["--twin", res(tag + "t", bse[0]), "--out", out])
            outs.append(json.load(open(out)))
        a, b = outs[0]["comparisons"]["base"], outs[1]["comparisons"]["base"]
        assert abs(a["delta"] - b["delta"]) < 1e-9
        assert b["se_comb"] > a["se_comb"]
        assert outs[0]["models"]["adapter"]["sd_decode"] == 0.0
        assert outs[1]["models"]["adapter"]["sd_decode"] > 0.0

        bad = res("bad", same)
        bd = json.load(open(bad))
        bd["per_case"] = bd["per_case"][:-1]
        json.dump(bd, open(bad, "w"))
        out4 = os.path.join(t, "o4.json")
        try:
            run_round(["--cases", cp, "--adapter", res("ok", same), "--base", bad,
                       "--twin", res("okt", same), "--out", out4])
            raise AssertionError("key mismatch was not refused")
        except Refused:
            pass
        assert not os.path.exists(out4)

        out5 = os.path.join(t, "o5.json")
        run_twinrep(["--set", "n1", cp, res("tb", same), res("t0", same),
                     res("t1", same), res("t2", same), res("t3", same), "--out", out5])
        d5 = json.load(open(out5))
        assert d5["verdict"] == "NOT SUPPORTED", d5["verdict"]
        assert d5["sets"]["n1"]["delta"] == 0.0

        # cluster bootstrap: advantage concentrated in one Juliet file -> case
        # PASS, cluster FAIL (mirrors the validated T11 design)
        cc, cad, cbs = [], [], []
        for c in range(12):
            for k in range(30 if c == 0 else 5):
                f = "CWE134_Uncontrolled_Format_String__char_src%d_printf_%02d.c" % (c, k + 1)
                for lab in ("VULNERABLE", "SAFE"):
                    b = min(1.0, max(0.0, 0.5 + rng.uniform(-0.25, 0.25)))
                    cc.append({"id": "j3s:%s:%s" % (f, lab[0]), "code": "x;" * (100 + (k * 7 + c) % 200),
                               "label": lab, "cwe": "CWE134", "pair": f})
                    cbs.append(b)
                    cad.append((0.95 if lab == "VULNERABLE" else 0.05) if c == 0 else b)
        ccp = os.path.join(t, "ccases.json")
        json.dump({"cases": cc}, open(ccp, "w"))
        ckeys = [(c["id"], c["label"]) for c in cc]
        cres = lambda tag, sc, method=SEL: _st_result(os.path.join(t, tag + ".json"), ckeys, sc, method)
        outc = os.path.join(t, "oc.json")
        run_round(["--cases", ccp, "--cluster-bootstrap", "--adapter"]
                  + [cres("cc%d" % i, cad, COT) for i in range(3)]
                  + ["--base"] + [cres("cb%d" % i, cbs, COT) for i in range(3)]
                  + ["--twin", cres("ct", cbs), "--out", outc])
        dc = json.load(open(outc))
        assert dc["verdict_case"] == "PASS", dc["comparisons"]["base"]
        assert dc["verdict_cluster"] == "FAIL" and dc["verdict"] == "FAIL", dc["comparisons"]["base"]
        assert dc["n_clusters"] == 12 and 0 < dc["cluster_resamples_used"] <= B
        assert all("pass_cluster" in v for v in dc["comparisons"].values())

        # project clustering (--cluster-by project, VSP-T brief part B): one
        # project carries the whole advantage -> case bootstrap passes, the
        # cluster bootstrap fails
        pc, pad, pbs = [], [], []
        for c in range(12):
            for k in range(30 if c == 0 else 5):
                pair = "p%d_%d" % (c, k)
                for lab in ("VULNERABLE", "SAFE"):
                    b = min(1.0, max(0.0, 0.5 + rng.uniform(-0.25, 0.25)))
                    pc.append({"id": "vsp:%s:%s" % (pair, lab[0]),
                               "code": "y;" * (100 + (k * 3 + c) % 150),
                               "label": lab, "cwe": "CWE000", "pair": pair,
                               "project": "proj%d" % c})
                    pbs.append(b)
                    pad.append((0.95 if lab == "VULNERABLE" else 0.05) if c == 0 else b)
        pcp = os.path.join(t, "pcases.json")
        json.dump({"cases": pc}, open(pcp, "w"))
        pkeys = [(c["id"], c["label"]) for c in pc]
        pres = lambda tag, sc, method=SEL: _st_result(os.path.join(t, tag + ".json"), pkeys, sc, method)
        outp = os.path.join(t, "op.json")
        run_round(["--cases", pcp, "--cluster-bootstrap", "--cluster-by", "project", "--adapter"]
                  + [pres("pc%d" % i, pad, COT) for i in range(3)]
                  + ["--base"] + [pres("pb%d" % i, pbs, COT) for i in range(3)]
                  + ["--twin", pres("pt", pbs), "--out", outp])
        dp = json.load(open(outp))
        assert dp["verdict_case"] == "PASS", dp["comparisons"]["base"]
        assert dp["verdict_cluster"] == "FAIL" and dp["verdict"] == "FAIL", dp["comparisons"]["base"]
        assert dp["n_clusters"] == 12
        print("project-cluster: OK")

        # within-cluster veto (--within-cluster): pooled comparison passes but
        # the pair-weighted within-cluster delta is negative -> FAIL. Two
        # projects, each wrong within itself (V < S), the label-count
        # imbalance makes the pooled adapter AUROC beat the constant base.
        wc, wad, wbs = [], [], []
        for proj, n1c, n0c, va, vs in (("wA", 40, 4, 0.80, 0.90), ("wB", 4, 40, 0.50, 0.60)):
            for i in range(n1c):
                wc.append({"id": "vsp:%s:v%d:V" % (proj, i), "code": "x;", "label": "VULNERABLE",
                           "cwe": "CWE000", "pair": "%s%d" % (proj, i), "project": proj})
                wad.append(va)
                wbs.append(0.5)
            for i in range(n0c):
                wc.append({"id": "vsp:%s:s%d:S" % (proj, i), "code": "x;", "label": "SAFE",
                           "cwe": "CWE000", "pair": "%s%d" % (proj, i), "project": proj})
                wad.append(vs)
                wbs.append(0.5)
        wcp = os.path.join(t, "wcases.json")
        json.dump({"cases": wc}, open(wcp, "w"))
        wkeys = [(c["id"], c["label"]) for c in wc]
        wres = lambda tag, sc: _st_result(os.path.join(t, tag + ".json"), wkeys, sc)
        outw = os.path.join(t, "ow.json")
        run_round(["--cases", wcp, "--adapter", wres("wa", wad), "--base", wres("wb", wbs),
                   "--within-cluster", "--cluster-by", "project", "--out", outw])
        dw = json.load(open(outw))
        assert dw["comparisons"]["base"]["pass"] is True, dw["comparisons"]["base"]
        assert dw["within"]["adapter"] == 0.0 and dw["within"]["base"] == 0.5, dw["within"]
        assert dw["within"]["delta"] == -0.5 and dw["within"]["pass"] is False, dw["within"]
        assert dw["within"]["clusters_used"] == 2, dw["within"]
        assert dw["verdict_within"] == "FAIL" and dw["verdict"] == "FAIL", dw["verdict"]
        print("within-veto: OK")
    except (AssertionError, Refused) as exc:
        print("SELFTEST FAIL: %r" % (exc,))
        return 1
    print("SELFTEST PASS")
    return 0


# ---------------------------------------------------------------- entry point

def main(argv):
    if argv and argv[0] == "--selftest":
        return selftest()
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE, file=sys.stderr)
        return 2
    try:
        if argv[0] == "round":
            run_round(argv[1:])
        elif argv[0] == "twinrep":
            run_twinrep(argv[1:])
        else:
            raise Refused("unknown mode: %r (expected round, twinrep or --selftest)" % argv[0])
    except Refused as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
