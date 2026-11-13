"""Ground-truth vulnerability-detection dataset (synthetic-by-construction).

Each item's label is correct *by construction* (we emit a known-vulnerable or a
known-safe variant of a real weakness pattern), so the benchmark is honest: no human
labelling error, fully reproducible from the seed. Instances vary by identifier/value
so train and test snippets are textually distinct. Two families (ssrf, weak_token) are
held out entirely for test, to measure generalisation to unseen weakness types.

This is the increment-1 internal benchmark that lets us measure a REAL train->benchmark
delta now. Recognised public benchmarks (CyberSecEval, CTIBench, PrimeVul, injection
suites) are wired as modules in suites.py and integrated next.
"""
from __future__ import annotations
import random
from typing import Callable

VARS = ["user_input", "name", "payload", "raw", "arg", "value", "data", "param",
        "q", "item", "token_in", "req", "field", "x", "entry", "text"]
VALS = ["abc", "foo", "order42", "alpha", "node7", "demo", "svc", "u123", "main", "beta"]


def _id(rng: random.Random) -> str:
    return rng.choice(VARS) + str(rng.randint(0, 999))


def _val(rng: random.Random) -> str:
    return rng.choice(VALS) + str(rng.randint(0, 99))


# Each family: rng -> (vulnerable_code, safe_code). Label is assigned by caller.
def f_sql(rng):
    v = _id(rng)
    return (
        f'def lookup({v}):\n    cur.execute("SELECT * FROM users WHERE name = \'" + {v} + "\'")\n    return cur.fetchone()',
        f'def lookup({v}):\n    cur.execute("SELECT * FROM users WHERE name = %s", ({v},))\n    return cur.fetchone()',
        "CWE-89 SQL Injection",
    )


def f_cmd(rng):
    v = _id(rng)
    return (
        f'import os\ndef ping({v}):\n    os.system("ping -c 1 " + {v})',
        f'import subprocess\ndef ping({v}):\n    subprocess.run(["ping", "-c", "1", {v}], check=True)',
        "CWE-78 OS Command Injection",
    )


def f_path(rng):
    v = _id(rng)
    return (
        f'def read({v}):\n    with open("/var/data/" + {v}) as fh:\n        return fh.read()',
        f'import os\ndef read({v}):\n    safe = os.path.basename({v})\n    with open(os.path.join("/var/data", safe)) as fh:\n        return fh.read()',
        "CWE-22 Path Traversal",
    )


def f_hash(rng):
    v = _id(rng)
    return (
        f'import hashlib\ndef store_pw({v}):\n    return hashlib.md5({v}.encode()).hexdigest()',
        f'import bcrypt\ndef store_pw({v}):\n    return bcrypt.hashpw({v}.encode(), bcrypt.gensalt())',
        "CWE-327 Weak Hash",
    )


def f_secret(rng):
    val = _val(rng)
    return (
        f'API_KEY = "sk_live_{val}{val}"\ndef client():\n    return Service(API_KEY)',
        f'import os\nAPI_KEY = os.environ["API_KEY"]\ndef client():\n    return Service(API_KEY)',
        "CWE-798 Hardcoded Credentials",
    )


def f_deser(rng):
    v = _id(rng)
    return (
        f'import pickle\ndef load({v}):\n    return pickle.loads({v})',
        f'import json\ndef load({v}):\n    return json.loads({v})',
        "CWE-502 Insecure Deserialization",
    )


def f_eval(rng):
    v = _id(rng)
    return (
        f'def calc({v}):\n    return eval({v})',
        f'import ast\ndef calc({v}):\n    return ast.literal_eval({v})',
        "CWE-95 Code Injection via eval",
    )


def f_xss(rng):
    v = _id(rng)
    return (
        f'def render({v}):\n    return "<div>" + {v} + "</div>"',
        f'import html\ndef render({v}):\n    return "<div>" + html.escape({v}) + "</div>"',
        "CWE-79 Cross-Site Scripting",
    )


# ---- held-out families (test only: unseen weakness types) ----
def f_ssrf(rng):
    v = _id(rng)
    return (
        f'import requests\ndef fetch({v}):\n    return requests.get({v}).text',
        f'import requests\nALLOW = {{"api.internal"}}\ndef fetch({v}):\n    host = urlparse({v}).hostname\n    if host not in ALLOW:\n        raise ValueError("blocked host")\n    return requests.get({v}).text',
        "CWE-918 SSRF",
    )


def f_token(rng):
    v = _id(rng)
    return (
        f'import random\ndef new_token():\n    return "".join(random.choice("0123456789abcdef") for _ in range(16))',
        f'import secrets\ndef new_token():\n    return secrets.token_hex(16)',
        "CWE-330 Insufficiently Random Token",
    )


TRAIN_FAMILIES: list[Callable] = [f_sql, f_cmd, f_path, f_hash, f_secret, f_deser, f_eval, f_xss]
HELDOUT_FAMILIES: list[Callable] = [f_ssrf, f_token]


def build_dataset(seed: int = 0, n_per_family: int = 24, n_heldout: int = 12,
                  train_frac: float = 0.7) -> dict:
    rng = random.Random(seed)
    train, test = [], []
    cid = 0
    for fam in TRAIN_FAMILIES:
        insts = [fam(rng) for _ in range(n_per_family)]
        k = int(round(n_per_family * train_frac))
        for i, (vuln, safe, cwe) in enumerate(insts):
            bucket = train if i < k else test
            for code, label in ((vuln, "VULNERABLE"), (safe, "SAFE")):
                bucket.append({"id": cid, "family": fam.__name__[2:], "cwe": cwe,
                               "code": code, "label": label, "heldout": False})
                cid += 1
    for fam in HELDOUT_FAMILIES:
        for _ in range(n_heldout):
            vuln, safe, cwe = fam(rng)
            for code, label in ((vuln, "VULNERABLE"), (safe, "SAFE")):
                test.append({"id": cid, "family": fam.__name__[2:], "cwe": cwe,
                             "code": code, "label": label, "heldout": True})
                cid += 1
    rng.shuffle(train)
    rng.shuffle(test)
    return {"train": train, "test": test}


# ---------- suite registry ----------
def suite_vuln_detect(seed: int = 0) -> list[dict]:
    return build_dataset(seed)["test"]


def _stub(name: str):
    def _f(seed: int = 0):
        raise NotImplementedError(
            f"suite '{name}' not integrated yet. Next increment: wire the recognised "
            f"public benchmark. Defensive/blue-team use only; open-weight teachers only."
        )
    return _f


SUITES = {
    "vuln_detect": suite_vuln_detect,     # IMPLEMENTED
    "secure_code": _stub("secure_code"),   # -> CyberSecEval (Meta Purple Llama)
    "soc_triage": _stub("soc_triage"),     # -> CTIBench / SECURE
    "robustness": _stub("robustness"),     # -> prompt-injection / jailbreak suites
}
