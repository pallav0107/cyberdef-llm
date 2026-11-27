"""Acceptance checker for acceptance/improve/check_template_compat.py (criterion C1 of cyberdef-a6-tooling).

Usage:
  HF_HUB_OFFLINE=1 .venv/bin/python acceptance/improve/check_a6_template.py [--tool F] [--tok-dir D]

THE TOOL CONTRACT (this checker is the spec):
  check_template_compat.py MODEL [MODEL ...]   MODEL = a hub id resolved from the local cache (offline) or a directory
                                                 holding tokenizer files; CPU only, tokenizers only, no weights loaded.
        prints one line per model starting PASS or FAIL; exit 0 iff every model passes, exit 1 if any fails.
  check_template_compat.py --selftest          exit 0 iff it proves it FAILS a think-prefix template and a channel-prefix
                                                 template (and passes a plain one).
The tool must build its prompts with cyberdef.evaluate.SYSTEM and make_user (Qwen3.8's template changes its think block
with the user text, so a hand-written prompt gives a different answer).
What a PASS means, recomputed here independently of the tool: for the training layout of scripts/imp_train.py (system +
user prompt, assistant answer VERDICT: <label>, newline, SITE: ...) the generation prompt ids are a strict prefix of the
full sequence ids, and the tokens after that prefix start with the answer tokens (so the label mask and the verdict slot
are right).
Cases (expected outcome fixed from CURRENT_PLAN.md section 1; the checker first verifies each with its own oracle):
  Qwen/Qwen2.5-7B-Instruct PASS, Qwen/Qwen3.8-27B PASS, Qwen2.5-32B tokenizer PASS (zero change, ChatML),
  DeepSeek-R1-Distill-Qwen-32B tokenizer FAIL (think block opened by the generation prompt, absent from the turn),
  gpt-oss-20b tokenizer FAIL (harmony channel header inserted before the answer: slot shifted by 3),
  plus two synthetic mutants of the Qwen2.5-32B template (think-prefix, channel-prefix) that must FAIL, and an unchanged
  copy that must PASS. Mixed lists exit 1. Tokenizer directories (the R1 / gpt-oss / 32B tokenizer files only) are
  looked up in --tok-dir, $A6_TOK_DIR, ~/a6_tok_fixtures, /tmp/a6_tok (in that order); not found = FIXTURE error (FAIL).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ENV = {**os.environ, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "CUDA_VISIBLE_DEVICES": ""}
CODE = "int f(char *s){\n  char b[8];\n  strcpy(b,s);\n  return 0;\n}"
sys.path.insert(0, str(ROOT / "src"))
from cyberdef.evaluate import SYSTEM, make_user  # noqa: E402  the prompt builders imp_train / imp_selective use
USER = make_user(CODE)


def oracle(path):
    """(prefix_ok, tail_starts_with_target) for both labels, from the tokenizer alone."""
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(path)
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": USER}]
    ids = lambda text: tok(text, add_special_tokens=False)["input_ids"]
    res = []
    for lab in ("VULNERABLE", "SAFE"):
        tgt = f"VERDICT: {lab}\nSITE:   strcpy(b,s);"
        p = ids(tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False))
        full = msgs + [{"role": "assistant", "content": tgt}]
        f = ids(tok.apply_chat_template(full, add_generation_prompt=False, tokenize=False))
        t = ids(tgt)
        res.append((f[:len(p)] == p, f[len(p):][:len(t)] == t))
    return all(a for a, _ in res), all(b for _, b in res)


def find_dir(name, extra):
    for base in [extra, os.environ.get("A6_TOK_DIR"), str(Path.home() / "a6_tok_fixtures"), "/tmp/a6_tok"]:
        if base and (Path(base) / name / "tokenizer.json").is_file():
            return str(Path(base) / name)
    return None


def run_tool(tool, models):
    p = subprocess.run([sys.executable, str(tool), *models], cwd=ROOT, env=ENV, capture_output=True, text=True,
                       timeout=600)
    return p.returncode, p.stdout + p.stderr


Q = chr(39)
BS = chr(92)   # single quote, so the jinja snippets below stay readable
START = Q + "<|im_start|>"
THINK_OLD = "{{- " + START + "assistant" + BS + "n" + Q + " }}"
THINK_NEW = "{{- " + START + "assistant" + BS + "n<think>" + BS + "n" + Q + " }}"
CHAN_OLD = START + Q + " + message.role + " + Q + BS + "n" + Q + " + message.content + " + Q + "<|im_end|>" + Q + " + " + Q + BS + "n" + Q
CHAN_NEW = (START + Q + " + message.role + " + Q + BS + "n" + Q + " + (" + Q + "<|channel|>final<|message|>" + Q
            + " if message.role == " + Q + "assistant" + Q + " else " + Q + Q + ") + message.content + " + Q
            + "<|im_end|>" + Q + " + " + Q + BS + "n" + Q)


def mutant_dir(src, kind, tmp):
    dst = Path(tmp) / kind
    shutil.copytree(src, dst)
    cfg = json.load(open(dst / "tokenizer_config.json"))
    t = cfg["chat_template"]
    old, new = {"think": (THINK_OLD, THINK_NEW), "channel": (CHAN_OLD, CHAN_NEW)}.get(kind, (None, None))
    if old is None:
        return str(dst)
    if old not in t:
        raise RuntimeError(f"cannot build the {kind} mutant: template text not found")
    cfg["chat_template"] = t.replace(old, new)
    json.dump(cfg, open(dst / "tokenizer_config.json", "w"))
    return str(dst)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default=str(ROOT / "acceptance/improve/check_template_compat.py"))
    ap.add_argument("--tok-dir", default=None)
    a = ap.parse_args(argv)
    fails = 0

    def report(ok, name, detail=""):
        nonlocal fails
        fails += 0 if ok else 1
        print(("PASS " if ok else "FAIL ") + name + (" - " + detail if detail else ""), flush=True)

    tool = Path(a.tool)
    if not tool.is_file():
        report(False, "TOOL_EXISTS", f"{tool} does not exist (target not built yet)")
        print(f"RESULT: FAIL ({fails} failed; nothing else can run)")
        return 1
    report(True, "TOOL_EXISTS", str(tool))
    code, out = run_tool(tool, ["--selftest"])
    report(code == 0, "TOOL_SELFTEST", f"exit {code}; {out.strip()[-150:]}")
    tmp = tempfile.mkdtemp(prefix="a6tpl_")
    try:
        dirs = {n: find_dir(n, a.tok_dir) for n in ("q32", "r1", "gptoss")}
        missing = [n for n, d in dirs.items() if not d]
        if missing:
            report(False, "FIXTURE_TOKENIZERS", f"tokenizer dirs not found: {missing} (set A6_TOK_DIR)")
            return 1
        models = {"Qwen/Qwen2.5-7B-Instruct": True, "Qwen/Qwen3.8-27B": True, dirs["q32"]: True,
                  dirs["r1"]: False, dirs["gptoss"]: False}
        for kind, want in (("plain", True), ("think", False), ("channel", False)):
            models[mutant_dir(dirs["q32"], kind, tmp)] = want
        for m, want in models.items():
            label = (m.replace(tmp, "mutant") if tmp in m else m)
            try:
                pre, tail = oracle(m)
            except Exception as exc:  # noqa: BLE001
                report(False, f"FIXTURE_ORACLE {label}", f"{type(exc).__name__}: {exc}")
                continue
            if (pre and tail) != want:
                report(False, f"FIXTURE_ORACLE {label}", f"oracle says prefix={pre} tail={tail}; expected "
                       f"{'compatible' if want else 'incompatible'}")
                continue
            code, out = run_tool(tool, [m])
            lines = [ln for ln in out.splitlines() if ln.startswith(("PASS", "FAIL"))]
            ok = (code == 0) == want and len(lines) == 1 and lines[0].startswith("PASS" if want else "FAIL")
            verb = "accepts" if want else "rejects"
            report(ok, f"TOOL {verb} {label}", f"exit {code}; {lines[:1]}; oracle prefix={pre} tail={tail}")
        good = [m for m, w in models.items() if w][:2]
        bad = [m for m, w in models.items() if not w][0]
        code, out = run_tool(tool, good)
        report(code == 0, "TOOL accepts a list of two compatible models", f"exit {code}")
        code, out = run_tool(tool, [good[0], bad])
        report(code == 1, "TOOL fails a list holding one incompatible model", f"exit {code}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("RESULT: " + ("FAIL" if fails else "PASS") + f" ({fails} failed)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
