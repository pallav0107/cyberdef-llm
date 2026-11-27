#!/usr/bin/env python3
"""CPU-only chat-template / verdict-slot compatibility check for a candidate base model (attempt-6 screen).

  check_template_compat.py MODEL [MODEL ...]   MODEL = hub id (local cache, offline) or a tokenizer directory
  check_template_compat.py --selftest          proves the check FAILS a think-prefix and a channel-prefix template

Prints one line per model, "PASS <model> - ..." or "FAIL <model> - <reason>"; exit 0 iff all pass, 1 if any fails.
Tokenizers only; no weights are loaded. Prompts are built with cyberdef.evaluate.SYSTEM and make_user exactly as
scripts/imp_train.build_examples does (generation prompt = apply_chat_template(system+user, add_generation_prompt),
full = the same plus the assistant turn). A model is compatible iff, for both labels:
  1. the generation-prompt ids are a strict prefix of the full-sequence ids (the label mask is len(prompt_ids));
  2. the tokens after that prefix start with the answer tokens (no hidden header such as a think block or a harmony
     channel between the prompt and the answer), so the pair slot pos0 + vdiv - 1 lands on the verdict token;
  3. the verdict slot is located (vdiv >= 0) and the token at that slot is the label's own verdict token;
  4. the scoring prompt (model_io.chat_prompt) equals the training prompt.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

CODE = "int f(char *s){\n  char b[8];\n  strcpy(b,s);\n  return 0;\n}"
SITE = "  strcpy(b,s);"
FIXTURE_DIRS = (os.environ.get("A6_TOK_DIR"), str(Path.home() / "a6_tok_fixtures"), "/tmp/a6_tok")


def _ids(x):
    x = x["input_ids"] if hasattr(x, "keys") else x
    return list(x)


def check_tok(tok):
    """(ok, reason) for an already-loaded tokenizer."""
    from cyberdef.evaluate import SYSTEM, make_user
    from cyberdef.model_io import chat_prompt
    from imp_train import verdict_slot
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": make_user(CODE)}]
    prompt = _ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False))
    for lab in ("VULNERABLE", "SAFE"):
        tgt = f"VERDICT: {lab}\nSITE: {SITE}"
        full = _ids(tok.apply_chat_template(msgs + [{"role": "assistant", "content": tgt}],
                                            add_generation_prompt=False, return_dict=False))
        ans = tok(tgt, add_special_tokens=False)["input_ids"]
        if full[:len(prompt)] != prompt:
            return False, f"{lab}: generation prompt is not a prefix of the full sequence (label mask would be wrong)"
        tail = full[len(prompt):]
        if tail[:len(ans)] != ans:
            return False, (f"{lab}: tokens after the prompt do not start with the answer tokens "
                           f"(hidden header; tail {tail[:6]} vs answer {ans[:6]})")
        vd, tv, ts = verdict_slot(tok, tgt)
        if vd < 0:
            return False, f"{lab}: verdict slot not located"
        if tail[vd] != (tv if lab == "VULNERABLE" else ts):
            return False, f"{lab}: token at slot {vd} is not the {lab} verdict token"
        if _ids(chat_prompt(tok, SYSTEM, make_user(CODE))) != prompt:
            return False, "scoring prompt differs from the training prompt"
    return True, f"prompt is a strict prefix; answer starts right after it; slot index {vd}; tokens {tv}/{ts}"


def check_model(model):
    from transformers import AutoTokenizer
    try:
        tok = AutoTokenizer.from_pretrained(model)
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot load tokenizer: {type(exc).__name__}: {str(exc)[:120]}"
    try:
        return check_tok(tok)
    except Exception as exc:  # noqa: BLE001  a template that cannot be applied is incompatible, not a crash
        return False, f"{type(exc).__name__}: {str(exc)[:160]}"


def _fixture_base():
    for d in FIXTURE_DIRS:
        if d and (Path(d) / "q32" / "tokenizer.json").is_file():
            return str(Path(d) / "q32")
    return "Qwen/Qwen2.5-7B-Instruct"


def selftest():
    from transformers import AutoTokenizer
    q, bs = chr(39), chr(92)
    start = q + "<|im_start|>"
    think_old = "{{- " + start + "assistant" + bs + "n" + q + " }}"
    think_new = "{{- " + start + "assistant" + bs + "n<think>" + bs + "n" + q + " }}"
    chan_old = start + q + " + message.role + " + q + bs + "n" + q + " + message.content"
    chan_new = (start + q + " + message.role + " + q + bs + "n" + q + " + ("
                + q + "<|channel|>final<|message|>" + q + " if message.role == " + q + "assistant" + q + " else "
                + q + q + ") + message.content")
    base = _fixture_base()
    results = []
    for name, old, new, want in (("plain", None, None, True), ("think-prefix", think_old, think_new, False),
                                 ("channel-prefix", chan_old, chan_new, False)):
        tok = AutoTokenizer.from_pretrained(base)
        if old is not None:
            if old not in tok.chat_template:
                print(f"selftest ERROR: cannot build the {name} mutant from {base}")
                return 1
            tok.chat_template = tok.chat_template.replace(old, new)
        ok, why = check_tok(tok)
        good = ok == want
        results.append(good)
        print(f"selftest {'ok' if good else 'WRONG'}: {name} -> {'compatible' if ok else 'incompatible'} ({why[:90]})")
    return 0 if all(results) else 1


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: check_template_compat.py MODEL [MODEL ...] | --selftest", file=sys.stderr)
        return 2
    bad = 0
    for m in argv:
        ok, why = check_model(m)
        print(("PASS " if ok else "FAIL ") + f"{m} - {why}", flush=True)
        bad += 0 if ok else 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
