#!/usr/bin/env python3
"""Print `model_path=<path>` for a base model id. If its tokenizer already has a chat template, the id is used as-is.
Otherwise (e.g. fdtn-ai/Foundation-Sec-8B, a base model) build models/<name>-chat/: symlinks to the cached HF snapshot
plus a tokenizer_config.json with a plain ### System / ### User / ### Assistant template. Weights are untouched.
Also checks the trainer's assumption that the generation prompt tokenizes as a prefix of the full conversation."""
from __future__ import annotations
import argparse, json, os, sys

TEMPLATE = ("{{ bos_token }}{% for m in messages %}{% if m['role'] == 'system' %}### System\n{{ m['content'] }}\n\n"
            "{% elif m['role'] == 'user' %}### User\n{{ m['content'] }}\n\n"
            "{% elif m['role'] == 'assistant' %}### Assistant\n{{ m['content'] }}{{ eos_token }}\n\n"
            "{% endif %}{% endfor %}{% if add_generation_prompt %}### Assistant\n{% endif %}")


def _ids(x):
    return x["input_ids"] if hasattr(x, "keys") else x


def prefix_ok(tok):
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    p = _ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False))
    f = _ids(tok.apply_chat_template(msgs + [{"role": "assistant", "content": '{"argv": [], "stdin": ""}'}],
                                     add_generation_prompt=False, return_dict=False))
    return f[:len(p)] == p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--models-dir", default="models")
    a = ap.parse_args()
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(a.model)
    if getattr(tok, "chat_template", None):
        print(f"[chatmodel] {a.model} has a chat template; prefix_ok={prefix_ok(tok)}", file=sys.stderr)
        print(f"model_path={a.model}")
        return
    # resolve the cached snapshot dir from a file we know is there (snapshot_download(local_files_only=True) refuses a
    # snapshot that lacks non-essential files such as README.md)
    from huggingface_hub import try_to_load_from_cache
    cfg_path = try_to_load_from_cache(a.model, "config.json")
    if not isinstance(cfg_path, str) or not os.path.exists(cfg_path):
        sys.exit(f"{a.model}: config.json not in the local HF cache")
    snap = os.path.dirname(cfg_path)
    dst = os.path.abspath(os.path.join(a.models_dir, a.model.split("/")[-1] + "-chat"))
    os.makedirs(dst, exist_ok=True)
    for f in os.listdir(snap):
        link = os.path.join(dst, f)
        if f == "tokenizer_config.json":
            continue
        if not os.path.lexists(link):
            os.symlink(os.path.realpath(os.path.join(snap, f)), link)
    cfg = json.load(open(os.path.join(snap, "tokenizer_config.json")))
    cfg["chat_template"] = TEMPLATE
    json.dump(cfg, open(os.path.join(dst, "tokenizer_config.json"), "w"), indent=1)
    tok2 = AutoTokenizer.from_pretrained(dst)
    print(f"[chatmodel] built {dst} (template added); prefix_ok={prefix_ok(tok2)}", file=sys.stderr)
    print(f"model_path={dst}")


if __name__ == "__main__":
    main()
