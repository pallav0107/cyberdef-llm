"""Usability smoke test: can the trained models actually be LOADED and produce a verdict?
Runs base Qwen2.5-7B vs our PrimeVul-tuned adapter on a few hand-written, unambiguous C
snippets (NOT drawn from any training/eval set) through the real inference path (model_io.generate).
This is the interactive 'does it run and give sane output' check; the statistical quality is the
separately-reported benchmark. Offline, cached model.
"""
import os
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
from cyberdef import model_io
from cyberdef.evaluate import SYSTEM, make_user, parse_pred

CASES = [
    ("strcpy, no bounds check", "VULNERABLE",
     "void copy_name(char *in){\n    char buf[8];\n    strcpy(buf, in);\n}"),
    ("printf of untrusted input (format string)", "VULNERABLE",
     "void log_msg(char *u){\n    printf(u);\n}"),
    ("system() on sprintf'd user host", "VULNERABLE",
     "void ping(char *host){\n    char cmd[256];\n    sprintf(cmd, \"ping -c1 %s\", host);\n    system(cmd);\n}"),
    ("bounds-checked strncpy + NUL", "SAFE",
     "void copy_name(char *in){\n    char buf[64];\n    strncpy(buf, in, sizeof(buf)-1);\n    buf[63] = '\\0';\n}"),
    ("printf with fixed format string", "SAFE",
     "void log_msg(char *u){\n    printf(\"%s\", u);\n}"),
    ("pure arithmetic, no I/O", "SAFE",
     "int add(int a, int b){\n    return a + b;\n}"),
]


def run(label, model_id, adapter):
    print(f"\n{'='*70}\n{label}: {model_id}" + (f" + {adapter}" if adapter else "") + f"\n{'='*70}")
    model, tok = model_io.load_hf(model_id, adapter=adapter)
    ok = 0
    for name, expect, code in CASES:
        out = model_io.generate(model, tok, SYSTEM, make_user(code), max_new_tokens=40)
        pred = parse_pred(out)
        hit = "✓" if pred == expect else "✗"
        if pred == expect:
            ok += 1
        first = out.strip().splitlines()[0] if out.strip() else "(empty)"
        second = ""
        lines = out.strip().splitlines()
        if len(lines) > 1:
            second = " | " + lines[1].strip()
        print(f"  [{hit}] expect {expect:10s} got {pred:10s}  <- {name}")
        print(f"        model said: {first}{second}")
    print(f"  --> {ok}/{len(CASES)} of the illustrative cases correct")
    del model


if __name__ == "__main__":
    run("BASE", "Qwen/Qwen2.5-7B-Instruct", None)
    run("OURS", "Qwen/Qwen2.5-7B-Instruct", "out/qlora-primevul")
