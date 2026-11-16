"""Stage I GPU pass: dump last-prompt-token residual-stream activations of a model (optionally + adapter) for the length-matched eval set and the class-probe set.
Prompt = the standard detector prompt exactly as the logprob scorer builds it (SYSTEM + make_user + generation prompt); activation = hidden state of the LAST prompt token at layers 4,8,...,28 (every 4th + the last).
Output results/imp_acts_<tag>_<set>.npz (ids + one float16 array per layer).  python3 scripts/imp_probe_dump.py --model M [--adapter A] --tag base7b"""
import argparse, json, sys
import numpy as np
sys.path.insert(0, "src")
import torch
from cyberdef.evaluate import SYSTEM, make_user
from cyberdef.train import _ids
from cyberdef import model_io

LAYERS = [4, 8, 12, 16, 20, 24, 28]
SETS = {"pv": "results/lenmatched_eval_cases.json", "class": "results/imp_probe_class_cases.json"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    model, tok = model_io.load_hf(a.model, adapter=a.adapter)
    model.eval()
    dt = next(model.parameters()).dtype
    if dt not in (torch.bfloat16, torch.float16, torch.float32):
        sys.exit(f"LOAD CHECK FAILED: unexpected parameter dtype {dt} (a quantised or broken load would give meaningless activations)")
    print(f"[load check] dtype={dt} device={model.device} adapter={a.adapter}", flush=True)
    for sk, cf in SETS.items():
        cases = json.load(open(cf))["cases"]
        if a.limit:
            cases = cases[:a.limit]
        acts = {L: [] for L in LAYERS}
        for i, c in enumerate(cases):
            ids = torch.tensor([_ids(model_io.chat_prompt(tok, SYSTEM, make_user(c["code"]), tensors=False))], device=model.device)
            with torch.no_grad():
                hs = model(ids, output_hidden_states=True).hidden_states
            if len(hs) != 29:
                sys.exit(f"LOAD CHECK FAILED: expected 29 hidden states (embeddings + 28 layers), got {len(hs)}")
            for L in LAYERS:
                if not torch.isfinite(hs[L][0, -1]).all():
                    sys.exit(f"LOAD CHECK FAILED: non-finite activation at layer {L} case {i}")
                acts[L].append(hs[L][0, -1].float().cpu().numpy().astype(np.float16))
            if i % 200 == 0:
                print(f"[dump {a.tag} {sk}] {i}/{len(cases)}", flush=True)
        for L in LAYERS:
            sd = float(np.stack(acts[L]).astype(np.float32).std(0).mean())
            if sd < 1e-3 or len(acts[L]) != len(cases):
                sys.exit(f"LOAD CHECK FAILED: layer {L} activations degenerate across cases (mean per-dim sd {sd:.2e}, n {len(acts[L])}/{len(cases)})")
        print(f"[load check] {sk}: all layers finite, varying across cases", flush=True)
        np.savez_compressed(f"results/imp_acts_{a.tag}_{sk}.npz", ids=np.array([c["id"] + "|" + c["label"] for c in cases]), **{f"L{L}": np.stack(v) for L, v in acts.items()})
        print("saved", sk, len(cases), flush=True)


if __name__ == "__main__":
    main()
