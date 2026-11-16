"""#6 mechanical check: a ridge probe predicting ln(chars) from the final-layer hidden state at the last prompt token. The adversarially trained adapter must
give a LOWER held-out R^2 than the plain control (and both are reported next to the untuned base). Data: PrimeVul validation natural sample (benchdata), 400 cases, 70/30 split.
  python3 scripts/imp_probe_length.py --out results/imp_6_probe.json --adapters out/imp_advctl out/imp_adv"""
import argparse, json, math, sys
sys.path.insert(0, "src")
import torch
from cyberdef.evaluate import SYSTEM, make_user
from cyberdef.train import _ids
from cyberdef import model_io, benchdata

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--adapters", nargs="*", default=[])
ap.add_argument("--model", default="Qwen/Qwen2.5-7B-Instruct")
a = ap.parse_args()
cases, _ = benchdata.balanced_sample("primevul", "validation", 200, 0, 4000)
y = torch.tensor([math.log(max(1, len(c["code"]))) for c in cases], dtype=torch.float64)
res = {"n": len(cases), "split": "first 70% train / last 30% test (cases in file order after seeded balanced sampling)", "probes": {}}


def r2_for(model, tok):
    H = []
    with torch.no_grad():
        for c in cases:
            ids = torch.tensor([_ids(model_io.chat_prompt(tok, SYSTEM, make_user(c["code"]), tensors=False))], device=model.device)
            out = model(ids, output_hidden_states=True)
            H.append(out.hidden_states[-1][0, -1].double().cpu())
    X = torch.stack(H)
    X = (X - X.mean(0)) / (X.std(0) + 1e-6)
    k = int(0.7 * len(cases))
    Xtr, Xte, ytr, yte = X[:k], X[k:], y[:k], y[k:]
    mu = ytr.mean()
    lam = 10.0 * Xtr.shape[1]
    w = torch.linalg.solve(Xtr.T @ Xtr + lam * torch.eye(Xtr.shape[1], dtype=torch.float64), Xtr.T @ (ytr - mu))
    pred = Xte @ w + mu
    return float(1 - ((yte - pred) ** 2).sum() / ((yte - yte.mean()) ** 2).sum())


for name in ["base"] + a.adapters:
    model, tok = model_io.load_hf(a.model, adapter=None if name == "base" else name)
    model.eval()
    res["probes"][name] = {"r2_test": round(r2_for(model, tok), 4)}
    print(name, res["probes"][name], flush=True)
    del model; torch.cuda.empty_cache()
json.dump(res, open(a.out, "w"), indent=1)
