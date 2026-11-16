"""Acceptance for #6 gradient reversal (written BEFORE src/cyberdef/imp_adv.py). Run from repo root with .venv/bin/python (CPU only).
  check_6.py grl        unit controls on toy tensors:
     G1 forward of grad_reverse is the identity
     G2 backward multiplies the gradient by -lambda exactly (compare with a plain graph)
     G3 lambda=0 blocks the gradient to the features entirely
     G4 BROKEN variant (identity backward) must be detected: gradient sign check must FAIL for it (--broken exits 1)
  check_6.py smoke      tiny-LM end-to-end: python scripts/imp_adv_smoke.py must write results/imp_6_smoke.json with
     grads_flow true, grl_grad_is_negated true, adv_mse_final(lambda>0) > adv_mse_final(lambda=0) + margin, task_loss_final < task_loss_initial.
     margin pre-registered = 0.05 (standardised MSE)."""
import json, sys

sys.path.insert(0, "src")


def grl():
    import torch
    from cyberdef import imp_adv
    broken = "--broken" in sys.argv
    fn = imp_adv.grad_reverse_broken if broken else imp_adv.grad_reverse
    fails = []
    x = torch.randn(5, 3, requires_grad=True)
    w = torch.randn(3)
    y = fn(x, 2.0)
    if not torch.allclose(y, x):
        fails.append("G1 forward not identity")
    (y * w).sum().backward()
    g_rev = x.grad.clone()
    x2 = x.detach().clone().requires_grad_(True)
    (x2 * w).sum().backward()
    if not torch.allclose(g_rev, -2.0 * x2.grad):
        fails.append("G2 backward is not -lambda * plain gradient")
    x3 = x.detach().clone().requires_grad_(True)
    (fn(x3, 0.0) * w).sum().backward()
    if x3.grad is not None and x3.grad.abs().sum() > 0:
        fails.append("G3 lambda=0 did not block gradient")
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails]; return 1
    print("PASS: gradient reversal controls G1-G3 hold"); return 0


def smoke():
    try:
        d = json.load(open("results/imp_6_smoke.json"))
    except Exception as e:
        print("FAIL: smoke output missing:", e); return 1
    fails = []
    for k in ("grads_flow", "grl_grad_is_negated"):
        if d.get(k) is not True:
            fails.append(f"{k} not true")
    if not d["adv_mse_final_lam_pos"] > d["adv_mse_final_lam_zero"] + 0.05:
        fails.append("adversary loss did not rise vs lambda=0 control (%s vs %s)" % (d["adv_mse_final_lam_pos"], d["adv_mse_final_lam_zero"]))
    if not d["task_loss_final_lam_pos"] < d["task_loss_initial"]:
        fails.append("task loss did not fall under gradient reversal")
    if fails:
        print("FAIL:"); [print(" -", f) for f in fails]; return 1
    print("PASS: smoke", json.dumps({k: d[k] for k in d if k != "log"})); return 0


if __name__ == "__main__":
    sys.exit(grl() if sys.argv[1] == "grl" else smoke())
