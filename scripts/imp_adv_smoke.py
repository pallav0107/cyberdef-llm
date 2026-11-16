"""#6 CPU smoke test of gradient reversal on a TINY random-init Qwen2 (no download). Mirrors the pooling used in imp_train.py
(hidden state at the last prompt position, standardised ln chars target). Writes results/imp_6_smoke.json.
 - grads_flow: adversary loss gives non-zero gradient to a backbone parameter when lambda>0
 - grl_grad_is_negated: that gradient equals -lambda x the gradient of the same loss without reversal
 - adv_mse_final_lam_pos > adv_mse_final_lam_zero + 0.05 (adversary made worse by reversal, vs a lambda=0 control)
 - task_loss_final_lam_pos < task_loss_initial (task still learned)
Run: nice -n 19 .venv/bin/python scripts/imp_adv_smoke.py"""
import json, math, random, sys
sys.path.insert(0, "src")
import torch
from transformers import AutoTokenizer, Qwen2Config, Qwen2ForCausalLM
from cyberdef import imp_adv

torch.set_num_threads(6)
tok = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-7B-Instruct")
V = len(tok)


def make_items(n, seed):
    rng = random.Random(seed)
    items = []
    for _ in range(n):
        vul = rng.random() < 0.5
        long_ = rng.random() < (0.8 if vul else 0.2)           # length is 80% predictive of the label: the confound
        filler = " ".join(rng.choice(["alpha", "beta", "gamma", "delta", "x", "y"]) for _ in range(rng.randint(40, 70) if long_ else rng.randint(3, 8)))
        code = ("strcpy(a,b); " if (vul and rng.random() < 0.75) or (not vul and rng.random() < 0.25) else "snprintf(a,n,b); ") + filler
        items.append((code, 1 if vul else 0))
    return items


def enc(code):
    ids = tok("Code: " + code + "\nAnswer:", add_special_tokens=False)["input_ids"]
    return ids


A, B = tok(" V", add_special_tokens=False)["input_ids"][0], tok(" S", add_special_tokens=False)["input_ids"][0]


def run(lam, seed=0, steps=120, bs=8):
    torch.manual_seed(seed)
    cfg = Qwen2Config(vocab_size=V, hidden_size=64, intermediate_size=128, num_hidden_layers=2, num_attention_heads=4, num_key_value_heads=2,
                      max_position_embeddings=512)
    model = Qwen2ForCausalLM(cfg)
    adv = imp_adv.LengthAdversary(64, 16, lam)
    items = make_items(256, 1)
    lens = [math.log(len(c)) for c, _ in items]
    mu = sum(lens) / len(lens); sd = (sum((x - mu) ** 2 for x in lens) / len(lens)) ** 0.5
    opt = torch.optim.AdamW(list(model.parameters()) + list(adv.parameters()), lr=2e-3)
    rng = random.Random(seed)
    log, task_first, adv_hist, task_hist = [], None, [], []
    probe = None
    for step in range(steps):
        batch = rng.sample(items, bs)
        loss_task = 0.0; pooled = []; tg = []
        L = max(len(enc(c)) for c, _ in batch)
        ids = torch.full((bs, L), tok.pad_token_id or 0); mask = torch.zeros(bs, L, dtype=torch.long)
        last = []
        for i, (c, y) in enumerate(batch):
            e = enc(c); ids[i, :len(e)] = torch.tensor(e); mask[i, :len(e)] = 1; last.append(len(e) - 1)
            tg.append((math.log(len(c)) - mu) / sd)
        out = model(input_ids=ids, attention_mask=mask, output_hidden_states=True)
        lg = torch.stack([out.logits[i, last[i]] for i in range(bs)])
        y = torch.tensor([b for _, b in batch])
        tgt_tok = torch.where(y == 1, torch.tensor(A), torch.tensor(B))
        task = torch.nn.functional.cross_entropy(lg[:, [A, B]], 1 - y)    # 2-way CE over {V,S}: label 1 -> index 0
        h = out.hidden_states[-1]
        pooled = torch.stack([h[i, last[i]] for i in range(bs)])
        al = adv(pooled, torch.tensor(tg))
        if step == 0:
            task_first = float(task)
            # gradient-flow / negation test on one backbone parameter
            p = model.model.layers[0].self_attn.q_proj.weight
            g_adv = torch.autograd.grad(al, p, retain_graph=True)[0]
            z = pooled.detach().clone().requires_grad_(True)
            # plain (non-reversed) graph: same loss with reversal strength forced to +1 by double negation
            probe = {"grads_flow": bool(g_adv.abs().sum() > 0)}
            al_plain = adv.lam * 0 + ((adv.net(pooled.float()).squeeze(-1) - torch.tensor(tg)) ** 2).mean()
            g_plain = torch.autograd.grad(al_plain, p, retain_graph=True)[0]
            probe["grl_grad_is_negated"] = bool(torch.allclose(g_adv, -lam * g_plain, rtol=1e-3, atol=1e-6)) if lam > 0 else None
        opt.zero_grad(); (task + al).backward(); opt.step()
        task_hist.append(float(task)); adv_hist.append(float(al))
    return {"task_initial": task_first, "task_final": sum(task_hist[-20:]) / 20, "adv_final": sum(adv_hist[-20:]) / 20, **probe}


r0 = run(0.0, steps=240)
r1 = run(1.0, steps=240)
res = {"grads_flow": r1["grads_flow"], "grl_grad_is_negated": r1["grl_grad_is_negated"], "task_loss_initial": r1["task_initial"],
       "task_loss_final_lam_pos": r1["task_final"], "task_loss_final_lam_zero": r0["task_final"],
       "adv_mse_final_lam_pos": r1["adv_final"], "adv_mse_final_lam_zero": r0["adv_final"], "lambda_pos": 1.0, "steps": 240,
       "note": "tiny random-init Qwen2 (2 layers, d=64) on CPU; length is an 80%-predictive confound in the toy data"}
json.dump(res, open("results/imp_6_smoke.json", "w"), indent=1)
print(json.dumps(res))
