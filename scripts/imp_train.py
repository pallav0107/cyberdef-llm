"""imp_train.py: COPY of scripts/train_devign.py (taken 2026-11-14) with extra flags for the imp_ experiments:
  --pair-loss W   pairwise ranking term (items-file in pair-adjacent order, batch = one pair, accum 4)
  --pair-batches  same batching WITHOUT the ranking term (the #1 control)
  --adv-length L  gradient-reversal length adversary (#6)
train_devign.py itself is never modified. Original docstring follows.
QLoRA fine-tune on a registered benchmark's TRAIN split (Devign or PrimeVul via --dataset),
leakage-deduped vs val/test. Teacher-free: targets are the dataset's ground-truth labels.
Lower LR + weight decay + modest epochs so real (non-separable) data does not collapse to a
memorised ~1e-5 loss. Trains + prints an in-process validation sanity; the headline
baseline-vs-tuned comparison is run separately by extbench.py / selective_eval.py on TEST."""
from __future__ import annotations
import argparse, json, math, re
import torch
from transformers import AutoTokenizer, TrainingArguments, Trainer, DataCollatorForSeq2Seq
from datasets import Dataset
import sys
sys.path.insert(0, "src")
from cyberdef.evaluate import SYSTEM, make_user, parse_pred
from cyberdef.train import load_model, _ids
from cyberdef import model_io, benchdata
from cyberdef import imp_adv, imp_pairs


def target(label: str) -> str:
    return f"VERDICT: {label}"


VERDICT_RE = re.compile(r'"verdict"\s*:\s*"(VULNERABLE|SAFE|UNCERTAIN)"')


def verdict_slot(tok, tgt):
    """(vdiv, tid_vuln, tid_safe): index (within the answer tokens) of the token that carries the verdict value, and the vocabulary ids of the
    VULNERABLE / SAFE alternatives at that slot. (-1, 0, 0) if the verdict cannot be located."""
    m = VERDICT_RE.search(tgt)
    if m:
        vs, cur = m.start(1), m.group(1)
    elif tgt.startswith("VERDICT: "):
        vs, cur = len("VERDICT: "), tgt[len("VERDICT: "):].strip()
    else:
        return -1, 0, 0
    if cur not in ("VULNERABLE", "SAFE"):
        return -1, 0, 0
    enc = tok(tgt, add_special_tokens=False, return_offsets_mapping=True)
    ids, offs = enc["input_ids"], enc["offset_mapping"]
    i = next((k for k, o in enumerate(offs) if o[1] > vs), None)
    if i is None:
        return -1, 0, 0
    other = "SAFE" if cur == "VULNERABLE" else "VULNERABLE"
    alt = tok(tgt[:vs] + other + tgt[vs + len(cur):], add_special_tokens=False)["input_ids"]
    if alt[:i] != ids[:i] or len(alt) <= i:
        return -1, 0, 0
    return (i, ids[i], alt[i]) if cur == "VULNERABLE" else (i, alt[i], ids[i])


def build_examples(tok, items):
    feats = []
    for it in items:
        sysm = it.get("system") or SYSTEM
        usr = it.get("user") or make_user(it["code"])
        msgs = [{"role": "system", "content": sysm}, {"role": "user", "content": usr}]
        prompt_ids = _ids(tok.apply_chat_template(msgs, add_generation_prompt=True, return_dict=False))
        tgt = it.get("target") or target(it["label"])
        full = msgs + [{"role": "assistant", "content": tgt}]
        full_ids = _ids(tok.apply_chat_template(full, add_generation_prompt=False, return_dict=False))
        labels = [-100] * len(prompt_ids) + full_ids[len(prompt_ids):]
        vd, tv_, ts_ = verdict_slot(tok, tgt)
        feats.append({"input_ids": full_ids, "attention_mask": [1] * len(full_ids), "labels": labels,
                      "len_feat": math.log(max(1, it.get("code_chars", len(it["code"])))),
                      "vdiv": vd, "tidv": tv_, "tids": ts_, "rank": int(bool(it.get("rank", True)))})
    return Dataset.from_list(feats)


class PairSampler(torch.utils.data.Sampler):
    """Yield 2i, 2i+1 (one adjacent pair = one batch of two) for each pair i of imp_pairs.epoch_order(...).
    The epoch is taken from set_epoch(e) when the Trainer / accelerate call it (the Trainer calls it once per epoch
    before iterating); otherwise the n-th iteration is epoch n. `log` gets one entry per iteration, counting the
    strata of the pairs actually handed out."""

    def __init__(self, strata, mode, seed):
        self.strata, self.mode, self.seed = strata, mode, seed
        self.epoch, self.explicit, self.iters, self.log = 0, False, 0, []

    def set_epoch(self, epoch):
        self.epoch, self.explicit = int(epoch), True

    def __len__(self):
        return 2 * len(self.strata)

    def __iter__(self):
        epoch = self.epoch if self.explicit else self.iters
        self.iters += 1
        entry = {"epoch": epoch, "A": 0, "B": 0, "E": 0, "n_pairs": 0}
        self.log.append(entry)
        for i in imp_pairs.epoch_order(self.strata, self.mode, self.seed, epoch):
            entry[self.strata[i]] += 1
            entry["n_pairs"] += 1
            yield 2 * i
            yield 2 * i + 1


def sampler_summary(strata, mode, seed):
    """Epoch-0 counts and length-only accuracy of the chosen mode."""
    c = imp_pairs.counts(strata, imp_pairs.epoch_order(strata, mode, seed, 0))
    return c, imp_pairs.length_only_acc(c)


def print_balance(items):
    """Class / length-bucket balance of a train set (chars quantile buckets over all items)."""
    import statistics
    ch = sorted(i["code_chars"] for i in items)
    cuts = [ch[int(len(ch) * q / 5)] for q in range(1, 5)]
    rows = {}
    for i in items:
        k = sum(i["code_chars"] > c for c in cuts)
        rows.setdefault(k, [0, 0, [], []])
        rows[k][0 if i["label"] == "VULNERABLE" else 1] += 1
        rows[k][2 if i["label"] == "VULNERABLE" else 3].append(i["code_chars"])
    print("[balance] chars-quintile: vuln/safe counts, median chars vuln/safe", flush=True)
    for k in sorted(rows):
        v, s_, cv, cs = rows[k]
        # an empty class inside a quintile (e.g. category-balanced CoT items) must not crash this diagnostic
        mv = statistics.median(cv) if cv else "empty"
        ms = statistics.median(cs) if cs else "empty"
        print(f"[balance] Q{k+1}: vuln={v} safe={s_} median_chars vuln={mv} safe={ms}", flush=True)
    for lab in ("VULNERABLE", "SAFE"):
        c = [i["code_chars"] for i in items if i["label"] == lab]
        t = [i["toks"] for i in items if i["label"] == lab]
        if not c:
            print(f"[balance] {lab}: n=0 (empty)", flush=True)
            continue
        print(f"[balance] {lab}: n={len(c)} mean_chars={statistics.mean(c):.1f} median_chars={statistics.median(c)} "
              f"mean_toks={statistics.mean(t):.1f}", flush=True)
    from collections import Counter
    pj = Counter(i["project"] for i in items if i["label"] == "VULNERABLE")
    print(f"[balance] top vuln projects: {pj.most_common(6)}", flush=True)


def val_sanity(model, tok, dataset, n_per_class, seed, max_chars, cap_to_pool=False):
    cases, _ = benchdata.balanced_sample(dataset, "validation", n_per_class, seed, max_chars,
                                         cap_to_pool=cap_to_pool)
    model.eval()
    correct = 0
    for c in cases:
        raw = model_io.generate(model, tok, SYSTEM, make_user(c["code"]))
        correct += int(parse_pred(raw) == c["label"])
    print(f"[val-sanity] {dataset} tuned val acc={round(correct/len(cases),4)} (n={len(cases)})", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dataset", default="devign",
                    help="one of %s; or a comma-separated list (e.g. ml_java,ml_python,ml_js) to train one "
                         "adapter on several datasets: each is leakage-guarded on its own, balanced "
                         "per dataset using ALL its vulnerable functions + an equal number of safe "
                         "(--n-per-class is ignored), then concatenated and shuffled with --seed"
                    % ",".join(benchdata.BENCHES))
    ap.add_argument("--n-per-class", type=int, default=1000)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-chars", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--val-per-class", type=int, default=100)
    ap.add_argument("--length-match", action="store_true",
                    help="build a LENGTH-MATCHED train set (single dataset only): each vulnerable function "
                         "is paired with a safe one of near-identical chars and tokens (caliper "
                         "--match-tol); --n-per-class becomes the max number of PAIRS")
    ap.add_argument("--match-tol", type=float, default=0.03)
    ap.add_argument("--oversample-project", default=None,
                    help="with --length-match: duplicate matched pairs whose PrimeVul project equals this "
                         "(e.g. linux) up to --oversample-factor copies in total")
    ap.add_argument("--oversample-factor", type=int, default=2)
    ap.add_argument("--items-file", default=None,
                    help="JSON {'items':[{code,label,code_chars,toks,project,id}]} (e.g. scripts/build_vulspot_train.py); "
                         "bypasses benchdata and trains on exactly these items")
    ap.add_argument("--pair-loss", type=float, default=0.0, help="weight of -log sigmoid(s_vuln - s_fix); needs --items-file in pair-adjacent order")
    ap.add_argument("--pair-batches", action="store_true", help="batch = one adjacent pair (2 sequences), sequential order, grad-accum 4")
    ap.add_argument("--pair-sampler", choices=imp_pairs.MODES, default="sequential",
                    help="order of the pairs each epoch in pair mode: sequential (file order, the default), shuffle "
                         "(seeded permutation), balanced (every E pair once, the rest half A / half B so a length-only "
                         "rule scores 0.50 every epoch); shuffle and balanced need --items-file in pair-adjacent order")
    ap.add_argument("--adv-length", type=float, default=0.0, help="gradient-reversal strength for the ln(chars) adversary head (0 = off)")
    ap.add_argument("--meta", default="", help="free text recorded in the train log (e.g. bank=quick)")
    ap.add_argument("--logging-steps", type=int, default=10)
    ap.add_argument("--grad-ckpt", choices=["on", "off"], default="on", help="explicit gradient checkpointing + use_cache=False: a pure MEMORY optimisation (identical gradients), not a recipe change")
    ap.add_argument("--adv-hidden", type=int, default=16)
    ap.add_argument("--warmup-steps", type=int, default=15, help="LR warmup steps (default 15 = the previous hardcoded value)")
    ap.add_argument("--dry-run", action="store_true", help="build the data, print balance, then exit")
    a = ap.parse_args()
    torch.manual_seed(a.seed)

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    names = [d.strip() for d in a.dataset.split(",") if d.strip()]
    for d in names:
        benchdata.spec(d)
    if a.items_file:
        import json as _j
        items = _j.load(open(a.items_file))["items"]; stats = {"items_file": a.items_file}
        print_balance(items)
    elif a.oversample_project and not a.length_match:
        raise SystemExit("--oversample-project requires --length-match")
    if a.items_file:
        pass
    elif a.length_match:
        if len(names) != 1:
            raise SystemExit("--length-match supports a single --dataset")
        items, stats = benchdata.train_items_lenmatch(names[0], a.n_per_class, a.seed, a.max_chars, tok,
                                                      a.match_tol, a.oversample_project, a.oversample_factor)
        print_balance(items)
    elif len(names) == 1:
        items, stats = benchdata.train_items(names[0], a.n_per_class, a.seed, a.max_chars)
    else:
        items, stats = benchdata.train_items_multi(names, a.seed, a.max_chars)
    print(f"[data] dataset={a.dataset} items={len(items)} {stats}", flush=True)
    pair_mode = a.pair_loss > 0 or a.pair_batches
    if a.pair_loss > 0 and not a.items_file:
        raise SystemExit("--pair-loss needs --items-file (pair-adjacent order)")
    strata = None
    if a.pair_sampler != "sequential" and not (a.items_file and pair_mode):
        raise SystemExit(f"--pair-sampler {a.pair_sampler} needs --items-file (pair-adjacent order) and "
                         "--pair-batches or --pair-loss")
    if a.items_file and pair_mode:
        try:
            strata = imp_pairs.strata_of_items(items)
        except ValueError as exc:
            if a.pair_sampler != "sequential":
                raise SystemExit(f"--pair-sampler {a.pair_sampler}: {exc}")
    if strata is not None:
        c0, acc0 = sampler_summary(strata, a.pair_sampler, a.seed)
        print(f"[pair-sampler] mode={a.pair_sampler} epoch0 A={c0['A']} B={c0['B']} E={c0['E']} "
              f"length_only_acc={acc0:.2f}", flush=True)
    if a.dry_run:
        return
    ds = build_examples(tok, items)

    model, mode = load_model(a.base)
    from peft import LoraConfig, get_peft_model
    lc = LoraConfig(r=a.lora_r, lora_alpha=a.lora_alpha, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
                    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                    "gate_proj", "up_proj", "down_proj"])
    model = get_peft_model(model, lc)
    if a.grad_ckpt == "on":
        model.config.use_cache = False
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        model.enable_input_require_grads()
    model.print_trainable_parameters()

    adv = None
    if a.adv_length > 0:
        mu = sum(f["len_feat"] for f in ds) / len(ds)
        sd = (sum((f["len_feat"] - mu) ** 2 for f in ds) / len(ds)) ** 0.5 or 1.0
        adv = imp_adv.LengthAdversary(model.config.hidden_size, a.adv_hidden, a.adv_length).to(model.device)
        model.adv_head = adv
        print(f"[adv] length adversary on, lambda={a.adv_length}, ln-chars mean={mu:.3f} sd={sd:.3f}", flush=True)

    args = TrainingArguments(
        output_dir=a.out + "_ckpt",
        per_device_train_batch_size=2 if pair_mode else 1, gradient_accumulation_steps=4 if pair_mode else 8,
        num_train_epochs=a.epochs, learning_rate=a.lr, weight_decay=0.01,
        lr_scheduler_type="cosine", warmup_steps=a.warmup_steps,
        bf16=True, logging_steps=a.logging_steps, save_strategy="no", report_to=[], seed=a.seed,
        remove_unused_columns=False,
        optim=("paged_adamw_8bit" if mode == "4bit" else "adamw_torch"))
    base_coll = DataCollatorForSeq2Seq(tok, label_pad_token_id=-100)

    def coll(feats):
        extra = ("len_feat", "vdiv", "tidv", "tids", "rank")
        b = base_coll([{k: v for k, v in f.items() if k not in extra} for f in feats])
        b["len_feat"] = torch.tensor([f["len_feat"] for f in feats], dtype=torch.float32)
        for k in extra[1:]:
            b[k] = torch.tensor([f[k] for f in feats], dtype=torch.long)
        return b

    class ImpTrainer(Trainer):
        stats = {"ce": [], "pair": [], "adv": []}

        def _get_train_sampler(self, *x, **k):
            if pair_mode and a.pair_sampler != "sequential":
                self.pair_sampler = PairSampler(strata, a.pair_sampler, a.seed)
                return self.pair_sampler
            if pair_mode:
                return torch.utils.data.SequentialSampler(self.train_dataset)
            return super()._get_train_sampler(*x, **k)

        def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
            lf = inputs.pop("len_feat"); vdiv = inputs.pop("vdiv"); tidv = inputs.pop("tidv"); tids = inputs.pop("tids"); rk = inputs.pop("rank")
            need_h = adv is not None
            out = model(**inputs, output_hidden_states=need_h, num_items_in_batch=num_items_in_batch)   # token-weighted CE over the accumulation group, as the stock Trainer does (reviewer finding 1)
            loss = out.loss
            labels = inputs["labels"]
            pos0 = [int((labels[i] != -100).nonzero()[0]) for i in range(labels.shape[0])]
            self.stats["ce"].append(float(loss.detach()))
            if a.pair_loss > 0 and labels.shape[0] == 2 and int(rk.min()) == 1 and int(vdiv.min()) >= 0:
                sc = []
                for i in range(2):
                    lg = out.logits[i, pos0[i] + int(vdiv[i]) - 1].float()
                    sc.append(lg[int(tidv[i])] - lg[int(tids[i])])
                # item 0 is the vulnerable function, item 1 its fix (pair-adjacent order)
                pl = -torch.nn.functional.logsigmoid(sc[0] - sc[1])
                loss = loss + a.pair_loss * pl / self.args.gradient_accumulation_steps   # extra terms are per-microbatch means: scale like the GA-scaled CE
                self.stats["pair"].append(float(pl.detach()))
            if adv is not None:
                h = out.hidden_states[-1]
                pooled = torch.stack([h[i, pos0[i] + max(0, int(vdiv[i])) - 1] for i in range(h.shape[0])])   # position predicting the verdict token
                tgt = ((lf - mu) / sd).to(pooled.device)
                al = adv(pooled, tgt)
                loss = loss + al / self.args.gradient_accumulation_steps
                self.stats["adv"].append(float(al.detach()))
            if len(self.stats["ce"]) % 80 == 0:
                print("[imp] last80 mean ce=%.4f pair=%s adv_mse=%s" % (
                    sum(self.stats["ce"][-80:]) / 80,
                    ("%.4f" % (sum(self.stats["pair"][-80:]) / max(1, len(self.stats["pair"][-80:])))) if self.stats["pair"] else "-",
                    ("%.4f" % (sum(self.stats["adv"][-80:]) / max(1, len(self.stats["adv"][-80:])))) if self.stats["adv"] else "-"), flush=True)
            return (loss, out) if return_outputs else loss

    tr = ImpTrainer(model=model, args=args, train_dataset=ds, data_collator=coll)
    tr.train()
    if getattr(tr, "pair_sampler", None) is not None:
        sampler_log = {"mode": a.pair_sampler, "epochs_iterated": tr.pair_sampler.log}
    else:   # sequential: file order every epoch, so the epoch-0 counts hold for all of them
        sampler_log = {"mode": a.pair_sampler, "epochs_iterated": None,
                       "natural_counts": imp_pairs.counts(strata, range(len(strata))) if strata is not None else None}
    json.dump({"pair_sampler": sampler_log,
               "flags": {"pair_sampler": a.pair_sampler, "pair_loss": a.pair_loss, "pair_batches": a.pair_batches, "adv_length": a.adv_length, "items_file": a.items_file, "meta": a.meta,
                         "dataset": a.dataset, "n_per_class": a.n_per_class, "epochs": a.epochs, "lr": a.lr, "seed": a.seed,
                         "warmup_steps": a.warmup_steps, "base": a.base, "mode": mode},
               "n_train": len(items), "stats_means": {k: (sum(v) / len(v) if v else None) for k, v in ImpTrainer.stats.items()},
               "log_history": tr.state.log_history, "last200": {k: (sum(v[-200:]) / len(v[-200:]) if v else None) for k, v in ImpTrainer.stats.items()}},
              open(a.out.rstrip("/") + "_imp_train_log.json", "w"))
    if adv is not None:
        torch.save(adv.state_dict(), a.out.rstrip("/") + "_adv_head.pt")
    model.save_pretrained(a.out)
    tok.save_pretrained(a.out)
    print(f"[train] saved adapter -> {a.out} (dataset={a.dataset}, mode={mode}, "
          f"n_train={len(items)}, epochs={a.epochs}, lr={a.lr})", flush=True)
    for d in names:
        val_sanity(model, tok, d, a.val_per_class, a.seed, a.max_chars, cap_to_pool=len(names) > 1)


if __name__ == "__main__":
    main()
