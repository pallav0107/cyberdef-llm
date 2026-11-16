"""Adversarial length debiasing pieces for #6: gradient-reversal layer + length-prediction head. Pure torch."""
from __future__ import annotations
import torch
from torch import nn


class _GRL(torch.autograd.Function):
    @staticmethod
    def forward(ctx, x, lam):
        ctx.lam = float(lam)
        return x.view_as(x)

    @staticmethod
    def backward(ctx, g):
        return g.neg() * ctx.lam, None


class _GRLBroken(torch.autograd.Function):
    """MUTANT used only by the fail-first control: identity backward (reversal missing)."""
    @staticmethod
    def forward(ctx, x, lam):
        return x.view_as(x)

    @staticmethod
    def backward(ctx, g):
        return g, None


def grad_reverse(x, lam):
    return _GRL.apply(x, lam)


def grad_reverse_broken(x, lam):
    return _GRLBroken.apply(x, lam)


class LengthAdversary(nn.Module):
    """linear(d,hidden) -> tanh -> linear(hidden,1) predicting standardised ln(chars) from a pooled hidden state, behind a GRL."""
    def __init__(self, d_model, hidden=16, lam=1.0):
        super().__init__()
        self.lam = lam
        self.net = nn.Sequential(nn.Linear(d_model, hidden), nn.Tanh(), nn.Linear(hidden, 1))

    def forward(self, pooled, target):
        z = grad_reverse(pooled.float(), self.lam)
        pred = self.net(z).squeeze(-1)
        return ((pred - target.float()) ** 2).mean()
