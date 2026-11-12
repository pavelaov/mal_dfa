"""Conservative distributed comparison function of the paper.

Paper references
----------------
* Algorithm: Paper App. B, label ``alg:dcf`` (DCF-Cons) -- the DCF is
  assembled from ``n`` prefix DPFs, one per prefix length ``i`` with
  target ``alpha_1..alpha_{i-1} 0`` and payload ``beta * alpha_i``
  (zero payload when ``alpha_i = 0``).  Evaluation sums the ``n``
  prefix evaluations.  Correctness: Paper App. B, ``thm:dcf``.
* Orientation: ``DCF(alpha, beta)(x) = beta * 1[x < alpha]`` on n-bit
  unsigned integers read MSB first (Paper Sec. II, label ``sec:bg-fss``;
  App. B "Orientation").  This is the paper's ``<`` convention; the
  ``>`` orientation used elsewhere is converted explicitly at
  interfaces, never by changing the comparison symbol silently.
* Cost: ``sum_i i = n(n+1)/2`` expanded levels per evaluation, i.e.
  ``O(n^2)``.  The paper proves only this conservative construction;
  an optimized ``O(n)`` DCF is reported only as a projection that
  ``thm:dcf`` does not cover (Paper Sec. IV-C, App. B), so this
  reference does not construct it (``mode="optimized"`` raises
  :class:`NotImplementedError`).
* All ``n`` prefix keys, including zero-payload ones, are generated so
  that the schedule and the module's observable trace stay independent
  of ``alpha`` (Paper App. B, "All n keys, including zero payloads").

Mapping assumptions
-------------------
* "Fresh independent roots, depth i" (Paper App. B, ``alg:dcf``): the
  reference derives every prefix's roots from ``(key, label)`` under a
  distinct purpose ``dcf-prefix-<i>``; in the ledgered module the
  per-prefix labels come from the enclosing gate descriptor, which is
  what the fixed default label models here.
"""

from __future__ import annotations

from . import dpf
from .params import N, P, Label
from .field import fadd

__all__ = ["DCFGen", "DCFEval"]

_CONSERVATIVE = "conservative"


def DCFGen(key: bytes, alpha: int, beta: int, mode: str = _CONSERVATIVE, n: int = N):
    """``DCF.Gen`` (Paper App. B, label ``alg:dcf``).

    Returns ``(K0, K1)``, where ``K_b`` is a tuple of ``n`` DPF keys
    ``(k_b^<1>, ..., k_b^<n>)`` with prefix DPF ``i`` generated on the
    domain ``{0,1}^i``.  Only ``mode="conservative"`` (the construction
    the paper proves) is available.
    """
    if mode == "optimized":
        raise NotImplementedError(
            "the optimized O(n) DCF is not specified by the paper and is "
            "explicitly outside thm:dcf (Paper Sec. IV-C, App. B); this "
            "artifact ships only the proven conservative O(n^2) construction"
        )
    if mode != _CONSERVATIVE:
        raise ValueError("mode must be 'conservative' (or 'optimized', unsupported)")
    if not 0 <= alpha < (1 << n):
        raise ValueError("alpha out of range for the n-bit domain")
    if not 0 <= beta < P:
        raise ValueError("beta must be a canonical field element")

    keys0 = []
    keys1 = []
    for i in range(1, n + 1):
        a_i = (alpha >> (n - i)) & 1               # alpha_i, MSB first
        target = (alpha >> (n - i + 1)) << 1       # alpha_1..alpha_{i-1} 0
        beta_i = beta if a_i else 0                # beta * alpha_i (0 iff alpha_i = 0)
        label_i = Label(0, 0, 0, 0, "dcf-prefix-%d" % i)
        k0i, k1i = dpf.Gen(key, label_i, target, beta_i, n=i)
        keys0.append(k0i)
        keys1.append(k1i)
    return tuple(keys0), tuple(keys1)


def DCFEval(k, x: int) -> int:
    """``DCF.Eval`` (Paper App. B, label ``alg:dcf``): party ``b``'s
    share ``v_b`` of ``beta * 1[x < alpha]`` at query ``x``.

    ``k`` is the party's tuple of ``n`` prefix DPF keys; each prefix DPF
    ``i`` is evaluated at the ``i``-bit prefix ``x_1..x_i = x >> (n-i)``
    and the shares are summed in ``F_p``.
    """
    n = len(k)
    if not 0 <= x < (1 << n):
        raise ValueError("x out of range for the key's domain")
    acc = 0
    for i in range(1, n + 1):
        acc = fadd(acc, dpf.Eval(k[i - 1], x >> (n - i)))
    return acc
