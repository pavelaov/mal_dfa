"""Exact tree-based distributed point function of the paper.

Paper references
----------------
* Algorithms: Paper Sec. IV-B, Alg. 1 (``DPF.Gen``, label ``alg:gen``)
  and Alg. 2 (``DPF.Eval`` / ``DPF.EvalAll``, label ``alg:eval``); the
  definition is Paper Sec. II (label ``sec:bg-fss``, ``eq:dpf``).
* Correctness: Paper App. B, ``thm:dpf-correct`` (for every root pair,
  target, query and payload: ``y_0 + y_1 = beta * 1[x = alpha]``).
* Key format and size: Paper Sec. IV-C -- party ``b``'s key holds its
  initial root seed ``s_b^(0)``, the role bit ``b``, the ``n``
  correction words ``CW^(i) = (sCW, tCW^L, tCW^R)`` of ``128 + 2`` bits
  and the 64-bit ``CWout``; the final generator states are *never*
  substituted for the roots (Paper Sec. IV-B, App. B).

Conventions implemented
-----------------------
* The target ``alpha`` and the query ``x`` have ``n`` bits read most
  significant bit first; children are indexed ``L = 0``, ``R = 1``.
* ``t * v`` is the conditional XOR (Paper App. B "Conventions").
* Both generator updates and evaluator corrections use the *old*
  control bit (Paper Sec. IV-B, Alg. 1 line 5-6 and App. B).
* The payload ``beta`` and the role enter only through ``CWout`` and the
  output sign ``(-1)^b``.

Mapping assumptions
-------------------
* The paper's ``Gen`` samples independent roots ``s_0, s_1 <- {0,1}^128``;
  in the protected module these are joint PRF draws under distinct
  purposes (technical specification Sec. 3: "DO distinguish logical
  root-0 and root-1 draws").  This reference derives
  ``s_b = AES_K(sha256(encoded label)[:16])`` for the label with
  purpose ``root-0`` / ``root-1`` -- a documented, deterministic model
  of the joint sampler.  Freshness across gates comes from the
  session/epoch/gate fields of the label, exactly as in the ledgered
  module.
* The expansion and conversion are keyed by the joint AES-128 key
  ``K`` (see ``vigor_dfa.prg``).  The paper's key structure contains
  only the root seed, correction words and ``CWout``; the software key
  object additionally carries ``K`` so that ``Eval(k, x)`` is
  self-contained, mirroring the hardware where the key context lives in
  the AES engine and never in the transmitted key (Paper Sec. IV-B,
  VI).  ``key_size`` counts only the transmitted components.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .params import LAMBDA, MASK64, N, P, Label
from .field import fadd, fneg, fsub
from .prg import AES128, convert, expand_seed

__all__ = ["DPFKey", "Gen", "Eval", "EvalAll", "key_size", "key_size_bytes"]


@dataclass(frozen=True)
class DPFKey:
    """Party ``b``'s DPF key (Paper Sec. IV-B, Alg. 1 line 8).

    ``cw`` lists ``CW^(1)..CW^(n)`` in level order; each entry is the
    tuple ``(sCW, tCW^L, tCW^R)`` of a 128-bit seed correction and two
    control-bit corrections.  ``key`` is the joint AES-128 key context
    attached by the software model (see the module docstring); it is not
    part of the paper's transmitted key, which ``key_size`` counts.
    """

    party: int
    n: int
    seed: bytes
    cw: list
    cw_out: int
    key: bytes = None

    def __post_init__(self) -> None:
        if self.party not in (0, 1):
            raise ValueError("party must be 0 or 1")
        if self.n < 1:
            raise ValueError("n must be >= 1")
        if len(self.seed) != 16:
            raise ValueError("seed must be 16 bytes")
        if len(self.cw) != self.n:
            raise ValueError("a depth-n key holds exactly n correction words")
        if not 0 <= self.cw_out < P:
            raise ValueError("cw_out must be a canonical field element")


def _label_domain(label: Label) -> bytes:
    """Deterministic 16-byte domain separation of a ledger label."""
    if label.role not in (0, 1):
        raise ValueError("label role must be 0 or 1")
    purpose = label.purpose.encode("ascii", "strict")
    if len(purpose) > 255:
        raise ValueError("label purpose must be at most 255 bytes")
    payload = (
        struct.pack(
            ">QQQB",
            label.session & MASK64,
            label.epoch & MASK64,
            label.gate & MASK64,
            label.role,
        )
        + bytes([len(purpose)])
        + purpose
    )
    return hashlib.sha256(payload).digest()[:16]


def _derive_root(key: bytes, label: Label, purpose: str) -> bytes:
    """Joint root draw under the label with the given purpose."""
    root_label = Label(label.session, label.epoch, label.gate, label.role, purpose)
    return AES128(key).encrypt_block(_label_domain(root_label))


def Gen(key: bytes, label: Label, alpha: int, beta: int, n: int = N):
    """``DPF.Gen`` (Paper Sec. IV-B, Alg. 1, label ``alg:gen``).

    Generates the key pair ``(k0, k1)`` for the point function
    ``f(alpha, beta)`` on ``{0,1}^n``: target ``alpha`` (MSB first),
    payload ``beta`` in ``F_p``, roots derived from ``(key, label)``.
    Returns ``(k0, k1)`` sharing the same correction words.
    """
    if not 0 <= alpha < (1 << n):
        raise ValueError("alpha out of range for the n-bit domain")
    if not 0 <= beta < P:
        raise ValueError("beta must be a canonical field element")

    s0 = _derive_root(key, label, "root-0")
    s1 = _derive_root(key, label, "root-1")
    s0_init, s1_init = s0, s1          # save the initial seeds (Alg. 1 line 2)
    s0 = int.from_bytes(s0, "big")     # states are 128-bit ints below
    s1 = int.from_bytes(s1, "big")
    t0, t1 = 0, 1                      # root control bits fixed by role

    cws = []
    for i in range(1, n + 1):
        a = (alpha >> (n - i)) & 1     # target bit, MSB first
        keep, lose = a, 1 - a          # L = 0, R = 1

        s0L, t0L, s0R, t0R = expand_seed(key, s0.to_bytes(16, "big"))
        s1L, t1L, s1R, t1R = expand_seed(key, s1.to_bytes(16, "big"))

        s_cw = (s0L if lose == 0 else s0R) ^ (s1L if lose == 0 else s1R)
        t_cw_l = t0L ^ t1L ^ a ^ 1
        t_cw_r = t0R ^ t1R ^ a

        s0k, t0k = (s0L, t0L) if keep == 0 else (s0R, t0R)
        s1k, t1k = (s1L, t1L) if keep == 0 else (s1R, t1R)
        t_cw_keep = t_cw_l if keep == 0 else t_cw_r

        # conditional XOR with the OLD control bits (Alg. 1 lines 5-6)
        s0 = s0k ^ (s_cw if t0 else 0)
        t0 = t0k ^ (t_cw_keep if t0 else 0)
        s1 = s1k ^ (s_cw if t1 else 0)
        t1 = t1k ^ (t_cw_keep if t1 else 0)

        cws.append((s_cw, t_cw_l, t_cw_r))

    u0 = convert(key, s0.to_bytes(16, "big"))
    u1 = convert(key, s1.to_bytes(16, "big"))
    # CWout = (-1)^(t1) * (beta - u0 + u1), canonical in F_p (Alg. 1 line 9)
    cw_out = fadd(fsub(beta, u0), u1)
    if t1:
        cw_out = fneg(cw_out)

    k0 = DPFKey(party=0, n=n, seed=s0_init, cw=list(cws), cw_out=cw_out, key=key)
    k1 = DPFKey(party=1, n=n, seed=s1_init, cw=list(cws), cw_out=cw_out, key=key)
    return k0, k1


def Eval(k: DPFKey, x: int) -> int:
    """``DPF.Eval`` (Paper Sec. IV-B, Alg. 2, label ``alg:eval``):
    party ``k.party``'s share ``y_b`` at query ``x`` (single leaf).

    The evaluator starts from ``(s_b^(0), b)`` and corrects *both*
    children with its own old control bit before selecting the query
    branch (Paper Sec. IV-B, App. B).
    """
    if k.key is None:
        raise ValueError("the DPF key carries no AES key context; use Gen()")
    if not 0 <= x < (1 << k.n):
        raise ValueError("x out of range for the key's domain")

    s = int.from_bytes(k.seed, "big")
    t = k.party
    for i in range(1, k.n + 1):
        sL, tL, sR, tR = expand_seed(k.key, s.to_bytes(16, "big"))
        s_cw, t_cw_l, t_cw_r = k.cw[i - 1]
        if t:
            sL ^= s_cw
            tL ^= t_cw_l
            sR ^= s_cw
            tR ^= t_cw_r
        if (x >> (k.n - i)) & 1:
            s, t = sR, tR
        else:
            s, t = sL, tL

    raw = fadd(convert(k.key, s.to_bytes(16, "big")), k.cw_out if t else 0)
    return raw if k.party == 0 else fneg(raw)


def EvalAll(k: DPFKey) -> list:
    """``DPF.EvalAll`` (Paper Sec. IV-B, Alg. 2, label ``alg:eval``):
    all ``2^n`` leaf shares of party ``k.party`` in leaf-index order.

    Iterative left-first depth-first traversal with one explicit stack;
    the complete tree expands each of the ``2^n - 1`` internal nodes
    exactly once and keeps only ``O(n)`` pending siblings (Paper
    Sec. II, App. B).
    """
    if k.key is None:
        raise ValueError("the DPF key carries no AES key context; use Gen()")

    out = [0] * (1 << k.n)
    stack = [(int.from_bytes(k.seed, "big"), k.party, 0, 0)]
    while stack:
        s, t, depth, prefix = stack.pop()
        if depth == k.n:
            raw = fadd(
                convert(k.key, s.to_bytes(16, "big")), k.cw_out if t else 0
            )
            out[prefix] = raw if k.party == 0 else fneg(raw)
            continue
        sL, tL, sR, tR = expand_seed(k.key, s.to_bytes(16, "big"))
        s_cw, t_cw_l, t_cw_r = k.cw[depth]
        if t:
            sL ^= s_cw
            tL ^= t_cw_l
            sR ^= s_cw
            tR ^= t_cw_r
        # push right first so the left child is visited first
        stack.append((sR, tR, depth + 1, (prefix << 1) | 1))
        stack.append((sL, tL, depth + 1, (prefix << 1) | 0))
    return out


def key_size(n: int) -> int:
    """Transmitted key size of one party in bits (Paper Sec. IV-C):
    ``|k| = LAMBDA + n * (LAMBDA + 2) + 64`` -- root seed, ``n``
    correction words of ``128 + 2`` bits, 64-bit ``CWout``.  The root
    control bit is the public role.  Does not include the software-only
    AES key context carried by :class:`DPFKey`."""
    return LAMBDA + n * (LAMBDA + 2) + 64


def key_size_bytes(n: int) -> int:
    """``key_size`` rounded up to whole bytes (1016 B at ``n = 61``,
    Paper Sec. IV-C)."""
    return (key_size(n) + 7) // 8
