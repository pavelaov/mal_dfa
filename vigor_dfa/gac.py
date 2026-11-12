"""Malicious generate-and-consume with fresh authentication (alg:gac, thm:gac).

Streams the (Gen) lines of alg:gen for the two target-path generator states and the (Eval) lines of alg:eval for the local evaluator state, level by level. Each correction word is computed from the expanded children of the two generator seeds and the target bit alpha_i, applied to the generator states under their old control bits t_0, t_1 and to both evaluator children under the evaluator's old control bit t_tilde, and erased only after that use; t . s denotes a conditional XOR (alg:gac). The evaluator state starts from the party's own root seed and the fixed control bit b, never from a later generator state; the two state sets live in distinct contexts, and each pipeline context keeps separate registers for the *old* generator control bits and the old evaluator control bit (Sec. VI-A, thm:gac prerequisites). The raw share never leaves the module: the epilogue lines of alg:gac replace it with a freshly authenticated tuple, so thm:main needs no DPF key-privacy term.

Inputs and outputs (Sec. V-D "Inputs and outputs"): the query x is read from a verified masked opening of the same gate, never from unchecked host data; the target alpha and the payload come from the gate's protected preprocessing record, so they are joint draws; beta is the gate payload. The gate label must be VERIFIED in the ledger before this call (alg:gac line 1), and the caller marks it CONSUMED afterwards; labels for roots and pads are drawn from the reserved label (S4, S5).

Roots: the two root seeds are the joint draws of dpf._derive_root under purposes "root-0"/"root-1" - byte-identical to the roots of dpf.Gen, so the coupling of thm:gac (streaming GaC versus the materialized alg:gen/alg:eval of dpf.py on the same label) is testable and holds node by node.

Cost accounting (Sec. VI-A, prg.py docstring): each PRG expansion costs two AES-128 blocks. A GaC output performs 3n expansions per module (two generator states plus one evaluator state per level), i.e. 6n blocks, plus three blocks for the output conversion and the four pads, for the architecture's 6n + 3 blocks per GaC output. The reference model draws pads with the SHAKE joint PRF and expands with the pinned AES-128 PRG of prg.py; the aes_blocks counter reports the architecture's accounting. Full-domain uses (LUT gates, PIR scans) keep each CW^{(i)} in protected registers until its level is fully expanded, which costs O(n) words, and a complete tree takes 2^n - 1 internal expansions (Sec. VI-A); thm:gac applies node by node to every dependency-respecting depth-first order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional, Sequence

from . import prg
from .auth import (AuthVal, Counters, FieldOps, FIELD61, bits_draw, sublabel)
from .dpf import _derive_root
from .epilogue import Epilogue, EpilogueState
from .params import N as NBITS

# Declared AES-block accounting of Sec. VI-A.
AES_BLOCKS_PER_EXPANSION = 2
AES_BLOCKS_CONVERSION_AND_PADS = 3


@dataclass
class GaCState:
    """The three separate states of alg:gac: the two generator states
    (s0, t0), (s1, t1) on the target path, the evaluator state (st, tt) on
    the query path, the current level, and the AES-block counter. Seeds are
    128-bit integers; prg.expand_seed/convert take them as 16-byte words."""
    s0: int
    t0: int
    s1: int
    t1: int
    st: int
    tt: int
    level: int = 0
    aes_blocks: int = 0


def _gen_level(key: bytes, s0: int, t0: int, s1: int, t1: int, a: int):
    """One (Gen) level of alg:gac: expands both target-path states, forms
    CW^{(i)} = (sCW, tCW_L, tCW_R) from the target bit a, and advances both
    generator states using their *old* control bits."""
    s0L, t0L, s0R, t0R = prg.expand_seed(key, s0.to_bytes(16, "big"))
    s1L, t1L, s1R, t1R = prg.expand_seed(key, s1.to_bytes(16, "big"))
    keep, lose = a, 1 - a
    s0keep = s0L if keep == 0 else s0R
    t0keep = t0L if keep == 0 else t0R
    s1keep = s1L if keep == 0 else s1R
    t1keep = t1L if keep == 0 else t1R
    sCW = (s0L if lose == 0 else s0R) ^ (s1L if lose == 0 else s1R)
    tCWL = t0L ^ t1L ^ a ^ 1
    tCWR = t0R ^ t1R ^ a
    s0n = s0keep ^ (sCW if t0 else 0)
    t0n = t0keep ^ (tCWL if (t0 and keep == 0) else (tCWR if (t0 and keep == 1) else 0))
    s1n = s1keep ^ (sCW if t1 else 0)
    t1n = t1keep ^ (tCWL if (t1 and keep == 0) else (tCWR if (t1 and keep == 1) else 0))
    return s0n, t0n, s1n, t1n, sCW, tCWL, tCWR


def gac_raw(key: bytes, label, role: int, x: int, alpha: int, beta: int,
            counters: Optional[Counters] = None, ops: FieldOps = FIELD61,
            nbits: int = NBITS) -> int:
    """The (Gen) and (Eval) lines of alg:gac; returns the raw local share
    ytilde_b = (-1)^b (Conv(s_tilde) + t_tilde . CWout), which never leaves
    the module. The enclosing gate applies the ledger lines and one epilogue
    to its combined raw share (Appendix B). Counts two AES blocks per PRG
    expansion (6n blocks); the conversion and pad blocks are charged by the
    enclosing gate (6n + 3 per GaC output, Sec. VI-A)."""
    if role not in (0, 1):
        raise ValueError("role must be 0 or 1")
    n = nbits
    s0 = int.from_bytes(_derive_root(key, label, "root-0"), "big")
    s1 = int.from_bytes(_derive_root(key, label, "root-1"), "big")
    t0, t1 = 0, 1
    st, tt = (s0, 0) if role == 0 else (s1, 1)
    aes = 0
    for i in range(1, n + 1):
        a = (alpha >> (n - i)) & 1
        s0, t0, s1, t1, sCW, tCWL, tCWR = _gen_level(key, s0, t0, s1, t1, a)
        aes += 2 * AES_BLOCKS_PER_EXPANSION
        # (Eval) own query path; corrections use the old evaluator bit tt
        shL, thL, shR, thR = prg.expand_seed(key, st.to_bytes(16, "big"))
        aes += AES_BLOCKS_PER_EXPANSION
        shL = shL ^ (sCW if tt else 0)
        thL = thL ^ (tCWL if tt else 0)
        shR = shR ^ (sCW if tt else 0)
        thR = thR ^ (tCWR if tt else 0)
        xi = (x >> (n - i)) & 1
        st, tt = (shL, thL) if xi == 0 else (shR, thR)
        # CW^{(i)} is erased after its evaluator use (alg:gac line 10)
    # (Gen) output correction from the final generator states
    u0 = prg.convert(key, s0.to_bytes(16, "big"))
    u1 = prg.convert(key, s1.to_bytes(16, "big"))
    cw_out = ops.add(ops.sub(beta, u0), u1)
    if t1 == 1:
        cw_out = ops.neg(cw_out)
    # (Eval) raw share, never exported
    u = prg.convert(key, st.to_bytes(16, "big"))
    raw = ops.add(u, ops.mul(tt, cw_out))
    if role == 1:
        raw = ops.neg(raw)
    if counters is not None:
        counters.aes_blocks += aes
    return ops.add(raw, 0)


def gac_gate(key: bytes, label, role: int, x: int, beta: int,
             delta: Sequence[int], state: Optional[GaCState] = None,
             counters: Optional[Counters] = None, ops: FieldOps = FIELD61,
             nbits: int = NBITS) -> AuthVal:
    """alg:gac in full: joint draws, streaming (Gen) + (Eval), output
    conversion and the fresh authentication epilogue. The gate label must be
    VERIFIED in the ledger before this call and is marked CONSUMED by the
    caller afterwards (alg:gac lines 1 and 14).

    alpha is a joint draw from the gate's protected preprocessing record
    (purpose "target"); roots and pads carry distinct sublabels, and the
    local role is never appended to a joint draw (Sec. V-C). The AES-block
    counter reports 6n + 3 blocks per output (Sec. VI-A: 3n expansions of
    two blocks each, one conversion block, two pad blocks)."""
    if counters is None:
        counters = Counters()
    alpha = bits_draw(key, sublabel(label, "target"), nbits)
    raw = gac_raw(key, label, role, x, alpha, beta, counters, ops, nbits)
    counters.aes_blocks += AES_BLOCKS_CONVERSION_AND_PADS
    ep = Epilogue(key, tuple(delta), ops)
    pads = ep.fresh_pads(key, label)
    out = ep.authenticate(raw, EpilogueState(role, pads, counters))
    if state is not None:
        state.level = nbits
        state.aes_blocks = counters.aes_blocks
    return out


def stream_full_domain(key: bytes, label, role: int, target: int, nbits: int,
                       counters: Optional[Counters] = None,
                       ops: FieldOps = FIELD61) -> Iterator[tuple[int, int]]:
    """Full-domain GaC streaming for LUT gates and PIR scans (alg:gac with the
    depth-first EvalAll traversal of Sec. V-D/V-I): the generator advances
    once per level, the per-level correction word stays in protected registers
    until its level is fully expanded, and every internal node is expanded
    exactly once (2^nbits - 1 internal expansions, Sec. VI-A). Yields
    (a, weight_b) in lexicographic order; the enclosing gate folds the
    weights with the public table or snapshot records and applies one
    epilogue to its combined raw share. AES accounting: two blocks per
    expansion, i.e. 2 (2^nbits - 1 + 2 nbits) blocks, matching the LUT row of
    tab:gates. The payload is 1, the payload of alg:lut and alg:pir."""
    if role not in (0, 1):
        raise ValueError("role must be 0 or 1")
    s0 = int.from_bytes(_derive_root(key, label, "root-0"), "big")
    s1 = int.from_bytes(_derive_root(key, label, "root-1"), "big")
    t0, t1 = 0, 1
    st, tt = (s0, 0) if role == 0 else (s1, 1)
    nodes: list[tuple[int, int]] = [(st, tt)]
    aes = 0
    for i in range(1, nbits + 1):
        a = (target >> (nbits - i)) & 1
        s0, t0, s1, t1, sCW, tCWL, tCWR = _gen_level(key, s0, t0, s1, t1, a)
        aes += 2 * AES_BLOCKS_PER_EXPANSION
        nxt: list[tuple[int, int]] = []
        for (sn, tn) in nodes:
            shL, thL, shR, thR = prg.expand_seed(key, sn.to_bytes(16, "big"))
            aes += AES_BLOCKS_PER_EXPANSION
            shL = shL ^ (sCW if tn else 0)
            thL = thL ^ (tCWL if tn else 0)
            shR = shR ^ (sCW if tn else 0)
            thR = thR ^ (tCWR if tn else 0)
            nxt.append((shL, thL))
            nxt.append((shR, thR))
        nodes = nxt
    u0 = prg.convert(key, s0.to_bytes(16, "big"))
    u1 = prg.convert(key, s1.to_bytes(16, "big"))
    cw_out = ops.add(ops.sub(1, u0), u1)
    if t1 == 1:
        cw_out = ops.neg(cw_out)
    for idx, (sn, tn) in enumerate(nodes):
        u = prg.convert(key, sn.to_bytes(16, "big"))
        w = ops.add(u, ops.mul(tn, cw_out))
        if role == 1:
            w = ops.neg(w)
        yield idx, ops.add(w, 0)
    if counters is not None:
        counters.aes_blocks += aes
