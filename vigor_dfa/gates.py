"""Authenticated nonlinear gates, exact fallback circuits and the matrix check.

Implements the gates of Sec. V-G/V-H/V-I and their exact fallback algorithms
from Appendix D:

  * lut_gate             alg:lut (thm:lut): authenticated small XOR-masked LUT,
                         full-domain GaC scan in fixed lexicographic order;
  * interval_indicator   alg:interval (thm:interval, thm:dcf): shifted
                         intervals with two conservative DCFs derived from one
                         mask, plus the wrap-bit sharing;
  * polynomial_gate      the Horner evaluation of alg:interval (thm:arith):
                         d authenticated products, independent of the number
                         of pieces;
  * direct_gate          the direct protected gate of Sec. V-G (thm:arith):
                         after a verified opening c = x + r the module holds c
                         and r, computes x = c - r inside its boundary,
                         evaluates the approved deterministic g and returns a
                         fresh authenticated sharing through AuthShare;
  * bitdec / cmp / trunc alg:bitdec / alg:trunc (thm:bitdec, thm:cmp-trunc):
                         2n authenticated multiplications and 2n + 1 rounds
                         for bit decomposition, 5n + 2 multiplications and
                         5n + 4 rounds for exact toward-zero signed
                         truncation (122/123 and 307/309 for n = 61);
  * exact_comparison     the one-round interval candidate of alg:interval on
                         [0, theta); cmp() is the bit-based fallback;
  * freivalds            alg:freivalds (thm:freivalds): frozen-operand
                         Freivalds check with s = 3 secret challenge vectors,
                         soundness p^{-s}.

Conventions (Appendix D): alg:bitdec/alg:trunc use canonical bits LSB-first,
the opposite of the MSB-first DPF path convention; the two never meet inside
one algorithm. Every secret product goes through Pi_Mult (beaver_mul in
auth.py) and its opened differences; the caller supplies fresh one-time
triples and an open_fn that performs the CheckOpen batch (the reference tests
reconstruct the differences from both parties' shares).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from . import field, gac
from .auth import (AuthVal, Counters, FieldOps, FIELD61, beaver_mul,
                   auth_add, auth_add_public, auth_neg, auth_scalar, auth_sub,
                   bits_draw, field_draw, public_constant, share_from_draws,
                   sublabel)
from .epilogue import Epilogue, EpilogueState
from .ledger import AbortError


def gate_mask(key: bytes, label, p: int, nbits: int) -> int:
    """The joint field mask r of alg:interval/alg:bitdec and of direct gates,
    drawn by one joint draw under purpose "mask"; the caller opens
    c = x + r with the same sublabel (Sec. V-G)."""
    return field_draw(key, sublabel(label, "mask"), p, nbits)


def authenticated_xor(x: AuthVal, r: AuthVal, triple, open_fn,
                      party: int, delta_share: Sequence[int],
                      counters: Optional[Counters] = None,
                      ops: FieldOps = FIELD61) -> AuthVal:
    """The host-side XOR product of alg:lut: u_i = x_i + r_i - 2 x_i r_i via
    Pi_Mult; the w products of one LUT form one batched multiplication round
    (tab:gates footnote)."""
    d, e = open_fn(x, r, triple)
    pr = beaver_mul(x, r, triple, d, e, delta_share, party, counters, ops)
    return auth_add(auth_add(x, r, ops), auth_scalar(pr, (-2) % ops.p, ops), ops)


def lut_gate(key: bytes, label, party: int, delta: Sequence[int], u: int,
             r: int, w: int, table: Sequence[int],
             counters: Optional[Counters] = None,
             ops: FieldOps = FIELD61) -> AuthVal:
    """alg:lut inside T_b: ytilde_b = sum_a T[a xor u] . DPF.Eval(k_b, a) over
    the full public domain in fixed lexicographic order, streamed by GaC so
    the key k_b is never materialized; one epilogue authenticates and
    reshares the combined raw share. u is the CheckOpen-verified masked
    vector (both modules check Boolean encoding and hold the same vector) and
    r is the joint mask that is also the DPF target for (r, 1) - the two are
    one logical draw and are never resampled independently (thm:lut,
    lem:bijection). AES accounting: two blocks per expansion,
    2 (2^w - 1 + 2w) blocks, matching the LUT row of tab:gates."""
    if len(table) != 1 << w:
        raise AbortError("table length mismatch")
    if not (0 <= u < (1 << w)) or not (0 <= r < (1 << w)):
        raise AbortError("masked vector out of range")
    raw = 0
    for a, weight in gac.stream_full_domain(key, label, party, r, w, counters, ops):
        raw = ops.add(raw, ops.mul(table[a ^ u], weight))
    if counters is not None:
        counters.field_mults += 1 << w  # the 2^w weighted table products
    ep = Epilogue(key, tuple(delta), ops)
    pads = ep.fresh_pads(key, label)
    return ep.authenticate(raw, EpilogueState(party, pads, counters))


def interval_indicator(key: bytes, label, party: int, delta: Sequence[int],
                       c: int, a: int, b: int,
                       counters: Optional[Counters] = None,
                       ops: FieldOps = FIELD61) -> AuthVal:
    """alg:interval for a proper nonempty public interval [a, b) subset [0, p):
    the module derives L = (a + r) mod p, H = (b + r) mod p and the wrap bit
    omega = 1[L > H] from the same joint mask r that the caller used to open
    c = x + r; it then evaluates two conservative DCFs (thm:dcf, orientation
    1[. < theta], payload 1, independent coins per prefix) by streaming GaC
    and hands the combined raw share
        stilde_b = omega_b + DCF_H(c)_b - DCF_L(c)_b
    to one epilogue. By thm:interval the reconstructed value is
    1[a <= x < b]; empty and full intervals are public constants. AES
    accounting: 6n(n + 1) blocks for the two thresholds (3n(n + 1) each),
    matching the conservative-DCF row of tab:gates; the thresholds and the
    wrap-bit sharing never leave the modules."""
    r = gate_mask(key, label, ops.p, ops.n)
    L = ops.add(a, r)
    H = ops.add(b, r)
    if L == H:
        raise AbortError("empty or full interval is a public constant")
    omega = 1 if L > H else 0
    w0 = bits_draw(key, sublabel(label, "wrap_share"), 1)
    w1 = ops.sub(omega, w0)
    raw = w0 if party == 0 else w1
    for theta, tag in ((H, "dcf_H"), (L, "dcf_L")):
        for i in range(1, ops.n + 1):
            # prefix DPF i of alg:dcf: target alpha_1..alpha_{i-1}0, payload theta_i (kept if zero), evaluated at the prefix c_1..c_i
            target = (theta >> (ops.n - i + 1)) << 1
            payload = (theta >> (ops.n - i)) & 1
            query = c >> (ops.n - i)
            raw_i = gac.gac_raw(key, sublabel(label, f"{tag}:{i}"), party,
                                query, target, payload, counters, ops, i)
            if tag == "dcf_H":
                raw = ops.add(raw, raw_i)
            else:
                raw = ops.sub(raw, raw_i)
    ep = Epilogue(key, tuple(delta), ops)
    pads = ep.fresh_pads(key, label)
    return ep.authenticate(raw, EpilogueState(party, pads, counters))


def direct_gate(key: bytes, label, party: int, delta: Sequence[int], c: int,
                r: int, g: Callable[[int], int],
                counters: Optional[Counters] = None,
                ops: FieldOps = FIELD61) -> AuthVal:
    """The direct protected gate of Sec. V-G (thm:arith): after a verified
    opening c = x + r each module holds c and r, computes x = c - r inside
    its boundary, evaluates the approved deterministic g from protected
    memory in data-independent time, and returns a fresh authenticated
    sharing of g(x) through AuthShare.

    Honest discussion (Sec. V-G): the module has already seen c and r, hence
    the plaintext x; under Profile T this is permitted (the modules may see
    every input), FSS gains no formal confidentiality over the direct gate,
    and the gate's observable trace must meet the same simulatability
    assumption (eps_trace). The four fresh share draws occupy two AES blocks;
    the paper charges a direct gate five field multiplications (Sec. V-G),
    while the reference sharing primitive performs exactly the three tag
    products Delta_j g(x); the remaining two products belong to the
    manifest-declared evaluation g and are charged to g by the compiler's
    cost tuple, not to the sharing."""
    x = ops.sub(c, r)
    y = g(x) % ops.p
    v0 = field_draw(key, sublabel(label, "share_v"), ops.p, ops.n)
    g0 = tuple(field_draw(key, sublabel(label, f"share_g{j}"), ops.p, ops.n)
               for j in range(len(delta)))
    out = share_from_draws(y, delta, v0, g0, ops)[party]
    if counters is not None:
        counters.aes_blocks += 2   # four 61-bit draws occupy two AES blocks
        counters.field_mults += 3  # the tag products Delta_j g(x)
    return out


def polynomial_gate(x: AuthVal, indicators: Sequence[AuthVal],
                    coeffs: Sequence[Sequence[int]], party: int,
                    delta_share: Sequence[int], triples,
                    open_fn, counters: Optional[Counters] = None,
                    ops: FieldOps = FIELD61) -> AuthVal:
    """The Horner evaluation of alg:interval (Sec. V-G, thm:interval): the
    selected coefficients bar_a_j = sum_i a_{i,j} [s_i] are local affine
    maps with public coefficients, then y = bar_a_d and
    y <- y . x + bar_a_j for j = d - 1 .. 0, i.e. d authenticated products
    independent of the number m of pieces. coeffs[i][j] = a_{i,j}; triples
    supplies one fresh triple per product; open_fn opens the two Beaver
    differences of each product."""
    m = len(indicators)
    d = len(coeffs[0]) - 1
    bars: list[AuthVal] = []
    for j in range(d + 1):
        acc: Optional[AuthVal] = None
        for i in range(m):
            term = auth_scalar(indicators[i], coeffs[i][j], ops)
            acc = term if acc is None else auth_add(acc, term, ops)
        assert acc is not None
        bars.append(acc)
    y = bars[d]
    it = iter(triples)
    for j in range(d - 1, -1, -1):
        triple = next(it)
        dd, ee = open_fn(y, x, triple)
        y = beaver_mul(y, x, triple, dd, ee, delta_share, party, counters, ops)
        y = auth_add(y, bars[j], ops)
    return y


def bitdec(x: AuthVal, r: AuthVal, r_bits: Sequence[AuthVal], c: int,
           party: int, delta_share: Sequence[int], triples, open_fn,
           counters: Optional[Counters] = None,
           ops: FieldOps = FIELD61) -> list[AuthVal]:
    """alg:bitdec (Appendix D, thm:bitdec): canonical bit decomposition of x
    over the Mersenne field p = 2^n - 1, bits LSB-first. Loop 1 is a full
    subtractor computing d = (c - r) mod 2^n and the final borrow
    br = 1[c < r]; because p = 2^n - 1 the wrap equals the borrow, and
    Loop 2 subtracts it: x = d - br. The caller supplies the joint mask r,
    its authenticated canonical bits r_bits, the opened c = x + r mod p, one
    fresh triple per product and an open_fn for the Beaver differences.
    Cost: 2n authenticated multiplications (a conservative count, since the
    first product of Loop 1 multiplies by a public zero) and 2n + 1
    sequential rounds including the masked opening (122 and 123 for n = 61,
    tab:gates)."""
    n = ops.n
    zero = public_constant(0, delta_share, party, ops)
    br = zero
    d: list[AuthVal] = []
    it = iter(triples)
    for i in range(n):
        ci = (c >> i) & 1
        # tau_i = c_i xor r_i = c_i + (1 - 2 c_i) r_i: local, c_i public
        tau = auth_add_public(auth_scalar(r_bits[i], (1 - 2 * ci) % ops.p, ops),
                              ci, delta_share, ops)
        triple = next(it)
        dd, ee = open_fn(tau, br, triple)
        g = beaver_mul(tau, br, triple, dd, ee, delta_share, party, counters, ops)
        # d_i = tau_i XOR br_i = tau_i + br_i - 2 tau_i br_i (bits in {0,1})
        d_i = auth_add(auth_add(tau, br, ops),
                       auth_scalar(g, (-2) % ops.p, ops), ops)
        d.append(d_i)
        # full-subtractor borrow-out: (1 - c_i) r_i + br_i - tau_i br_i
        br = auth_add(auth_add(auth_scalar(r_bits[i], (1 - ci) % ops.p, ops), br, ops),
                      auth_neg(g, ops), ops)
    v = br
    x_bits: list[AuthVal] = []
    for i in range(n):
        triple = next(it)
        dd, ee = open_fn(d[i], v, triple)
        h = beaver_mul(d[i], v, triple, dd, ee, delta_share, party, counters, ops)
        # x_i = d_i XOR v_i = d_i + v_i - 2 d_i v_i
        x_i = auth_add(auth_add(d[i], v, ops),
                       auth_scalar(h, (-2) % ops.p, ops), ops)
        x_bits.append(x_i)
        # borrow-out = (1 - d_i) v_i
        v = auth_sub(v, h, ops)
    if counters is not None:
        counters.rounds += 1  # the masked opening c = x + r (one round)
    return x_bits


def cmp(x_bits: Sequence[AuthVal], theta: int, party: int,
        delta_share: Sequence[int], triples, open_fn,
        counters: Optional[Counters] = None,
        ops: FieldOps = FIELD61) -> AuthVal:
    """The Cmp procedure of alg:trunc (thm:cmp-trunc): the public-threshold
    comparator 1[x < theta] from canonical authenticated bits. eq tracks the
    equality of the processed prefix, lt gains a term exactly at the first
    position with secret bit 0 and threshold bit 1 (mutually exclusive
    events); endpoints theta in {0, 2^n} are public constants. At most n
    authenticated multiplications."""
    n = ops.n
    if theta == 0:
        return public_constant(0, delta_share, party, ops)
    if theta == 2 ** n:
        return public_constant(1, delta_share, party, ops)
    eq = public_constant(1, delta_share, party, ops)
    lt = public_constant(0, delta_share, party, ops)
    it = iter(triples)
    for i in range(n - 1, -1, -1):
        triple = next(it)
        dd, ee = open_fn(eq, x_bits[i], triple)
        m = beaver_mul(eq, x_bits[i], triple, dd, ee, delta_share, party, counters, ops)
        if (theta >> i) & 1:
            lt = auth_add(auth_add(lt, eq, ops), auth_neg(m, ops), ops)
            eq = m
        else:
            eq = auth_sub(eq, m, ops)
    return lt


def trunc(z: AuthVal, f: int, bitdec_inputs, party: int,
          delta_share: Sequence[int], triples, open_fn,
          counters: Optional[Counters] = None,
          ops: FieldOps = FIELD61) -> AuthVal:
    """The Trunc procedure of alg:trunc (thm:cmp-trunc): exact toward-zero
    signed truncation of the centered value of z by 2^f. It chains two bit
    decompositions, the sign comparator s = 1[z >= (p+1)/2] = 1[zbar < 0],
    the magnitude u = z - 2 s z (no wrap), the shifted local sum
    q = sum_{i=f}^{n-1} 2^{i-f} u_i and the sign restoration q - 2 s q.
    Cost: 5n + 2 authenticated multiplications and 5n + 4 sequential rounds
    including the two masked openings (307 and 309 for n = 61, tab:gates).
    bitdec_inputs = (r1, r1_bits, c1, r2, r2_bits, c2) supplies the two
    masks, their authenticated bits and the two opened values. The declared
    magnitude of z must remain below p/2 before truncation (Appendix D,
    Remark ii); fixed-point rescaling is inserted where the manifest
    specifies it."""
    r1, r1_bits, c1, r2, r2_bits, c2 = bitdec_inputs
    z_bits = bitdec(z, r1, r1_bits, c1, party, delta_share, triples, open_fn,
                    counters, ops)
    s = cmp(z_bits, (ops.p + 1) // 2, party, delta_share, triples, open_fn,
            counters, ops)
    s = auth_add_public(auth_neg(s, ops), 1, delta_share, ops)  # s = 1 - 1[z < 2^{n-1}]
    it = iter(triples)
    triple = next(it)
    dd, ee = open_fn(s, z, triple)
    sz = beaver_mul(s, z, triple, dd, ee, delta_share, party, counters, ops)
    u = auth_sub(z, auth_scalar(sz, 2, ops), ops)                # u = |zbar|
    u_bits = bitdec(u, r2, r2_bits, c2, party, delta_share, triples, open_fn,
                    counters, ops)
    q = public_constant(0, delta_share, party, ops)
    for i in range(f, ops.n):
        q = auth_add(q, auth_scalar(u_bits[i], (2 ** (i - f)) % ops.p, ops), ops)
    triple = next(it)
    dd, ee = open_fn(s, q, triple)
    sq = beaver_mul(s, q, triple, dd, ee, delta_share, party, counters, ops)
    return auth_sub(q, auth_scalar(sq, 2, ops), ops)


def exact_comparison(key: bytes, label, party: int, delta: Sequence[int],
                     delta_share: Sequence[int], c: int, r: int, theta: int,
                     counters: Optional[Counters] = None,
                     ops: FieldOps = FIELD61) -> AuthVal:
    """Exact comparison 1[x < theta] realized as the one-round interval
    indicator of alg:interval on [0, theta) (thm:interval): the caller opens
    c = x + r with the joint mask of `label` and the module derives both
    translated endpoints from the same r. Endpoint thresholds are public
    constants. The bit-based Cmp of alg:trunc (cmp above) is the fallback the
    compiler selects when no one-round candidate meets the gate's contract
    (Sec. V-G); both are exact in the declared finite arithmetic."""
    if theta == 0:
        return public_constant(0, delta_share, party, ops)
    if theta == ops.p:
        return public_constant(1, delta_share, party, ops)
    if not 0 < theta < ops.p:
        raise AbortError("threshold out of range")
    return interval_indicator(key, label, party, delta, c, 0, theta, counters, ops)


@dataclass(frozen=True)
class FreivaldsResult:
    accepted: bool
    repetitions: int
    frozen_root: bytes


def freivalds(A: Sequence[Sequence[int]], B: Sequence[Sequence[int]],
              C: Sequence[Sequence[int]], s: int = 3,
              key: Optional[bytes] = None, label=None,
              rng=None, counters: Optional[Counters] = None,
              ops: FieldOps = FIELD61) -> FreivaldsResult:
    """alg:freivalds (Appendix D, thm:freivalds): the frozen-operand Freivalds
    check. A in F^{m x k} and B in F^{k x n} are the module's bound
    authoritative records (the manifest permits the check only when exposing
    those operands to that GPU is already allowed - never for global triple
    masks); C is the frozen candidate, consumed from frozen bytes only. The
    candidate digest rho_C is fixed before any challenge exists, and s secret
    uniform challenge vectors v_l in F^n are drawn under labels bound to
    (session, epoch, gate, rho_C, l); each repetition tests
    C v_l == A (B v_l). A wrong C != AB passes all s repetitions with
    probability at most p^{-s}, and over Q_F calls an incorrect product is
    consumed with probability at most Q_F / p^s (thm:freivalds, s = 3 gives
    about 2^{-183} per call). Tag-array transformations repeat the loop on
    their own equations (alg:freivalds last line); the caller poisons the
    epoch on a rejected candidate."""
    m, k = len(A), len(A[0])
    k2, n = len(B), len(B[0])
    if k != k2 or len(C) != m or any(len(row) != n for row in C):
        raise AbortError("dimension mismatch")
    for M in (A, B, C):
        for row in M:
            for v in row:
                if not 0 <= v < ops.p:
                    raise AbortError("non-canonical matrix element")
    cbytes = b"".join(b"".join(v.to_bytes(8, "big") for v in row) for row in C)
    frozen_root = hashlib.sha256(b"freivalds" + cbytes).digest()
    for ell in range(1, s + 1):
        v: list[int] = []
        for i in range(n):
            if key is not None and label is not None:
                v.append(field_draw(key, sublabel(label, f"freiv:{ell}:{i}"),
                                    ops.p, ops.n))
            else:
                if rng is None:
                    raise AbortError("no challenge source")
                v.append(rng.randrange(ops.p))
        g: list[int] = []
        for i in range(k):
            acc = 0
            for j in range(n):
                acc = ops.add(acc, ops.mul(B[i][j], v[j]))
            g.append(acc)
        gp: list[int] = []
        for i in range(m):
            acc = 0
            for j in range(k):
                acc = ops.add(acc, ops.mul(A[i][j], g[j]))
            gp.append(acc)
        for i in range(m):
            acc = 0
            for j in range(n):
                acc = ops.add(acc, ops.mul(C[i][j], v[j]))
            if acc != gp[i]:
                return FreivaldsResult(False, ell, frozen_root)
    if counters is not None:
        counters.field_mults += s * (k * n + m * k + m * n)
    return FreivaldsResult(True, s, frozen_root)
