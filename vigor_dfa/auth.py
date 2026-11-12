"""Authenticated representation, joint sampling, Beaver triples and the batched MAC check.

Implements the authenticated layer of the VIGOR-DFA protocol (the S&P 2027
submission "Trusted Hardware Acceleration for Malicious-Secure Function Secret
Sharing"):

  * Sec. V-B  (Authenticated Representation): SPDZ-style sharings over
    F_p, p = 2^61 - 1, with t = 3 independent MAC lanes; a canonical wire is
    four 64-bit words, i.e. 32 bytes per party; the parser rejects
    non-canonical encodings instead of reducing them.
  * Sec. V-C  (Session Setup and Joint Randomness): the reference joint-PRF
    sampler (length-prefixed labels; the local role must never be appended to
    a joint draw; bounded rejection sampling), AuthShare, and Beaver triples
    whose product c = a*b is computed correctly inside the protected boundary
    (S7: a MAC on c would not prove c = ab).
  * fig:arith (Pi_Lin, Pi_Mult): the local linear operations and the Beaver
    multiplication combination.
  * Sec. V-F / alg:checkopen steps 3-5 / thm:mac-sound / lem:hidden-key /
    clm:residual (Appendix C): the challenge derivation, per-lane residuals
    and the acceptance test of the batched MAC check, including the shared-
    challenge configuration that injection 8 of tab:attacks must refuse.

Cross-module contract (dependency modules, implemented elsewhere in this
package): params.py provides P, BITS, T, N and the label tuple
Label(session, epoch, gate, role, purpose); field.py provides
fadd/fsub/fmul/fneg/to_canonical/encode/decode/inner over F_p;
prg.py provides the pinned AES-128 PRG (expand_seed, convert) used by gac.py
and pir.py. This module assumes those signatures; every use is confined to
the documented call shapes below so that the contract stays auditable.

Randomness note (Sec. VIII evidence): the CPU reference model expands joint
draws with SHAKE-256 under length-prefixed labels; the AES-128 block
accounting reported by the counters is the architecture's cost accounting of
Sec. VI-A (two blocks per PRG expansion, 1.5 blocks per checked element), not
a claim about how many SHAKE calls the reference performs.
"""

from __future__ import annotations

import hashlib
import random
import struct
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from . import field, params
from .ledger import AbortError

P = params.P
BITS = params.BITS
T = params.T
N = params.N
Label = params.Label

# Bounded rejection sampling (Sec. V-C): sample nbits pseudorandom bits and reject the single value p; a bounded sampler aborts on retry exhaustion instead of introducing a silent bias.
REJECT_RETRIES = 8


# --------------------------------------------------------------------------- Labels and the joint random function ---------------------------------------------------------------------------

def encode_label(label) -> bytes:
    """Unambiguous, length-prefixed encoding of (session, epoch, gate, role,
    purpose) (Sec. V-C); session/epoch/gate are 64-bit integers as in
    params.Label. Length prefixes make the encoding injective. An already
    encoded fragment (bytes) is passed through under the same prefix so
    that derived identifiers such as "cid" || encode_label(label) stay
    deterministic in both modules."""
    if isinstance(label, (bytes, bytearray)):
        return b"LBL" + bytes(label)
    session, epoch, gate, role, purpose = label
    pb = purpose.encode("utf-8")
    return (
        b"LBL"
        + struct.pack(">qqqB", session, epoch, gate, role)
        + struct.pack(">H", len(pb)) + pb
    )


def sublabel(label, purpose: str):
    """The same label with a different purpose. Joint draws use the same label
    (and hence the same role field) in both modules; the local role must not
    be appended to a joint draw, or T_0 and T_1 would generate two unrelated
    DPF instances (Sec. V-C)."""
    return Label(label.session, label.epoch, label.gate, label.role, purpose)


def prf_bytes(key: bytes, label, nbytes: int) -> bytes:
    """Reference joint PRF: SHAKE-256 keyed with the session key and evaluated
    on the length-prefixed label (Sec. VIII evidence note: the reference
    expands seeds with SHAKE rather than the pinned AES-based PRG; the FSS
    expansions themselves use prg.expand_seed/convert)."""
    h = hashlib.shake_256(key)
    h.update(b"\x01")
    h.update(encode_label(label))
    return h.digest(nbytes)


def prf_ctx(key: bytes, context: bytes, label, nbytes: int) -> bytes:
    """PRF with an extra bound context: the paper's PRF_K(chk, h_0, h_1, cid,
    j, i) of alg:checkopen step 3, where the frozen roots and check id are
    mixed into the context and the lane/position names into the label."""
    h = hashlib.shake_256(key)
    h.update(b"\x02")
    h.update(struct.pack(">H", len(context)) + context)
    h.update(encode_label(label))
    return h.digest(nbytes)


def field_draw_ctx(key: bytes, context: bytes, label, p: int = P,
                   nbits: int = BITS, retries: int = REJECT_RETRIES) -> int:
    """A uniform element of F_p by rejection sampling (Sec. V-C): take nbits
    pseudorandom bits and reject the single value p, which occurs with
    probability 2^-nbits. Retries carry distinct sublabels; exhaustion aborts
    instead of biasing the sampler."""
    for k in range(retries):
        lab = label if k == 0 else sublabel(label, f"{label.purpose}~r{k}")
        w = int.from_bytes(prf_ctx(key, context, lab, 8), "big") & ((1 << nbits) - 1)
        if w != p:
            return w
    raise AbortError("joint draw retry budget exhausted")


def field_draw(key: bytes, label, p: int = P, nbits: int = BITS,
               retries: int = REJECT_RETRIES) -> int:
    """Uniform field element under a joint label (field_draw_ctx with no extra
    context)."""
    return field_draw_ctx(key, b"", label, p, nbits, retries)


def bits_draw(key: bytes, label, nbits: int) -> int:
    """nbits uniform bits as an integer, most-significant-bit first (the DPF
    path convention of alg:gen/alg:eval; opposite to the LSB-first convention
    of alg:bitdec, and the two never meet inside one algorithm, Appendix D)."""
    if not 1 <= nbits <= 64:
        raise ValueError("bit draw supports 1..64 bits")
    return int.from_bytes(prf_bytes(key, label, 8), "big") & ((1 << nbits) - 1)


def seed_draw(key: bytes, label) -> bytes:
    """128-bit DPF root seed (lambda = 128 in the paper)."""
    return prf_bytes(key, label, 16)


# --------------------------------------------------------------------------- Counters ---------------------------------------------------------------------------

@dataclass
class Counters:
    """Work counters of the reference model.

    aes_blocks    declared AES-128 block accounting of Sec. VI-A: two blocks
                  per PRG expansion (so 6n + 3 per GaC output), 1.5 blocks per
                  checked element for challenge derivation, two blocks for
                  four 61-bit pads.
    field_mults   field multiplications: for MACCheck this is the residual
                  cost of two products per lane and element (2t per element,
                  Sec. VI-A); for the authenticated gates it counts one unit
                  per Pi_Mult call, matching tab:gates.
    rounds        sequential verified-opening rounds: one per Pi_Mult and one
                  per masked opening; "one online round is one CheckOpen"
                  (tab:gates footnote).
    releases      values released under certificates.
    """
    aes_blocks: int = 0
    field_mults: int = 0
    rounds: int = 0
    releases: int = 0


# --------------------------------------------------------------------------- Authenticated values (Sec. V-B) ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthVal:
    """Party-local authenticated share [x]_b = (x_b, gamma_{b,1}, ..., gamma_{b,t}).

    x_0 + x_1 = x and gamma_{0,j} + gamma_{1,j} = Delta_j x for every lane j.
    A canonical wire occupies four 64-bit words, i.e. 32 bytes per party
    before metadata; the parser rejects non-canonical encodings (values at
    least p) instead of reducing arbitrary integers modulo p, which keeps
    frozen bytes and checked field elements in one-to-one correspondence
    (Sec. V-B)."""
    x: int
    gamma: tuple[int, ...]
    party: int

    def __post_init__(self) -> None:
        if self.party not in (0, 1):
            raise ValueError("party must be 0 or 1")
        if len(self.gamma) != T:
            raise ValueError(f"expected {T} tag lanes")
        object.__setattr__(self, "gamma", tuple(int(g) for g in self.gamma))

    def to_bytes(self) -> bytes:
        """Canonical 32-byte wire encoding: four 64-bit words, little endian."""
        for v in (self.x, *self.gamma):
            if not 0 <= v < P:
                raise ValueError("non-canonical element: parser rejects, never reduces")
        return b"".join(struct.pack("<Q", v) for v in (self.x, *self.gamma))

    @classmethod
    def from_bytes(cls, data: bytes, party: int) -> "AuthVal":
        """Strict frame parser (Sec. VI-B): exact length, canonical field
        elements only; truncation, trailing bytes and non-canonical words are
        rejected, never reduced."""
        if len(data) != 32:
            raise ValueError("tuple frame is truncated or padded")
        words = struct.unpack("<4Q", data)
        if any(v >= P for v in words):
            raise ValueError("non-canonical field encoding")
        return cls(words[0], words[1:], party)


# --------------------------------------------------------------------------- AuthShare and linear operations (Sec. V-C, fig:arith) ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FieldOps:
    """Field parameters and operations. The production field is FIELD61; the
    toy field (p = 31, n = 5) serves the finite correctness tests of
    Sec. VIII (bit decomposition, intervals, truncation fibers)."""
    p: int
    n: int
    add: Callable[[int, int], int]
    sub: Callable[[int, int], int]
    mul: Callable[[int, int], int]
    neg: Callable[[int], int]


FIELD61 = FieldOps(P, N, field.fadd, field.fsub, field.fmul, field.fneg)


def share_from_draws(x: int, delta: Sequence[int], v0: int,
                     gamma0: Sequence[int], ops: FieldOps = FIELD61) -> tuple[AuthVal, AuthVal]:
    """AuthShare with explicit joint draws (Sec. V-C): party 0's value and tag
    shares are uniform draws; party 1's shares are the differences, so
    v_0 + v_1 = x and gamma_{0,j} + gamma_{1,j} = Delta_j x for every lane,
    and either party's tuple is uniform on F_p^{1+t} and independent of x and
    of the global keys (the hypothesis of clm:otp, Appendix E)."""
    if len(gamma0) != T or len(delta) != T:
        raise ValueError("t lane mismatch")
    g0 = tuple(int(g) for g in gamma0)
    v1 = ops.sub(x, v0)
    g1 = tuple(ops.sub(ops.mul(delta[j], x), g0[j]) for j in range(T))
    return (AuthVal(ops.add(v0, 0), tuple(ops.add(g, 0) for g in g0), 0),
            AuthVal(ops.add(v1, 0), tuple(ops.add(g, 0) for g in g1), 1))


def AuthShare(x: int, delta: Sequence[int], rng: Optional[random.Random] = None,
              ops: FieldOps = FIELD61) -> tuple[AuthVal, AuthVal]:
    """AuthShare of Sec. V-C with injectable uniform coins. Tests fix the rng
    seed (Sec. VIII: seeds are fixed only for public synthetic inputs); the
    concrete module supplies the draws from joint PRF labels via
    share_from_draws. Without an rng this call is deliberately
    non-deterministic, so protocol code never uses that default."""
    if rng is None:
        rng = random.Random()
    v0 = rng.randrange(ops.p)
    g0 = [rng.randrange(ops.p) for _ in range(T)]
    return share_from_draws(x, delta, v0, g0, ops)


def public_constant(c: int, delta_share: Sequence[int], party: int,
                    ops: FieldOps = FIELD61) -> AuthVal:
    """An authenticated public constant (Pi_Lin step 3): x_0 = c, x_1 = 0 and
    gamma_{b,j} = Delta_{b,j} c for both parties."""
    xb = c if party == 0 else 0
    tags = tuple(ops.mul(delta_share[j], c) for j in range(T))
    return AuthVal(ops.add(xb, 0), tuple(ops.add(g, 0) for g in tags), party)


def auth_add(u: AuthVal, v: AuthVal, ops: FieldOps = FIELD61) -> AuthVal:
    """Pi_Lin step 1: add the value shares and each of the t tag shares."""
    return AuthVal(ops.add(u.x, v.x),
                   tuple(ops.add(a, b) for a, b in zip(u.gamma, v.gamma)), u.party)


def auth_sub(u: AuthVal, v: AuthVal, ops: FieldOps = FIELD61) -> AuthVal:
    return AuthVal(ops.sub(u.x, v.x),
                   tuple(ops.sub(a, b) for a, b in zip(u.gamma, v.gamma)), u.party)


def auth_neg(u: AuthVal, ops: FieldOps = FIELD61) -> AuthVal:
    return AuthVal(ops.neg(u.x), tuple(ops.neg(g) for g in u.gamma), u.party)


def auth_scalar(u: AuthVal, c: int, ops: FieldOps = FIELD61) -> AuthVal:
    """Pi_Lin step 2: multiply the value share and every tag share by c."""
    return AuthVal(ops.mul(u.x, c), tuple(ops.mul(g, c) for g in u.gamma), u.party)


def auth_add_public(u: AuthVal, c: int, delta_share: Sequence[int],
                    ops: FieldOps = FIELD61) -> AuthVal:
    """Pi_Lin step 3: x_0 <- x_0 + c (party 0 only); gamma_{b,j} <-
    gamma_{b,j} + Delta_{b,j} c for both parties and all lanes."""
    x = ops.add(u.x, c) if u.party == 0 else u.x
    tags = tuple(ops.add(g, ops.mul(delta_share[j], c))
                 for j, g in enumerate(u.gamma))
    return AuthVal(x, tags, u.party)


# --------------------------------------------------------------------------- Beaver triples (Sec. V-C, fig:arith) ---------------------------------------------------------------------------

Triple = tuple[AuthVal, AuthVal, AuthVal]  # ([a]_b, [b]_b, [c]_b)


def beaver_mul(x: AuthVal, y: AuthVal, triple: Triple, d: int, e: int,
               delta_share: Sequence[int], party: int, counters: Optional[Counters] = None,
               ops: FieldOps = FIELD61) -> AuthVal:
    """Beaver combination of Pi_Mult (fig:arith, Sec. V-G "Arithmetic"):

        z_b    = c_b + d b_b + e a_b + 1[b=0] d e
        gamma_{z,b,j} = gamma_{c,b,j} + d gamma_{b,b,j} + e gamma_{a,b,j}
                        + Delta_{b,j} d e

    d = x - a and e = y - b are the values opened by CheckOpen before this
    call (batched with the independent openings of the layer); the triple is
    a fresh one-time joint draw whose one-time use the ledger enforces
    (S4, S7). The party-local combination performs six raw products
    (d*b, e*a, d*e on the value layer and d*gamma_b, e*gamma_a, Delta_b*de on
    the tags; d*e is shared by both layers); the counter charges one
    authenticated multiplication unit and one verified-opening round, the
    unit of tab:gates."""
    a, b, c = triple
    add, sub, mul = ops.add, ops.sub, ops.mul
    de = mul(d, e)
    z = add(add(add(c.x, mul(d, b.x)), mul(e, a.x)), de if party == 0 else 0)
    tags = []
    for j in range(T):
        gj = add(add(add(c.gamma[j], mul(d, b.gamma[j])), mul(e, a.gamma[j])),
                 mul(delta_share[j], de))
        tags.append(gj)
    if counters is not None:
        counters.rounds += 1
        counters.field_mults += 1
    return AuthVal(z, tuple(tags), party)


def GenTriples(key: bytes, label, count: int, delta: Sequence[int],
               ops: FieldOps = FIELD61) -> list[tuple[Triple, Triple]]:
    """Joint Beaver triples generated inside the protected boundary (Sec. V-C).

    a and b are joint uniform draws; c = a*b is computed correctly inside the
    TCB, because a MAC on c would not prove c = ab (S7, "Malformed
    preprocessing"); all three values are then authenticated independently
    with fresh share draws. The returned list holds (party-0 triple, party-1
    triple) per index so the caller hands each host only its own tuples."""
    out: list[tuple[Triple, Triple]] = []
    for i in range(count):
        a = field_draw(key, sublabel(label, f"triple:{i}:a"), ops.p, ops.n)
        b = field_draw(key, sublabel(label, f"triple:{i}:b"), ops.p, ops.n)
        c = ops.mul(a, b)  # computed inside the boundary, never imported
        shares = []
        for name, v in (("a", a), ("b", b), ("c", c)):
            v0 = field_draw(key, sublabel(label, f"triple:{i}:{name}:v0"), ops.p, ops.n)
            g0 = tuple(field_draw(key, sublabel(label, f"triple:{i}:{name}:g{j}"),
                                  ops.p, ops.n) for j in range(T))
            shares.append(share_from_draws(v, delta, v0, g0, ops))
        out.append(((shares[0][0], shares[1][0], shares[2][0]),
                    (shares[0][1], shares[1][1], shares[2][1])))
    return out


# --------------------------------------------------------------------------- Batched MAC check core (alg:checkopen steps 3-5, thm:mac-sound) ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BatchOpenings:
    """A frozen batch as seen by the global check core: the agreed check
    identifier, the ordered pair of frozen roots (h_0, h_1) and both parties'
    submitted tuples (fixed by the freeze before any challenge exists)."""
    cid: int
    h0: bytes
    h1: bytes
    party0: tuple[AuthVal, ...]
    party1: tuple[AuthVal, ...]


@dataclass(frozen=True)
class CheckOutcome:
    status: str                          # "VERIFIED" | "ABORT"
    residuals: tuple[int, ...]           # lane sums sigma_{0,j} + sigma_{1,j}
    field_mults: int                     # 2t products per element (one module)
    aes_blocks: int                      # 1.5 blocks per element (one module)


def derive_challenges(key: bytes, h0: bytes, h1: bytes, cid: int, m: int,
                      t: int = T, shared: bool = False,
                      counters: Optional[Counters] = None,
                      p: int = P, nbits: int = BITS) -> list[list[int]]:
    """Step 3 of alg:checkopen: rho_{j,i} = PRF_K(chk, h_0, h_1, cid, j, i),
    derived only after both frozen roots are fixed, one independent vector per
    MAC lane (thm:mac-sound multiplies the per-lane bounds (2/p)^t).

    With shared=True one vector is reused across lanes: this configuration is
    refused at session setup (injection 8, tab:attacks) because it collapses
    the product bound to a single lane (Sec. VII, "Independent challenges").

    AES accounting (Sec. VI-A): three 64-bit words per checked element per
    module (three 61-bit candidates) occupy ceil(3m/2) AES-128 blocks, i.e.
    1.5 blocks per element."""
    if counters is not None:
        counters.aes_blocks += (3 * m + 1) // 2
    ctx = b"chk" + bytes(h0) + bytes(h1) + cid.to_bytes(8, "big")
    rows: list[list[int]] = []
    for j in range(1 if shared else t):
        row = [field_draw_ctx(key, ctx, Label(0, 0, 0, 0, f"chk:{j}:{i}"), p, nbits)
               for i in range(m)]
        rows.append(row)
    if shared:
        rows = [list(rows[0]) for _ in range(t)]
    return rows


def residual(submitted: Sequence[AuthVal], z: Sequence[int],
             delta_share: Sequence[int], rho: Sequence[Sequence[int]],
             party: int, counters: Optional[Counters] = None) -> tuple[int, ...]:
    """Step 4 of alg:checkopen: sigma_{b,j} = sum_i rho_{j,i}
    (gamma_{b,j,i} - Delta_{b,j} z_i). Two field products per lane and
    element (2t per element, Sec. VI-A); the tags never cross the peer link."""
    m = len(submitted)
    sigma: list[int] = []
    for j in range(T):
        acc = 0
        for i in range(m):
            term = field.fsub(submitted[i].gamma[j], field.fmul(delta_share[j], z[i]))
            acc = field.fadd(acc, field.fmul(rho[j][i], term))
        sigma.append(acc)
    if counters is not None:
        counters.field_mults += 2 * T * m
    return tuple(sigma)


def decide(sigma0: Sequence[int], sigma1: Sequence[int]) -> bool:
    """Step 5 of alg:checkopen: accept iff sigma_{0,j} + sigma_{1,j} = 0 for
    every lane j. The zero tests of all lanes are aggregated into one generic
    status; residuals and challenges never leave the modules."""
    return all(field.fadd(a, b) == 0 for a, b in zip(sigma0, sigma1))


def MACCheck(key: bytes, openings: BatchOpenings, delta0: Sequence[int],
             delta1: Sequence[int], shared_challenges: bool = False,
             counters: Optional[Counters] = None) -> CheckOutcome:
    """Global batched MAC check core (alg:checkopen steps 3-5, thm:mac-sound).

    Reconstructs the candidates z_i = x_{0,i} + x_{1,i} inside the check
    engine, derives the per-lane challenges from the frozen roots and the
    check identifier, forms each module's residuals with its own key share
    (Delta_{b,j} comes from the protected key store, never from host input),
    and accepts iff every lane cancels. By clm:residual (Appendix C),
    sigma_{0,j} + sigma_{1,j} = <rho_j, d_j - Delta_j e>, where (e, d_j) are
    the value- and tag-error vectors fixed by the freeze; if e != 0 the
    acceptance probability is at most (2/p)^t over independent lanes.

    shared_challenges=True implements the injection-8 configuration for the
    counterexample of Sec. VII; it is refused at session setup in any real
    deployment. CheckOutcome.field_mults reports the per-module residual cost
    (2t products per element); the reference computes both parties' residuals
    in one process."""
    m = len(openings.party0)
    if len(openings.party1) != m:
        raise ValueError("batch length mismatch")
    c = counters if counters is not None else Counters()
    before_mults = c.field_mults
    rho = derive_challenges(key, openings.h0, openings.h1, openings.cid, m,
                            shared=shared_challenges, counters=c)
    z = [field.fadd(a.x, b.x) for a, b in zip(openings.party0, openings.party1)]
    sigma0 = residual(openings.party0, z, delta0, rho, 0, c)
    sigma1 = residual(openings.party1, z, delta1, rho, 1, c)
    sums = tuple(field.fadd(a, b) for a, b in zip(sigma0, sigma1))
    status = "VERIFIED" if all(s == 0 for s in sums) else "ABORT"
    # The reference computes both parties' residuals in one process; the exposed field_mults is the per-module residual cost (2t per element, Sec. VI-A), i.e. half of the two residuals just accumulated.
    per_module_mults = (c.field_mults - before_mults) // 2
    return CheckOutcome(status, sums, per_module_mults, c.aes_blocks)
