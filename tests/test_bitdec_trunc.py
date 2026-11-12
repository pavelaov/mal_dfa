"""Tests for ``vigor_dfa.gates`` bit decomposition and exact signed truncation (Paper Appendix D, alg:bitdec/alg:trunc; correctness thm:bitdec, thm:cmp-trunc).

Contract (paper evidence table): all 31 elements of the toy field p = 31 for bit decomposition, and exactly ``TRUNC_CASES = 124`` signed-truncation cases (4 shift configurations x 31 elements), each compared against the plaintext toward-zero reference. The production field (n = 61) pins the cost counters of tab:gates: bitdec performs 2n = 122 authenticated multiplications in 2n + 1 = 123 sequential rounds (including its masked opening), and truncation performs 5n + 2 = 307 multiplications in 5n + 4 = 309 rounds (including the two masked openings). The Beaver differences are opened through a synchronized paired opener - the reference for the CheckOpen batch of each multiplication round. Fixed seeds throughout; the toy field serves finite correctness only (Sec. VIII).
"""

import queue
import random
import threading
import unittest

from vigor_dfa import field, gates
from vigor_dfa.auth import FIELD61, Counters, FieldOps, share_from_draws
from vigor_dfa.params import P

TRUNC_CASES = 124  # 4 shift configurations x 31 toy-field elements
_SEED = 0xB17DEC
_DELTA = (2, 3, 5)

_TOY = FieldOps(31, 5,
                lambda a, b: (a + b) % 31,
                lambda a, b: (a - b) % 31,
                lambda a, b: (a * b) % 31,
                lambda a: (-a) % 31)


def _ds(ops):
    return ((1, 2, 3), tuple(ops.sub(_DELTA[j], (1, 2, 3)[j]) for j in range(3)))


def _share(v, rng, ops):
    v0 = rng.randrange(ops.p)
    g0 = [rng.randrange(ops.p) for _ in range(3)]
    return share_from_draws(v, _DELTA, v0, g0, ops)


def _triples(rng, ops, n):
    out = []
    for _ in range(n):
        a = rng.randrange(ops.p)
        b = rng.randrange(ops.p)
        c = ops.mul(a, b)                    # c = ab (inside the boundary, S7)
        A = _share(a, rng, ops)
        B = _share(b, rng, ops)
        C = _share(c, rng, ops)
        out.append(((A[0], B[0], C[0]), (A[1], B[1], C[1])))
    return out


class _PairedOpener:
    """Reconstructs the Beaver differences for the two parties' concurrent
    runs (the reference for the CheckOpen batch of each multiplication)."""

    def __init__(self, ops):
        self.ops = ops
        self.q = {0: queue.Queue(), 1: queue.Queue()}

    def __call__(self, u, v, triple):
        party = u.party
        self.q[party].put((u.x, v.x, triple[0].x, triple[1].x))
        oux, ovx, oax, obx = self.q[1 - party].get()
        d = self.ops.sub(self.ops.add(u.x, oux), self.ops.add(triple[0].x, oax))
        e = self.ops.sub(self.ops.add(v.x, ovx), self.ops.add(triple[1].x, obx))
        return d, e


def _run_pair(fn, party_args, ops):
    """Run fn for both parties concurrently with one paired opener; fn takes
    (party arguments..., opener, counters) and returns the party's output."""
    opener = _PairedOpener(ops)
    cb = [Counters(), Counters()]
    out = {}

    def go(party):
        out[party] = fn(*party_args[party], opener, cb[party])

    t0 = threading.Thread(target=go, args=(0,))
    t1 = threading.Thread(target=go, args=(1,))
    t0.start()
    t1.start()
    t0.join(60)
    t1.join(60)
    return out[0], out[1], cb[0], cb[1]


def _bitdec_pair(x, r, c, rng, ops):
    """Share x and the canonical bits of r, generate 2n triples and run
    alg:bitdec for both parties; returns (bits0, bits1, counters0,
    counters1)."""
    n = ops.n
    xs = _share(x, rng, ops)
    rs = _share(r, rng, ops)
    rb = [_share((r >> i) & 1, rng, ops) for i in range(n)]
    tris = _triples(rng, ops, 2 * n)
    ds0, ds1 = _ds(ops)

    def drive(party_bits, rshare, rbits, cc, party, ds, tri, opener, counters):
        return gates.bitdec(party_bits, rshare, rbits, cc, party, ds,
                            iter(tri), opener, counters, ops)

    args0 = (xs[0], rs[0], [b[0] for b in rb], c, 0, ds0, [t[0] for t in tris])
    args1 = (xs[1], rs[1], [b[1] for b in rb], c, 1, ds1, [t[1] for t in tris])
    return _run_pair(drive, (args0, args1), ops)


def _trunc_pair(z, f, rng, ops):
    """Run alg:trunc for both parties: two masks with their authenticated
    bits and opened values, 5n + 2 fresh triples."""
    p, n = ops.p, ops.n
    zb = z if z <= (p - 1) // 2 else z - p
    mag = abs(zb)
    r1 = rng.randrange(p)
    c1 = ops.add(z, r1)
    r2 = rng.randrange(p)
    c2 = ops.add(mag, r2)
    zs = _share(z, rng, ops)
    r1s = _share(r1, rng, ops)
    r2s = _share(r2, rng, ops)
    r1b = [_share((r1 >> i) & 1, rng, ops) for i in range(n)]
    r2b = [_share((r2 >> i) & 1, rng, ops) for i in range(n)]
    tris = _triples(rng, ops, 5 * n + 2)
    ds0, ds1 = _ds(ops)

    def drive(zshare, f2, inputs, party, ds, tri, opener, counters):
        return gates.trunc(zshare, f2, inputs, party, ds, iter(tri), opener,
                           counters, ops)

    args0 = (zs[0], f,
             (r1s[0], [b[0] for b in r1b], c1, r2s[0], [b[0] for b in r2b], c2),
             0, ds0, [t[0] for t in tris])
    args1 = (zs[1], f,
             (r1s[1], [b[1] for b in r1b], c1, r2s[1], [b[1] for b in r2b], c2),
             1, ds1, [t[1] for t in tris])
    return _run_pair(drive, (args0, args1), ops)


def _plain_trunc(z, f, p):
    """Plaintext toward-zero truncation of the centered value of z."""
    zb = z if z <= (p - 1) // 2 else z - p
    if zb == 0:
        return 0
    mag = zb if zb > 0 else -zb
    q = mag >> f
    return q % p if zb > 0 else (-q) % p


class TestBitDecTrunc(unittest.TestCase):
    """Canonical bit decomposition and exact signed truncation."""

    def test_bitdec_trunc_matches_plaintext(self):
        rng = random.Random(_SEED)

        # toy field p = 31, n = 5: bit decomposition of all 31 elements
        for x in range(31):
            r = rng.randrange(31)
            c = (x + r) % 31
            bits0, bits1, _, _ = _bitdec_pair(x, r, c, rng, _TOY)
            bits = [(bits0[i].x + bits1[i].x) % 31 for i in range(5)]
            self.assertEqual(bits, [(x >> i) & 1 for i in range(5)])
            self.assertEqual(sum(bits[i] * (1 << i) for i in range(5)), x)

        # truncation: 4 shift configurations x 31 elements = 124 cases
        count = 0
        for f in (1, 2, 3, 4):
            for z in range(31):
                got0, got1, _, _ = _trunc_pair(z, f, rng, _TOY)
                self.assertEqual((got0.x + got1.x) % 31, _plain_trunc(z, f, 31))
                count += 1
        self.assertEqual(count, TRUNC_CASES)
        self.assertEqual(count, 4 * 31)

        # production field n = 61: counters of tab:gates (307/309 and 122/123)
        z = rng.randrange(P)
        got0, got1, cb0, cb1 = _trunc_pair(z, 16, rng, FIELD61)
        self.assertEqual(field.fadd(got0.x, got1.x), _plain_trunc(z, 16, P))
        self.assertEqual(cb0.field_mults, 5 * 61 + 2)
        self.assertEqual(cb0.rounds, 5 * 61 + 4)
        self.assertEqual(cb1.field_mults, 5 * 61 + 2)
        self.assertEqual(cb1.rounds, 5 * 61 + 4)

        x = rng.randrange(P)
        r = rng.randrange(P)
        c = field.fadd(x, r)
        bits0, bits1, cb0, cb1 = _bitdec_pair(x, r, c, rng, FIELD61)
        s0 = sum(field.fmul(bits0[i].x, 1 << i) for i in range(61))
        s1 = sum(field.fmul(bits1[i].x, 1 << i) for i in range(61))
        self.assertEqual(field.fadd(s0, s1), x)
        self.assertEqual(cb0.field_mults, 2 * 61)
        self.assertEqual(cb0.rounds, 2 * 61 + 1)
        self.assertEqual(cb1.field_mults, 2 * 61)
        self.assertEqual(cb1.rounds, 2 * 61 + 1)


if __name__ == "__main__":
    unittest.main()
