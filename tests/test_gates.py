"""Tests for ``vigor_dfa.gates`` (Paper Sec. V-G/V-H: alg:lut, alg:interval,
the direct protected gate, the Horner polynomial and alg:freivalds;
correctness thm:lut, thm:interval, thm:arith, thm:freivalds).

One test function covers the five gate families:

  * LUT: all 16 inputs of a 4-bit table (the paper's "all 16 inputs of a
    small LUT"), with the AES-block counter checked against the tab:gates
    LUT formula 2 (2^w - 1 + 2w);
  * intervals: exhaustive over the toy field p = 31 (n = 5) for one plain
    and one wrapping interval (the paper's "selected exhaustive toy
    intervals"), with the conservative-DCF AES accounting
    2 x sum_i 3i x 2 blocks;
  * direct gate: the module recovers x = c - r and returns a fresh sharing
    of g(x) (Sec. V-G);
  * polynomial: Horner evaluation with d = 2 authenticated products,
    reconstructing P(x) = 3 + 4x + 5x^2;
  * Freivalds: s = 3 challenges accept the correct product and reject a
    candidate whose last column is wrong (injection 7; soundness p^{-s},
    thm:freivalds).

The Beaver differences of the polynomial evaluation are opened through a
synchronized paired opener that reconstructs both parties' shares - the
reference for the CheckOpen batch of each multiplication round. Fixed seeds
throughout.
"""

import queue
import random
import threading
import unittest

from vigor_dfa import auth, field, gates
from vigor_dfa.auth import (Counters, FieldOps, GenTriples, bits_draw,
                            share_from_draws)
from vigor_dfa.params import Label, P, T

_SEED = 0x6A7E52027
_KEY = bytes(range(16))
_DELTA = (2, 3, 5)

_TOY = FieldOps(31, 5,
                lambda a, b: (a + b) % 31,
                lambda a, b: (a - b) % 31,
                lambda a, b: (a * b) % 31,
                lambda a: (-a) % 31)


class _PairedOpener:
    """Reconstructs the Beaver differences for the two parties' concurrent
    gate runs (the reference for the CheckOpen batch of each multiplication
    round; in the protocol the modules open [d] and [e] over their channel)."""

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


class TestGates(unittest.TestCase):
    """LUT, interval, direct, polynomial and Freivalds correctness."""

    def test_lut_interval_direct_polynomial_freivalds(self):
        rng = random.Random(_SEED)

        # --- LUT (alg:lut): all 16 inputs of a 4-bit table ---
        w = 4
        table = tuple(rng.randrange(P) for _ in range(1 << w))
        for x in range(1 << w):
            label = Label(0, 0, 100 + x, 0, "lut")
            r = bits_draw(_KEY, auth.sublabel(label, "mask"), w)
            u = x ^ r
            c0, c1 = Counters(), Counters()
            y0 = gates.lut_gate(_KEY, label, 0, _DELTA, u, r, w, table, c0)
            y1 = gates.lut_gate(_KEY, label, 1, _DELTA, u, r, w, table, c1)
            self.assertEqual(field.fadd(y0.x, y1.x), table[x])
            # AES: 2 (2^w - 1 + 2w) blocks (tab:gates LUT row)
            self.assertEqual(c0.aes_blocks, 2 * ((1 << w) - 1 + 2 * w))
            # field mults: the 2^w reduction products plus the 3 epilogue ones
            self.assertEqual(c0.field_mults, (1 << w) + 3)

        # --- interval (alg:interval): exhaustive over the toy field p = 31 ---
        for a, b in ((3, 7), (10, 3)):      # plain and wrapping intervals
            for x in range(31):
                label = Label(0, 0, 200 + 100 * a + x, 0, "ivl")
                r = gates.gate_mask(_KEY, label, 31, 5)
                c = (x + r) % 31
                c0, c1 = Counters(), Counters()
                y0 = gates.interval_indicator(_KEY, label, 0, _DELTA, c, a, b,
                                              c0, _TOY)
                y1 = gates.interval_indicator(_KEY, label, 1, _DELTA, c, a, b,
                                              c1, _TOY)
                expected = 1 if ((x - a) % 31) < ((b - a) % 31) else 0
                self.assertEqual((y0.x + y1.x) % 31, expected)
                for j in range(T):
                    self.assertEqual((y0.gamma[j] + y1.gamma[j]) % 31,
                                     (_DELTA[j] * expected) % 31)
                # conservative DCF: two thresholds x sum_i 3i expansions x 2 blocks
                self.assertEqual(c0.aes_blocks,
                                 2 * 2 * sum(3 * i for i in range(1, 6)))

        # --- direct gate (Sec. V-G): x = c - r inside the boundary ---
        g = lambda v: (v * v + 1) % P
        for x in (0, 1, 12345, P - 2):
            label = Label(0, 0, 400 + x, 0, "dir")
            r = gates.gate_mask(_KEY, label, P, 61)
            c = field.fadd(x, r)
            c0 = Counters()
            y0 = gates.direct_gate(_KEY, label, 0, _DELTA, c, r, g, c0)
            y1 = gates.direct_gate(_KEY, label, 1, _DELTA, c, r, g)
            self.assertEqual(field.fadd(y0.x, y1.x), g(x))
            self.assertEqual(c0.aes_blocks, 2)   # four 61-bit share draws
            self.assertEqual(c0.field_mults, 3)  # the tag products Delta_j g(x)

        # --- polynomial (Horner, alg:interval): P(x) = 3 + 4x + 5x^2 ---
        coeffs = [[3, 4, 5], [0, 0, 0]]
        xval = 7
        s_one = share_from_draws(1, _DELTA, rng.randrange(P),
                                 [rng.randrange(P) for _ in range(T)])
        s_zero = share_from_draws(0, _DELTA, rng.randrange(P),
                                  [rng.randrange(P) for _ in range(T)])
        xsh = share_from_draws(xval, _DELTA, rng.randrange(P),
                               [rng.randrange(P) for _ in range(T)])
        triples = GenTriples(_KEY, Label(0, 0, 700, 0, "tri"), 2, _DELTA)
        tri0 = [t[0] for t in triples]
        tri1 = [t[1] for t in triples]
        ds0 = tuple(rng.randrange(P) for _ in range(T))
        ds1 = tuple(field.fsub(_DELTA[j], ds0[j]) for j in range(T))
        ds = (ds0, ds1)
        opener = _PairedOpener(auth.FIELD61)
        out = {}

        def go(party, tri):
            out[party] = gates.polynomial_gate(
                xsh[party], [s_one[party], s_zero[party]], coeffs, party,
                ds[party], iter(tri), opener, Counters())

        t0 = threading.Thread(target=go, args=(0, tri0))
        t1 = threading.Thread(target=go, args=(1, tri1))
        t0.start()
        t1.start()
        t0.join(30)
        t1.join(30)
        self.assertEqual(field.fadd(out[0].x, out[1].x),
                         (3 + 4 * xval + 5 * xval * xval) % P)

        # --- Freivalds (alg:freivalds): s = 3 challenges, soundness p^{-3} ---
        A = [[rng.randrange(P) for _ in range(3)] for _ in range(2)]
        B = [[rng.randrange(P) for _ in range(4)] for _ in range(3)]
        C = [[field.mersenne_reduce(sum(field.fmul(A[i][k], B[k][j])
                                        for k in range(3))) for j in range(4)]
             for i in range(2)]
        good = tuple(tuple(row) for row in C)
        res = gates.freivalds(A, B, good, s=3, rng=rng)
        self.assertTrue(res.accepted)
        self.assertEqual(res.repetitions, 3)
        bad = [list(row) for row in C]
        for i in range(2):
            bad[i][-1] = field.fadd(bad[i][-1], 1)   # wrong last column (injection 7)
        res2 = gates.freivalds(A, B, tuple(tuple(r) for r in bad), s=3, rng=rng)
        self.assertFalse(res2.accepted)


if __name__ == "__main__":
    unittest.main()
