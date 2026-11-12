"""Tests for ``vigor_dfa.auth`` (Paper Sec. V-B/V-C, fig:arith, thm:mac-sound core).

Covers the MAC linearity of Pi_Lin, the rejection of a forged value by the batched MAC check (thm:mac-sound: acceptance of a wrong value is bounded by (2/p)^t; the bound is analytic, and the fixed-seed tests check conformance, Sec. VIII), the parser's rejection of non-canonical encodings (Sec. V-B) and the in-TCB Beaver triple generation (Sec. V-C, S7: c = ab is computed inside the boundary, never imported). Fixed seeds for public synthetic inputs only (Sec. VIII measurement protocol).
"""

import random
import unittest

from vigor_dfa import auth, field
from vigor_dfa.auth import (AuthShare, AuthVal, BatchOpenings, Counters,
                            GenTriples, MACCheck, auth_add, auth_add_public,
                            auth_scalar, derive_challenges, share_from_draws)
from vigor_dfa.params import Label, P, T

_SEED = 0xA07B2027


def _reconstruct(u: AuthVal, v: AuthVal, delta):
    return field.fadd(u.x, v.x), [field.fadd(u.gamma[j], v.gamma[j]) for j in range(T)]


class TestAuth(unittest.TestCase):
    """Authenticated representation, MAC check and triples."""

    def test_mac_linearity(self):
        rng = random.Random(_SEED)
        delta = tuple(rng.randrange(P) for _ in range(T))
        x, y, c = rng.randrange(P), rng.randrange(P), rng.randrange(P)
        u = AuthShare(x, delta, rng)
        v = AuthShare(y, delta, rng)
        # Pi_Lin step 1: addition
        s = (auth_add(u[0], v[0]), auth_add(u[1], v[1]))
        val, tags = _reconstruct(*s, delta)
        self.assertEqual(val, field.fadd(x, y))
        for j in range(T):
            self.assertEqual(tags[j], field.fmul(delta[j], val))
        # Pi_Lin step 2: multiplication by a public scalar
        sc = (auth_scalar(s[0], c), auth_scalar(s[1], c))
        val2, tags2 = _reconstruct(*sc, delta)
        self.assertEqual(val2, field.fmul(val, c))
        for j in range(T):
            self.assertEqual(tags2[j], field.fmul(delta[j], val2))
        # Pi_Lin step 3: adding a public constant (party 0 only on the value; both parties add Delta_{b,j} c to the tags)
        ds0 = tuple(rng.randrange(P) for _ in range(T))
        ds1 = tuple(field.fsub(delta[j], ds0[j]) for j in range(T))
        p0 = auth_add_public(sc[0], c, ds0)
        p1 = auth_add_public(sc[1], c, ds1)
        val3, tags3 = _reconstruct(p0, p1, delta)
        self.assertEqual(val3, field.fadd(val2, c))
        for j in range(T):
            self.assertEqual(tags3[j], field.fmul(delta[j], val3))
            self.assertEqual(p0.gamma[j], field.fadd(sc[0].gamma[j], field.fmul(ds0[j], c)))
            self.assertEqual(p1.gamma[j], field.fadd(sc[1].gamma[j], field.fmul(ds1[j], c)))

    def test_forged_value_maccheck_fails(self):
        rng = random.Random(_SEED ^ 0xF0F0)
        key = bytes(rng.getrandbits(8) for _ in range(16))
        delta = tuple(rng.randrange(P) for _ in range(T))
        ds0 = tuple(rng.randrange(P) for _ in range(T))
        ds1 = tuple(field.fsub(delta[j], ds0[j]) for j in range(T))
        x = rng.randrange(P)
        s0, s1 = share_from_draws(x, delta, rng.randrange(P),
                                  [rng.randrange(P) for _ in range(T)])
        h0, h1, cid = b"h0", b"h1", 7
        rho = derive_challenges(key, h0, h1, cid, 1)
        outcome = None
        # The harness adapts the forgery to the fixed-seed challenges (fixed seeds are for public synthetic inputs; the (2/p)^t bound of thm:mac-sound is analytic, Sec. VIII): submit a value error e with the tags left intact (d_j = 0) and check the residual identity sigma_{0,j} + sigma_{1,j} = -Delta_j rho_{j,0} e (clm:residual).
        for e in range(1, 64):
            forged = BatchOpenings(cid, h0, h1,
                                   (AuthVal(field.fadd(s0.x, e), s0.gamma, 0),),
                                   (s1,))
            outcome = MACCheck(key, forged, ds0, ds1)
            sums = tuple(field.fmul(field.fneg(delta[j]),
                                    field.fmul(rho[j][0], e)) for j in range(T))
            self.assertEqual(outcome.status,
                             "VERIFIED" if all(s == 0 for s in sums) else "ABORT")
            if outcome.status == "ABORT":
                break
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.status, "ABORT")
        # counters: 2t field products and 1.5 AES blocks per element (Sec. VI-A)
        self.assertEqual(outcome.field_mults, 2 * T)
        self.assertEqual(outcome.aes_blocks, (3 * 1 + 1) // 2)
        # the parser rejects non-canonical encodings instead of reducing them
        with self.assertRaises(ValueError):
            AuthVal.from_bytes(b"\xff" * 8 + b"\x00" * 24, 0)
        with self.assertRaises(ValueError):
            AuthVal.from_bytes(b"\x00" * 31, 0)
        with self.assertRaises(ValueError):
            AuthVal(P, (0, 0, 0), 0).to_bytes()

    def test_beaver_triples_correct(self):
        rng = random.Random(_SEED ^ 0xBEA7)
        key = bytes(rng.getrandbits(8) for _ in range(16))
        delta = tuple(rng.randrange(P) for _ in range(T))
        label = Label(0, 0, 3, 0, "triples")
        triples = GenTriples(key, label, 8, delta)
        self.assertEqual(len(triples), 8)
        for t0, t1 in triples:
            for u, v in zip(t0, t1):
                val = field.fadd(u.x, v.x)
                for j in range(T):
                    self.assertEqual(field.fadd(u.gamma[j], v.gamma[j]),
                                     field.fmul(delta[j], val))
            a = field.fadd(t0[0].x, t1[0].x)
            b = field.fadd(t0[1].x, t1[1].x)
            c = field.fadd(t0[2].x, t1[2].x)
            self.assertEqual(c, field.fmul(a, b))  # c = ab computed inside the TCB


if __name__ == "__main__":
    unittest.main()
