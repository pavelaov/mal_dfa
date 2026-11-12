"""Tests for ``vigor_dfa.dpf`` (Paper Sec. IV-B, Alg. 1-2; correctness Paper App. B, ``thm:dpf-correct``).

Contract (paper evidence table): exactly ``DPF_CASES = 21840`` DPF cases, made up of 6 depths x 56 seeds x 65 payloads, each asserting ``Eval(k0, x) + Eval(k1, x)`` is ``beta`` iff ``x == alpha`` and ``0`` otherwise, for a deterministic random query ``x``.  Fixed seeds throughout.  The pure-Python AES reference keeps this test in the tens of seconds; runtime is not part of the contract.
"""

import hashlib
import random
import unittest

from vigor_dfa import dpf
from vigor_dfa.params import N, P, Label

DPF_CASES = 21840  # 6 depths x 56 seeds x 65 payloads
_DEPTHS = (1, 2, 3, 4, 5, 6)
_N_SEEDS = 56
_N_PAYLOADS = 65
_SEED = 0xD0F7E57
_MASTER_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def _test_keys() -> list:
    """56 deterministic 16-byte gate keys derived from the master key."""
    return [
        hashlib.sha256(_MASTER_KEY + i.to_bytes(8, "big")).digest()[:16]
        for i in range(_N_SEEDS)
    ]


class TestDPF(unittest.TestCase):
    """Exact DPF correctness, key shape, and full-domain evaluation."""

    def test_dpf_correctness_spot(self):
        keys = _test_keys()
        rng = random.Random(_SEED)
        label = Label(0, 0, 0, 0, "dpf-spot")
        count = 0
        for n in _DEPTHS:
            domain = 1 << n
            for key in keys:
                for beta in range(_N_PAYLOADS):
                    alpha = rng.randrange(domain)
                    x = rng.randrange(domain)
                    k0, k1 = dpf.Gen(key, label, alpha, beta, n=n)
                    y0 = dpf.Eval(k0, x)
                    y1 = dpf.Eval(k1, x)
                    self.assertTrue(0 <= y0 < P)
                    self.assertTrue(0 <= y1 < P)
                    s = y0 + y1  # canonical shares: field sum is s mod p
                    if x == alpha:
                        self.assertIn(s, (beta, beta + P))
                    else:
                        self.assertIn(s, (0, P))
                    count += 1
        self.assertEqual(count, DPF_CASES)
        self.assertEqual(count, len(_DEPTHS) * _N_SEEDS * _N_PAYLOADS)

    def test_dpf_key_shape(self):
        rng = random.Random(_SEED ^ 0x5A17)
        for n in (1, 3, N):
            alpha = rng.randrange(1 << n)
            beta = rng.randrange(P)
            k0, k1 = dpf.Gen(_MASTER_KEY, Label(0, 0, 0, 0, "shape"), alpha, beta, n=n)
            self.assertEqual(k0.party, 0)
            self.assertEqual(k1.party, 1)
            self.assertEqual(k0.n, n)
            self.assertEqual(k1.n, n)
            self.assertEqual(len(k0.cw), n)
            self.assertEqual(len(k1.cw), n)
            self.assertEqual(k0.cw, k1.cw)          # correction words are common
            self.assertNotEqual(k0.seed, k1.seed)   # independent roots
            self.assertEqual(len(k0.seed), 16)
            for (s_cw, t_l, t_r) in k0.cw:
                self.assertLess(s_cw, 1 << 128)
                self.assertIn(t_l, (0, 1))
                self.assertIn(t_r, (0, 1))
            self.assertTrue(0 <= k0.cw_out < P)
            self.assertEqual(k0.cw_out, k1.cw_out)  # CWout is common
            # Paper Sec. IV-C: |k| = 128 + 130 n + 64 bits, 1016 B at n = 61
            self.assertEqual(dpf.key_size(n), 128 + 130 * n + 64)
        self.assertEqual(dpf.key_size_bytes(61), 1016)
        self.assertEqual((dpf.key_size(61) + 7) // 8, 1016)

    def test_dpf_evalall_matches(self):
        rng = random.Random(_SEED ^ 0xEA11)
        for n in (1, 2, 3, 5, 8):
            alpha = rng.randrange(1 << n)
            beta = rng.randrange(64)
            k0, k1 = dpf.Gen(_MASTER_KEY, Label(0, 0, 0, 0, "evalall"), alpha, beta, n=n)
            all0 = dpf.EvalAll(k0)
            all1 = dpf.EvalAll(k1)
            self.assertEqual(len(all0), 1 << n)
            self.assertEqual(len(all1), 1 << n)
            for x in range(1 << n):
                self.assertEqual(all0[x], dpf.Eval(k0, x))
                self.assertEqual(all1[x], dpf.Eval(k1, x))
                s = all0[x] + all1[x]
                if x == alpha:
                    self.assertIn(s, (beta, beta + P))
                else:
                    self.assertIn(s, (0, P))


if __name__ == "__main__":
    unittest.main()
