"""Tests for ``vigor_dfa.dcf`` (Paper App. B, label ``alg:dcf``; correctness Paper App. B, ``thm:dcf``; orientation ``beta * 1[x < alpha]``, Paper Sec. II).

Contract (paper evidence table): exactly ``DCF_CASES = 1364`` DCF comparisons, made up of 4 depths x 341 deterministic ``(alpha, x)`` pairs, each asserting ``DCFEval(K0, x) + DCFEval(K1, x)`` equals ``beta`` iff ``x < alpha`` and ``0`` otherwise.  The second test pins the endpoint behavior of the conservative O(n^2) construction at ``x = alpha - 1``, ``x = alpha`` and ``x = alpha + 1`` against the explicit prefix-point-function sum.  Fixed seeds throughout.
"""

import random
import unittest

from vigor_dfa import dcf
from vigor_dfa.params import P

DCF_CASES = 1364  # 4 depths x 341 (alpha, x) pairs
_DEPTHS = (2, 3, 4, 5)
_PAIRS = 341
_SEED = 0xDCF00D
_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestDCF(unittest.TestCase):
    """Conservative DCF correctness and endpoint behavior."""

    def test_dcf_correctness(self):
        rng = random.Random(_SEED)
        count = 0
        for n in _DEPTHS:
            domain = 1 << n
            for _ in range(_PAIRS):
                alpha = rng.randrange(domain)
                x = rng.randrange(domain)
                beta = rng.randrange(P)
                K0, K1 = dcf.DCFGen(_KEY, alpha, beta, mode="conservative", n=n)
                self.assertEqual(len(K0), n)  # all n prefix keys, incl. zero payloads
                self.assertEqual(len(K1), n)
                for i in range(n):
                    self.assertEqual(K0[i].n, i + 1)
                v0 = dcf.DCFEval(K0, x)
                v1 = dcf.DCFEval(K1, x)
                self.assertTrue(0 <= v0 < P)
                self.assertTrue(0 <= v1 < P)
                s = v0 + v1
                if x < alpha:
                    self.assertIn(s, (beta, beta + P))
                else:
                    self.assertIn(s, (0, P))
                count += 1
        self.assertEqual(count, DCF_CASES)
        self.assertEqual(count, len(_DEPTHS) * _PAIRS)

    def test_dcf_interval_endpoints(self):
        # Pin the "<" orientation at the boundary and cross-check the O(n^2) conservative construction against the explicit prefix point-function sum P_i(x) = beta * alpha_i * 1[x_1..x_i = alpha_1..alpha_{i-1} 0] (Paper App. B, proof of thm:dcf).
        for n in (1, 2, 3, 4):
            domain = 1 << n
            for alpha in (0, 1, 2, domain // 2, domain - 2, domain - 1):
                if not 0 <= alpha < domain:
                    continue
                beta = 5
                K0, K1 = dcf.DCFGen(_KEY, alpha, beta, mode="conservative", n=n)
                for x in (alpha - 1, alpha, alpha + 1):
                    if not 0 <= x < domain:
                        continue
                    s = dcf.DCFEval(K0, x) + dcf.DCFEval(K1, x)
                    ref = 0
                    for i in range(1, n + 1):
                        a_i = (alpha >> (n - i)) & 1
                        target = (alpha >> (n - i + 1)) << 1
                        if a_i and (x >> (n - i)) == target:
                            ref = (ref + beta) % P
                    if x < alpha:
                        self.assertIn(s, (beta, beta + P))
                    else:
                        self.assertIn(s, (0, P))
                    self.assertEqual(s % P, ref)


if __name__ == "__main__":
    unittest.main()
