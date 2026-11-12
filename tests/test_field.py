"""Tests for ``vigor_dfa.field``.

Contract (paper evidence table / technical specification Sec. 15): exactly ``MERSENNE_CASES = 20004`` checks of the Mersenne reduction against direct arithmetic mod ``p``, made up of 4 field operations (add, sub, mul, neg) x 5001 deterministic random vectors.  Fixed seeds make the whole module reproducible.
"""

import random
import unittest

from vigor_dfa import field
from vigor_dfa.params import P

MERSENNE_CASES = 20004  # 4 operations x 5001 random vectors
_VECTORS = 5001
_OPS = 4
_SEED = 0x5EED0001


class TestFieldOps(unittest.TestCase):
    """Mersenne reduction vs direct arithmetic mod p."""

    def test_field_ops_properties(self):
        rng = random.Random(_SEED)
        count = 0
        for i in range(_VECTORS):
            if i == 0:
                a, b = 0, 0
            elif i == 1:
                a, b = P - 1, P - 1
            else:
                a = rng.randrange(P)
                b = rng.randrange(P)
            # each operation routes through mersenne_reduce and is compared against the direct definition modulo p
            self.assertEqual(field.fadd(a, b), (a + b) % P)
            count += 1
            self.assertEqual(field.fsub(a, b), (a - b) % P)
            count += 1
            self.assertEqual(field.fmul(a, b), (a * b) % P)
            count += 1
            self.assertEqual(field.fneg(a), (-a) % P)
            count += 1
        self.assertEqual(count, MERSENNE_CASES)
        self.assertEqual(count, _VECTORS * _OPS)

    def test_field_canonical_encoding(self):
        rng = random.Random(_SEED ^ 0xABCD)
        values = [0, 1, 2, P - 2, P - 1]
        values += [rng.randrange(P) for _ in range(200)]
        for x in values:
            enc = field.encode(x)
            self.assertIsInstance(enc, bytes)
            self.assertEqual(len(enc), 8)
            self.assertEqual(int.from_bytes(enc, "little"), x)
            self.assertEqual(field.decode(enc), x)
        # noncanonical encodings are rejected, never reduced
        with self.assertRaises(ValueError):
            field.decode(P.to_bytes(8, "little"))          # the value p
        with self.assertRaises(ValueError):
            field.decode((1 << 61).to_bytes(8, "little"))  # 2**61
        with self.assertRaises(ValueError):
            field.decode((2**64 - 1).to_bytes(8, "little"))
        with self.assertRaises(ValueError):
            field.decode(b"\x00" * 7)                      # wrong length
        with self.assertRaises(ValueError):
            field.encode(P)
        with self.assertRaises(ValueError):
            field.encode(-1)

    def test_field_rejection_sampling(self):
        # canonical range with the real entropy source (bounded draws)
        values = {field.random_element() for _ in range(200)}
        self.assertTrue(all(0 <= v < P for v in values))
        self.assertTrue(all(v < (1 << 61) for v in values))
        self.assertGreater(len(values), 1)  # non-degenerate source

        # deterministic rejection behavior: a source that returns the forbidden value p first must be re-sampled
        stream = iter(
            [P.to_bytes(8, "little"), b"\x00" * 8, b"\x01" * 8]
        )

        def src(_n: int) -> bytes:
            return next(stream)

        self.assertEqual(field.random_element(src), 0)  # p rejected
        self.assertEqual(field.random_element(src), 0x0101010101010101)
        with self.assertRaises(StopIteration):
            field.random_element(src)  # exhausted source: bounded loop


if __name__ == "__main__":
    unittest.main()
