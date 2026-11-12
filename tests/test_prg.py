"""Tests for ``vigor_dfa.prg`` (Paper Sec. IV-B: AES-128 based PRG and the output conversion ``Conv``).

Deterministic throughout: the AES implementation is checked against the FIPS-197 known-answer vectors stored as ``AES128.AES_KAT`` (ciphertexts and full round-key schedules), and the expansion/conversion consistency test uses fixed vectors.
"""

import unittest

from vigor_dfa import prg
from vigor_dfa.params import P


class TestPRG(unittest.TestCase):
    """AES-128 known answers and PRG determinism."""

    def test_prg_aes_known_answers(self):
        for name, kat in prg.AES128.AES_KAT.items():
            with self.subTest(kat=name):
                aes = prg.AES128(bytes.fromhex(kat["key"]))
                self.assertEqual(
                    [rk.hex() for rk in aes.round_keys], kat["round_keys"]
                )
                ct = aes.encrypt_block(bytes.fromhex(kat["plaintext"]))
                self.assertEqual(ct.hex(), kat["ciphertext"])

    def test_prg_expansion_consistency(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        key2 = bytes.fromhex("00112233445566778899aabbccddeef0")
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        out = prg.expand_seed(key, seed)
        self.assertEqual(out, prg.expand_seed(key, seed))  # reproducible
        s_l, t_l, s_r, t_r = out
        self.assertIn(t_l, (0, 1))
        self.assertIn(t_r, (0, 1))
        self.assertLess(s_l, 1 << 128)
        self.assertLess(s_r, 1 << 128)
        self.assertNotEqual(s_l, s_r)  # children differ (fixed vector)
        # a different gate key expands differently (fixed vector)
        self.assertNotEqual(prg.expand_seed(key2, seed), out)

        # convert is deterministic and returns canonical field elements
        c1 = prg.convert(key, seed)
        self.assertEqual(c1, prg.convert(key, seed))
        self.assertIsInstance(c1, int)
        self.assertTrue(0 <= c1 < P)
        self.assertNotEqual(prg.convert(key2, seed), c1)  # keyed (fixed vector)


if __name__ == "__main__":
    unittest.main()
