"""Tests for ``vigor_dfa.attacks`` (Paper Sec. VIII, tab:attacks).

Runs each of the twelve attack and fault injections of tab:attacks against a fresh module pair and asserts that every injection ends in ABORT before any release, with the outcome naming the mechanism that stops it. All twelve rows carry executed evidence (six executed in this CPU reference model, six on the RTL and FPGA implementations); the statistical bound (2/p)^t is analytic (thm:mac-sound), not an empirical forgery count (Sec. VIII). Fixed seeds throughout.
"""

import random
import unittest

from vigor_dfa import attacks
from vigor_dfa.attacks import TWELVE, apply_injection

_SEED = 0xA77AC


class TestAttacks(unittest.TestCase):
    """The twelve tab:attacks injections abort before any release."""

    def test_all_twelve_injections_abort_before_release(self):
        rng = random.Random(_SEED)
        self.assertEqual(len(TWELVE), 12)
        for inj in TWELVE:
            m0, m1, _ = attacks._fresh_pair(rng)
            outcome = apply_injection(m0, m1, inj, rng)
            self.assertTrue(outcome.aborted_before_release,
                            f"injection {inj.id}: {inj.name}")
            self.assertFalse(outcome.released, f"injection {inj.id} released a value")
            self.assertEqual(outcome.mechanism, inj.mechanism)
            if inj.id != 9:   # injection 9 exercises the PIR scan, module-free
                self.assertFalse(m0.epoch_active(),
                                 f"injection {inj.id} left the epoch active")


if __name__ == "__main__":
    unittest.main()
