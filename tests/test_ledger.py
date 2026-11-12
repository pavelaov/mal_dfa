"""Tests for ``vigor_dfa.ledger`` (Paper Sec. V-D, fig:ledger; Sec. VI-A).

Covers the one-time lifecycle NEW -> RESERVED -> PREPARED -> FROZEN -> VERIFIED -> CONSUMED -> RELEASED, the label and role binding (S4, S5), the freeze semantics (exact copied bytes, S3), the release guard (S6), epoch poisoning, release certificates and the reboot rule (erase-and-rekey without a trusted monotonic service). Fixed seeds throughout.
"""

import unittest

from vigor_dfa.ledger import (AbortError, Certificate, Ledger, LedgerState,
                              ReleaseGuard)
from vigor_dfa.params import Label

_SESSION = 0
_KEY = b"\x11" * 16


class TestLedger(unittest.TestCase):
    """One-time ledger, poisoning, release guard and reboot."""

    def test_ledger_one_time_binding_poison_and_guard(self):
        lab = Label(_SESSION, 0, 42, 0, "gate")
        lg = Ledger(0, _SESSION, 0, seal_key=_KEY)
        g = ReleaseGuard(lg)

        # Reservation burns the label before any share is issued
        rec = lg.reserve(42, lab)
        self.assertIs(lg.state(42), LedgerState.RESERVED)
        self.assertEqual(rec.label, lab)
        with self.assertRaises(AbortError):
            lg.reserve(42, lab)                       # identifier already burned (S4)
        with self.assertRaises(AbortError):
            lg.reserve(42, Label(_SESSION, 0, 42, 1, "gate"))   # role mismatch (S5)
        with self.assertRaises(AbortError):
            lg.reserve(41, Label(_SESSION, 0, 43, 0, "gate"))   # misrouted gate (S5)

        # PREPARED issues the party-local preprocessing exactly once
        lg.issue(42)
        self.assertIs(lg.state(42), LedgerState.PREPARED)
        with self.assertRaises(AbortError):
            lg.issue(42)

        # Freeze copies the exact submitted bytes; a later host rewrite of its buffer changes nothing that is consumed (S3)
        data = bytearray(b"abcd")
        handle, root = lg.freeze(42, bytes(data), b"desc")
        data[0] = 0xFF
        self.assertEqual(lg.get_frozen(handle), b"abcd")
        self.assertIs(lg.state(42), LedgerState.FROZEN)

        # VERIFIED is reached only from FROZEN
        lg.verify(42)
        self.assertIs(lg.state(42), LedgerState.VERIFIED)

        # The release guard opens only for a VERIFIED gate (S6)
        with self.assertRaises(AbortError):
            g.release(42)
        self.assertEqual(g.state(42), "PENDING")
        g.arm(42)
        self.assertEqual(g.state(42), "VERIFIED")
        g.release(42)                                 # CONSUMED -> RELEASED
        self.assertIs(lg.state(42), LedgerState.RELEASED)
        with self.assertRaises(AbortError):
            g.release(42)                             # one-time release

        # Release certificate binding and verification
        cert = lg.certificate(42, (0, 1), b"hash", "RELEASED", _KEY)
        self.assertIsInstance(cert, Certificate)
        self.assertTrue(cert.verify(_KEY))
        self.assertFalse(cert.verify(b"\x22" * 16))

        # Any invalid transition moves the gate to ABORTED and poisons the epoch
        lab2 = Label(_SESSION, 0, 43, 0, "gate2")
        lg.reserve(43, lab2)
        lg.issue(43)
        with self.assertRaises(AbortError):
            lg.consume(43)                            # CONSUMED requires VERIFIED
        self.assertEqual(lg.epoch_state, "poisoned")
        self.assertIs(lg.state(43), LedgerState.ABORTED)
        self.assertFalse(lg.epoch_active())
        with self.assertRaises(AbortError):
            lg.verify(43)                             # poisoned: no new transitions

        # Reboot without a trusted monotonic service erases the key and requires a freshly attested session (Sec. V-D)
        lg.reboot(monotonic_service=False)
        self.assertTrue(lg.key_erased)
        with self.assertRaises(AbortError):
            lg.require_active()

        # With a trusted monotonic service the session survives the reboot
        lg2 = Ledger(1, _SESSION, 0, seal_key=_KEY)
        lg2.reboot(monotonic_service=True)
        self.assertFalse(lg2.key_erased)
        lg2.require_active()


if __name__ == "__main__":
    unittest.main()
