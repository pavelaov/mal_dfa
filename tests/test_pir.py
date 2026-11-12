"""Tests for ``vigor_dfa.pir`` (Paper Sec. V-I, alg:pir; correctness thm:pir, Appendix E).

Covers the versioned-snapshot PIR: correct retrieval through the joint GaC path (PIRServerEvalJoint) with certificates, the same-byte snapshot check rejecting substituted or stale bytes (S8) and out-of-range indices, and the client-generated-key alternative of Sec. V-I (PIRQuery/PIRServerEval) with client-side reconstruction. Fixed seeds throughout.
"""

import random
import unittest
from dataclasses import replace

from vigor_dfa import field, pir
from vigor_dfa.ledger import AbortError
from vigor_dfa.params import Label, P

_SEED = 0x9112027
_KEY = bytes(range(16))


class TestPIR(unittest.TestCase):
    """Versioned snapshot retrieval and stale-version rejection."""

    def test_versioned_snapshot_pir_and_stale_rejection(self):
        rng = random.Random(_SEED)
        db = [rng.randrange(P).to_bytes(8, "little") for _ in range(8)]
        snap1 = pir.PIRCommit(db, version=1)
        db2 = list(db)
        db2[3] = field.fadd(int.from_bytes(db2[3], "little"), 1).to_bytes(8, "little")
        snap2 = pir.PIRCommit(db2, version=2)
        self.assertNotEqual(snap1.commitment, snap2.commitment)

        # correct retrieval through the joint GaC path with certificates
        for alpha in (0, 3, 7):
            label = Label(0, 0, 500 + alpha, 0, "q")
            y0, cert0 = pir.PIRServerEvalJoint(_KEY, label, 0, alpha, snap1)
            y1, cert1 = pir.PIRServerEvalJoint(_KEY, label, 1, alpha, snap1)
            self.assertEqual(pir.PIRReconstruct(y0, y1), db[alpha])
            self.assertTrue(cert0.verify(_KEY))
            self.assertTrue(cert1.verify(_KEY))

        # S8: the module hashes exactly the bytes it consumes; substituted (or stale-version) records mismatch cm_v and abort, never release
        tampered = replace(snap1, records=snap2.records, padded=snap2.padded)
        with self.assertRaises(AbortError):
            pir.PIRServerEvalJoint(_KEY, Label(0, 0, 777, 0, "q"), 0, 3, tampered)
        # only alpha < N is authorized (alg:pir step 1)
        with self.assertRaises(AbortError):
            pir.PIRServerEvalJoint(_KEY, Label(0, 0, 778, 0, "q"), 0, 8, snap1)

        # client-generated-key alternative of Sec. V-I
        k0, k1 = pir.PIRQuery(5, snap1.n, qid=5)
        y0, cert0 = pir.PIRServerEval(k0, snap1, 0, key=_KEY, qid=5)
        y1, cert1 = pir.PIRServerEval(k1, snap1, 1, key=_KEY, qid=5)
        self.assertEqual(pir.PIRReconstruct(y0, y1), db[5])
        self.assertTrue(cert0.verify(_KEY))
        self.assertTrue(cert1.verify(_KEY))


if __name__ == "__main__":
    unittest.main()
