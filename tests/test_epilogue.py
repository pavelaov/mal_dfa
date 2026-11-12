"""Tests for ``vigor_dfa.epilogue`` (Paper Sec. V-E, thm:epilogue).

Checks that the epilogue output equals the direct authentication formulas y_b = ytilde_b + (-1)^b zeta and gamma_{b,j} = Delta_j y_b + (-1)^b kappa_j, that the reconstructed value and tag sums are exactly the authenticated sharing of ytilde_0 + ytilde_1, and that the counters expose the claimed cost: exactly three field multiplications and four fresh pads per output (Sec. V-E). Fixed seeds throughout.
"""

import unittest

from vigor_dfa import field
from vigor_dfa.auth import Counters
from vigor_dfa.epilogue import Epilogue, EpilogueState
from vigor_dfa.params import Label

_KEY = b"\x13" * 16
_DELTA = (7, 11, 13)


class TestEpilogue(unittest.TestCase):
    """Epilogue correctness and the 3-multiplication / 4-pad counters."""

    def test_epilogue_matches_direct_authentication_and_counters(self):
        label = Label(0, 0, 5, 0, "out")
        ep = Epilogue(_KEY, _DELTA)
        self.assertEqual(Epilogue.FIELD_MULTS, 3)
        self.assertEqual(Epilogue.PADS_PER_OUTPUT, 4)
        pads = ep.fresh_pads(_KEY, label)
        self.assertEqual(len(pads), 4)
        yt0, yt1 = 1000, field.fsub(500, 1000)      # yt_0 + yt_1 = 500
        c0, c1 = Counters(), Counters()
        y0 = ep.authenticate(yt0, EpilogueState(0, pads, c0))
        y1 = ep.authenticate(yt1, EpilogueState(1, pads, c1))

        # authenticated sharing of ytilde_0 + ytilde_1 (thm:epilogue)
        self.assertEqual(field.fadd(y0.x, y1.x), 500)
        for j in range(3):
            self.assertEqual(field.fadd(y0.gamma[j], y1.gamma[j]),
                             field.fmul(_DELTA[j], 500))
        # direct authentication formulas
        self.assertEqual(y0.x, field.fadd(yt0, pads[0]))
        self.assertEqual(y1.x, field.fsub(yt1, pads[0]))
        for j in range(3):
            self.assertEqual(y0.gamma[j],
                             field.fadd(field.fmul(_DELTA[j], y0.x), pads[j + 1]))
            self.assertEqual(y1.gamma[j],
                             field.fsub(field.fmul(_DELTA[j], y1.x), pads[j + 1]))
        # counters: exactly 3 field multiplications and 4 pads per output
        self.assertEqual(c0.field_mults, 3)
        self.assertEqual(c1.field_mults, 3)
        # the pads' two AES blocks are charged by the enclosing gate (Sec. VI-A)
        self.assertEqual(c0.aes_blocks, 0)


if __name__ == "__main__":
    unittest.main()
