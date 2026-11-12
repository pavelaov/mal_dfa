"""Tests for ``vigor_dfa.gac`` (Paper Sec. V-D, alg:gac; correctness thm:gac, Appendix B).

Contract (paper evidence table): exactly ``GAC_CASES = 2728`` party-local comparisons between the streaming generate-and-consume output and the materialized reference path (dpf.Gen followed by dpf.Eval on the same label), made up of 8 depths x 341 deterministic cases. Each case couples, for both parties, the epilogue output of gac_gate with the raw share of alg:gen/alg:eval plus the direct authentication formulas of thm:epilogue, and checks thm:dpf-correct through the epilogue (y_0 + y_1 = beta * 1[x = alpha]). The AES-block counters must equal the architecture's 6n + 3 blocks per GaC output (Sec. VI-A: 3n expansions of two blocks each, one conversion block, two pad blocks). Fixed seeds throughout.

The coupling uses the same joint root derivation on both sides (gac and dpf.Gen both draw the roots of purposes "root-0"/"root-1"), so thm:gac's node-by-node induction applies.
"""

import random
import unittest

from vigor_dfa import auth, dpf, field, gac
from vigor_dfa.auth import Counters, sublabel
from vigor_dfa.params import Label, P

GAC_CASES = 2728  # 8 depths x 341 deterministic cases
_DEPTHS = tuple(range(1, 9))
_CASES_PER_DEPTH = 341
_SEED = 0x6AC2027
_KEY = bytes(range(16))
_DELTA = (3, 5, 7)


class TestGaC(unittest.TestCase):
    """Streaming GaC equals the materialized Gen/Eval path, node by node."""

    def test_gac_gate_matches_materialized_reference(self):
        rng = random.Random(_SEED)
        count = 0
        for n in _DEPTHS:
            for case in range(_CASES_PER_DEPTH):
                label = Label(0, 0, case, 0, f"gac:{n}:{case}")
                alpha = auth.bits_draw(_KEY, sublabel(label, "target"), n)
                x = rng.getrandbits(n)
                beta = rng.randrange(P)
                c0, c1 = Counters(), Counters()
                y0 = gac.gac_gate(_KEY, label, 0, x, beta, _DELTA,
                                  counters=c0, nbits=n)
                y1 = gac.gac_gate(_KEY, label, 1, x, beta, _DELTA,
                                  counters=c1, nbits=n)
                # Materialized reference: dpf.Gen + dpf.Eval on the same label (thm:gac couples the streaming and materialized executions).
                k0, k1 = dpf.Gen(_KEY, label, alpha, beta, n=n)
                raw0 = dpf.Eval(k0, x)
                raw1 = dpf.Eval(k1, x)
                # Epilogue with the same joint pads (thm:epilogue)
                pads = tuple(auth.field_draw(_KEY, sublabel(label, f"pad_{j}"))
                             for j in range(4))
                self.assertEqual(y0.x, field.fadd(raw0, pads[0]))
                self.assertEqual(y1.x, field.fsub(raw1, pads[0]))
                for j in range(3):
                    self.assertEqual(y0.gamma[j],
                                     field.fadd(field.fmul(_DELTA[j], y0.x),
                                                pads[j + 1]))
                    self.assertEqual(y1.gamma[j],
                                     field.fsub(field.fmul(_DELTA[j], y1.x),
                                                pads[j + 1]))
                # thm:dpf-correct through the epilogue
                self.assertEqual(field.fadd(y0.x, y1.x),
                                 beta if x == alpha else 0)
                # AES accounting: 6n + 3 blocks per GaC output (Sec. VI-A)
                self.assertEqual(c0.aes_blocks, 6 * n + 3)
                self.assertEqual(c1.aes_blocks, 6 * n + 3)
                self.assertEqual(c0.field_mults, 3)   # epilogue products
                count += 1
        self.assertEqual(count, GAC_CASES)
        self.assertEqual(count, len(_DEPTHS) * _CASES_PER_DEPTH)


if __name__ == "__main__":
    unittest.main()
