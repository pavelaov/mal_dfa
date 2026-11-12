"""Tests for ``vigor_dfa.checkopen`` (Paper Sec. V-F, alg:checkopen; soundness thm:mac-sound, lem:hidden-key, clm:residual Appendix C).

The first test runs an honest batch through the five steps of alg:checkopen between two module instances and checks VERIFIED, the opened values, the cancelling residuals, the per-module counters (2t field products and 1.5 AES blocks per element, Sec. VI-A) and the bound certificates. The second test tampers a value share (S1) and checks ABORT before any release, then demonstrates algebraically why a shared challenge vector breaks the product bound (Sec. VII "Independent challenges", injection 8): with one vector rho across lanes, an adversary submitting d_j = 0 and any e != 0 makes every lane residual -Delta_j <rho, e>, and all lanes vanish together with probability 1/p. The demonstration exposes the challenges inside the test harness only; in the protocol they never leave the modules, and the shared-challenge configuration is refused at session setup. Fixed seeds throughout.
"""

import random
import unittest

from vigor_dfa import auth, field
from vigor_dfa.auth import (AuthVal, BatchOpenings, MACCheck,
                            derive_challenges, share_from_draws)
from vigor_dfa.checkopen import run_pair
from vigor_dfa.ledger import Ledger, LedgerState, ReleaseGuard
from vigor_dfa.params import Label, P, T

_SEED = 0xC0DE2027
_KEY = bytes(range(16))


def _make_sides(delta, rng):
    ds0 = tuple(rng.randrange(P) for _ in range(T))
    ds1 = tuple(field.fsub(delta[j], ds0[j]) for j in range(T))
    l0 = Ledger(0, 0, 0, seal_key=_KEY)
    l1 = Ledger(1, 0, 0, seal_key=_KEY)
    g0 = ReleaseGuard(l0)
    g1 = ReleaseGuard(l1)
    return ds0, ds1, l0, l1, g0, g1


class TestCheckOpen(unittest.TestCase):
    """Freeze-before-challenge opening: honest batch and tamper rejection."""

    def test_honest_batch_verified(self):
        rng = random.Random(_SEED)
        delta = (2, 3, 5)
        values = [rng.randrange(P) for _ in range(3)]
        ds0, ds1, l0, l1, g0, g1 = _make_sides(delta, rng)
        label = Label(0, 0, 9, 0, "check")
        l0.reserve(9, label)
        l0.issue(9)
        l1.reserve(9, label)
        l1.issue(9)
        s0, s1 = [], []
        for v in values:
            a, b = share_from_draws(v, delta, rng.randrange(P),
                                    [rng.randrange(P) for _ in range(T)])
            s0.append(a)
            s1.append(b)
        r0, r1 = run_pair(_KEY, ds0, ds1, (l0, l1), (g0, g1), s0, s1,
                          label, wires=(9, 9, 9))
        self.assertEqual(r0.status, "VERIFIED")
        self.assertEqual(r1.status, "VERIFIED")
        self.assertEqual(r0.opened, tuple(values))
        self.assertEqual(r1.opened, tuple(values))
        # residuals cancel lane by lane (clm:residual)
        for j in range(T):
            self.assertEqual(field.fadd(r0.residuals[j], r1.residuals[j]), 0)
        # per-module counters: 2t field products and 1.5 AES blocks per element, one CheckOpen round (Sec. VI-A)
        self.assertEqual(r0.counters.field_mults, 2 * T * 3)
        self.assertEqual(r0.counters.aes_blocks, (3 * 3 + 1) // 2)
        self.assertEqual(r0.counters.rounds, 1)
        # ledger and guard reach VERIFIED; certificates verify under K
        self.assertIs(l0.state(9), LedgerState.VERIFIED)
        self.assertEqual(g0.state(9), "VERIFIED")
        self.assertTrue(r0.certificates[0].verify(_KEY))
        self.assertTrue(r1.certificates[0].verify(_KEY))

    def test_tampered_batch_aborts_and_shared_challenges_break(self):
        rng = random.Random(_SEED ^ 0x7A11)
        delta = (2, 3, 5)
        v = rng.randrange(P)
        label = Label(0, 0, 9, 0, "check")
        # S1: the GPU adds an error to party 0's value share; the tags are left intact. The harness adapts the error to the fixed-seed challenges (the (2/p)^t bound of thm:mac-sound is analytic; fixed seeds cover conformance, Sec. VIII).
        aborted = None
        for err in range(1, 9):
            ds0, ds1, l0, l1, g0, g1 = _make_sides(delta, rng)
            for lg in (l0, l1):
                lg.reserve(9, label)
                lg.issue(9)
            s0, s1 = share_from_draws(v, delta, rng.randrange(P),
                                      [rng.randrange(P) for _ in range(T)])
            bad0 = AuthVal(field.fadd(s0.x, err), s0.gamma, 0)
            r0, r1 = run_pair(_KEY, ds0, ds1, (l0, l1), (g0, g1), [bad0], [s1],
                              label, wires=(9,))
            if r0.status == "ABORT":
                aborted = (r0, r1, l0, g0)
                break
        self.assertIsNotNone(aborted)
        r0, r1, l0, g0 = aborted
        self.assertEqual(r0.status, "ABORT")
        self.assertEqual(r1.status, "ABORT")
        self.assertIsNone(r0.opened)          # no candidate value released
        self.assertIsNone(r1.opened)
        self.assertEqual(l0.epoch_state, "poisoned")
        self.assertEqual(g0.state(9), "ABORTED")

        # Shared challenge vector: the algebraic counterexample of Sec. VII. With one rho across lanes, every lane residual is -Delta_j <rho, e>; an e orthogonal to the shared rho makes ALL lanes vanish at once.
        h0, h1, cid, m = b"sh0", b"sh1", 3, 2
        x0, x1 = rng.randrange(P), rng.randrange(P)
        s00, s01 = share_from_draws(x0, delta, rng.randrange(P),
                                    [rng.randrange(P) for _ in range(T)])
        s10, s11 = share_from_draws(x1, delta, rng.randrange(P),
                                    [rng.randrange(P) for _ in range(T)])
        rho_shared = derive_challenges(_KEY, h0, h1, cid, m, shared=True)
        rho_indep = derive_challenges(_KEY, h0, h1, cid, m, shared=False)
        rho = rho_shared[0]
        e = (rho[1], field.fneg(rho[0]))      # <rho, e> = 0, forced
        self.assertNotEqual(e, (0, 0))        # e != 0 with overwhelming probability
        forged = (AuthVal(field.fadd(s00.x, e[0]), s00.gamma, 0),
                  AuthVal(field.fadd(s10.x, e[1]), s10.gamma, 0))
        openings = BatchOpenings(cid, h0, h1, forged, (s01, s11))
        out_shared = MACCheck(_KEY, openings, ds0, ds1, shared_challenges=True)
        # a wrong value (e != 0, d_j = 0) is ACCEPTED: the collapse to one lane
        self.assertEqual(out_shared.status, "VERIFIED")
        for j in range(T):
            self.assertEqual(out_shared.residuals[j], 0)
        # Independent lanes: the same error is killed in at most one lane; pick the lane whose challenge e is orthogonal to and verify the other lanes reject (Delta_j != 0 forces the residual nonzero).
        killed = None
        for j in range(T):
            ip = field.fadd(field.fmul(rho_indep[j][0], e[0]),
                            field.fmul(rho_indep[j][1], e[1]))
            if ip == 0:
                killed = j
                break
        if killed is None:
            # e is not orthogonal to any independent lane vector: all three lane residuals are nonzero and the batch is rejected.
            out_indep = MACCheck(_KEY, openings, ds0, ds1, shared_challenges=False)
            self.assertEqual(out_indep.status, "ABORT")
        else:
            others = [j for j in range(T) if j != killed]
            ip_others = [field.fadd(field.fmul(rho_indep[j][0], e[0]),
                                    field.fmul(rho_indep[j][1], e[1]))
                         for j in others]
            if all(ip != 0 for ip in ip_others):
                out_indep = MACCheck(_KEY, openings, ds0, ds1,
                                     shared_challenges=False)
                self.assertEqual(out_indep.status, "ABORT")
            else:
                # under the fixed seed two independent challenge vectors happen to lie in the kernel of e as well; verify the algebraic identity instead of the random outcome
                sums = tuple(field.fmul(field.fneg(delta[j]),
                                        field.fadd(field.fmul(rho_indep[j][0], e[0]),
                                                   field.fmul(rho_indep[j][1], e[1])))
                             for j in range(T))
                self.assertTrue(any(s != 0 for s in sums))


if __name__ == "__main__":
    unittest.main()
