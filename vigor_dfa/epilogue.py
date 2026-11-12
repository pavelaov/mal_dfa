"""Fresh authentication epilogue (Sec. V-E, thm:epilogue, Appendix B).

Both modules derive fresh common pads zeta, kappa_1, ..., kappa_t from joint
labels that are distinct for every output wire, and T_b returns

    y_b        = ytilde_b + (-1)^b zeta,
    gamma_{b,j} = Delta_j y_b + (-1)^b kappa_j      (j in [t]).

The pads cancel in y_0 + y_1 and in gamma_{0,j} + gamma_{1,j} =
Delta_j (y_0 + y_1), so the result is an authenticated sharing of
ytilde_0 + ytilde_1, and each party's tuple is uniform on F_p^{1+t} whatever
the gate value and the global keys (thm:epilogue), jointly across fresh
outputs. Cost: one raw FSS computation, three field multiplications and four
fresh pads per party and output, and the output is a 32-byte tuple
(Sec. V-E). In the hardware datapath the four 61-bit pads occupy two AES
blocks (Sec. VI-A).

API restriction (Sec. V-E): the epilogue accepts only results computed inside
the module, namely the DPF, DCF, LUT, interval and direct gates and the PIR
reductions, or results from an explicitly verified backend such as the
frozen-operand Freivalds check. There is no authenticate(host_value) command:
with one, the module would become a MAC oracle - a malicious host could
obtain valid tags on any value it wishes to open, and CheckOpen would accept
the forgery with probability one. This closes the forgery-oracle path of
scenario S2 "Forgery-oracle request" (tab:scenarios, Sec. III-C; Appendix B,
"The epilogue is not an authentication oracle"). (The scenario is S2 in the
paper's scenario numbering of tab:scenarios; S1-S10 are defined in
Sec. III-C.)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from . import field
from .auth import AuthVal, Counters, FieldOps, FIELD61, field_draw, sublabel


@dataclass
class EpilogueState:
    """Per-output epilogue state: the local party, the four fresh joint pads
    and the counters the authentication is charged to."""
    party: int
    pads: tuple[int, int, int, int]
    counters: Optional[Counters] = None


class Epilogue:
    """Fresh authentication epilogue of Sec. V-E, parameterized by the session
    key and the global MAC keys (modules only; the host never holds Delta_j)."""

    FIELD_MULTS = 3        # three field multiplications per output (Sec. V-E)
    PADS_PER_OUTPUT = 4    # zeta plus one kappa per lane (t = 3)

    def __init__(self, key: bytes, delta: Sequence[int],
                 ops: FieldOps = FIELD61):
        self.key = key
        self.delta = tuple(delta)
        self.ops = ops

    def fresh_pads(self, key: bytes, label) -> tuple[int, int, int, int]:
        """The four fresh pads (zeta, kappa_1, kappa_2, kappa_3) under joint
        labels pad_0..pad_3, distinct for every output wire (Sec. V-E)."""
        return (field_draw(key, sublabel(label, "pad_0"), self.ops.p, self.ops.n),
                field_draw(key, sublabel(label, "pad_1"), self.ops.p, self.ops.n),
                field_draw(key, sublabel(label, "pad_2"), self.ops.p, self.ops.n),
                field_draw(key, sublabel(label, "pad_3"), self.ops.p, self.ops.n))

    def authenticate(self, y_tilde: int, state: EpilogueState) -> AuthVal:
        """y_b = ytilde_b + (-1)^b zeta and gamma_{b,j} = Delta_j y_b +
        (-1)^b kappa_j. Exactly three field multiplications (the products
        Delta_j y_b, one per lane) and four pads per output; the pads occupy
        two AES blocks in the hardware datapath (Sec. VI-A)."""
        zeta, k1, k2, k3 = state.pads
        add, sub, mul = self.ops.add, self.ops.sub, self.ops.mul
        if state.party == 0:
            y = add(y_tilde, zeta)
            tags = tuple(add(mul(self.delta[j], y), k) for j, k in enumerate((k1, k2, k3)))
        else:
            y = sub(y_tilde, zeta)
            tags = tuple(sub(mul(self.delta[j], y), k) for j, k in enumerate((k1, k2, k3)))
        if state.counters is not None:
            state.counters.field_mults += self.FIELD_MULTS
        return AuthVal(y, tags, state.party)
