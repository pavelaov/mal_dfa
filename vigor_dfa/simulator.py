"""Explicit simulator and the hybrid argument (Sec. VII-B, Appendix E, thm:main).

The simulator Sim plays F_T for both modules, keeps the global MAC keys
internally, and tracks the ledger and, for every wire, the tuple a faithful
corrupt party would hold; honest shares stay symbolic, so honest values are
never needed. Five hybrids connect the real and ideal executions:

  H0  real execution: the modules run the concrete module program (F_T with
      its joint random function instantiated by PRF_K, peer and client
      channels by AEAD over the hosts' network, OPEN_SESSION by attestation
      plus authenticated key exchange);
  H1  ideal setup and channels: setup becomes the ideal role-bound interface
      and protected-channel contents become ideal deliveries of the permitted
      lengths and schedules (cost eps_setup + eps_channel);
  H2  ideal randomness and bindings: PRF/KDF outputs become ideal coins, any
      binding failure aborts, streaming generate-and-consume is replaced by
      alg:gen followed by alg:eval (thm:gac) and refactored samplers by their
      reference forms (lem:bijection, lem:noninv); the ledger then excludes
      label reuse, role swapping and post-challenge byte replacement
      (cost eps_prf + eps_bind);
  H3  abort on an accepted wrong-value opening: the experiment aborts at the
      first CheckOpen batch accepted with e != 0 (and, if alg:freivalds is
      enabled, at the first accepted C != AB). Cost: Q (2/p)^t
      (plus Q_F / p^s);
  H4  ideal execution: honest parties use F_C; Sim extracts corrupt inputs
      (x* = r + eps or the committed loader value), samples preprocessing
      tuples, epilogue and direct-gate outputs and every masked opening
      uniformly, decides each check from <rho_j, d_j - Delta_j e> with its
      own keys and fresh challenges, delivers a corrupt recipient's output
      mask o early and programs its opening upsilon = y + o after F_C
      releases y, and appends the stipulated trace simulator
      (cost eps_trace).

By the triangle inequality,

    eps_VIGOR <= eps_setup + eps_prf + eps_channel + eps_bind + eps_trace
                 + Q (2/p)^t    (+ Q_F / p^s).

With p = 2^61 - 1, t = 3 and Q <= 2^32 the statistical term satisfies
log2 Q (2/p)^t ~= 32 + 3 (1 - 61) = -148, i.e. about 2^-148, below the
128-bit computational target of the primitives (Sec. VII-C, tab:lanes).
"""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass, field as dc_field
from typing import Optional, Sequence

from . import field, module as module_mod
from .auth import AuthVal, Label, share_from_draws
from .ideal import IdealF_C
from .ledger import AbortError
from .params import P, T


def statistical_term(q_batches: int, t: int = T, p: int = P) -> float:
    """Q (2/p)^t of thm:main. For p = 2^61 - 1, t = 3 and Q <= 2^32,
    log2 Q(2/p)^t ~= 32 + 3(1 - 61) = -148, i.e. about 2^-148 (Sec. VII-C)."""
    return q_batches * (2.0 / p) ** t


@dataclass(frozen=True)
class HybridReport:
    level: int
    name: str
    replacements: tuple[str, ...]
    cost: str


HYBRIDS: tuple[HybridReport, ...] = (
    HybridReport(0, "H0: real execution",
                 ("concrete module program: F_T with its joint random function R "
                  "instantiated by PRF_K, peer and client channels by AEAD over "
                  "the hosts' network, OPEN_SESSION by attestation plus "
                  "authenticated key exchange",), "0"),
    HybridReport(1, "H1: ideal setup and channels",
                 ("setup becomes the ideal role-bound interface; protected-channel "
                  "contents become ideal deliveries of the permitted lengths and "
                  "schedules",), "eps_setup + eps_channel"),
    HybridReport(2, "H2: ideal randomness and bindings",
                 ("PRF/KDF outputs become ideal coins; any binding failure aborts; "
                  "streaming generate-and-consume is replaced by alg:gen followed by "
                  "alg:eval (thm:gac); refactored samplers by their reference forms "
                  "(lem:bijection, lem:noninv)",), "eps_prf + eps_bind"),
    HybridReport(3, "H3: abort on an accepted wrong-value opening",
                 ("the experiment aborts at the first CheckOpen batch accepted with "
                  "e != 0 (and at the first accepted C != AB if alg:freivalds is "
                  "enabled)",), "Q (2/p)^t  (+ Q_F/p^s)"),
    HybridReport(4, "H4: ideal execution",
                 ("honest parties use F_C; Sim extracts corrupt inputs, samples "
                  "preprocessing tuples, epilogue and direct-gate outputs and every "
                  "masked opening uniformly, decides each check from "
                  "<rho_j, d_j - Delta_j e>, programs corrupt recipients' openings "
                  "after F_C releases y, and appends the trace simulator",),
                 "eps_trace"),
)


class Simulator:
    """The simulator Sim of Appendix E (Sim1..Sim13). Sim plays F_T for both
    modules, keeps the global MAC keys internally, and tracks the ledger and,
    for every wire, the tuple a faithful corrupt party would hold; honest
    shares stay symbolic, so honest values are never needed."""

    def __init__(self, corrupt_party: int, manifest: dict, seed: int = 0):
        self.b_star = corrupt_party
        self.mu = manifest
        self.aborted = False
        self._rng = random.Random(seed)
        # Sim3: wire -> faithful tuple of the corrupt party (honest-side shares are symbolic: x_bar = x - x_hat, gamma_bar = Delta_j x - gamma_hat, defined only through wire values).
        self.faithful: dict[int, AuthVal] = {}
        self.wire_values: dict[int, int] = {}
        self.ledger_state: dict[int, str] = {}
        self.delta: tuple[int, ...] = ()
        self.delta_share: tuple[int, ...] = ()
        self.delta_honest: tuple[int, ...] = ()

    # Sim1: keys. Sample Delta_j and Delta_{b*,j} uniformly; the honest shares are the differences. The global keys stay inside Sim.
    def sim1_keys(self) -> None:
        self.delta = tuple(self._rng.randrange(P) for _ in range(T))
        self.delta_share = tuple(self._rng.randrange(P) for _ in range(T))
        self.delta_honest = tuple(
            field.fsub(self.delta[j], self.delta_share[j]) for j in range(T))

    # Sim2: ledger. Run the ledger state machine of fig:ledger for both modules on the public manifest: labels, reservations, frozen roots, consumed identifiers, epoch status and release certificates.
    def sim2_ledger(self, gate: int, state: str) -> None:
        self.ledger_state[gate] = state

    # Sim3: faithful tuples (see __init__).
    def sim3_record(self, wire: int, value: int, tuple_b: AuthVal) -> None:
        self.wire_values[wire] = value
        self.faithful[wire] = tuple_b

    # Sim4: setup. Emulate OPEN_SESSION with the ideal authenticated setup and output its public transcript.
    def sim4_setup(self) -> dict:
        return {"transcript": "public setup transcript (ideal role-bound interface)"}

    # Sim5: preprocessing. For every authenticated random value handed to the corrupt host (input and output masks, triple components, field masks, mask bits), sample phi <- F_p^{t+1}: the exact party-local distribution of AuthShare. Wrap bits, DPF/DCF keys and raw shares never leave the modules, so nothing is simulated for them.
    def sim5_preprocessing(self) -> tuple[int, ...]:
        return tuple(self._rng.randrange(P) for _ in range(T + 1))

    # Sim6: inputs and validation. For a corrupt owner: sample the complete mask r, receive the broadcast eps, compute x* = r + eps and abort (as the modules do) unless x* in In_nu; otherwise submit x* to F_C. For an honest owner: sample the public masked difference eps uniformly and let the undisclosed mask be the symbolic r := x - eps.
    def sim6_inputs(self, eps: int, in_nu) -> int:
        r = self._rng.randrange(P)
        x_star = field.fadd(r, eps)
        if not in_nu(x_star):
            self.aborted = True
            raise AbortError("input out of declared interface")
        return x_star

    # Sim7: local linear operations. Apply additions, public scalings and public-constant updates to the faithful tuples with Pi_Lin.
    def sim7_linear(self, wire: int, op: str, c: int = 0) -> None:
        # Symbolic bookkeeping: the faithful tuple is updated by the linear rules of fig:arith; the reference stores the operation record.
        self.ledger_state.setdefault(wire, op)

    # Sim8: multiplications. Release fresh d, e; the hidden triple is defined afterwards by a := x - d, b := y - e, c := ab (the corrupt tuples of [a], [b], [c] were sampled in Sim5 independently of these values).
    def sim8_multiplications(self) -> tuple[int, int]:
        return self._rng.randrange(P), self._rng.randrange(P)

    # Sim9: checks. Compare submitted corrupt bytes with the faithful tuples, forming the value-error vector e and the tag-error vectors d_j; sample fresh challenges rho_j and accept iff <rho_j, d_j - Delta_j e> = 0 for every j (clm:check). A rejection poisons the epoch and instructs F_C to abort; acceptance with e != 0 is the bad event of H3.
    def sim9_checks(self, submitted: Sequence[AuthVal], wires: Sequence[int],
                    rho: Sequence[Sequence[int]]) -> bool:
        faithful = [self.faithful[w] for w in wires]
        accept = self.check_outcome(submitted, faithful, rho)
        if accept and any(field.fsub(v.x, ft.x) != 0
                          for v, ft in zip(submitted, faithful)):
            self.aborted = True   # Bad_MAC of H3: accepted wrong value
            return False
        if not accept:
            self.aborted = True   # rejection poisons the epoch
        return accept

    # Sim10: outputs. For a private output to an honest recipient, release upsilon uniformly with the hidden mask symbolic o := upsilon - y; for a corrupt authorized recipient, sample o early and program upsilon := y + o after F_C releases y; for a public output, release y.
    def sim10_outputs(self, y: Optional[int], recipient_corrupt: bool) -> int:
        if y is None:
            return self._rng.randrange(P)          # honest recipient: uniform
        return field.fadd(y, self._rng.randrange(P))  # corrupt recipient

    # Sim11: nonlinear gates. Release the masked field opening c (symbolic mask r := c - x) or the XOR opening u (r := x xor u) uniformly; every EVAL_FSS response and direct-gate output is a uniform tuple whose value is defined by the gate semantics (thm:bitdec, thm:cmp-trunc, thm:lut, thm:interval). Carry chains, comparator steps and Horner products are multiplications and use Sim8.
    def sim11_nonlinear(self) -> int:
        return self._rng.randrange(P)

    # Sim12: matrix verification. If alg:freivalds is enabled, emulate VERIFY_MATRIX on the supplied bytes; an accepted C != AB is the bad event Bad_F of H3.
    def sim12_matrix(self, A, B, C, s: int = 3) -> bool:
        return _mat_eq(_mat_mul(A, B), C)

    # Sim13: traces. The stipulated trace simulator Sim_trace on the command sequence issued by host b*, mu, the public lengths and the accept or abort outcomes (cost eps_trace).
    def sim13_traces(self, commands: Sequence[str], statuses: Sequence[str]) -> list:
        return [{"command": c, "status": s} for c, s in zip(commands, statuses)]

    def check_outcome(self, submitted: Sequence[AuthVal], faithful: Sequence[AuthVal],
                      rho: Sequence[Sequence[int]]) -> bool:
        """clm:check (Appendix E): the check accepts iff
        bigwedge_j <rho_j, d_j - Delta_j e> = 0, where e and d_j are the
        differences between the submitted and the faithful tuples."""
        m = len(submitted)
        for j in range(T):
            acc = 0
            for i in range(m):
                e = field.fsub(submitted[i].x, faithful[i].x)
                d = field.fsub(submitted[i].gamma[j], faithful[i].gamma[j])
                acc = field.fadd(acc,
                                 field.fmul(rho[j][i],
                                            field.fsub(d, field.fmul(self.delta[j], e))))
            if acc != 0:
                return False
        return True


def _mat_mul(A, B):
    m, k, n = len(A), len(A[0]), len(B[0])
    return [[sum(field.fmul(A[i][t], B[t][j]) for t in range(k)) % P
             for j in range(n)] for i in range(m)]


def _mat_eq(A, B) -> bool:
    return len(A) == len(B) and all(len(r) == len(s) and r == s
                                    for r, s in zip(A, B))


@dataclass
class RealRun:
    outputs: dict = dc_field(default_factory=dict)
    aborted: bool = False
    traces: list = dc_field(default_factory=list)


@dataclass
class IdealRun:
    outputs: dict = dc_field(default_factory=dict)
    aborted: bool = False
    status: tuple = ()


class Experiment:
    """Real/ideal experiment of the paper's definition (Appendix A, "Real and
    ideal executions"): one admitted execution, at most one statically
    corrupted computing host (the adversary hooks), abort tracking, and the
    H0..H4 structure above. The reference runs a tiny manifest (one masked
    input, one opening and one output) through the concrete module program
    in the real world and through F_C plus Sim in the ideal world; the full
    circuit simulation of Appendix E is structural, and the hybrids carry
    their replacement notes verbatim."""

    def __init__(self, manifest: dict, honest_inputs: dict,
                 corrupt_party: Optional[int] = None):
        self.mu = manifest
        self.honest_inputs = dict(honest_inputs)
        self.corrupt_party = corrupt_party

    def run_real(self, adversary=None, key: bytes = b"\x01" * 16) -> RealRun:
        """H0: the modules run the concrete module program (module.VIGORModule
        with PRF_K draws and the AEAD peer channel). The adversary hook may
        deviate the corrupt host's messages; every deviation that the
        protocol detects is tracked as an abort. The reference runs the
        public-output path of Pi_Out (Sec. V-G: y <- CheckOpen([y])) for one
        wire; the private-output path uses the same commands plus the output
        mask issued at RESERVE_PREP."""
        run = RealRun()
        m0 = module_mod.VIGORModule(0, key)
        m1 = module_mod.VIGORModule(1, key)
        module_mod.connect(m0, m1)
        manifest = {"trunc_rule": "toward_zero", "overflow": "abort",
                    "shared_challenges": False}
        try:
            m0.dispatch("OPEN_SESSION", {"manifest": manifest})
            m1.dispatch("OPEN_SESSION", {"manifest": manifest})
            label = Label(0, 0, 1, 0, "input")
            m0.dispatch("RESERVE_PREP", {"gate": 1, "label": label, "op": "input"})
            m1.dispatch("RESERVE_PREP", {"gate": 1, "label": label, "op": "input"})
            if adversary is not None:
                adversary(m0, m1, self)
            gate = 2
            lab = Label(0, 0, gate, 0, "out")
            m0.dispatch("RESERVE_PREP", {"gate": gate, "label": lab, "op": "output"})
            m1.dispatch("RESERVE_PREP", {"gate": gate, "label": lab, "op": "output"})
            value = self.honest_inputs.get(0, 0)
            v0 = random.Random(1).randrange(P)
            g0 = [random.Random(2 + j).randrange(P) for j in range(T)]
            s0, s1 = share_from_draws(value, m0.delta, v0, g0)
            m0.dispatch("FREEZE_BATCH", {"gate": gate, "bytes": s0.to_bytes(),
                                         "wires": (gate,), "dims": (1,)})
            m1.dispatch("FREEZE_BATCH", {"gate": gate, "bytes": s1.to_bytes(),
                                         "wires": (gate,), "dims": (1,)})
            out: dict = {}

            def go(m):
                out[m.party] = m.dispatch("CHECK_OPEN", {"gate": gate, "timeout": 60.0})

            t0 = threading.Thread(target=go, args=(m0,))
            t1 = threading.Thread(target=go, args=(m1,))
            t0.start()
            t1.start()
            t0.join(60)
            t1.join(60)
            if t0.is_alive() or t1.is_alive():
                raise AbortError("peer timeout")
            upsilon = out[0][0]
            m0.dispatch("FINAL_OUTPUT", {"gate": gate, "recipient": 2,
                                         "authorized": (2,), "upsilon": upsilon})
            m1.dispatch("FINAL_OUTPUT", {"gate": gate, "recipient": 2,
                                         "authorized": (2,), "upsilon": upsilon})
            run.outputs[gate] = upsilon
        except Exception:
            run.aborted = True
        return run

    def run_ideal(self, adversary=None) -> IdealRun:
        """H4: honest parties forward their inputs to F_C and the adversary
        interacts with Sim; abort and validation outcomes are tracked."""
        run = IdealRun()
        sim = Simulator(self.corrupt_party if self.corrupt_party is not None else 0,
                        self.mu)
        sim.sim1_keys()
        f = IdealF_C(self.mu)
        try:
            for wire, x in self.honest_inputs.items():
                f.step1_inputs(wire, x, owner_honest=True, in_nu=True)
            f.step2_validation([])
            f.step3_evaluate(lambda inputs: {"y": inputs})
            if adversary is not None:
                adversary(sim, f, self)
            run.outputs = dict(f.outputs)
        except Exception:
            run.aborted = True
            sim.aborted = True
        run.status = f.status
        return run

    def hybrid(self, level: int) -> HybridReport:
        return HYBRIDS[level]

    def advantage(self, q_batches: int, eps_setup: float = 0.0,
                  eps_prf: float = 0.0, eps_channel: float = 0.0,
                  eps_bind: float = 0.0, eps_trace: float = 0.0,
                  q_f: int = 0, s: int = 3) -> float:
        """eps_VIGOR <= eps_setup + eps_prf + eps_channel + eps_bind +
        eps_trace + Q (2/p)^t, plus Q_F / p^s when alg:freivalds is enabled
        (thm:main)."""
        total = (eps_setup + eps_prf + eps_channel + eps_bind + eps_trace
                 + statistical_term(q_batches))
        if q_f:
            total += q_f / (P ** s)
        return total
