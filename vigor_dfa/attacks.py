"""Attack and fault injections (tab:attacks, Sec. VIII).

The twelve injections of tab:attacks, named verbatim after the table's "Injection" column, each with the mechanism that stops it (the table's "Mechanism" column) and each ending in ABORT before any release. The scenario identifiers refer to tab:scenarios (Sec. III-C): the injections cover S1 and S3-S8 plus the engine-conformance, challenge-configuration and numeric-contract cases; S2 is excluded by construction (no command authenticates a host-supplied value), and S9 is permitted by the functionality (its commitment-bound loader variant is the model-provenance mechanism, not an injection) - exactly as Sec. VIII states.

Evidence status (tab:attacks): every row carries executed evidence. Six rows are executed in the CPU reference model implemented in this package; the other six are executed on the RTL and FPGA implementations. Observing zero accepted forgeries in a finite campaign cannot support a bound such as 2^-148; that bound comes from thm:mac-sound together with the ledger rules (Sec. VIII).
"""

from __future__ import annotations

import hashlib
import random
import threading
from dataclasses import dataclass, replace
from typing import Optional

from . import field, pir
from .auth import AuthVal, Label, share_from_draws
from .ledger import AbortError, FrozenPage
from .module import VIGORModule, connect
from .params import P, T

MANIFEST = {"trunc_rule": "toward_zero", "overflow": "abort",
            "shared_challenges": False}


@dataclass(frozen=True)
class Injection:
    id: int
    name: str
    scenario: str
    mechanism: str
    reference_model: bool     # executed in the CPU reference model
    evidence: str


TWELVE: tuple[Injection, ...] = (
    Injection(1, "Change payload, query, role, gate id, table hash or shape (S5)",
              "S5",
              "Ledger descriptor binding; role- and gate-bound PRF labels (Sec. V-D)",
              True, "executed in the CPU reference model"),
    Injection(2, "Flip a control bit, root seed or correction word in a candidate engine",
              "engine conformance (S2 boundary)",
              "Conformance against the reference DPF (thm:dpf-correct); unverified "
              "engine output is never authenticated",
              False, "executed on the RTL and FPGA implementations"),
    Injection(3, "Change a GPU value share or tag (S1)",
              "S1",
              "CheckOpen with t=3 independent lanes (thm:mac-sound)",
              True, "executed in the CPU reference model"),
    Injection(4, "Triple with valid-looking tags but c != ab (S7)",
              "S7",
              "Triples computed inside the TCB; imported material needs a correctness proof",
              False, "executed on the RTL and FPGA implementations"),
    Injection(5, "Reuse a mask or counter; reset and resume old keys (S4)",
              "S4",
              "One-time ledger, epoch poisoning, erase-and-rekey",
              True, "executed in the CPU reference model"),
    Injection(6, "Modify a DMA buffer after freezing (S3)",
              "S3",
              "Freeze-before-challenge; consume only frozen pages",
              True, "executed in the CPU reference model"),
    Injection(7, "Swap only the last column of a GPU matrix product",
              "S7",
              "Frozen-operand Freivalds over all columns, s=3 (thm:freivalds)",
              False, "executed on the RTL and FPGA implementations"),
    Injection(8, "Reuse one challenge vector across MAC lanes",
              "check-engine configuration",
              "Independent per-lane challenges; configuration check "
              "(counterexample in Appendix C)",
              False, "executed on the RTL and FPGA implementations"),
    Injection(9, "Change database bytes or version after hashing (S8)",
              "S8",
              "Same-byte snapshot hash and certificate binding (thm:pir)",
              True, "executed in the CPU reference model"),
    Injection(10, "Request output before the verification barrier (S6)",
               "S6",
               "Release guard (Sec. V-D)",
               False, "executed on the RTL and FPGA implementations"),
    Injection(11, "Overflow or truncate with the wrong signed rule",
              "numeric contract",
              "Exact finite reference; numeric contract (thm:cmp-trunc)",
              True, "executed in the CPU reference model"),
    Injection(12, "Delay, drop or reorder packets (S10)",
              "S10",
              "Bounded resources and abort",
              False, "executed on the RTL and FPGA implementations"),
)


@dataclass(frozen=True)
class AttackOutcome:
    injection_id: int
    aborted_before_release: bool
    released: bool
    mechanism: str
    detail: str = ""


def _fresh_pair(rng: random.Random, freeze_sram_bytes: int = VIGORModule.FREEZE_SRAM_BYTES):
    """A fresh module pair with a fixed-seed session key, wired through the
    AEAD peer channel (Sec. VIII: seeds are fixed only for public synthetic
    inputs; production randomness stays fresh)."""
    key = bytes(rng.getrandbits(8) for _ in range(16))
    m0 = VIGORModule(0, key, freeze_sram_bytes=freeze_sram_bytes)
    m1 = VIGORModule(1, key, freeze_sram_bytes=freeze_sram_bytes)
    connect(m0, m1)
    return m0, m1, key


def _open(m0: VIGORModule, m1: VIGORModule) -> None:
    for m in (m0, m1):
        m.dispatch("OPEN_SESSION", {"manifest": dict(MANIFEST)})


def _checked_value(m0: VIGORModule, m1: VIGORModule, gate: int, value: int,
                   rng: random.Random, tamper: int = 0, timeout: float = 5.0):
    """Freeze a shared value under the gate and run CHECK_OPEN on both modules
    concurrently; returns the opened value (or the status string on abort).
    `tamper` adds an error to party 0's value share (injection 3)."""
    delta = m0.delta
    v0 = rng.randrange(P)
    g0 = [rng.randrange(P) for _ in range(T)]
    s0, s1 = share_from_draws(value, delta, v0, g0)
    if tamper:
        s0 = AuthVal(field.fadd(s0.x, tamper), s0.gamma, 0)
    for m, s in ((m0, s0), (m1, s1)):
        m.dispatch("FREEZE_BATCH", {"gate": gate, "bytes": s.to_bytes(),
                                    "wires": (gate,), "dims": (1,)})
    out: dict = {}

    def go(m):
        out[m.party] = m.dispatch("CHECK_OPEN", {"gate": gate, "timeout": timeout})

    t0 = threading.Thread(target=go, args=(m0,))
    t1 = threading.Thread(target=go, args=(m1,))
    t0.start()
    t1.start()
    t0.join(30)
    t1.join(30)
    if t0.is_alive() or t1.is_alive():
        raise AbortError("peer timeout")
    return out[0], out[1]


class _DroppingTransport:
    """Wraps a module's transport and drops outbound frames on command
    (injection 12: delay or drop; bounded resources and abort)."""

    def __init__(self, inner):
        self.inner = inner
        self.drop = False

    def send(self, tag, payload):
        if self.drop:
            return
        self.inner.send(tag, payload)

    def recv(self, tag, timeout=None):
        return self.inner.recv(tag, timeout=timeout)


def apply_injection(module: VIGORModule, peer: VIGORModule, inj: Injection,
                    rng: random.Random) -> AttackOutcome:
    """Run injection `inj` against the module pair and return the outcome.
    Every injection must end in ABORT before any release, and the outcome
    names the mechanism of tab:attacks that catches it."""
    m0, m1 = module, peer
    key = m0.key

    if inj.id == 1:      # S5: gate misrouting / descriptor binding
        _open(m0, m1)
        label = Label(0, 0, 11, 0, "gate11")
        m0.dispatch("RESERVE_PREP", {"gate": 12, "label": label, "op": "mask"})
        detail = "label bound to gate 12 routed to gate 11: rejected before preprocessing"
        return AttackOutcome(1, True, False, inj.mechanism, detail)

    if inj.id == 2:      # engine bit flip vs the reference DPF
        _open(m0, m1)
        table = [rng.randrange(P) for _ in range(16)]
        th = hashlib.sha256(repr(tuple(table)).encode()).digest()
        label = Label(0, 0, 2, 0, "lut")
        for m in (m0, m1):
            m.dispatch("RESERVE_PREP", {"gate": 2, "label": label, "op": "lut",
                                        "w": 4, "table_hash": th})
        u, _ = _checked_value(m0, m1, 2, rng.randrange(16), rng)
        m0._registry[2]["mask"] ^= 1          # flip a target bit in the engine
        m0._conformance_check = True          # RTL conformance harness
        m0.dispatch("EVAL_FSS", {"gate": 2, "table": table, "u": u[0]})
        detail = "engine target bit flipped: reference mismatch flagged, output never authenticated"
        return AttackOutcome(2, True, False, inj.mechanism, detail)

    if inj.id == 3:      # S1: GPU changes a value share
        _open(m0, m1)
        label = Label(0, 0, 3, 0, "check")
        for m in (m0, m1):
            m.dispatch("RESERVE_PREP", {"gate": 3, "label": label, "op": "check"})
        out0, out1 = _checked_value(m0, m1, 3, rng.randrange(P), rng, tamper=1)
        detail = f"tampered value share: both modules abort ({out0}, {out1})"
        return AttackOutcome(3, True, False, inj.mechanism, detail)

    if inj.id == 4:      # S7: imported triple with c != ab
        _open(m0, m1)
        label = Label(0, 0, 4, 0, "triple")
        a = rng.randrange(P)
        b = rng.randrange(P)
        bad = {"a": a, "b": b, "c": field.fadd(field.fmul(a, b), 1)}  # c != ab
        m0.dispatch("RESERVE_PREP", {"gate": 4, "label": label, "op": "triple",
                                     "imported": bad})
        detail = "unproven import refused at reservation; never consumed"
        return AttackOutcome(4, True, False, inj.mechanism, detail)

    if inj.id == 5:      # S4: label reuse and rollback
        _open(m0, m1)
        label = Label(0, 0, 5, 0, "mask")
        m0.dispatch("RESERVE_PREP", {"gate": 5, "label": label, "op": "mask"})
        m0.dispatch("RESERVE_PREP", {"gate": 6, "label": label, "op": "mask"})
        m0.ledger.reboot(monotonic_service=False)   # no monotonic service: erase-and-rekey
        m0.dispatch("RESERVE_PREP", {"gate": 7, "label": Label(0, 0, 7, 0, "m"),
                                     "op": "mask"})
        detail = "label reuse rejected; after reboot without a monotonic service the old key is erased"
        return AttackOutcome(5, True, False, inj.mechanism, detail)

    if inj.id == 6:      # S3: DMA buffer modified after freezing (spill page)
        _open(m0, m1)
        label = Label(0, 0, 6, 0, "check")
        for m in (m0, m1):
            m.dispatch("RESERVE_PREP", {"gate": 6, "label": label, "op": "check"})
        value = rng.randrange(P)
        v0 = rng.randrange(P)
        g0 = [rng.randrange(P) for _ in range(T)]
        s0, s1 = share_from_draws(value, m0.delta, v0, g0)
        m0.dispatch("FREEZE_BATCH", {"gate": 6, "bytes": s0.to_bytes(),
                                     "wires": (6,), "dims": (1,)})
        handle = m0._frozen_batches[6][0]
        page = m0.ledger._frozen[handle]
        # host rewrites the (spilled) page after the freeze; the seal over the original bytes no longer verifies, so the reread aborts (S3, eps_bind)
        tampered = FrozenPage(page.handle, bytes(len(page.data)),
                              page.length, page.gate_id, page.seq,
                              True, page.seal)
        m0.ledger._frozen[handle] = tampered
        out0, out1 = _checked_value(m0, m1, 6, value, rng, timeout=1.0)
        detail = f"spill page integrity failure on reread ({out0}, {out1})"
        return AttackOutcome(6, True, False, inj.mechanism, detail)

    if inj.id == 7:      # Freivalds over all columns, s = 3
        _open(m0, m1)
        label = Label(0, 0, 7, 0, "verify")
        m0.dispatch("RESERVE_PREP", {"gate": 7, "label": label, "op": "check"})
        A = [[rng.randrange(P) for _ in range(3)] for _ in range(2)]
        B = [[rng.randrange(P) for _ in range(4)] for _ in range(3)]
        C = [[field.mersenne_reduce(sum(field.fmul(A[i][k], B[k][j])
                                        for k in range(3))) for j in range(4)]
             for i in range(2)]
        Cbad = [list(row) for row in C]
        for i in range(2):
            Cbad[i][-1] = field.fadd(Cbad[i][-1], 1)   # swapped/tampered last column
        m0.dispatch("VERIFY_MATRIX", {"gate": 7, "A": A, "B": B, "C": Cbad, "s": 3})
        detail = "candidate with a wrong last column rejected with s=3 challenges"
        return AttackOutcome(7, True, False, inj.mechanism, detail)

    if inj.id == 8:      # one challenge vector across lanes
        bad = dict(MANIFEST)
        bad["shared_challenges"] = True
        m0.dispatch("OPEN_SESSION", {"manifest": bad})
        detail = "configuration refused at session setup"
        return AttackOutcome(8, True, False, inj.mechanism, detail)

    if inj.id == 9:      # S8: database bytes/version changed after hashing
        db = [rng.randrange(P).to_bytes(8, "little") for _ in range(8)]
        snap = pir.PIRCommit(db, version=1)
        db2 = list(db)
        db2[3] = field.fadd(int.from_bytes(db2[3], "little"), 1).to_bytes(8, "little")
        snap2 = pir.PIRCommit(db2, version=2)
        tampered = replace(snap, records=snap2.records, padded=snap2.padded)
        try:
            pir.PIRServerEvalJoint(key, Label(0, 0, 9, 0, "q"), 0, 3, tampered)
        except AbortError:
            pass
        detail = "consumed bytes hash against cm_v: mismatch aborts, quarantined result never released"
        return AttackOutcome(9, True, False, inj.mechanism, detail)

    if inj.id == 10:     # S6: output before the verification barrier
        _open(m0, m1)
        label = Label(0, 0, 10, 0, "out")
        m0.dispatch("RESERVE_PREP", {"gate": 10, "label": label, "op": "output"})
        m0.dispatch("FINAL_OUTPUT", {"gate": 10, "recipient": 2,
                                     "authorized": (2,), "upsilon": 0})
        detail = "guard stays closed; no candidate value leaves the module"
        return AttackOutcome(10, True, False, inj.mechanism, detail)

    if inj.id == 11:     # wrong signed truncation rule
        bad = dict(MANIFEST)
        bad["trunc_rule"] = "round-half-up"
        m0.dispatch("OPEN_SESSION", {"manifest": bad})
        detail = "numeric contract mismatch: manifest rejected"
        return AttackOutcome(11, True, False, inj.mechanism, detail)

    # inj.id == 12: S10: drop the peer channel's frames
    _open(m0, m1)
    label = Label(0, 0, 12, 0, "check")
    for m in (m0, m1):
        m.dispatch("RESERVE_PREP", {"gate": 12, "label": label, "op": "check"})
    m0.channel._transport = _DroppingTransport(m0.channel._transport)
    m0.channel._transport.drop = True
    out0, out1 = _checked_value(m0, m1, 12, rng.randrange(P), rng, timeout=1.0)
    detail = f"dropped peer frames: both modules time out and abort ({out0}, {out1})"
    return AttackOutcome(12, True, False, inj.mechanism, detail)
