"""Ideal functionalities and the protected-module resource (Appendix A).

Executable reference classes for the three boxed ideal objects of Appendix A:

  * IdealF_C       F_C^abort (app:func-circuit), Steps 1-5 with the leakage
                   Leak_C = (mu, len, sched, pub, status);
  * IdealF_PIR     F_PIR^abort (app:func-pir), Steps 1-3 with the corruption
                   regimes (R1) malicious server host and (R2) malicious
                   client only - the regimes are separate statements and are
                   not combined;
  * IdealModule    the resource F_T^{(b)} of one protected module
                   (app:func-module): its state, the ideal peer channel, the
                   global rule and the eight numbered commands of the box.

The ideal executions are those of the real/ideal definition (Appendix A,
"Real and ideal executions"): at most one statically corrupted computing
host, or for F_PIR in regime (R2) the client alone; the adversary may prevent
honest outputs, and neither fairness nor availability is provided.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field as dc_field
from typing import Optional, Sequence

from .auth import Counters, Label, encode_label, field_draw, share_from_draws
from .ledger import AbortError, LedgerState
from .params import P, T


@dataclass
class IdealF_C:
    """F_C^abort, Appendix A.1 (app:func-circuit), Steps 1-5."""

    manifest: dict
    inputs: dict = dc_field(default_factory=dict)      # wire -> value
    outputs: dict = dc_field(default_factory=dict)     # k -> y_k
    status: tuple = ()
    halted: bool = False
    halt_reason: Optional[tuple] = None

    def leakage(self) -> dict:
        """Leak_C = (mu, len, sched, pub, status) of the paper: len and sched
        are functions of mu alone, pub are the outputs Step 4 releases that mu
        declares public, and status is the validation vector and the abort
        outcomes of Steps 1-2 (Appendix A.1 "Leakage")."""
        return {"mu": self.manifest, "len": None, "sched": self.manifest.get("schedule"),
                "pub": None, "status": self.status}

    def step1_inputs(self, wire: int, x: int, owner_honest: bool,
                     in_nu: bool, sim_x_star: Optional[int] = None) -> None:
        """Step 1 (Inputs): if the owner is honest, receive x from it; if it
        is corrupted, receive x* from Sim. Send (input, nu) and the public
        metadata of nu to Sim. If x is missing, malformed or not in In_nu,
        send (abort, nu) to all parties and halt."""
        if self.halted:
            raise AbortError("functionality halted")
        value = x if owner_honest else sim_x_star
        if value is None or not in_nu:
            self.halted = True
            self.halt_reason = ("abort", wire)
            raise AbortError(f"abort on input wire {wire}")
        self.inputs[wire] = value

    def step2_validation(self, predicates) -> None:
        """Step 2 (Validation): compute status = (V(x))_V on the recorded
        inputs and send it to Sim; if some V(x) = 0, send (abort, V) to all
        parties and halt. The accept/abort outcome is the status component of
        Leak_C."""
        if self.halted:
            raise AbortError("functionality halted")
        self.status = tuple(bool(p(self.inputs)) for p in predicates)
        for k, ok in enumerate(self.status):
            if not ok:
                self.halted = True
                self.halt_reason = ("abort", k)
                raise AbortError(f"validation predicate {k} failed")

    def step3_evaluate(self, circuit) -> None:
        """Step 3 (Evaluation): compute (y_1, ..., y_K) = C(x) exactly in the
        finite arithmetic of mu, including every declared comparison,
        truncation, table lookup and piecewise polynomial."""
        if self.halted:
            raise AbortError("functionality halted")
        self.outputs = circuit(self.inputs)

    def step4_outputs(self, corrupted_recipients: Sequence[int],
                      public_outputs: Sequence[int]) -> dict:
        """Step 4 (Corrupt and public outputs): send to Sim every y_k whose
        recipient R_k is corrupted and every y_k that mu declares public."""
        return {k: self.outputs[k] for k in self.outputs
                if k in corrupted_recipients or k in public_outputs}

    def step5_delivery(self, k: int, sim_action: str) -> Optional[object]:
        """Step 5 (Delivery): at each public interaction boundary of the
        schedule, Sim may send delay or abort. On abort, send abort to every
        honest party and halt; on (deliver, k), give y_k to its honest
        recipient."""
        if sim_action == "abort":
            self.halted = True
            self.halt_reason = ("abort",)
            return None
        if sim_action == "delay":
            return None
        return self.outputs[k]


@dataclass
class IdealF_PIR:
    """F_PIR^abort, Appendix A.2 (app:func-pir), Steps 1-3. The public
    descriptor desc_v = (id, v, N, enc, cm_v), including cm_v, is part of
    Leak_PIR in both regimes; padding to 2^n records is invisible in F_PIR
    because only alpha < N is admissible."""

    desc_v: dict
    snapshot: Sequence[bytes]
    query: Optional[tuple] = None
    halted: bool = False

    def step1_query(self, qid: int, alpha: int, desc_v: dict,
                    client_honest: bool, sim_alpha: Optional[int] = None) -> None:
        """Step 1 (Query): receive (query, qid, alpha, desc_v) from the client
        with a fresh qid. If the request is malformed or alpha not in
        {0, ..., N-1}, send reject to the client and to Sim and halt.
        Otherwise send Leak_PIR to Sim. In regime (R2) Sim chooses alpha*
        (extraction)."""
        if self.halted:
            raise AbortError("functionality halted")
        a = alpha if client_honest else sim_alpha
        if desc_v != self.desc_v or a is None or not 0 <= a < len(self.snapshot):
            self.halted = True
            raise AbortError("reject")
        self.query = (qid, a, desc_v)

    def step2_retrieval(self) -> bytes:
        """Step 2 (Retrieval): set y = D[alpha]; for a multi-field record, y
        contains every coordinate of D[alpha]."""
        if self.query is None:
            raise AbortError("no query")
        return self.snapshot[self.query[1]]

    def step3_delivery(self, sim_action: str) -> Optional[bytes]:
        """Step 3 (Delivery): Sim may send abort, and then the client receives
        abort; otherwise the client receives y. In regime (R2) Sim receives
        D[alpha*] only."""
        if sim_action == "abort":
            self.halted = True
            return None
        return self.step2_retrieval()


class IdealModule:
    """The resource F_T^{(b)} of one protected module, Appendix A.3
    (app:func-module). The instance accepts commands from host b and from
    external endpoints over authenticated confidential channels, and it talks
    to its peer instance over an ideal protected channel. The boxed commands
    are numbered 1-8 below exactly as in the appendix; in the concrete module
    program the joint random function R is PRF_K with length-prefixed labels,
    the channels are AEAD, and OPEN_SESSION is attestation plus authenticated
    key exchange (H1/H2 of Appendix E idealize them)."""

    def __init__(self, party: int, seed: bytes):
        self.party = party
        self.role = party
        self.sid = 0
        self.epoch = -1
        self.mu: Optional[dict] = None
        self.epoch_state = "fresh"          # fresh | active | poisoned
        self._seed = seed
        self._r_draws: dict = {}            # joint random function R
        self.delta: tuple[int, ...] = ()
        self.delta_share: tuple[int, ...] = ()
        self.gates: dict = {}               # gate -> LedgerState
        self.frozen_store: dict = {}
        self.burned: set = set()
        self.counters = Counters()

    # -- state of the box: joint random function ------------------------------

    def _draw(self, label, nbytes: int = 8) -> bytes:
        """The joint random function R: a fresh uniform string for every new
        label, the same string in both instances for a joint label."""
        key = encode_label(label)
        if key not in self._r_draws:
            h = hashlib.shake_256(self._seed)
            h.update(key)
            self._r_draws[key] = h.digest(nbytes)
        return self._r_draws[key]

    # -- channel of the box ---------------------------------------------------

    def peer_channel_note(self) -> str:
        """Messages between the two instances are delivered privately and
        unmodified; the adversary learns their lengths and times and may
        delay or drop them, and a missing message leads to abort."""
        return "ideal protected peer channel"

    # -- global rule ----------------------------------------------------------

    def global_rule(self, command: str, frame: dict) -> None:
        """Every command first checks that the epoch state is active, that
        the frame is canonical (length prefixed, field elements below p, no
        truncation, extra bytes or duplicate identifiers) and that mu allows
        the requested ledger transition; gates move only along the chain of
        fig:ledger. Any failure executes ABORT; no command authenticates a
        host-supplied value."""
        if self.epoch_state != "active":
            raise AbortError("epoch not active")
        if "role" in frame and frame["role"] != self.party:
            raise AbortError("role binding")
        if "gate" in frame and frame["gate"] in self.burned:
            raise AbortError("identifier burned")

    def abort(self) -> None:
        """Command 8: ABORT (host or internal): set the epoch state to
        poisoned and every open gate to ABORTED; withhold all candidate
        values and pending responses; draw no further challenge; never return
        burned identifiers to a free list."""
        self.epoch_state = "poisoned"
        for g in self.gates:
            if self.gates[g] not in (LedgerState.RELEASED, LedgerState.ABORTED):
                self.gates[g] = LedgerState.ABORTED

    # -- the eight commands of the box ----------------------------------------

    def cmd_1_open_session(self, sid: int, epoch: int, mu: dict) -> dict:
        """Command 1: OPEN_SESSION - with the peer instance, agree on the
        ordered identities, roles 0 and 1, sid, a fresh ep, the manifest
        hash, the field and tag parameters and the protocol version, or
        abort. Return a session capability and Delta_{b,1..t} to host b."""
        if self.epoch_state != "fresh":
            raise AbortError("session already opened")
        self.sid = sid
        self.epoch = epoch
        self.mu = mu
        self.epoch_state = "active"
        self.delta = tuple(field_draw(self._seed,
                                      Label(sid, epoch, 0, 0, f"delta:{j}"))
                           for j in range(T))
        if self.party == 0:
            self.delta_share = tuple(field_draw(self._seed,
                                                Label(sid, epoch, 0, 0, f"delta0:{j}"))
                                     for j in range(T))
        else:
            self.delta_share = tuple(
                (self.delta[j] - field_draw(self._seed,
                                            Label(sid, epoch, 0, 0, f"delta0:{j}")))
                % P for j in range(T))
        return {"sid": sid, "epoch": epoch, "delta_share": self.delta_share}

    def cmd_2_reserve_prep(self, gate: int, label, op: str, ids: Sequence[int]):
        """Command 2: RESERVE_PREP(g, ids) - if g is NEW and ids are unused,
        burn ids and set RESERVED; draw the preprocessing of g from R (masks,
        triples with c = ab, authenticated bits, internally held FSS
        material) and share it with AuthShare; set PREPARED and return the
        tuples of party b once. For an input gate nu, also send the full mask
        r to the owner over its confidential channel, bind the owner's eps
        after comparing it with the peer, and execute ABORT unless
        r + eps in In_nu; for a private output, send the full output mask o
        to the recipient."""
        if any(i in self.burned for i in ids):
            raise AbortError("identifier reuse")
        if gate in self.gates:
            raise AbortError("gate not NEW")
        for i in ids:
            self.burned.add(i)
        self.gates[gate] = LedgerState.RESERVED
        r = field_draw(self._seed, label)
        sh = share_from_draws(r, self.delta,
                              field_draw(self._seed, Label(label.session, label.epoch,
                                                           label.gate, 0, "v0")),
                              [field_draw(self._seed, Label(label.session, label.epoch,
                                                            label.gate, 0, f"g{j}"))
                               for j in range(T)])
        self.gates[gate] = LedgerState.PREPARED
        return sh[self.party]

    def cmd_3_freeze_batch(self, gate: int, data: bytes, dims: Sequence[int],
                           wires: Sequence[int]):
        """Command 3: FREEZE_BATCH(g, bytes, dims, wires) - parse canonically;
        copy the bytes into the frozen store or into immutable AEAD pages
        bound to sequence numbers, lengths, gate identifiers and a protected
        root; hash the descriptor and the bytes; set FROZEN; return the
        handle and the root."""
        if self.gates.get(gate) is not LedgerState.PREPARED:
            raise AbortError("gate not PREPARED")
        if len(data) % 32 or not data:
            raise AbortError("non-canonical frame")
        for i in range(0, len(data), 32):
            for w in range(0, 32, 8):
                if int.from_bytes(data[i + w:i + w + 8], "little") >= P:
                    raise AbortError("non-canonical field element")
        self.frozen_store[gate] = bytes(data)
        self.gates[gate] = LedgerState.FROZEN
        root = hashlib.sha256(bytes(data)).digest()
        return (gate, root)

    def cmd_4_check_open(self, handle: int):
        """Command 4: CHECK_OPEN(h) - with the peer, run alg:checkopen on the
        frozen bytes of handle h; on acceptance set VERIFIED and return the
        authorized opened values; otherwise return one generic failure and
        execute ABORT."""
        gate = handle
        if self.gates.get(gate) is not LedgerState.FROZEN:
            raise AbortError("not FROZEN")
        if self.epoch_state != "active":
            raise AbortError("epoch not active")
        self.gates[gate] = LedgerState.VERIFIED
        data = self.frozen_store[gate]
        return [int.from_bytes(data[i:i + 8], "little")
                for i in range(0, len(data), 8)]

    def cmd_5_eval_fss(self, gate: int, handle: int, func):
        """Command 5: EVAL_FSS(g, h) - only for a VERIFIED masked opening
        bound to g and role b; evaluate the bound FSS or direct gate
        internally, apply the epilogue, set CONSUMED and return the fresh
        tuple [y]_b."""
        if self.gates.get(gate) is not LedgerState.VERIFIED:
            raise AbortError("gate not VERIFIED")
        y = func(self.frozen_store[handle])
        self.gates[gate] = LedgerState.CONSUMED
        v0 = field_draw(self._seed, Label(self.sid, self.epoch, gate, 0, "out_v0"))
        g0 = [field_draw(self._seed, Label(self.sid, self.epoch, gate, 0, f"out_g{j}"))
              for j in range(T)]
        return share_from_draws(y, self.delta, v0, g0)[self.party]

    def cmd_6_verify_matrix(self, gate: int, handle: int, check) -> bool:
        """Command 6: VERIFY_MATRIX(g, h) - for operands anchored to
        authoritative records, run alg:freivalds on the frozen candidate;
        return a verified immutable handle or execute ABORT."""
        if not check(self.frozen_store[gate]):
            self.abort()
            return False
        self.gates[gate] = LedgerState.VERIFIED
        return True

    def cmd_7_final_output(self, gate: int, recipient: int, upsilon: int) -> dict:
        """Command 7: FINAL_OUTPUT(g, R_k) - only for a VERIFIED output
        opening; record the one-time use of its mask and check material
        (CONSUMED), then set RELEASED and send the opened upsilon = y + o (or
        a public y) to R_k with a certificate binding sid, ep, g, R_k, the
        output hash and the terminal status."""
        if self.gates.get(gate) is not LedgerState.VERIFIED:
            raise AbortError("gate not VERIFIED")
        self.gates[gate] = LedgerState.CONSUMED
        self.gates[gate] = LedgerState.RELEASED
        return {"recipient": recipient, "upsilon": upsilon,
                "status": "RELEASED", "gate": gate}
