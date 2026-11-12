"""One-time ledger, freeze store, release guard and release certificates.

Implements the per-gate lifecycle of Sec. V-D (fig:ledger):

    NEW -> RESERVED -> PREPARED -> FROZEN -> VERIFIED -> CONSUMED -> RELEASED

with ABORTED reachable from every state; any invalid transition or failed
check moves the gate to ABORTED and poisons the whole epoch. The ledger binds
every gate to its operation, predecessor and output wires, numeric type,
table or model hash, public dimensions and allowed command sequence.
Reservation burns the gate's randomness identifiers *before* any
preprocessing share is issued, so no label is ever issued twice (S4, S5);
PREPARED issues the authorized party-local preprocessing exactly once and is
not permission to release an unchecked result; CONSUMED records the one-time
use of verified openings and preprocessing; RELEASED records that the result
left the module under a certificate; an accepted CHECK_OPEN only sets
VERIFIED, EVAL_FSS consumes the opening of an FSS or direct gate, and an
output gate is moved by FINAL_OUTPUT through CONSUMED to RELEASED.

Freeze semantics (Sec. V-D, VI-A): before any checking challenge is drawn the
module copies the exact submitted bytes into protected storage or spills them
into AEAD-sealed immutable pages bound to sequence numbers, exact lengths,
gate identifiers and a protected root, and hashes the descriptor and the
bytes into the frozen root h_b. A host's claim that a buffer has this hash is
not a freeze; after challenge generation only authenticated frozen pages are
reread. The hardware sizes are 32 KB ledger SRAM and 256 KB freeze SRAM
(8,192 tuples of 32 B); larger batches spill (Sec. VI-A). The paper fixes the
SRAM sizes but not the ledger entry count, so the reference models 256
in-flight entries of about 128 B (minimal reasonable choice).

Reboot rule (Sec. V-D, tab:obligations): either a separately justified
trusted monotonic service preserves freshness, or the old master key is
irrecoverably erased and a freshly attested session is required; a
host-controlled counter file is not anti-rollback protection.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence


class AbortError(Exception):
    """Protected abort. The module interface returns one generic failure
    status that exposes no residual, challenge, key or data-dependent
    diagnostic (Sec. V-F); the exception detail is reference-model
    introspection only."""


class LedgerState(str, Enum):
    NEW = "NEW"
    RESERVED = "RESERVED"
    PREPARED = "PREPARED"
    FROZEN = "FROZEN"
    VERIFIED = "VERIFIED"
    CONSUMED = "CONSUMED"
    RELEASED = "RELEASED"
    ABORTED = "ABORTED"


LEDGER_SRAM_BYTES = 32 * 1024
FREEZE_SRAM_BYTES = 256 * 1024
MAX_FROZEN_TUPLES = FREEZE_SRAM_BYTES // 32      # 8,192 tuples of 32 B
MAX_LEDGER_ENTRIES = 256                          # minimal reasonable choice


@dataclass
class GateRecord:
    gate_id: int
    label: object          # params.Label binding session, epoch, gate, purpose
    op: str = ""           # input | output | lut | interval | direct | polynomial | check
    state: LedgerState = LedgerState.NEW
    issued: bool = False   # PREPARED issues party-local preprocessing exactly once
    frozen_handle: Optional[int] = None
    wires: tuple[int, ...] = ()
    descriptor: bytes = b""


@dataclass(frozen=True)
class FrozenPage:
    handle: int
    data: bytes             # exact submitted bytes (immutable)
    length: int
    gate_id: int
    seq: int
    spilled: bool = False
    seal: bytes = b""       # AEAD seal for spilled pages


@dataclass(frozen=True)
class Certificate:
    """Release certificate binding the session, epoch, gate, recipients,
    output encoding or hash and terminal status (Sec. V-D)."""
    sid: int
    epoch: int
    gate: int
    recipients: tuple[int, ...]
    output_hash: bytes
    status: str
    mac: bytes

    def payload(self) -> bytes:
        rec = b",".join(str(r).encode() for r in self.recipients)
        return (struct.pack(">q", self.sid)
                + struct.pack(">q", self.epoch) + struct.pack(">q", self.gate)
                + struct.pack(">H", len(rec)) + rec
                + struct.pack(">H", len(self.output_hash)) + self.output_hash
                + self.status.encode("utf-8"))

    def verify(self, key: bytes) -> bool:
        return hmac.compare_digest(
            self.mac, hmac.new(key, self.payload(), hashlib.sha256).digest())


def sign_certificate(key: bytes, sid: int, epoch: int, gate: int,
                     recipients: Sequence[int], output_hash: bytes,
                     status: str) -> Certificate:
    cert = Certificate(sid, epoch, gate, tuple(recipients), output_hash, status, b"")
    mac = hmac.new(key, cert.payload(), hashlib.sha256).digest()
    return Certificate(sid, epoch, gate, tuple(recipients), output_hash, status, mac)


class Ledger:
    """Authoritative protected ledger of T_b (Sec. V-D; state, channel and
    global rule of F_T, Appendix A)."""

    def __init__(self, party: int, session_id: int, epoch: int,
                 seal_key: bytes = b"", freeze_sram_bytes: int = FREEZE_SRAM_BYTES):
        self.party = party
        self.session_id = session_id
        self.epoch = epoch
        self.epoch_state = "active"      # "active" | "poisoned"
        self._seal_key = seal_key
        self._freeze_sram_bytes = freeze_sram_bytes
        self._gates: dict[int, GateRecord] = {}
        self._frozen: dict[int, FrozenPage] = {}
        self._frozen_sram_bytes = 0
        self._seq = 0
        self._burned: set = set()        # burned randomness identifiers
        self.key_erased = False          # erase-and-rekey after reboot
        self.monotonic_service = False

    # -- epoch --------------------------------------------------------------

    def require_active(self) -> None:
        """Every command first checks that the epoch is active (the global
        rule of F_T, Appendix A)."""
        if self.epoch_state != "active":
            raise AbortError("epoch poisoned")
        if self.key_erased:
            raise AbortError("master key erased; fresh attested session required")

    def epoch_active(self) -> bool:
        return self.epoch_state == "active" and not self.key_erased

    # -- transitions (fig:ledger) -------------------------------------------

    def transition(self, gate_id: int, new_state: LedgerState) -> None:
        """Validate one gate transaction. Any invalid transition moves the
        gate to ABORTED and poisons the epoch (fig:ledger)."""
        self.require_active()
        rec = self._gates.get(gate_id)
        if rec is None:
            raise AbortError("unknown gate")
        allowed = {
            LedgerState.NEW: (LedgerState.RESERVED,),
            LedgerState.RESERVED: (LedgerState.PREPARED,),
            LedgerState.PREPARED: (LedgerState.FROZEN,),
            LedgerState.FROZEN: (LedgerState.VERIFIED,),
            LedgerState.VERIFIED: (LedgerState.CONSUMED,),
            LedgerState.CONSUMED: (LedgerState.RELEASED,),
            LedgerState.RELEASED: (),
            LedgerState.ABORTED: (),
        }[rec.state]
        if new_state not in allowed:
            rec.state = LedgerState.ABORTED
            self.poison_epoch()
            raise AbortError(
                f"invalid transition {rec.state.value} -> {new_state.value}")
        rec.state = new_state

    def reserve(self, gate_id: int, label, op: str = "check",
                wires: Sequence[int] = (), descriptor: bytes = b"") -> GateRecord:
        """NEW -> RESERVED. Burns the gate's randomness identifiers before any
        preprocessing share is issued (Sec. V-D). The label must bind this
        session, epoch and gate, and its role must be 0 (joint) or the local
        party, so replayed or misrouted material is rejected (S4, S5)."""
        self.require_active()
        if len(self._gates) >= MAX_LEDGER_ENTRIES and gate_id not in self._gates:
            raise AbortError("ledger SRAM full")
        if label.session != self.session_id or label.epoch != self.epoch \
                or label.gate != gate_id:
            raise AbortError("label does not bind session/epoch/gate")
        if label.role not in (0, self.party):
            raise AbortError("role mismatch")
        if label in self._burned:
            raise AbortError("randomness identifier already burned")
        rec = self._gates.setdefault(gate_id, GateRecord(gate_id, label, op))
        if rec.state is not LedgerState.NEW:
            raise AbortError("gate not NEW")
        rec.op = op
        rec.wires = tuple(wires)
        rec.descriptor = descriptor
        self._burned.add(label)
        rec.state = LedgerState.RESERVED
        return rec

    def issue(self, gate_id: int) -> GateRecord:
        """RESERVED -> PREPARED: the authorized party-local preprocessing is
        issued exactly once; PREPARED is not permission to release an
        unchecked result (Sec. V-D)."""
        self.require_active()
        rec = self._gates[gate_id]
        if rec.issued:
            raise AbortError("preprocessing already issued once")
        if rec.state is not LedgerState.RESERVED:
            raise AbortError("gate not RESERVED")
        rec.issued = True
        rec.state = LedgerState.PREPARED
        return rec

    # -- freeze store (Sec. V-D, VI-A) ---------------------------------------

    def _store_page(self, gate_id: int, data: bytes) -> int:
        self._seq += 1
        handle = self._seq
        spilled = self._frozen_sram_bytes + len(data) > self._freeze_sram_bytes
        seal = b""
        if spilled:
            # AEAD-sealed immutable spill page bound to sequence number, exact length, gate id and a protected root (Sec. VI-A). The reference seals with HMAC-SHA256 under the module's directional seal key.
            seal = hmac.new(
                self._seal_key,
                struct.pack(">Q", handle) + struct.pack(">Q", len(data))
                + struct.pack(">q", gate_id) + data,
                hashlib.sha256).digest()
        self._frozen[handle] = FrozenPage(handle, bytes(data), len(data),
                                          gate_id, handle, spilled, seal)
        if not spilled:
            self._frozen_sram_bytes += len(data)
        return handle

    def freeze_batch(self, gate_ids: Sequence[int], data_list: Sequence[bytes],
                     descriptor: bytes) -> tuple[list[int], bytes]:
        """PREPARED -> FROZEN for every gate of the batch (fig:ledger): copy
        the exact submitted bytes into protected storage, then hash the
        complete descriptor and these bytes into the frozen root h_b."""
        self.require_active()
        if len(gate_ids) != len(data_list) or not data_list:
            raise AbortError("batch length mismatch")
        grouped: dict[int, list[bytes]] = {}
        order: list[int] = []
        for gid in gate_ids:
            if gid not in grouped:
                grouped[gid] = []
                order.append(gid)
        for gid, data in zip(gate_ids, data_list):
            grouped[gid].append(bytes(data))
        handles_by_gate: dict[int, list[int]] = {}
        for gid in order:
            rec = self._gates.get(gid)
            if rec is None or rec.state is not LedgerState.PREPARED:
                raise AbortError("gate not freezable")
            rec.state = LedgerState.FROZEN
            handles_by_gate[gid] = [self._store_page(gid, d) for d in grouped[gid]]
        handles = [h for gid in gate_ids for h in handles_by_gate[gid]]
        root = hashlib.sha256(descriptor + b"".join(data_list)).digest()
        return handles, root

    def freeze(self, gate_id: int, data: bytes, descriptor: bytes) -> tuple[int, bytes]:
        """Single-page variant of freeze_batch (used by FREEZE_BATCH and by
        the attack harness)."""
        handles, root = self.freeze_batch([gate_id], [bytes(data)], descriptor)
        return handles[0], root

    def get_frozen(self, handle: int) -> bytes:
        """Reread only authenticated frozen pages (Sec. V-D): spilled pages
        are re-verified under their seal; a tampered spill page aborts
        (S3, eps_bind)."""
        page = self._frozen.get(handle)
        if page is None:
            raise AbortError("unknown frozen handle")
        if page.spilled:
            seal = hmac.new(
                self._seal_key,
                struct.pack(">Q", page.handle) + struct.pack(">Q", page.length)
                + struct.pack(">q", page.gate_id) + page.data,
                hashlib.sha256).digest()
            if not hmac.compare_digest(seal, page.seal):
                raise AbortError("spill page integrity failure")
        return page.data

    # -- verification, consumption, release ----------------------------------

    def verify(self, gate_id: int) -> GateRecord:
        """FROZEN -> VERIFIED: set only by an accepted CHECK_OPEN
        (fig:ledger)."""
        self.require_active()
        rec = self._gates[gate_id]
        if rec.state is not LedgerState.FROZEN:
            rec.state = LedgerState.ABORTED
            self.poison_epoch()
            raise AbortError("gate not FROZEN")
        rec.state = LedgerState.VERIFIED
        return rec

    def certificate(self, gate_id: int, recipients: Sequence[int],
                    output_hash: bytes, status: str, key: bytes) -> Certificate:
        """Issue a release certificate bound to session, epoch, gate,
        recipients, output hash and terminal status (Sec. V-D)."""
        return sign_certificate(key, self.session_id, self.epoch, gate_id,
                                recipients, output_hash, status)

    def consume(self, gate_id: int) -> GateRecord:
        """VERIFIED -> CONSUMED: records the one-time use of verified openings
        and preprocessing (EVAL_FSS, or FINAL_OUTPUT on its way to
        RELEASED)."""
        self.require_active()
        rec = self._gates[gate_id]
        if rec.state is not LedgerState.VERIFIED:
            rec.state = LedgerState.ABORTED
            self.poison_epoch()
            raise AbortError("gate not VERIFIED or already consumed")
        rec.state = LedgerState.CONSUMED
        return rec

    def release(self, gate_id: int) -> GateRecord:
        """CONSUMED -> RELEASED: the result left the module under a
        certificate."""
        self.require_active()
        rec = self._gates[gate_id]
        if rec.state is not LedgerState.CONSUMED:
            rec.state = LedgerState.ABORTED
            self.poison_epoch()
            raise AbortError("gate not CONSUMED")
        rec.state = LedgerState.RELEASED
        return rec

    def state(self, gate_id: int) -> Optional[LedgerState]:
        rec = self._gates.get(gate_id)
        return rec.state if rec is not None else None

    # -- abort and reboot ----------------------------------------------------

    def poison_epoch(self) -> None:
        """Any failure poisons the whole epoch (Sec. V-D): outstanding output
        responses are gated, no new challenge is derived, and aborted
        reservations never return to a free list."""
        self.epoch_state = "poisoned"
        for rec in self._gates.values():
            if rec.state not in (LedgerState.RELEASED, LedgerState.ABORTED):
                rec.state = LedgerState.ABORTED

    def reboot(self, monotonic_service: bool) -> None:
        """Sec. V-D reboot rule: either a separately justified trusted
        monotonic service preserves freshness, or the old master key is
        irrecoverably erased and a freshly attested session is required. A
        host-controlled counter file is not anti-rollback protection."""
        self.monotonic_service = monotonic_service
        if not monotonic_service:
            self.key_erased = True
            self.epoch_state = "poisoned"
            for rec in self._gates.values():
                if rec.state not in (LedgerState.RELEASED, LedgerState.ABORTED):
                    rec.state = LedgerState.ABORTED


class ReleaseGuard:
    """Small state machine in front of the module's output path (Sec. V-D,
    VI-A): PENDING -> VERIFIED -> RELEASED per gate; any failure ->
    ABORTED. Its enabling inputs originate from the protected checkers and
    the ledger, never from host-writable registers, so a host cannot open it
    by writing a status bit (S6); resetting the guard is not a secure session
    reset."""

    def __init__(self, ledger: Ledger):
        self._ledger = ledger
        self._guards: dict[int, str] = {}

    def state(self, gate_id: int) -> str:
        st = self._ledger.state(gate_id)
        if st is LedgerState.ABORTED or not self._ledger.epoch_active():
            return "ABORTED"
        return self._guards.get(gate_id, "PENDING")

    def arm(self, gate_id: int) -> None:
        """The guard opens for a gate only in state VERIFIED (fig:ledger)."""
        if self._ledger.state(gate_id) is not LedgerState.VERIFIED:
            raise AbortError("release guard stays closed")
        self._guards[gate_id] = "VERIFIED"

    def release(self, gate_id: int) -> None:
        """Authorized output release: VERIFIED -> CONSUMED -> RELEASED, the
        FINAL_OUTPUT path of fig:ledger."""
        if self._guards.get(gate_id) != "VERIFIED":
            raise AbortError("release guard stays closed")
        self._ledger.consume(gate_id)
        self._guards[gate_id] = "RELEASED"
        self._ledger.release(gate_id)

    def abort_all(self) -> None:
        """An epoch abort closes every outstanding response atomically
        (Sec. VI-A)."""
        for g in self._guards:
            if self._guards[g] != "RELEASED":
                self._guards[g] = "ABORTED"
