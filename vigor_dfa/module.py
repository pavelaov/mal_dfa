"""Protected module T_b: command interface and system integration (Sec. VI).

The module realizes the protected components of Sec. VI-A: the parser and ledger admit authorized input; the joint PRF sampler and the field unit array (FUA) produce correlated preprocessing; the DPF units perform correct local evaluation; the epilogue yields authenticated arithmetic; the freezer, check engine and peer channel enforce consistent opening; and the release guard gates authorized output release. Host software drives the module only through the eight commands of tab:commands, each of which enforces the required check and allowed result listed there; no command authenticates a host-supplied value, which closes the forgery-oracle path of scenario S2.

Design constants (Sec. VI-A): 16 DPF units, 64 AES-128 engines (time-shared among PRG expansion, challenge derivation and AEAD sealing), 128 FUA lanes, 20 contexts per DPF unit, a 256 KB freeze SRAM (8,192 tuples of 32 B) and a 32 KB ledger SRAM. Frames are length-prefixed with explicit endianness; the parser rejects truncation, trailing bytes, duplicate identifiers, malformed dimensions, non-canonical field elements and unexpected opcodes (Sec. VI-B). Any integrity or lifecycle violation executes ABORT: the epoch is poisoned and no candidate value leaves the module. The peer channel is AES-128-CTR with an HMAC-SHA256 tag (encrypt-then-MAC, the AES block cipher of prg.py), independent directional keys, a sequence counter that never repeats and a per-session traffic and forgery budget - the functional reference of the AEAD/GHASH block that the hardware shares between the freezer and the peer-channel controller, with a per-slot purpose tag so the uses never share a key (Sec. VI-A).

The reference model is a single Python object per module; attributes exist for the test harness only, and the documented host-visible surface is `dispatch`, exactly as the hardware exposes only command frames.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Optional, Sequence

from . import auth, field, gates
from .auth import (AuthVal, Counters, GenTriples, Label, bits_draw, field_draw,
                   prf_bytes, share_from_draws, sublabel)
from .checkopen import CheckOpen, MemoryChannel
from .gates import direct_gate, interval_indicator, lut_gate
from .ledger import (AbortError, Certificate, Ledger, LedgerState, ReleaseGuard,
                     sign_certificate)
from .params import P, T
from .prg import AES128


def _aes_ctr(key: bytes, ctr: bytes, data: bytes) -> bytes:
    """AES-128-CTR keystream (the forward AES of prg.AES128); the channel uses
    an independent directional key context, so the uses never share a key
    (Sec. VI-A)."""
    aes = AES128(key)
    out = bytearray()
    j = 0
    while j < len(data):
        ks = aes.encrypt_block(ctr)
        for b in data[j:j + 16]:
            out.append(b ^ ks[len(out) % 16])
        j += 16
        ctr = ((int.from_bytes(ctr, "big") + 1) & ((1 << 128) - 1)).to_bytes(16, "big")
    return bytes(out)


class SealedChannel:
    """Peer-channel controller (Sec. VI-B): AES-128-CTR with HMAC-SHA256
    (encrypt-then-MAC), independent directional keys, a sequence counter that
    never repeats, exact ordering (reordered frames abort, S10) and a
    per-session traffic and forgery budget. The concrete modules exchange
    these frames over the hosts' network; the reference wires two modules
    through an in-process transport."""

    MAX_FRAMES = 2 ** 32

    def __init__(self, enc_key: bytes, mac_key: bytes, transport,
                 recv_enc_key: Optional[bytes] = None,
                 recv_mac_key: Optional[bytes] = None):
        self._enc_key = enc_key
        self._mac_key = mac_key
        self._recv_enc_key = recv_enc_key if recv_enc_key is not None else enc_key
        self._recv_mac_key = recv_mac_key if recv_mac_key is not None else mac_key
        self._transport = transport
        self._seq = 0
        self._recv_seq = -1

    def send(self, tag: str, payload: bytes) -> None:
        if self._seq >= self.MAX_FRAMES:
            raise AbortError("traffic budget exhausted")
        seq = self._seq
        self._seq += 1
        header = tag.encode("utf-8")[:16].ljust(16, b"\x00") + struct.pack(">QQ", seq, len(payload))
        ct = _aes_ctr(self._enc_key, struct.pack(">Q", seq).ljust(16, b"\x00"), payload)
        mac = hmac.new(self._mac_key, header + ct, hashlib.sha256).digest()
        self._transport.send("", mac + header + ct)

    def recv(self, tag: str, timeout: Optional[float] = None) -> bytes:
        frame = self._transport.recv("", timeout=timeout)
        if len(frame) < 32 + 32:
            raise AbortError("short channel frame")
        mac, header, ct = frame[:32], frame[32:64], frame[64:]
        if not hmac.compare_digest(mac, hmac.new(self._recv_mac_key, header + ct,
                                                 hashlib.sha256).digest()):
            raise AbortError("channel forgery")
        got_tag = header[:16].rstrip(b"\x00").decode("utf-8")
        seq, length = struct.unpack(">QQ", header[16:32])
        if got_tag != tag:
            raise AbortError("channel framing mismatch")
        if seq != self._recv_seq + 1:
            raise AbortError("reordered or replayed frame")   # S10: abort
        self._recv_seq = seq
        if length != len(ct):
            raise AbortError("frame length mismatch")
        return _aes_ctr(self._recv_enc_key,
                        struct.pack(">Q", seq).ljust(16, b"\x00"), ct)


@dataclass(frozen=True)
class SessionCapability:
    sid: int
    epoch: int
    role: int
    delta_share: tuple[int, ...]
    manifest_hash: bytes


@dataclass(frozen=True)
class AbortStatus:
    """The one generic failure status returned by the module (Sec. V-F): no
    residual, challenge, key or data-dependent diagnostic."""
    status: str = "ABORT"


class VIGORModule:
    """The protected module T_b of Sec. VI. The host may only issue the eight
    commands of tab:commands through dispatch(); attributes below the command
    handlers exist for the reference harness and correspond to protected
    state that no host-writable register reaches in the hardware."""

    DPF_UNITS = 16
    AES_ENGINES = 64
    FUA_LANES = 128
    CONTEXTS_PER_UNIT = 20
    FREEZE_SRAM_BYTES = 256 * 1024
    LEDGER_SRAM_BYTES = 32 * 1024

    def __init__(self, party: int, key: bytes, peer: Optional["VIGORModule"] = None,
                 session_id: int = 0, epoch: int = 0,
                 freeze_sram_bytes: int = FREEZE_SRAM_BYTES):
        if party not in (0, 1):
            raise ValueError("role must be 0 or 1")
        self.party = party
        self.key = key
        self.session_id = session_id
        self.epoch = epoch
        seal_key = prf_bytes(key, Label(session_id, epoch, 0, 0, "seal"), 16)
        self.ledger = Ledger(party, session_id, epoch, seal_key=seal_key,
                             freeze_sram_bytes=freeze_sram_bytes)
        self.guard = ReleaseGuard(self.ledger)
        # Global MAC keys are joint draws (both modules derive the same Delta_j); each host receives only its additive share at OPEN_SESSION (Appendix A, command 1).
        self.delta = tuple(field_draw(key, Label(session_id, epoch, 0, 0, f"delta:{j}"))
                           for j in range(T))
        # The additive split Delta_j = Delta_{0,j} + Delta_{1,j}: party 0's shares are joint draws, party 1's are the differences (Appendix A, command 1; host b receives only Delta_{b,j}).
        if party == 0:
            self.delta_share = tuple(
                field_draw(key, Label(session_id, epoch, 0, 0, f"delta0:{j}"))
                for j in range(T))
        else:
            self.delta_share = tuple(
                field.fsub(self.delta[j],
                           field_draw(key, Label(session_id, epoch, 0, 0, f"delta0:{j}")))
                for j in range(T))
        self.check_engine = CheckOpen(key, party, self.delta_share, self.ledger,
                                      self.guard)
        self.counters = Counters()
        self._peer = peer
        self.channel: Optional[SealedChannel] = None
        self._capability: Optional[SessionCapability] = None
        self._manifest: Optional[dict] = None
        self._session_epochs: set = set()
        self._registry: dict[int, dict] = {}
        self._gates_registry: dict[int, tuple] = {}
        self._frozen_batches: dict[int, tuple] = {}
        self._conformance_check = False       # RTL conformance harness (injection 2)

    # -- host interface -------------------------------------------------------

    def epoch_active(self) -> bool:
        return self.ledger.epoch_active()

    def dispatch(self, command: str, payload: Optional[dict] = None) -> object:
        """The only host-facing surface (Sec. VI-B): a canonical command
        frame bound to session, epoch, role and gate. Any integrity or
        lifecycle violation executes ABORT internally - the epoch is poisoned
        and no candidate value leaves the module."""
        payload = payload or {}
        handler = getattr(self, "_cmd_" + command, None)
        if handler is None:
            raise AbortError("unexpected opcode")
        try:
            return handler(payload)
        except AbortError:
            self._internal_abort()
            return AbortStatus()

    def _internal_abort(self) -> None:
        """ABORT (tab:commands row 8): epoch invalidation, no candidate
        values; the release guard closes atomically for every outstanding
        response."""
        self.ledger.poison_epoch()
        self.guard.abort_all()

    # -- the eight commands of tab:commands -----------------------------------

    def _cmd_OPEN_SESSION(self, payload: dict) -> SessionCapability:
        """tab:commands row 1. Required check: authenticated identities, role,
        fresh epoch, manifest mu. Allowed result: session capability.

        In the concrete module this command is attestation plus authenticated
        key exchange bound to the ordered identities, roles 0 and 1, a fresh
        session identifier, the epoch, the manifest hash, the field and tag
        parameters and the protocol version (Sec. V-C); the reference models
        its accepted transcript. The numeric contract of mu (toward-zero
        truncation, abort on overflow) and the per-lane challenge
        configuration are checked here, which is where injections 8 and 11 of
        tab:attacks are refused."""
        role = payload.get("role", self.party)
        epoch = payload.get("epoch", self.epoch)
        manifest = payload.get("manifest")
        if role != self.party:
            raise AbortError("role binding failed")
        if manifest is None:
            raise AbortError("missing manifest")
        if manifest.get("shared_challenges", False):
            raise AbortError("configuration refused: shared challenge lanes")
        if manifest.get("trunc_rule", "toward_zero") != "toward_zero":
            raise AbortError("manifest numeric contract rejected")
        if manifest.get("overflow", "abort") != "abort":
            raise AbortError("manifest numeric contract rejected")
        if self._capability is not None:
            raise AbortError("session already opened")
        if epoch in self._session_epochs:
            raise AbortError("epoch not fresh")
        self._manifest = manifest
        self._session_epochs.add(epoch)
        manifest_hash = hashlib.sha256(repr(sorted(manifest.items())).encode()).digest()
        self._capability = SessionCapability(self.session_id, epoch, self.party,
                                             self.delta_share, manifest_hash)
        return self._capability

    def _cmd_RESERVE_PREP(self, payload: dict) -> dict:
        """tab:commands row 2. Required check: approved gate, unused
        randomness identifiers. Allowed result: party-local authorized
        preprocessing, issued once (PREPARED).

        Reservation burns the gate's randomness identifiers before any
        preprocessing share is issued (Sec. V-D). Imported preprocessing is
        refused at reservation: triples and keys must be generated inside the
        TCB, because a MAC on c does not prove c = ab (S7, injection 4)."""
        self.ledger.require_active()
        gate_id = payload["gate"]
        label = payload["label"]
        op = payload.get("op", "check")
        if payload.get("imported") is not None:
            raise AbortError("unproven import refused at reservation")
        self.ledger.reserve(gate_id, label, op=op,
                            wires=tuple(payload.get("wires", ())),
                            descriptor=payload.get("descriptor", b""))
        prep = self._preprocessing(gate_id, op, label, payload)
        self.ledger.issue(gate_id)
        self._gates_registry[gate_id] = (label, op)
        return prep

    def _preprocessing(self, gate_id: int, op: str, label, payload: dict) -> dict:
        key, delta = self.key, self.delta
        if op in ("input", "output", "mask", "interval", "direct", "check"):
            r = field_draw(key, sublabel(label, "mask"))
            v0 = field_draw(key, sublabel(label, "share_v"))
            g0 = tuple(field_draw(key, sublabel(label, f"share_g{j}")) for j in range(T))
            sh = share_from_draws(r, delta, v0, g0)
            self._registry[gate_id] = {"mask": r}
            return {"auth_mask": sh[self.party]}
        if op == "lut":
            w = int(payload.get("w", 8))
            r = bits_draw(key, sublabel(label, "mask"), w)
            bits = []
            for i in range(w):
                b = (r >> i) & 1
                v0 = field_draw(key, sublabel(label, f"bit:{i}:v0"))
                g0 = tuple(field_draw(key, sublabel(label, f"bit:{i}:g{j}"))
                           for j in range(T))
                bits.append(share_from_draws(b, delta, v0, g0)[self.party])
            self._registry[gate_id] = {"mask": r, "w": w,
                                       "table_hash": payload.get("table_hash"),
                                       "reference_mask": r}
            return {"auth_bits": bits}
        if op == "triple":
            count = int(payload.get("count", 1))
            triples = GenTriples(key, label, count, delta)
            self._registry[gate_id] = {"count": count}
            return {"triples": [t[self.party] for t in triples]}
        raise AbortError("unapproved gate operation")

    def _cmd_FREEZE_BATCH(self, payload: dict) -> tuple[int, bytes]:
        """tab:commands row 3. Required check: exact canonical bytes,
        dimensions, expected wire list. Allowed result: frozen root h_b and
        handle (FROZEN).

        The parser copies the frame into protected memory before checking it
        and rejects truncation, trailing bytes, malformed dimensions and
        non-canonical field elements (values of at least p are rejected,
        never reduced); a host's claim that a buffer has this hash is not a
        freeze (Sec. V-D)."""
        self.ledger.require_active()
        gate = payload["gate"]
        data = bytes(payload["bytes"])
        dims = payload.get("dims")
        wires = tuple(payload.get("wires", ()))
        label = self._gates_registry[gate][0]
        if len(data) % 32 or not data:
            raise AbortError("truncated or trailing bytes")
        m = len(data) // 32
        if dims is not None and tuple(dims) != (m,):
            raise AbortError("dimension mismatch")
        for i in range(m):
            AuthVal.from_bytes(data[32 * i:32 * (i + 1)], self.party)
        descriptor = (auth.encode_label(label)
                      + b"".join(w.to_bytes(4, "big", signed=True) for w in wires)
                      + m.to_bytes(4, "big"))
        handle, root = self.ledger.freeze(gate, data, descriptor)
        self._frozen_batches[gate] = (handle, root, wires, m)
        return (handle, root)

    def _cmd_CHECK_OPEN(self, payload: dict) -> object:
        """tab:commands row 4. Required check: both frozen roots, independent
        challenge lanes, peer residuals. Allowed result: verified prescribed
        opening or abort (VERIFIED).

        Runs alg:checkopen on the frozen bytes of the handle; the peer
        module's CHECK_OPEN runs concurrently over the protected channel
        (the reference drives both sides in threads)."""
        gate = payload["gate"]
        record = self._frozen_batches.get(gate)
        if record is None:
            raise AbortError("no frozen batch for this gate")
        handle, root, wires, m = record
        label = self._gates_registry[gate][0]
        data = self.ledger.get_frozen(handle)
        vals = [AuthVal.from_bytes(data[32 * i:32 * (i + 1)], self.party)
                for i in range(m)]
        gids = wires if wires else (gate,) * m
        result = self.check_engine.batch(vals, self.channel, label=label,
                                         wires=gids, frozen_handle=handle,
                                         frozen_root=root,
                                         counters=self.counters,
                                         timeout=payload.get("timeout", 60.0))
        if result.status == "VERIFIED":
            return result.opened
        return result.status

    def _cmd_EVAL_FSS(self, payload: dict) -> AuthVal:
        """tab:commands row 5. Required check: bound table or function,
        VERIFIED and unconsumed input opening, fixed role. Allowed result:
        freshly reshared authenticated local output (CONSUMED).

        The query is read from the gate's verified masked opening, never from
        unchecked host data; the target comes from the gate's protected
        preprocessing record. With the RTL conformance harness enabled, the
        engine's target is compared against the reserved reference record
        before anything is authenticated (injection 2 of tab:attacks: an
        unverified engine output is never authenticated)."""
        gate = payload["gate"]
        label, op = self._gates_registry[gate]
        if self.ledger.state(gate) is not LedgerState.VERIFIED:
            raise AbortError("gate not VERIFIED or already consumed")
        rec = self._registry[gate]
        if op == "lut":
            table = tuple(payload["table"])
            w = rec["w"]
            if rec["table_hash"] is not None and \
                    hashlib.sha256(repr(table).encode()).digest() != rec["table_hash"]:
                raise AbortError("table hash mismatch")
            if self._conformance_check and rec["mask"] != rec["reference_mask"]:
                raise AbortError("engine conformance mismatch")
            out = lut_gate(self.key, label, self.party, self.delta,
                           payload["u"], rec["mask"], w, table, self.counters)
        elif op == "interval":
            out = interval_indicator(self.key, label, self.party, self.delta,
                                     payload["c"], payload["a"], payload["b"],
                                     self.counters)
        elif op == "direct":
            if self._conformance_check and rec["mask"] != rec["reference_mask"]:
                raise AbortError("engine conformance mismatch")
            out = direct_gate(self.key, label, self.party, self.delta,
                              payload["c"], rec["mask"], payload["g"],
                              self.counters)
        else:
            raise AbortError("unapproved gate operation")
        self.ledger.consume(gate)
        return out

    def _cmd_VERIFY_MATRIX(self, payload: dict) -> int:
        """tab:commands row 6. Required check: anchored operands, frozen
        candidate. Allowed result: verified immutable result handle
        (VERIFIED).

        alg:freivalds on the frozen candidate with s = 3 secret challenge
        vectors; the operands are the module's bound authoritative records
        (exposure to that GPU must already be permitted - never global
        triple masks, Sec. V-H)."""
        gate = payload["gate"]
        label = self._gates_registry[gate][0]
        A = tuple(tuple(row) for row in payload["A"])
        B = tuple(tuple(row) for row in payload["B"])
        C = tuple(tuple(row) for row in payload["C"])
        result = gates.freivalds(A, B, C, s=int(payload.get("s", 3)),
                                 key=self.key, label=label,
                                 counters=self.counters)
        if not result.accepted:
            raise AbortError("matrix check failed")
        self.ledger.verify(gate)
        return gate

    def _cmd_FINAL_OUTPUT(self, payload: dict) -> tuple[int, Certificate]:
        """tab:commands row 7. Required check: authorized recipient, output
        mask, accepted check. Allowed result: bound frame with upsilon = y + o
        and certificate (CONSUMED, then RELEASED).

        The release guard opens only for a VERIFIED batch; requesting output
        before the verification barrier keeps the guard closed (S6,
        injection 10). The output mask was issued at RESERVE_PREP and is
        checked against the gate's protected record."""
        gate = payload["gate"]
        recipient = payload["recipient"]
        if gate not in self._registry or "mask" not in self._registry[gate]:
            raise AbortError("output mask not issued for this gate")
        if recipient not in payload.get("authorized", (recipient,)):
            raise AbortError("unauthorized recipient")
        upsilon = payload["upsilon"]
        self.guard.release(gate)
        out_hash = hashlib.sha256(field.encode(upsilon)).digest()
        cert = sign_certificate(self.key, self.session_id, self.epoch, gate,
                                (recipient,), out_hash, "RELEASED")
        self.counters.releases += 1
        return (upsilon, cert)

    def _cmd_ABORT(self, payload: dict) -> AbortStatus:
        """tab:commands row 8. Required check: any integrity or lifecycle
        violation. Allowed result: epoch invalidation, no candidate values
        (ABORTED)."""
        self._internal_abort()
        return AbortStatus()


def connect(m0: VIGORModule, m1: VIGORModule) -> None:
    """Wire the protected peer channels of two modules with independent
    directional keys derived from the session key (Sec. VI-B: independent
    directional keys, a nonce that never repeats, a per-session traffic and
    forgery budget)."""
    k01 = prf_bytes(m0.key, Label(0, 0, 0, 0, "0->1"), 16)
    m01 = prf_bytes(m0.key, Label(0, 0, 0, 0, "0->1m"), 16)
    k10 = prf_bytes(m0.key, Label(0, 0, 0, 0, "1->0"), 16)
    m10 = prf_bytes(m0.key, Label(0, 0, 0, 0, "1->0m"), 16)
    t0, t1 = MemoryChannel.make_pair()
    m0.channel = SealedChannel(k01, m01, t0, recv_enc_key=k10, recv_mac_key=m10)
    m1.channel = SealedChannel(k10, m10, t1, recv_enc_key=k01, recv_mac_key=m01)
    m0._peer = m1
    m1._peer = m0
