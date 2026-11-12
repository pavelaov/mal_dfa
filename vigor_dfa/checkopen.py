"""Freeze-before-challenge CheckOpen (alg:checkopen, Sec. V-F, thm:mac-sound).

The five steps of alg:checkopen run inside the module pair:

  1. freeze the exact submitted bytes into protected SRAM or sealed AEAD
     pages, hash the descriptor and these bytes into h_b, mark FROZEN,
     exchange (h_b, cid) with the peer and abort unless both modules hold the
     same ordered pair (h_0, h_1) and the same cid;
  2. exchange the frozen value shares and reconstruct the candidates
     z_i = x_{0,i} + x_{1,i} inside the modules (not exposed to the host);
  3. derive the independent per-lane challenges rho_{j,i} = PRF_K(chk, h_0,
     h_1, cid, j, i) only after both freezes;
  4. compute the per-lane residuals sigma_{b,j} = sum_i rho_{j,i}
     (gamma_{b,j,i} - Delta_{b,j} z_i) from the frozen pages only, and
     exchange the residual vectors;
  5. accept iff sigma_{0,j} + sigma_{1,j} = 0 for every lane: agree on the
     output digest and status, mark VERIFIED, record the checked material as
     used and return z with certificates bound to session, epoch, gates and
     output hash; otherwise release no candidate value, poison the epoch and
     return one generic failure status.

Metadata, field encoding, gate order and length mismatches abort before any
challenge is derived (alg:checkopen line 1). The error vectors (e, d_j) are
fixed by the freeze before any rho_{j,i} exists, so a host cannot place its
errors in the kernel of a challenge; by clm:residual (Appendix C) the sum of
the residuals equals <rho_j, d_j - Delta_j e>, and thm:mac-sound bounds
acceptance of a wrong value by (2/p)^t per batch.

Cost per batch of m elements (Sec. VI-A): challenge derivation costs 1.5 AES
blocks per element per module (three 64-bit words for three 61-bit
challenges), and each residual costs 2t field multiplications per element.
Tags never cross the peer link, but every local tag is read by its module.
Shared challenge vectors are refused at session setup (injection 8,
tab:attacks): one vector collapses the product bound to a single lane
(Sec. VII). Residuals and challenges never leave the modules; CheckResult
exposes them only as reference-model introspection, and the module interface
returns one generic status.
"""

from __future__ import annotations

import hashlib
import queue
import threading
from dataclasses import dataclass
from typing import Optional, Sequence

from . import field
from .auth import (AuthVal, Counters, derive_challenges, decide, encode_label,
                   prf_bytes, residual)
from .ledger import AbortError, Certificate, Ledger, ReleaseGuard


class PeerChannel:
    """Protected peer channel used by CheckOpen (ideal in the module model of
    Appendix A; AEAD over the hosts' network in the concrete program,
    Sec. VI-B)."""

    def send(self, tag: str, payload: bytes) -> None:
        raise NotImplementedError

    def recv(self, tag: str, timeout: Optional[float] = None) -> bytes:
        raise NotImplementedError


class MemoryChannel(PeerChannel):
    """In-process duplex channel for the reference model and the tests: two
    endpoints connected by queues. The two module instances' batch() calls
    run in separate threads, exactly as two concrete modules would exchange
    frames over their protected channel."""

    def __init__(self) -> None:
        self._in: "queue.Queue[tuple[str, bytes]]" = queue.Queue()
        self._peer: Optional["MemoryChannel"] = None

    @staticmethod
    def make_pair() -> tuple["MemoryChannel", "MemoryChannel"]:
        a, b = MemoryChannel(), MemoryChannel()
        a._peer = b
        b._peer = a
        return a, b

    def send(self, tag: str, payload: bytes) -> None:
        assert self._peer is not None
        self._peer._in.put((tag, bytes(payload)))

    def recv(self, tag: str, timeout: Optional[float] = None) -> bytes:
        try:
            got, payload = self._in.get(timeout=timeout)
        except queue.Empty:
            # A missing peer message leads to abort (Appendix A, peer channel); delay or drop is scenario S10, bounded resources and abort.
            raise AbortError("peer message missing (timeout)") from None
        if got != tag:
            raise AbortError("peer channel framing mismatch")
        return payload


@dataclass
class CheckResult:
    status: str                              # "VERIFIED" | "ABORT"
    residuals: Optional[tuple[int, ...]]     # own sigma_b (introspection only)
    counters: Counters
    opened: Optional[tuple[int, ...]]        # authorized z values (VERIFIED only)
    certificates: Optional[tuple[Certificate, ...]]


class CheckOpen:
    """Per-module check engine of T_b (Sec. VI-A)."""

    def __init__(self, key: bytes, party: int, delta_share: Sequence[int],
                 ledger: Ledger, guard: ReleaseGuard):
        self.key = key
        self.party = party
        # Delta_{b,j} comes from the protected key store, never from host input (alg:checkopen Require line).
        self.delta_share = tuple(delta_share)
        self.ledger = ledger
        self.guard = guard

    def batch(self, submitted: Sequence[AuthVal], peer_channel: PeerChannel,
              counters: Optional[Counters] = None, label=None,
              wires: Optional[Sequence[int]] = None,
              timeout: Optional[float] = None,
              frozen_handle: Optional[int] = None,
              frozen_root: Optional[bytes] = None) -> CheckResult:
        """alg:checkopen on a nonempty batch. `submitted` are host b's tuples;
        when frozen_handle is given (the FREEZE_BATCH command path) the
        submitted bytes are reread from the frozen store instead, so a host
        that overwrites its DMA buffer after the freeze changes nothing that
        is checked or consumed (S3, fig:checkopen)."""
        counters = counters if counters is not None else Counters()
        self.ledger.require_active()
        if not submitted and frozen_handle is None:
            raise AbortError("empty batch")
        for v in submitted:
            if v.party != self.party:
                raise AbortError("party mismatch")
            v.to_bytes()  # canonical encoding enforced; parser rejects, never reduces
        if label is None:
            raise AbortError("missing gate label")
        cid = int.from_bytes(prf_bytes(self.key, b"cid" + encode_label(label), 8), "big")
        gids = tuple(wires) if wires is not None else (label.gate,) * len(submitted)
        if len(gids) != len(submitted):
            raise AbortError("wire list length mismatch")
        descriptor = (encode_label(label)
                      + b"".join(g.to_bytes(4, "big", signed=True) for g in gids)
                      + len(submitted).to_bytes(4, "big"))
        # Step 1: freeze, then agree on both roots (and the check id)
        if frozen_handle is not None:
            data = self.ledger.get_frozen(frozen_handle)
            if len(data) % 32:
                raise AbortError("frozen batch length mismatch")
            vals = [AuthVal.from_bytes(data[32 * i:32 * (i + 1)], self.party)
                    for i in range(len(data) // 32)]
            h_b = bytes(frozen_root) if frozen_root is not None else \
                hashlib.sha256(descriptor + data).digest()
        else:
            vals = list(submitted)
            datas = [v.to_bytes() for v in vals]
            _, h_b = self.ledger.freeze_batch(gids, datas, descriptor)
        peer_channel.send("roots", h_b + cid.to_bytes(8, "big"))
        reply = peer_channel.recv("roots", timeout=timeout)
        if len(reply) != 40:
            raise AbortError("malformed root frame")
        h_other, cid_other = reply[:32], int.from_bytes(reply[32:40], "big")
        if cid_other != cid:
            raise AbortError("check id mismatch")
        h0, h1 = (h_b, h_other) if self.party == 0 else (h_other, h_b)
        # Step 2: reconstruct candidates inside the modules
        x_share = b"".join(field.encode(v.x) for v in vals)
        peer_channel.send("values", x_share)
        peer_vals = peer_channel.recv("values", timeout=timeout)
        if len(peer_vals) != 8 * len(vals):
            raise AbortError("value vector length mismatch")
        x_other = [field.decode(peer_vals[8 * i:8 * (i + 1)]) for i in range(len(vals))]
        z = [field.fadd(vals[i].x, x_other[i]) for i in range(len(vals))]
        # Step 3: internal challenges, only after both freezes
        rho = derive_challenges(self.key, h0, h1, cid, len(vals), shared=False,
                                counters=counters)
        # Step 4: per-lane residuals from frozen pages only
        sigma = residual(vals, z, self.delta_share, rho, self.party, counters)
        peer_channel.send("residuals", b"".join(field.encode(s) for s in sigma))
        peer_res = peer_channel.recv("residuals", timeout=timeout)
        if len(peer_res) != 8 * len(sigma):
            raise AbortError("residual vector length mismatch")
        sigma_other = tuple(field.decode(peer_res[8 * j:8 * (j + 1)])
                            for j in range(len(sigma)))
        # Step 5: decide and release
        counters.rounds += 1  # one online round is one CheckOpen (tab:gates)
        if not decide(sigma, sigma_other):
            self.ledger.poison_epoch()
            self.guard.abort_all()
            return CheckResult("ABORT", tuple(sigma), counters, None, None)
        for gid in dict.fromkeys(gids):   # one VERIFIED transition per gate
            self.ledger.verify(gid)
            self.guard.arm(gid)
        certs = tuple(
            self.ledger.certificate(gid, (0, 1),
                                    hashlib.sha256(field.encode(zv)).digest(),
                                    "VERIFIED", self.key)
            for gid, zv in zip(gids, z))
        return CheckResult("VERIFIED", tuple(sigma), counters, tuple(z), certs)


def run_pair(key: bytes, delta0: Sequence[int], delta1: Sequence[int],
             ledgers: Sequence[Ledger], guards: Sequence[ReleaseGuard],
             submitted0: Sequence[AuthVal], submitted1: Sequence[AuthVal],
             label, wires: Optional[Sequence[int]] = None,
             timeout: float = 60.0) -> tuple[CheckResult, CheckResult]:
    """Reference harness: run both modules' batch() concurrently over an
    in-process MemoryChannel pair (the concrete modules exchange over their
    AEAD peer channel). Each side returns its own CheckResult with its own
    counters, matching the per-module cost accounting of Sec. VI-A."""
    ch0, ch1 = MemoryChannel.make_pair()
    c0 = CheckOpen(key, 0, delta0, ledgers[0], guards[0])
    c1 = CheckOpen(key, 1, delta1, ledgers[1], guards[1])
    out: dict[int, CheckResult] = {}

    def run(party: int, c: CheckOpen, sub: Sequence[AuthVal], ch: PeerChannel) -> None:
        out[party] = c.batch(sub, ch, label=label, wires=wires, timeout=timeout)

    t0 = threading.Thread(target=run, args=(0, c0, submitted0, ch0))
    t1 = threading.Thread(target=run, args=(1, c1, submitted1, ch1))
    t0.start()
    t1.start()
    t0.join(timeout)
    t1.join(timeout)
    if t0.is_alive() or t1.is_alive():
        raise AbortError("peer timeout")
    return out[0], out[1]
