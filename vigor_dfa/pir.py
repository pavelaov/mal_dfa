"""Versioned-snapshot protected PIR (alg:pir, thm:pir, Sec. V-I, Appendix E).

Both role-bound modules receive the same canonical query from the client, compare the binding over their protected channel, pad the snapshot to 2^n records while authorizing only alpha < N, and run a joint DPF for (alpha, 1) by generate-and-consume. Each module scans the same canonical bytes in the same public order, hashes exactly the bytes it consumes, applies the same DPF weights to every record coordinate, and quarantines the reduction until the digest equals the authorized commitment cm_v; a host that swaps a record after hashing or serves an old version therefore causes an abort, never a wrong accepted record (scenario S8). The committed descriptor desc_v = (id, v, N, enc, cm_v) covers the database identifier, the version, the shape, the record encoding and the ordered record bytes. Each module releases only a freshly reshared value share (the value half of the epilogue) with a bound certificate, and the client reconstructs D[alpha] = y_0 + y_1; complete MAC-tag pairs are never delivered.

Regimes (Appendix A): (R1) with an honest client and at most one malicious server host, the client obtains the committed record or abort, and the host learns nothing about alpha beyond Leak_PIR; (R2) with a malicious client alone, accepted requests reveal nothing beyond the requested records and the public descriptor. The regimes are not combined. Honest statement (Sec. V-I): both modules learn alpha, so query privacy in (R1) relies on module trust - unlike untrusted two-server DPF-PIR (GPU-DPF, untrusted-mode DFA), which hides alpha from each server without trusted hardware. Batched execution (Sec. VII "Batched execution", VI-A): a batch of B = 512 queries walks the same public leaf order in lockstep, so each snapshot record is read and hashed once per batch and folded into per-query accumulators.

PIRQuery/PIRServerEval implement the bracketed client-generated-key alternative of Sec. V-I: the client generates the DPF keys with dpf.Gen (alg:gen) and each module evaluates its own key inside the boundary with the same hashing, quarantine, resharing and certificates. That variant adds a DPF key-privacy term and, against a malicious client, a key-verification step, which thm:main does not need because the primary alg:pir path (PIRServerEvalJoint) generates the key jointly inside the modules and exports no key. The client-key reference expansion uses a fixed public AES key context (minimal reasonable choice; the modules' own GaC path is keyed by the session key).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional, Sequence

from . import dpf, field, gac
from .auth import field_draw, sublabel
from .ledger import AbortError, sign_certificate
from .params import BITS, Label, P

CLIENT_ID = 2           # recipients field of release certificates (reference)
CLIENT_KEY = b"\x00" * 16  # fixed public expansion for the client-key variant


@dataclass(frozen=True)
class Snapshot:
    """A committed snapshot: desc_v = (db_id, version, n_records, k, cm_v) plus
    the ordered records, each encoded into k field coordinates, and the
    zero-padded copy of length 2^n (n = ceil(log2 N) for N >= 2; N = 1 is
    the constant-record special case with the same checks, Appendix A)."""
    db_id: bytes
    version: int
    n_records: int
    k: int
    records: tuple[tuple[int, ...], ...]
    commitment: bytes
    padded: tuple[tuple[int, ...], ...]

    @property
    def n(self) -> int:
        return 1 if self.n_records == 1 else (self.n_records - 1).bit_length()

    @property
    def padded_len(self) -> int:
        return 1 << self.n


def PIRCommit(db: Sequence[bytes], version: int,
              db_id: bytes = b"db") -> Snapshot:
    """Commitment cm_v covering the database identifier, version, shape,
    record encoding and ordered data bytes (alg:pir, Appendix A). Records
    encode into k field coordinates (8k bytes, little-endian canonical field
    elements); records of other lengths or with non-canonical coordinates are
    rejected, never padded or reduced (minimal reasonable choice: the
    reference supports 0 < k <= 4 coordinates)."""
    if not db:
        raise AbortError("empty database")
    n_records = len(db)
    first = db[0]
    if len(first) == 0 or len(first) % 8:
        raise AbortError("record length not a multiple of 8 bytes")
    k = len(first) // 8
    if k > 4:
        raise AbortError("record too wide for the reference encoding")
    records: list[tuple[int, ...]] = []
    for rec in db:
        if len(rec) != len(first):
            raise AbortError("ragged record lengths")
        words = struct.unpack("<" + "Q" * k, rec)
        if any(w >= P for w in words):
            raise AbortError("non-canonical record coordinate")
        records.append(tuple(words))
    n = 1 if n_records == 1 else (n_records - 1).bit_length()
    padded = tuple(records) + ((0,) * k,) * ((1 << n) - n_records)
    h = hashlib.sha256()
    h.update(db_id)
    h.update(struct.pack(">q", version))
    h.update(struct.pack(">q", n_records))
    h.update(struct.pack(">B", k))
    for rec in db:
        h.update(rec)
    return Snapshot(db_id, version, n_records, k, tuple(records), h.digest(),
                    padded)


def PIRQuery(alpha: int, n: int, qid: int = 0) -> tuple[object, object]:
    """Client-side key generation for (alpha, 1) on the domain 2^n
    (alg:gen). This is the client-generated-key alternative of Sec. V-I; it
    adds a DPF key-privacy term and a client key-verification step, which
    the primary alg:pir path (PIRServerEvalJoint) avoids by joint generation
    inside the modules. A fresh query identifier is folded into the label so
    distinct queries always draw fresh roots (the paper requires a fresh
    qid, Appendix A)."""
    label = Label(0, 0, qid, 0, "pir-key")
    return dpf.Gen(CLIENT_KEY, label, alpha, 1, n=n)


def _snapshot_hash_init(snapshot: Snapshot):
    h = hashlib.sha256()
    h.update(snapshot.db_id)
    h.update(struct.pack(">q", snapshot.version))
    h.update(struct.pack(">q", snapshot.n_records))
    h.update(struct.pack(">B", snapshot.k))
    return h


def _scan(snapshot: Snapshot, weights) -> list[int]:
    """The public-order scan of alg:pir: hash exactly the bytes consumed and
    reduce the DPF-weighted records per coordinate inside the protected path.
    Returns the raw per-coordinate shares; the caller verifies the digest
    against cm_v before anything is released (quarantine)."""
    h = _snapshot_hash_init(snapshot)
    y_tilde = [0] * snapshot.k
    for i, w in enumerate(weights):
        if i < snapshot.n_records:
            rec = snapshot.records[i]
            h.update(struct.pack("<" + "Q" * snapshot.k, *rec))
        for c in range(snapshot.k):
            y_tilde[c] = field.fadd(y_tilde[c],
                                    field.fmul(w, snapshot.padded[i][c]))
    if h.digest() != snapshot.commitment:
        raise AbortError("snapshot commitment mismatch")
    return y_tilde


def _reshare_and_certify(key: bytes, label, role: int, y_tilde: Sequence[int],
                         snapshot: Snapshot, counters=None):
    """alg:pir step 4: fresh resharing (the value half of the epilogue) and a
    certificate binding (sid, ep, qid, desc_v, role, Hash(y_b)). No MAC tag
    is delivered."""
    pads = tuple(field_draw(key, sublabel(label, f"pad:{c}"), P, BITS)
                 for c in range(snapshot.k))
    y_b = tuple(field.fadd(y_tilde[c], pads[c]) if role == 0
                else field.fsub(y_tilde[c], pads[c]) for c in range(snapshot.k))
    out_hash = hashlib.sha256(struct.pack("<" + "Q" * snapshot.k, *y_b)).digest()
    cert = sign_certificate(key, label.session, label.epoch, label.gate,
                            (CLIENT_ID,), out_hash, "VERIFIED")
    if counters is not None:
        counters.releases += 1
    return y_b, cert


def PIRServerEval(k_b, snapshot: Snapshot, role: int,
                  key: Optional[bytes] = None, qid: int = 0, label=None,
                  counters=None) -> tuple[tuple[int, ...], object]:
    """alg:pir scan with a client-generated key (the Sec. V-I bracket
    alternative): same public-order scan, same-byte hashing, quarantine,
    version check and certified release as the primary path. The fresh
    resharing pad requires the session key K, which both trusted modules
    hold regardless of who generated the keys (alg:pir step 4); without a
    key the scan aborts before any reshare."""
    if role not in (0, 1) or k_b.party != role:
        raise AbortError("role binding")
    y_tilde = _scan(snapshot, dpf.EvalAll(k_b))
    if key is None:
        raise AbortError("session key required for fresh resharing")
    if label is None:
        label = Label(0, 0, qid, 0, "q")
    return _reshare_and_certify(key, label, role, y_tilde, snapshot, counters)


def PIRServerEvalJoint(key: bytes, label, role: int, alpha: int,
                       snapshot: Snapshot, counters=None) -> tuple[tuple[int, ...], object]:
    """alg:pir with joint DPF generation inside the module (the primary path,
    thm:pir): the DPF for (alpha, 1) is streamed by GaC under label
    (qid, "pir") and never materialized, and the scan, hashing, quarantine,
    resharing and certified release follow PIRServerEval. Only alpha < N is
    authorized; the binding comparison over the protected channel is the
    caller's step 1 (alg:pir)."""
    if not 0 <= alpha < snapshot.n_records:
        raise AbortError("index out of range")
    weights = list(gac.stream_full_domain(key, sublabel(label, "pir"), role,
                                          alpha, snapshot.n, counters))
    y_tilde = _scan(snapshot, [w for _, w in weights])
    return _reshare_and_certify(key, label, role, y_tilde, snapshot, counters)


def PIRServerEvalBatch(keys: Sequence[object], snapshot: Snapshot, role: int,
                       key: Optional[bytes] = None, qid_base: int = 0,
                       counters=None) -> list[tuple[tuple[int, ...], object]]:
    """Batched execution (Sec. VII "Batched execution", VI-A): the B queries
    walk the same public leaf order in lockstep, so each snapshot record is
    read and hashed once per batch and folded into per-query accumulators;
    one abort (e.g. a snapshot mismatch) denies all B queries, which
    security with abort permits."""
    q = len(keys)
    h = _snapshot_hash_init(snapshot)
    weights = [dpf.EvalAll(k) for k in keys]
    accs = [[0] * snapshot.k for _ in range(q)]
    for i in range(snapshot.padded_len):
        if i < snapshot.n_records:
            rec = snapshot.records[i]
            h.update(struct.pack("<" + "Q" * snapshot.k, *rec))
        for qi in range(q):
            for c in range(snapshot.k):
                accs[qi][c] = field.fadd(accs[qi][c],
                                         field.fmul(weights[qi][i],
                                                    snapshot.padded[i][c]))
    if h.digest() != snapshot.commitment:
        raise AbortError("snapshot commitment mismatch")
    if key is None:
        raise AbortError("session key required for fresh resharing")
    out: list[tuple[tuple[int, ...], object]] = []
    for qi in range(q):
        label = Label(0, 0, qid_base + qi, 0, "q")
        out.append(_reshare_and_certify(key, label, role, accs[qi], snapshot,
                                        counters))
    return out


def PIRReconstruct(y0: Sequence[int], y1: Sequence[int]) -> bytes:
    """Client reconstruction D[alpha] = y_0 + y_1 coordinatewise (thm:pir):
    the client accepts only a pair of valid certificates with roles 0 and 1
    for its own qid and desc_v (checked by the caller), then decodes the
    record bytes."""
    z = tuple(field.fadd(a, b) for a, b in zip(y0, y1))
    return struct.pack("<" + "Q" * len(z), *z)
