# SPEC: The VIGOR-DFA Protected Module `T_b`

Normative specification of the protected module implemented by `vigor_dfa/module.py` (dispatch table) and exercised by `tests/`. Paper references: Section V (`sec:proto-ledger`, `sec:proto-check`), Section VI-D, Section III.  This spec restates the protocol and architecture sections; where they conflict, the paper is normative.

## 1. Trust boundary

Inside the boundary (TCB items, Section VI-B): session and identity keys, global MAC key shares, the joint PRF sampler, role and counters, DPF generator state and correction words, the protected table and reduction logic, check challenges and residuals, the ledger and freeze SRAMs, and release decisions.

Outside the boundary: host CPU, OS, drivers, runtime, GPU SMs, HBM/DRAM and the NIC.  Only these objects cross the boundary: command frames with share batches, PIR database records, authenticated output tuples, sealed spill pages and sealed channel frames; none carries a module secret in the clear.  A GPU result is always a candidate share, never a certified value, and there is **no** command that authenticates a host-supplied value (this closes the forgery-oracle path of scenario S2).

## 2. Frames

Every command is a canonical frame: version, session id, epoch, role, opcode, gate id, ordered input/output ids, field id, tag count, dimensions, payload length, sequence number, payload; all fields are length-prefixed with explicit endianness.  Frames between modules or from a client bind the header as AEAD associated data.  The parser copies each frame into protected memory before checking it and rejects truncation, trailing bytes, duplicate ids, malformed dimensions, noncanonical field elements (values `>= p` are rejected, never reduced) and unexpected opcodes.  Verification and consumption use the same immutable parsed bytes.

## 3. Command interface

`module.py` dispatches exactly these eight opcodes (Table `tab:commands`); the ledger state reached on success is given in parentheses.

| Command | Required check | Allowed result |
|---|---|---|
| `OPEN_SESSION` | Authenticated identities, role, fresh epoch, manifest `mu` | Session capability |
| `RESERVE_PREP` | Approved gate, unused randomness identifiers | Party-local authorized preprocessing, issued once (`PREPARED`) |
| `FREEZE_BATCH` | Exact canonical bytes, dimensions, expected wire list | Frozen root `h_b` and handle (`FROZEN`) |
| `CHECK_OPEN` | Both frozen roots, independent challenge lanes, peer residuals | Verified prescribed opening or abort (`VERIFIED`) |
| `EVAL_FSS` | Bound table or function, `VERIFIED` and unconsumed input opening, fixed role | Freshly reshared authenticated local output (`CONSUMED`) |
| `VERIFY_MATRIX` | Anchored operands, frozen candidate | Verified immutable result handle (`VERIFIED`) |
| `FINAL_OUTPUT` | Authorized recipient, output mask, accepted check | Bound frame with `upsilon = y + o` and certificate (`CONSUMED`, then `RELEASED`) |
| `ABORT` | Any integrity or lifecycle violation | Epoch invalidation, no candidate values (`ABORTED`) |

## 4. Ledger state machine and invariants

States: `NEW -> RESERVED -> PREPARED -> FROZEN -> VERIFIED -> CONSUMED -> RELEASED`; any invalid transition or failed check moves the gate (and poisons the epoch) to `ABORTED`.

Invariants:

* **Binding.** Every gate binds operation, predecessor wires, output wires, numeric type, table/model hash, public dimensions and the allowed command sequence.
* **Reservation burns randomness.** `RESERVE_PREP` burns the randomness identifiers before any preprocessing share is issued; `PREPARED` may issue party-local authorized preprocessing exactly once, and it is not permission to release an unchecked result.
* **One-time use.** `CONSUMED` records one-time consumption; aborted reservations never return to a free list.
* **No unchecked consumption.** A dependent nonlinear gate never consumes a masked opening that is not `VERIFIED`.
* **Freeze, then challenge.** Challenges are derived only after both modules froze the exact submitted bytes; after challenge generation only authenticated frozen bytes are reread (no TOCTOU).  A host claim "this buffer has hash h" is not a freeze.
* **Epoch poisoning.** Any integrity or lifecycle violation aborts the epoch atomically: no new challenges, and every outstanding response keeps its release guard closed.

## 5. Release guard

The release guard opens a gate only in state `VERIFIED`.  The release certificate binds session, epoch, gate, recipients, output encoding/hash and terminal status.  A missing peer acknowledgement can cause abort; it can never authorize output under a different transcript.  Resetting the guard is not a secure session reset: reboot either relies on a separately justified monotonic service or irrecoverably erases the old master key before a freshly attested session.

## 6. Freeze-before-challenge CheckOpen

For an ordered batch of expected wire ids and party-local tuples:

1. **Metadata first.** Validate metadata, field encoding, gate order and length; reject any mismatch.
2. **Freeze.** Each module copies its exact bytes into protected storage (256 KB freeze SRAM; larger batches spill to AEAD-sealed immutable pages bound to sequence numbers, lengths, gate ids and a protected root) and hashes descriptor + bytes into root `h_b`; the modules agree on the ordered pair of frozen roots and one check id over the protected channel.
3. **Exchange.** Exchange only the frozen value shares; reconstruct the candidate `z_i = x_{0,i} + x_{1,i}` inside the modules, not exposed to the host yet.
4. **Challenge.** Derive independent uniform `rho_{j,i}` per MAC lane `j` and batch position `i`; labels bind the frozen roots and check id; challenges stay internal.
5. **Residuals.** Compute `sigma_{b,j} = sum_i rho_{j,i} (gamma_{b,j,i} - Delta_{b,j} z_i)`; exchange the `t` residuals; accept iff `sigma_{0,j} + sigma_{1,j} = 0` for every `j`.
6. **Release.** On acceptance agree on the output digest/status, mark resources consumed, release the authorized `z` plus bound certificates.  On failure release nothing and poison the epoch; retries with the same material are forbidden.

Traffic: two vectors of `m` field values plus two vectors of `t` residuals between modules.  Status is one generic verdict computed after all lanes and positions are evaluated: neither the status nor its latency reveals which lane or position failed.

## 7. Counter conventions

* Randomness identifiers are (session, epoch, gate, purpose, logical draw, block) labels; joint draws carry the same label in both modules, the role never distinguishes a joint draw, and logical root-0 / root-1 are distinct purposes.
* Counters and masks are one-time: `RESERVE_PREP` burns ids before issue; `CONSUMED` prevents reuse; aborted reservations are never recycled; buffer reuse always carries a fresh transaction id.
* The peer channel keeps independent directional keys, never repeats a nonce and enforces a per-session traffic and forgery budget.
* Epochs are monotone within a session; `OPEN_SESSION` requires a fresh epoch; poisoned epochs cannot issue new challenges.
* Uniform field sampling uses bounded rejection sampling (reject the single value `p`; abort on exhaustion rather than bias).

## 8. Error model

The module never diagnoses: failures produce the single `ABORT` outcome.  No residuals, challenges, keys or data-dependent diagnostics are exposed to the host.  Abort poisons the epoch and closes the release guard for every outstanding response atomically.  Availability and fairness are not provided: a malicious host may delay, drop or reorder packets, and the module answers with bounded resources and abort (scenario S10).  Wrong-value acceptance is bounded by `Q (2/p)^t` per epoch by Theorem `thm:mac-sound`; observing zero accepted forgeries in the finite test campaign is evidence of conformance, not of the bound.

## 9. Conformance tests

`tests/` checks: exhaustive small-domain DPF cases, streaming GaC vs materialized evaluation, DCF comparisons, Mersenne multiplication vs arbitrary-precision arithmetic, toy-field bit decomposition (p = 31), signed truncation, small LUTs, toy intervals, a composed pipeline, PIR snapshot rejection, plus the negative tests for noncanonical encodings, tag/value mutation, poisoned epochs, role/replay/order errors, immutable frozen objects, joint sampling, truncation fibers and the ring zero-divisor counterexample.  `tools/verify_counts.py` asserts the archive contract (22 tests; 21,840 / 2,728 / 1,364 / 20,004 / 124 cases).
