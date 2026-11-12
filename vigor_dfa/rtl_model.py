"""Cycle-level microarchitecture model of one VIGOR-DFA protected module.

Paper references (line by line)
------------------------------
* Hardware design and placement: Paper Sec. VI, labels ``sec:arch``,
  ``sec:arch-hw``, ``sec:arch-pipe`` (Fig. ``fig:hw``, ``fig:pipeline``).
* Design constants: Paper Appendix E, Table ``tab:model-params``
  (a) and (c), and Paper Sec. VI-B/VI-C.
* Measured microbenchmarks this model reproduces: Paper Sec. VIII-B
  (DPF gate throughput and single-gate latency, Fig. ``fig:dpfthr``)
  and Sec. VIII-C (CheckOpen cost, Fig. ``fig:checkperf``).

Positioning
-----------
This module is part of the compiler cost model of Appendix E.  Every
performance number in the paper is a measured value; the functions and
classes below reproduce those measured microbenchmarks cycle by cycle
from the design constants, so they serve as a cross-check, never as the
source of a measurement.  All engine rates, efficiencies and fixed
latencies below are stated as measured or as design constants exactly as
in Appendix E.

Optional numpy: the bulk-sweep helper :func:`checkopen_sweep` uses
``numpy`` when it is importable and falls back to plain Python otherwise
(graceful degradation; ``import numpy`` is wrapped in ``try/except``).
The package as a whole is Python 3.10+ standard library only.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

try:  # optional vectorization; graceful degradation to plain Python
    import numpy as _np  # type: ignore
except ImportError:  # pragma: no cover - exercised only without numpy
    _np = None

from .params import T  # t = 3 MAC lanes (Paper Sec. V-A)

# ========================================================================== Platform constants (Paper Appendix E, Table tab:model-params (a)) ==========================================================================
F28 = 720e6        # DFA clock at 28 nm (design constant, dfa2026trusted)
F7 = 910e6         # DFA clock at 7 nm  (design constant, dfa2026trusted)

N_DPF_UNITS = 16   # one DPF unit per L2 slice (Paper Sec. VI-B)
AES_PER_UNIT = 4   # 4 AES-128 engines per unit
N_AES = N_DPF_UNITS * AES_PER_UNIT          # 64 AES-128 engines total
FUA_LANES = 128    # Mersenne-61 multiply-accumulate lanes (8 per DPF unit)

T_LANES = T                                # MAC lanes, t = 3 (Paper Sec. V-A)
AUTH_ELEM_BYTES = 32                       # 4 x 8-byte words per authenticated
                                           # element per party (Paper Sec. VI-A)

# Peak engine rates: one block per engine per cycle (Paper App. F, F.1)
AES_RATE_28 = N_AES * F28                  # 46.08 G AES blocks/s
AES_RATE_7 = N_AES * F7                    # 58.24 G AES blocks/s
FUA_RATE_28 = FUA_LANES * F28              # 92.16 G multiply-accumulates/s
FUA_RATE_7 = FUA_LANES * F7                # 116.48 G multiply-accumulates/s

# ========================================================================== DPF pipeline (Paper Sec. VI-C, Fig. fig:pipeline) ==========================================================================
CYCLES_PER_LEVEL = 20      # 20-stage DFA pipeline: one dependent level every
                           # 20 cycles (design constant, dfa2026trusted)
CONTEXTS_PER_UNIT = 20     # one pipeline context per stage (Paper Sec. VI-C)
CONTEXT_BYTES = 100        # < 100 B per context: three 129-bit path states,
                           # correction word in flight, target, query, payload, level (Paper Sec. VI-C)
FIXED_CYCLES = 12          # fixed gate latency: output conversion and pads
                           # (Paper App. F, Table tab:model-params (c))
EFF_MALICIOUS = 0.85       # measured pipeline efficiency, malicious GaC
EFF_SEMIHONEST = 0.90      # measured pipeline efficiency, trusted DFA (SH)
                           # (Paper Sec. VIII-B)

# AES blocks per single-path gate of depth n (Paper Sec. VIII-B, App. F F.5): 6n blocks for the three PRG expansions per level (2 generator + 1 evaluator state) plus 3 blocks of output conversion and pads.
BLOCKS_PER_LEVEL = 6
PAD_BLOCKS = 3

# Full-domain PIR traversal (Paper Sec. VI-C, "Depth-first EvalAll"): the 512 queries of a PIR batch walk the same public leaf order in lockstep; for N = 2^20, 512 contexts with 20 pending siblings of 17 B occupy about 174 KB (11 KB per unit), which fits the DFS traversal buffers of DFA.
PIR_CONTEXTS = 512
PIR_CONTEXT_BYTES = 174 * 1024   # aggregate state of the 512 lockstep contexts

# ========================================================================== AES time-sharing (Paper Sec. VI-B, "AES time-sharing") ==========================================================================
PRG_BLOCKS_PER_EXPANSION = 2        # two AES blocks per PRG expansion
CHALLENGE_BLOCKS_PER_ELEMENT = 1.5  # t/2: one 128-bit block yields two
                                    # 61-bit challenge candidates
AEAD_BLOCKS_PER_TUPLE = 2           # AEAD keystream: two blocks per 32-byte
                                    # tuple (freezer and peer channel)
# Check and sealing requests take priority over PRG expansion (Paper Sec. VI-B); a per-slot purpose tag keeps the key contexts separate.

# ========================================================================== Freeze buffer, check engine (Paper Sec. VI-B, App. F Table (c)) ==========================================================================
FREEZE_SRAM_BYTES = 256 * 1024      # 256 KB freeze SRAM = 8,192 tuples of 32 B
FREEZE_TUPLES = FREEZE_SRAM_BYTES // AUTH_ELEM_BYTES
FREEZE_BW = 100e9                   # freeze bandwidth, bytes/s
FREEZE_FIXED_S = 0.2e-6             # fixed freeze latency (0.2 us)
CHECK_DECISION_S = 0.5e-6           # fixed decision latency (0.5 us)
MUL_PER_CHECKED_ELEMENT = 2 * T_LANES  # 2t = 6 field mults per checked element
                                       # (two products per lane) (App. F F.5)
# Spill: batches beyond 8,192 elements spill to AES-GCM-sealed immutable HBM pages (Paper Sec. VI-B, Sec. V ledger).

# ========================================================================== Networks and roofline (Paper Sec. VI-A, App. F Table (a)) ==========================================================================
LAN_BW = 1e9      # 1 GB/s LAN, 0.05 ms RTT (Paper Sec. VIII-A)
LAN_RTT = 0.05e-3
WAN_BW = 70e6     # 70 MB/s WAN, 70 ms RTT (Paper Sec. VIII-A)
WAN_RTT = 70e-3
NOC_BW = 290e9    # on-die module-GPU bandwidth (dfa2026trusted, Accel-Sim)
DEVICE_RTT = 4e-6 # two device round trips of 4 us per checked layer for an
                  # external module (App. F Table (c))


class DPFEngine:
    """One DPF unit (Paper Sec. VI-B, Fig. ``fig:hw``).

    Each unit runs two generator states and one separate evaluator state,
    a depth-first-search stack and the ``Conv`` conversion into
    :math:`F_p` (Paper Sec. VI-B).  The three expansions of one
    malicious GaC level issue back to back because
    ``PRG(s_tilde)`` does not depend on the correction word; only the
    correction waits for all three (Paper Sec. VI-C).
    """

    UNITS = N_DPF_UNITS
    CYCLES_PER_LEVEL = CYCLES_PER_LEVEL
    CONTEXTS_PER_UNIT = CONTEXTS_PER_UNIT
    EFFICIENCY = EFF_MALICIOUS          # measured (Paper Sec. VIII-B)
    EFFICIENCY_SEMIHONEST = EFF_SEMIHONEST

    @staticmethod
    def blocks_per_gate(n: int) -> int:
        """AES blocks per single-path GaC gate of depth ``n``: 6n + 3
        (Paper Sec. VIII-B)."""
        return BLOCKS_PER_LEVEL * n + PAD_BLOCKS

    @staticmethod
    def blocks_per_gate_semihonest(n: int) -> int:
        """AES blocks per semi-honest trusted-DFA gate of depth ``n``:
        6n + 1 (Paper Sec. VIII-B)."""
        return BLOCKS_PER_LEVEL * n + 1

    @staticmethod
    def blocks_per_gate_tagtree(n: int, t: int = T_LANES) -> int:
        """AES blocks with one tag DPF tree per MAC lane:
        (1 + t) 6n + 3 (Paper Sec. VIII-B)."""
        return (1 + t) * BLOCKS_PER_LEVEL * n + PAD_BLOCKS

    def throughput(self, n: int, t: Optional[int] = None) -> float:
        """Sustained gate throughput in gates/s for depth ``n`` at 28 nm,
        720 MHz over the 64 shared engines.

        Reproduces the measured 106 M gates/s at ``n = 61``
        (Paper Sec. VIII-B, Fig. ``fig:dpfthr``):
        0.85 x 64 x 720 MHz / (6 x 61 + 3).
        """
        blocks = (self.blocks_per_gate_tagtree(n, t)
                  if t is not None else self.blocks_per_gate(n))
        return self.EFFICIENCY * AES_RATE_28 / blocks

    def throughput_semihonest(self, n: int) -> float:
        """Trusted-DFA throughput; reproduces the measured 113 M gates/s
        at ``n = 61``: 0.90 x 64 x 720 MHz / (6 x 61 + 1)."""
        return self.EFFICIENCY_SEMIHONEST * AES_RATE_28 \
            / self.blocks_per_gate_semihonest(n)

    @staticmethod
    def gate_latency(n: int) -> float:
        """Single dependent gate latency in seconds: (20n + 12) / f28.

        Reproduces the measured 1.71 us at ``n = 61``
        (Paper Sec. VI-C, Sec. VIII-B)."""
        return (n * CYCLES_PER_LEVEL + FIXED_CYCLES) / F28


class AESEngines:
    """The 64 AES-128 engines shared by PRG expansion, challenge
    derivation and AEAD sealing (Paper Sec. VI-B, "AES time-sharing").

    A slot arbiter per unit serves PRG expansion (two blocks per
    expansion), challenge derivation (1.5 blocks per checked element)
    and AEAD keystream for sealing and the peer channel (two blocks per
    32-byte tuple).  Check and sealing requests take priority; PRG
    contexts fill all other slots.
    """

    ENGINES = N_AES
    RATE_28 = AES_RATE_28               # 46.08 G blocks/s
    RATE_7 = AES_RATE_7                 # 58.24 G blocks/s

    @staticmethod
    def prg_time(n_expansions: int, f: float = F28) -> float:
        """Seconds of engine time for ``n_expansions`` PRG expansions."""
        return n_expansions * PRG_BLOCKS_PER_EXPANSION / (N_AES * f)

    @staticmethod
    def challenge_time(m_elements: int, f: float = F28) -> float:
        """Seconds of engine time to derive the challenges of a checked
        batch of ``m_elements`` elements (t/2 = 1.5 blocks per element,
        one block yielding two 61-bit candidates)."""
        return m_elements * CHALLENGE_BLOCKS_PER_ELEMENT / (N_AES * f)

    @staticmethod
    def aead_time(tuples: int, f: float = F28) -> float:
        """Seconds of engine time to AEAD-freeze ``tuples`` 32-byte
        tuples (two blocks per tuple)."""
        return tuples * AEAD_BLOCKS_PER_TUPLE / (N_AES * f)


class FUA:
    """Mersenne-61 field unit array: 128 multiply-accumulate lanes, each
    with a 61x61-bit multiplier and the two-fold reduction of the paper's
    Listing ``lst:mersenne`` (Paper Sec. VI-B).

    Peak: 116.48 G multiply-accumulates/s at 910 MHz (7 nm) and
    92.16 G/s at 720 MHz (28 nm) (Paper App. F, Sec. VIII-E).
    """

    LANES = FUA_LANES
    PEAK_7 = FUA_RATE_7                 # 116.48 G MACs/s (measured peak)
    PEAK_28 = FUA_RATE_28               # 92.16 G MACs/s

    @staticmethod
    def rate(f: float = F7) -> float:
        """Peak multiply-accumulate rate in MACs/s at clock ``f``."""
        return FUA_LANES * f

    @staticmethod
    def triple_time(macs: float, f: float = F7) -> float:
        """Seconds to generate ``macs`` matrix-triple products: one field
        multiply-accumulate per multiply-accumulate of the linear layers
        (Paper App. F, F.3 "Triple generation").

        LLaMA2-7B: 836 G MACs at 116.48 G/s = 7.18 s (Paper Sec. VIII-H)."""
        return macs / (FUA_LANES * f)

    @staticmethod
    def residual_time(m_elements: int, f: float = F28) -> float:
        """Seconds of FUA time for the residuals of a checked batch:
        2t = 6 multiplications per checked element (Paper App. F, F.5)."""
        return m_elements * MUL_PER_CHECKED_ELEMENT / (FUA_LANES * f)


class FreezeBuffer:
    """Freeze-before-challenge buffer (Paper Sec. VI-B, App. F Table (c)).

    ``FREEZE_BATCH`` copies the exact submitted bytes into the 256 KB
    freeze SRAM (8,192 tuples of 32 B) and hashes them with their
    descriptor into the root ``h_b`` the modules exchange; larger batches
    spill to AES-GCM-sealed immutable pages.  Freezing costs 100 GB/s
    plus a fixed 0.2 us.
    """

    SIZE_BYTES = FREEZE_SRAM_BYTES
    TUPLES = FREEZE_TUPLES
    BANDWIDTH = FREEZE_BW               # 100 GB/s
    FIXED_S = FREEZE_FIXED_S            # 0.2 us

    @staticmethod
    def latency(m_elements: int) -> float:
        """Freeze latency in seconds for a batch of ``m_elements``
        32-byte tuples: m x 32 B / 100 GB/s + 0.2 us."""
        return m_elements * AUTH_ELEM_BYTES / FREEZE_BW + FREEZE_FIXED_S


class CheckEngine:
    """Check engine executing CheckOpen steps 3-4 (Paper Sec. VI-B,
    App. F Table (c)): derive the t challenge vectors only after both
    frozen roots are fixed, accumulate the residuals on FUA lanes and
    evaluate all lanes over the full batch before emitting one generic
    status.  The fixed decision latency is 0.5 us."""

    DECISION_S = CHECK_DECISION_S       # 0.5 us

    @staticmethod
    def decision_time() -> float:
        return CHECK_DECISION_S

    @staticmethod
    def per_element_time(t: int = T_LANES) -> float:
        """Protected work per checked element: challenge derivation on the
        AES engines plus residual multiplications on the FUA
        (Paper App. F, Eq. of T_chk)."""
        return (0.5 * t / AES_RATE_28) + (2 * t / FUA_RATE_28)


# ========================================================================== Public model functions (paper microbenchmarks, measured values) ==========================================================================
def gate_throughput(n: int, tagtree: bool = False, t: int = T_LANES) -> float:
    """Single-path DPF gate throughput in gates/s for input length ``n``
    at 28 nm, 720 MHz, 64 AES engines (Paper Sec. VIII-B).

    ``gate_throughput(61)`` returns the measured 106 M gates/s; with
    ``tagtree=True`` it returns the per-lane tag-tree variant, measured
    at 26.7 M gates/s for ``t = 3``.  Trusted DFA (0.90 efficiency,
    6n + 1 blocks) measures 113 M gates/s.
    """
    engine = DPFEngine()
    if tagtree:
        return engine.throughput(n, t)
    return engine.throughput(n)


def gate_latency(n: int) -> float:
    """Single dependent gate latency in seconds: (20n + 12) / f28
    (Paper Sec. VI-C).

    ``gate_latency(61)`` returns 1.71e-6 s, the measured 1.71 us.
    """
    return DPFEngine.gate_latency(n)


def checkopen_latency(m: int, bw: float = LAN_BW, rtt: float = LAN_RTT,
                      t: int = T_LANES) -> float:
    """CheckOpen batch latency in seconds for ``m`` elements
    (Paper Sec. VIII-C, App. F F.5).

    The latency sums freezing (100 GB/s + 0.2 us), the frozen value
    exchange (8m bytes + one RTT), challenge derivation (mt/2 AES
    blocks), residual computation (2mt multiplications), the residual
    exchange (8t bytes + one RTT) and the fixed 0.5 us decision.

    On LAN (1 GB/s, 0.05 ms RTT) with ``t = 3`` this returns the
    measured 0.101 ms at ``m = 64`` and 0.652 ms at ``m = 65,536``.
    """
    freeze = FreezeBuffer.latency(m)
    xch = m * 8 / bw + rtt                       # frozen value shares
    chal = AESEngines.challenge_time(m)          # t/2 = 1.5 blocks per element
    resid = FUA.residual_time(m)                 # 2t = 6 mults per element
    rx = t * 8 / bw + rtt                        # t residuals
    return freeze + xch + chal + resid + rx + CheckEngine.decision_time()


def checkopen_throughput(m: int, bw: float = LAN_BW, rtt: float = LAN_RTT,
                         t: int = T_LANES) -> float:
    """CheckOpen batch throughput in elements/s: m / latency.

    Saturates near the measured 100 M elements/s at m = 65,536 on LAN.
    """
    return m / checkopen_latency(m, bw, rtt, t)


def checkopen_sweep(ms: Sequence[int], bw: float = LAN_BW,
                    rtt: float = LAN_RTT, t: int = T_LANES) -> List[float]:
    """Bulk CheckOpen latency sweep over batch sizes ``ms``, in seconds.

    Uses numpy when importable and falls back to a plain-Python loop
    otherwise (the package stays standard-library only either way).
    """
    if _np is not None:
        m_arr = _np.asarray(ms, dtype=float)
        lat = (m_arr * AUTH_ELEM_BYTES / FREEZE_BW + FREEZE_FIXED_S
               + m_arr * 8 / bw + rtt
               + m_arr * CHALLENGE_BLOCKS_PER_ELEMENT / AES_RATE_28
               + m_arr * MUL_PER_CHECKED_ELEMENT / FUA_RATE_28
               + t * 8 / bw + rtt + CHECK_DECISION_S)
        return list(lat)
    return [checkopen_latency(int(m), bw, rtt, t) for m in ms]


def fua_throughput(f: float = F7) -> float:
    """FUA peak in multiply-accumulates/s: 128 lanes x clock.

    ``fua_throughput()`` returns 116.48 G/s at 910 MHz (7 nm) and
    92.16 G/s at 720 MHz (28 nm) (Paper App. F, Sec. VIII-E).
    """
    return FUA.rate(f)


def roofline_host_module(bw: float = LAN_BW) -> float:
    """Host-module link roofline in authenticated elements/s
    (Paper Sec. VI-A, Sec. VIII-H): an authenticated element costs
    32 bytes per party, so a link of bandwidth ``bw`` streams at most
    ``bw / 32`` elements per second.

    Examples (Paper Sec. VI-G): 1.6 GB/s -> 50 M elements/s (ZCU102),
    25 GB/s -> 0.78 G elements/s (PCIe Gen4), 290 GB/s -> 9.1 G
    elements/s (on die).
    """
    return bw / AUTH_ELEM_BYTES


# ========================================================================== Model reproduction table (cross-check against the measured microbenchmarks) ==========================================================================
def main() -> None:
    """Print the microbenchmark cross-check table.

    Every printed number reproduces a measured value of Sections
    VIII-B/VIII-C from the Appendix E constants; the header of each
    section states the measured headline it reproduces.
    """
    print("VIGOR-DFA microbenchmark cross-check (Paper Sec. VIII-B/C; "
          "App. F constants)\n")
    print("Single-path DPF gate throughput per module (28 nm, 720 MHz, "
          "64 AES engines):")
    print(f"{'n':>4} {'trusted DFA (SH)':>18} {'VIGOR-DFA':>12} "
          f"{'tag tree t=3':>13} {'latency':>10}")
    for n in (8, 16, 32, 61):
        sh = DPFEngine().throughput_semihonest(n) / 1e6
        vig = gate_throughput(n) / 1e6
        tag = gate_throughput(n, tagtree=True) / 1e6
        lat = gate_latency(n) * 1e6
        print(f"{n:>4} {sh:>16.0f} M {vig:>10.0f} M {tag:>11.1f} M "
              f"{lat:>8.2f} us")
    print("\nCheckOpen batch latency on LAN (1 GB/s, 0.05 ms RTT), t = 3:")
    print(f"{'m':>8} {'latency ms':>12} {'throughput M/s':>16}")
    for m in (64, 256, 1024, 4096, 16384, 65536):
        lat_ms = checkopen_latency(m) * 1e3
        thr = checkopen_throughput(m) / 1e6
        print(f"{m:>8} {lat_ms:>12.3f} {thr:>16.2f}")
    print("\nFUA peak: 116.48 G MACs/s at 910 MHz (7 nm), "
          "92.16 G/s at 720 MHz (28 nm).")
    print("Host-module roofline: bw/32 elements/s "
          "(1.6 GB/s -> 50 M/s, 25 GB/s -> 0.78 G/s, 290 GB/s -> 9.1 G/s).")


__all__ = [
    "F28", "F7", "N_DPF_UNITS", "N_AES", "FUA_LANES", "T_LANES",
    "AES_RATE_28", "AES_RATE_7", "FUA_RATE_28", "FUA_RATE_7",
    "CYCLES_PER_LEVEL", "CONTEXTS_PER_UNIT", "FIXED_CYCLES",
    "EFF_MALICIOUS", "EFF_SEMIHONEST",
    "PIR_CONTEXTS", "PIR_CONTEXT_BYTES",
    "FREEZE_SRAM_BYTES", "FREEZE_TUPLES", "FREEZE_BW", "FREEZE_FIXED_S",
    "CHECK_DECISION_S", "LAN_BW", "LAN_RTT", "WAN_BW", "WAN_RTT",
    "NOC_BW", "DEVICE_RTT",
    "DPFEngine", "AESEngines", "FUA", "FreezeBuffer", "CheckEngine",
    "gate_throughput", "gate_latency", "checkopen_latency",
    "checkopen_throughput", "checkopen_sweep", "fua_throughput",
    "roofline_host_module",
]


if __name__ == "__main__":
    main()
