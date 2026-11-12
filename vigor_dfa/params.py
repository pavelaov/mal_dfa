"""Global parameters of the VIGOR-DFA protected FSS datapath.

Paper references
----------------
* Field and MAC parameters (Paper Sec. V-A, label ``sec:proto-repr``):
  every authenticated wire carries a value share and ``t = 3``
  independent SPDZ-style MAC lanes over ``F_p`` with ``p = 2**61 - 1``;
  a canonical element is an unsigned 64-bit word ``< p``.
* DPF parameters (Paper Sec. II, label ``sec:bg-fss``; Paper Sec. IV-B):
  the PRG seed length is ``lambda = 128`` bits (the Sec. V-A parameter
  table lists ``lambda = 128``, the expansion is
  ``PRG: {0,1}^128 -> ({0,1}^128 x {0,1})^2``, and each path state is a
  129-bit ``(seed, control)`` pair).  The default DPF domain width is
  ``n = 61`` bits, parameterizable at every call site.
* Key size (Paper Sec. IV-C): one party's key holds its 128-bit root
  seed, ``n`` correction words of ``128 + 2`` bits and a 64-bit output
  correction, i.e. ``ceil((128 + 130 n + 64) / 8)`` bytes = 1016 bytes
  at ``n = 61``.  The value 127 that appeared in an earlier draft of the
  parameter contract does not reproduce this formula; the paper's
  ``lambda = 128`` is authoritative and is used here.
* Ledger label (Paper Sec. V, label ``sec:proto-ledger``): every
  randomness draw is bound to ``(session, epoch, gate, purpose)``, with
  the role binding party-local draws; distinct draws (roots, pads,
  challenges, rejection-sampling retries, ...) carry distinct labels.

Every constant in this module is public protocol-level data.
"""

from typing import NamedTuple

# --- field (Paper Sec. V-A) -------------------------------------------------
P = (1 << 61) - 1      # Mersenne prime p = 2**61 - 1
BITS = 61              # bit width of F_p
T = 3                  # number of independent MAC lanes

# --- PRG / DPF (Paper Sec. II, Sec. IV-B, Sec. V-A) --------------------------
LAMBDA = 128           # PRG seed length in bits (paper value; see docstring)
N = 61                 # default DPF domain width in bits (parameterizable)
SEED_BYTES = LAMBDA // 8   # 16 bytes per seed
KEY_BYTES = 16             # AES-128 key length

MASK64 = (1 << 64) - 1     # 64-bit mask for canonical wire words


class Label(NamedTuple):
    """Ledger label binding one randomness draw
    (Paper Sec. V, label ``sec:proto-ledger``).

    ``purpose`` distinguishes uses (roots, pads, challenges, ...).  Joint
    draws carry the *same* label in both modules; logical root-0 and
    root-1 are distinct purposes, and the role never distinguishes a
    joint draw (Paper App. B and the technical specification Sec. 3).
    """

    session: int
    epoch: int
    gate: int
    role: int      # 0 or 1; party-local binding, unused by joint draws
    purpose: str
