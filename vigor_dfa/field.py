"""Exact arithmetic over F_p, p = 2**61 - 1 (Mersenne prime).

Paper references
----------------
* Representation (Paper Sec. V-A, label ``sec:proto-repr``): canonical
  field elements are integers in ``[0, p)``; the canonical wire encoding
  is one unsigned 64-bit word, and *noncanonical* encodings are
  rejected, never reduced (technical specification Sec. 2).
* Reduction: the exact Mersenne reduction used by the field kernels is
  fixed in the implementation contract (technical specification
  Sec. 15, "Exact A100 Mersenne arithmetic"): fold
  ``x = (x & p) + (x >> 61)`` and then subtract ``p`` once if needed.
  For a 122-bit product this is two folds plus one conditional
  subtraction.  :func:`mersenne_reduce` implements the same rule for
  arbitrary-width non-negative inputs and is the behavioural twin of
  the RTL unit ``rtl/fu_mersenne61.v`` (Paper Sec. VI field unit array).
* Sampling (technical specification Sec. 3): a uniform element is drawn
  by rejection sampling over 61 pseudorandom bits, rejecting the single
  value ``p`` (probability ``2**-61``), with a bounded retry loop.

The software reference is a functional model; it is not a claim about
constant-time behavior.
"""

from __future__ import annotations

import os
from typing import Callable

from .params import BITS, P

__all__ = [
    "mersenne_reduce",
    "fadd",
    "fsub",
    "fmul",
    "fneg",
    "to_canonical",
    "encode",
    "decode",
    "random_element",
    "inner",
    "inv",
]

_MAX_REJECTION_TRIES = 256  # bounded per the technical spec Sec. 3


def mersenne_reduce(x: int) -> int:
    """Reduce a non-negative integer to its canonical representative in
    ``[0, p)`` by Mersenne folding (technical specification Sec. 15).

    Each fold replaces ``x`` by ``(x & p) + (x >> 61)``, which is
    congruent to ``x`` modulo ``p`` and strictly smaller whenever
    ``x >= 2**61``; the loop therefore terminates for any finite input.
    At most one conditional subtraction of ``p`` is needed afterwards,
    because the loop exits with ``x <= p``.
    """
    if not isinstance(x, int):
        raise TypeError("mersenne_reduce expects an int")
    if x < 0:
        raise ValueError("mersenne_reduce expects a non-negative input")
    while x >= (1 << BITS):
        x = (x & P) + (x >> BITS)
    if x >= P:
        x -= P
    return x


def fadd(a: int, b: int) -> int:
    """Field addition: canonical ``a + b mod p`` via Mersenne folding."""
    return mersenne_reduce(a + b)


def fsub(a: int, b: int) -> int:
    """Field subtraction: canonical ``a - b mod p`` via Mersenne folding.

    ``a - b + p`` lies in ``[1, 2p - 1]`` for canonical inputs, so it is
    non-negative and :func:`mersenne_reduce` applies directly.
    """
    return mersenne_reduce(a - b + P)


def fmul(a: int, b: int) -> int:
    """Field multiplication: canonical ``a * b mod p`` via Mersenne
    folding.  For canonical inputs the product is below ``2**122``, so
    two folds plus the conditional subtraction suffice (the loop form
    also covers larger accumulators)."""
    return mersenne_reduce(a * b)


def fneg(x: int) -> int:
    """Field negation: canonical ``-x mod p`` via Mersenne folding
    (``P - x`` for ``x != 0``, ``0`` for ``x == 0``)."""
    return mersenne_reduce(P - x)


def to_canonical(x: int) -> int:
    """Canonicalize ``x`` when ``0 <= x < 2p`` by one conditional
    subtraction.  Unlike :func:`mersenne_reduce`, this helper does not
    fold; callers guarantee the precondition (e.g. the sum of two
    canonical elements)."""
    if not isinstance(x, int):
        raise TypeError("to_canonical expects an int")
    if not 0 <= x < 2 * P:
        raise ValueError("to_canonical requires 0 <= x < 2p")
    return x - P if x >= P else x


def encode(x: int) -> bytes:
    """Canonical wire encoding: 8-byte little-endian word ``< p``
    (Paper Sec. V-A).  Noncanonical values are rejected, not reduced."""
    if not isinstance(x, int) or not 0 <= x < P:
        raise ValueError("encode requires a canonical element in [0, p)")
    return x.to_bytes(8, "little")


def decode(b: bytes) -> int:
    """Inverse of :func:`encode`.  Rejects wrong lengths and noncanonical
    values (``>= p``) instead of reducing them (Paper Sec. V-A,
    technical specification Sec. 2)."""
    if len(b) != 8:
        raise ValueError("decode expects exactly 8 bytes")
    x = int.from_bytes(b, "little")
    if x >= P:
        raise ValueError("noncanonical field encoding")
    return x


def random_element(rng_bytes: Callable[[int], bytes] = os.urandom) -> int:
    """Uniform random element of F_p by rejection sampling over 61 bits
    (technical specification Sec. 3): draw 8 bytes, keep the low 61 bits
    (uniform on ``[0, p]``), and reject the single value ``p``.

    ``rng_bytes`` is the byte source (default ``os.urandom``); tests
    inject a deterministic source.  The retry loop is bounded and raises
    on exhaustion instead of biasing the distribution.
    """
    for _ in range(_MAX_REJECTION_TRIES):
        v = int.from_bytes(rng_bytes(8), "little") & P
        if v != P:
            return v
    raise RuntimeError("rejection sampling exhausted: source kept returning p")


def inner(a: list[int], b: list[int]) -> int:
    """Field inner product ``sum_i a[i] * b[i] mod p``.  The integer sum
    is exact (Python integers are unbounded) and reduced once at the
    end, which is congruent to the interleaved reduction used by the
    hardware because folding preserves the residue class exactly."""
    if len(a) != len(b):
        raise ValueError("inner expects equal-length vectors")
    acc = 0
    for x, y in zip(a, b):
        acc += x * y
    return mersenne_reduce(acc)


def inv(x: int) -> int:
    """Multiplicative inverse of a nonzero element by Fermat's little
    theorem: ``x**(p-2) mod p`` (p is prime).  General exponents can use
    the builtin ``pow(x, e, P)``; this helper exists for convenience in
    protocol tests."""
    if not 0 < x < P:
        raise ValueError("inv is defined for nonzero field elements only")
    return pow(x, P - 2, P)
