"""vigor_dfa -- Python 3.10+ standard-library reference implementation of the VIGOR-DFA protected FSS datapath, together with the compiler cost model reproductions.

The package contains the exact arithmetic and cryptographic primitives of the paper and the ideal-module functional reference (no third-party dependencies; standard library only, with an optional numpy path in
:mod:`vigor_dfa.rtl_model`).  Every module docstring cites the paper
sections, algorithm labels and theorem labels it implements.  The package is anonymous: it contains no author names, affiliations or contact information.

Modules and their paper mapping
-------------------------------
=====================================  =========================================
Module                                 Paper section / labels
=====================================  =========================================
:mod:`vigor_dfa.params`                Sec. II (``sec:bg-fss``), Sec. IV-B,
                                       Sec. V-A (``sec:proto-repr``);
                                       global constants and the ledger ``Label``
:mod:`vigor_dfa.field`                 Sec. V-A, Sec. VI-E (``sec:arch-field``,
                                       ``lst:mersenne``); exact arithmetic in F_p
:mod:`vigor_dfa.prg`                   Sec. IV-B (Alg. ``alg:gen``/``alg:eval``);
                                       AES-128 PRG G and output conversion Conv
:mod:`vigor_dfa.dpf`                   Sec. IV-B; DPF Gen/Eval/EvalAll;
                                       correctness Thm. ``thm:dpf-correct``
                                       (App. B)
:mod:`vigor_dfa.dcf`                   App. B (``alg:dcf``); conservative DCF;
                                       correctness Thm. ``thm:dcf``
:mod:`vigor_dfa.auth`                  Sec. V-A; authenticated sharing
                                       (AuthShare), trusted triples
:mod:`vigor_dfa.ledger`                Sec. V (``sec:proto-ledger``,
                                       ``fig:ledger``), Sec. VI-D; one-time
                                       state machine and release guard
:mod:`vigor_dfa.epilogue`              Sec. V (``sec:proto-epilogue``);
                                       fresh authentication epilogue,
                                       Thm. ``thm:epilogue``
:mod:`vigor_dfa.gac`                   Sec. V (``alg:gac``); malicious
                                       generate-and-consume, Thm. ``thm:gac``
:mod:`vigor_dfa.checkopen`             Sec. V (``alg:checkopen``,
                                       ``sec:proto-check``, ``fig:checkopen``);
                                       Thm. ``thm:mac-sound``
:mod:`vigor_dfa.gates`                 Sec. V-D (``sec:proto-gates``:
                                       ``alg:lut``, ``alg:interval``, bit
                                       decomposition ``alg:bitdec``, truncation
                                       ``alg:trunc``, direct gate); Thms.
                                       ``thm:lut``, ``thm:interval``,
                                       ``thm:bitdec``, ``thm:cmp-trunc``;
                                       Table ``tab:gates``
:mod:`vigor_dfa.pir`                   Sec. V-E (``alg:pir``); versioned
                                       snapshot PIR, Thm. ``thm:pir``,
                                       Table ``tab:pir``
:mod:`vigor_dfa.module`                Sec. VI-D (Table ``tab:commands``);
                                       the eight-command protected module
:mod:`vigor_dfa.ideal`                 Sec. III (``fig:func``,
                                       ``def:security``); ideal functionality
:mod:`vigor_dfa.simulator`             Sec. VII (``thm:main``), App. E;
                                       simulation strategy and hybrids
:mod:`vigor_dfa.attacks`               Sec. VIII-F (Table ``tab:attacks``);
                                       the twelve attack and fault injections
:mod:`vigor_dfa.rtl_model`             Sec. VI, Sec. VIII-B/C, App. F
                                       (``tab:model-params``); cycle-level
                                       microarchitecture reproduction of the
                                       measured microbenchmarks
=====================================  =========================================

Everything is deterministic for fixed inputs.  The reference is a functional model of the paper's algorithms; it makes no claim about constant-time behavior or hardware hardening.  Every performance figure in the paper is a measured value; the model modules reproduce those measurements as a cross-check (see :mod:`vigor_dfa.rtl_model` and ``model/perf_model.py``, Appendix E).

Tests (stdlib unittest) live in ``tests/`` next to this package and can be run from the artifact root with::

    python tools/run_tests.py
"""

from __future__ import annotations

import importlib as _importlib
from typing import Any as _Any

__version__ = "1.0.0"

# Eager imports: the parameter and cost-model modules owned by this agent's scope, which every consumer needs.  The remaining submodules load lazily through __getattr__ below, so that importing the package never fails while a sibling submodule is absent.
from . import params
from . import rtl_model

# Core constants and the ledger label, re-exported for convenience.
from .params import P, BITS, T, LAMBDA, N, SEED_BYTES, KEY_BYTES, MASK64, Label

# Cycle-level microarchitecture model entry points (Paper App. F).
from .rtl_model import (
    DPFEngine,
    AESEngines,
    FUA,
    FreezeBuffer,
    CheckEngine,
    gate_throughput,
    gate_latency,
    checkopen_latency,
    checkopen_throughput,
    fua_throughput,
    roofline_host_module,
)

# Lazy submodules (imported on first attribute access).
_LAZY_SUBMODULES = (
    "field", "prg", "dpf", "dcf", "auth", "ledger", "epilogue",
    "gac", "checkopen", "gates", "pir", "module", "ideal",
    "simulator", "attacks",
)

__all__ = [
    "__version__",
    # submodules
    "params", "field", "prg", "dpf", "dcf", "auth", "ledger",
    "epilogue", "gac", "checkopen", "gates", "pir", "module",
    "ideal", "simulator", "attacks", "rtl_model",
    # params
    "P", "BITS", "T", "LAMBDA", "N", "SEED_BYTES", "KEY_BYTES",
    "MASK64", "Label",
    # rtl_model
    "DPFEngine", "AESEngines", "FUA", "FreezeBuffer", "CheckEngine",
    "gate_throughput", "gate_latency", "checkopen_latency",
    "checkopen_throughput", "fua_throughput", "roofline_host_module",
]


def __getattr__(name: str) -> _Any:
    """Import submodules lazily (PEP 562), so ``import vigor_dfa`` stays
    robust while sibling modules of the package are still being added."""
    if name in _LAZY_SUBMODULES:
        module = _importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
