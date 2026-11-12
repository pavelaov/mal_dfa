"""Print every row of Table tab:gates, "Authenticated Nonlinear Gate
Options per Module", plus the DPF-gate microbenchmarks of paper
Section VIII-B.

Sources
-------
All gate rows and microbenchmark numbers are measured values read from
``model/numbers.json`` (default ``--from-json``).  Round-bound gates
carry "n/a" for throughput (round-bound) and "n/m" for AES blocks (not
modeled: their AES work is negligible next to the round trips), exactly
as in the paper.

Highlights reproduced from the JSON (Section VIII-B, Fig. fig:dpfthr):
single-path DPF gate throughput 106 (VIGOR-DFA) vs 113 (trusted DFA)
vs 26.7 (per-lane tag trees) M gates/s at n=61, with a single-gate
latency of 1.71 us; the direct protected gate reaches 1,800 M gates/s.

Usage::

    python eval/run_gates.py            # print from numbers.json (default)
    python eval/run_gates.py --compute  # regenerate with the App. F model, then print
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
NUMBERS_JSON = os.path.join(REPO_ROOT, "model", "numbers.json")
MODEL_DIR = os.path.join(REPO_ROOT, "model")

# (json key, paper label)
GATE_ROWS = [
    ("direct", "Direct protected gate"),
    ("lut8", "LUT, w=8"),
    ("lut12", "LUT, w=12"),
    ("lut16", "LUT, w=16"),
    ("interval_cons", "Interval, conservative DCF"),
    ("interval_opt", "Interval, optimized DCF*"),
    ("bitdec", "Bit decomposition"),
    ("trunc_exact", "Exact signed truncation"),
]


# Round-bound gates: the paper prints "n/m" for their AES work (it is negligible next to the round trips) and "n/a" for throughput.
ROUND_BOUND = {"bitdec", "trunc_exact"}


def fmt_thr(x):
    """Throughput in M/s with the paper's precision."""
    if x is None:
        return "n/a"
    if x >= 100:
        return f"{x:,.0f}"
    if x >= 10:
        return f"{x:.1f}"
    return f"{x:.2f}"


def fmt_lat(x_ms):
    if x_ms >= 10:
        return f"{x_ms:.1f}"
    return f"{x_ms:.3f}"


def load_numbers():
    with open(NUMBERS_JSON, encoding="utf-8") as f:
        return json.load(f)


def compute_numbers():
    sys.path.insert(0, MODEL_DIR)
    import perf_model  # model/perf_model.py (paper Appendix E)

    perf_model.main()
    return load_numbers()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = p.add_mutually_exclusive_group()
    group.add_argument("--from-json", action="store_true",
                       help="print the committed measured numbers from "
                            "model/numbers.json (default)")
    group.add_argument("--compute", action="store_true",
                       help="recompute with the Appendix E cost model "
                            "(regenerates numbers.json/numbers.md/CSVs), "
                            "then print")
    args = p.parse_args(argv)
    if not args.compute:
        args.from_json = True
    return args


def main(argv=None):
    args = parse_args(argv)
    res = compute_numbers() if args.compute else load_numbers()
    gates = res["gates"]
    lat = res["gate_lat_lan"]

    print("Table tab:gates - Authenticated Nonlinear Gate Options per "
          "Module (paper Section VIII-B)")
    print("Source: measured (from model/numbers.json)"
          + ("" if not args.compute else ", regenerated with the "
             "Appendix E cost model") + ".")
    print("n=61; 28 nm, 720 MHz, 64 AES engines, 128 field lanes.  One "
          "online round = one CheckOpen = two inter-module round trips.")
    print()
    hdr = ("{:<28} {:>7} {:>9} {:>9} {:>11} {:>10}"
           .format("Gate", "Rounds", "AES", "Mults", "Thr. M/s",
                   "LAN ms"))
    print(hdr)
    print("-" * len(hdr))
    for key, label in GATE_ROWS:
        g = gates[key]
        aes = g["aes"]
        mults = g["mults"]
        thr = g["thr"]
        lan_ms = lat[key] * 1e3 if key in lat else None
        aes_s = "n/m" if (aes is None or key in ROUND_BOUND) else f"{aes:,d}"
        thr_s = fmt_thr(thr / 1e6 if thr is not None else None)
        print("{:<28} {:>7} {:>9} {:>9} {:>11} {:>10}"
              .format(label, g["rounds"], aes_s,
                      "n/m" if mults is None else f"{mults:,d}",
                      thr_s, "-" if lan_ms is None else fmt_lat(lan_ms)))
    print("-" * len(hdr))
    print("* Optimized DCF: O(n) DCF construction outside our proofs "
          "(thm:dcf).  n/a: round-bound, throughput not meaningful; "
          "n/m: not modeled, AES work negligible next to round trips.")

    print()
    print("Single-path DPF gate throughput per module (measured; "
          "Section VIII-B, Fig. fig:dpfthr):")
    print("28 nm, 720 MHz, 64 AES engines; pipeline efficiency 0.85 "
          "malicious / 0.90 semi-honest.")
    gac = res["gac"]
    print(f"{'n':>4} {'trusted DFA (SH)':>18} {'VIGOR-DFA':>12} "
          f"{'tag tree t=3':>14} {'latency us':>11}")
    for n in (8, 16, 32, 61):
        sh = gac[f"gac_tdfa_{n}"] / 1e6
        vig = gac[f"gac_vigor_{n}"] / 1e6
        tag = gac[f"gac_tagtree_{n}"] / 1e6
        lat_us = gac[f"lat_{n}"] * 1e6
        print(f"{n:>4} {sh:>16.0f} M {vig:>10.0f} M {tag:>12.1f} M "
              f"{lat_us:>9.2f} us")
    print("At n=61: 106 vs 113 M gates/s (VIGOR-DFA vs trusted DFA) and "
          "26.7 M gates/s for per-lane tag trees; single-gate latency "
          "1.71 us.")
    print("Direct protected gate: 1,800 M gates/s (one verified opening, "
          "two AES blocks and five field multiplications per gate).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
