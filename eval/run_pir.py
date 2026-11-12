"""Print every row of Table tab:pir, "PIR Throughput and Energy per Query"
(paper Section VIII-E).

Sources
-------
All PIR rows are measured values read from ``model/numbers.json``
(default ``--from-json``).  The GPU-DPF and GPU+DFA rows are DFA's
semi-honest measurements (cited as dfa2026trusted); the GPU-DPF+APIR
and GPU+VIGOR-DFA rows are measured on our implementations.
The "k queries/s" column is the paper's printed rounding of the JSON
values (each script run asserts they agree within 0.5%, the paper's
three-significant-figure rounding).

Usage::

    python eval/run_pir.py            # print from numbers.json (default)
    python eval/run_pir.py --compute  # regenerate with the App. F model, then print
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
NUMBERS_JSON = os.path.join(REPO_ROOT, "model", "numbers.json")
MODEL_DIR = os.path.join(REPO_ROOT, "model")

SIZES = (16384, 1048576, 4194304)     # 16K, 1M, 4M entries of 128 bits
SIZE_LABELS = {16384: "16K", 1048576: "1M", 4194304: "4M"}

# Paper-printed "queries/s (k)" column of tab:pir, per DB size and method. These are display roundings of the numbers.json values (three significant figures in the paper); the script asserts they agree with the JSON within 0.5%.
K_DISPLAY = {
    16384: ["134", "1,125", "60.3", "1,046"],
    1048576: ["3.48", "17.58", "1.57", "16.35"],
    4194304: ["0.788", "4.39", "0.355", "4.08"],
}

METHODS = ("GPU-DPF", "GPU+DFA", "GPU-DPF+APIR", "GPU+VIGOR-DFA")
INTEGRITY = ("no", "no", "yes", "yes")          # tab:pir "Integ." column
INDEX_HIDDEN = ("yes", "yes", "yes", "no")      # tab:pir "Index hidden" column


def fmt_mj(x):
    """Energy per query in mJ with the paper's precision."""
    if x >= 100:
        return f"{x:.0f}"
    if x >= 10:
        return f"{x:.1f}"
    if x >= 1:
        return f"{x:.2f}"
    return f"{x:.3f}"


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
    pir = res["pir"]

    print("Table tab:pir - PIR Throughput and Energy per Query "
          "(paper Section VIII-E)")
    print("Source: measured (from model/numbers.json)"
          + ("" if not args.compute else ", regenerated with the "
             "Appendix E cost model") + ".")
    print()
    hdr = ("{:<8} {:<16} {:<9} {:<11} {:>13} {:>13} {:>13} {:>12}"
           .format("DB", "Method", "Integ.", "Idx hidden", "k q/s",
                   "raw q/s", "mJ/query", "Implied W"))
    print(hdr)
    print("-" * len(hdr))
    for size in SIZES:
        db = pir[str(size)]
        rows = [("gpu", "GPU-DPF"), ("dfa", "GPU+DFA"),
                ("apir", "GPU-DPF+APIR"), ("vig", "GPU+VIGOR-DFA")]
        for i, (key, name) in enumerate(rows):
            raw = db[key]
            k_raw = raw / 1e3
            paper_k = float(K_DISPLAY[size][i].replace(",", ""))
            # Consistency check: JSON values reproduce the paper's printed k column within its 3-significant-figure rounding.
            assert abs(k_raw - paper_k) <= 0.005 * paper_k, \
                (f"{name} at {size}: numbers.json gives {k_raw:.4f}k, "
                 f"paper prints {K_DISPLAY[size][i]}")
            e_key = key + "_e"
            w_key = key + "_w"
            print("{:<8} {:<16} {:<9} {:<11} {:>13} {:>13} {:>13} {:>12}"
                  .format(SIZE_LABELS[size], name, INTEGRITY[i],
                          INDEX_HIDDEN[i], K_DISPLAY[size][i],
                          f"{raw:,.0f}", fmt_mj(db[e_key]),
                          f"{db[w_key]:.0f}"))
        print("-" * len(hdr))
    print("Integ.: client obtains the committed record or abort against a "
          "malicious server host (R1).")
    print("Idx hidden: index hidden from each server without trusted "
          "hardware; both VIGOR-DFA modules learn the index, so its "
          "query privacy relies on module trust.")
    print("Batches of 512 queries; implied power = throughput x energy "
          "per query (unit cross-check).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
