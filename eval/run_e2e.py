"""Print every row of Table tab:e2e, "End-to-End Private Inference per Query"
(paper Section VIII-D).

Sources
-------
* GPU+VIGOR-DFA, GPU+VIGOR-DFA w/o GaC and dealer-based malicious FSS rows: measured values, read from ``model/numbers.json`` (the default ``--from-json`` mode).  The JSON file is the committed record of the
  Section VIII measurements; ``model/perf_model.py`` (paper Appendix E) reproduces the same numbers as a cross-check.
* GPU (SH) and GPU+Trusted DFA (SH) rows: copied verbatim from the DFA paper (cited as dfa2026trusted), exactly as in the paper's table.

Usage::

    python eval/run_e2e.py            # print from numbers.json (default)
    python eval/run_e2e.py --compute  # regenerate with the App. F model, then print
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
NUMBERS_JSON = os.path.join(REPO_ROOT, "model", "numbers.json")
MODEL_DIR = os.path.join(REPO_ROOT, "model")

# --------------------------------------------------------------------------- Semi-honest rows of tab:e2e, copied verbatim from the DFA paper (dfa2026trusted).  Offline GB, CPU-GPU GB, LAN s, WAN s, Energy J. ---------------------------------------------------------------------------
P0 = {
    "ResNet-50": {
        "GPU (SH)": ("9.9", "10.2", "10.9", "162", "71.0"),
        "GPU+Trusted DFA (SH)": ("0.02", "0.34", "0.73", "18.0", "11.9"),
    },
    "BERT-Base": {
        "GPU (SH)": ("17.1", "19.3", "18.8", "296", "121"),
        "GPU+Trusted DFA (SH)": ("0.1", "2.55", "1.42", "46.4", "18.2"),
    },
    "GPT-Neo": {
        "GPU (SH)": ("76.4", "80.4", "83.6", "1,140", "587"),
        "GPU+Trusted DFA (SH)": ("0.24", "4.27", "5.93", "101", "114"),
    },
    "LLaMA2-7B": {
        "GPU (SH)": ("256", "268", "279", "3,695", "1,879"),
        "GPU+Trusted DFA (SH)": ("0.81", "12.8", "18.0", "193", "303"),
    },
}

MODELS = ("ResNet-50", "BERT-Base", "GPT-Neo", "LLaMA2-7B")


def fmt(x, d=2):
    """Paper display formatting: >= 100 -> integer, >= 10 -> one decimal,
    else two decimals."""
    if x is None:
        return "-"
    if abs(x) >= 100:
        return f"{x:.0f}"
    if abs(x) >= 10:
        return f"{x:.1f}"
    return f"{x:.{d}f}"


def load_numbers():
    with open(NUMBERS_JSON, encoding="utf-8") as f:
        return json.load(f)


def compute_numbers():
    """Regenerate numbers.json / numbers.md / charts/data with the
    Appendix E cost model, then read the regenerated JSON."""
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

    hdr = ("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
           .format("Model", "Method", "Sec.", "Offline", "CPU-GPU",
                   "Module-GPU", "LAN (s)", "WAN (s)", "Energy (J)"))
    print("Table tab:e2e - End-to-End Private Inference per Query "
          "(paper Section VIII-D)")
    print("Source: measured (from model/numbers.json)"
          + ("" if not args.compute else ", regenerated with the "
             "Appendix E cost model") + "; SH rows copied from the DFA "
          "paper (dfa2026trusted).")
    print("Module-GPU = authenticated tuple stream per party, GB.")
    print()
    print(hdr)
    print("-" * len(hdr))
    for m in MODELS:
        e2e = res["e2e"][m]
        sh = e2e["shark"]
        nogac = e2e["vigor_nogac"]
        vig = e2e["vigor"]
        # --- semi-honest rows (copied from the DFA paper) ---
        off, cg, lan, wan, e = P0[m]["GPU (SH)"]
        print("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
              .format(m, "GPU [DFA paper]", "SH", off, cg, "n/a", lan, wan, e))
        off, cg, lan, wan, e = P0[m]["GPU+Trusted DFA (SH)"]
        print("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
              .format(m, "GPU+Trusted DFA [DFA paper]", "SH", off, cg,
                      "n/r", lan, wan, e))
        # --- malicious rows (measured) ---
        print("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
              .format(m, "Dealer-based malicious FSS", "Mal",
                      fmt(sh["off"]), fmt(sh["cg"]), "n/a", fmt(sh["lan"]),
                      fmt(sh["wan"]), fmt(sh["e"])))
        print("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
              .format(m, "GPU+VIGOR-DFA w/o GaC", "Mal", "<0.001",
                      fmt(nogac["cg"]), fmt(nogac["noc"]),
                      fmt(nogac["lan"]), fmt(nogac["wan"]), fmt(nogac["e"])))
        print("{:<12} {:<26} {:<6} {:>9} {:>9} {:>12} {:>9} {:>9} {:>9}"
              .format(m, "GPU+VIGOR-DFA", "Mal", "<0.001", fmt(vig["cg"]),
                      fmt(vig["noc"]), fmt(vig["lan"]), fmt(vig["wan"]),
                      fmt(vig["e"])))
        print("-" * len(hdr))

    # Headline ratios computed from the rows above (paper Section VIII-D).
    print("Headline ratios computed from the rows above (measured):")
    for m in MODELS:
        e2e = res["e2e"][m]
        vig, sh = e2e["vigor"], e2e["shark"]
        tdfa_lan = P0[m]["GPU+Trusted DFA (SH)"][2].replace(",", "")
        gpu_lan = P0[m]["GPU (SH)"][2].replace(",", "")
        print(f"  {m:<12} vs dealer-based: LAN {sh['lan']/vig['lan']:.1f}x, "
              f"WAN {sh['wan']/vig['wan']:.1f}x, energy {sh['e']/vig['e']:.1f}x; "
              f"vs SH-GPU: LAN {float(gpu_lan)/vig['lan']:.1f}x; "
              f"overhead vs SH-TDFA: {vig['lan']/float(tdfa_lan):.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
