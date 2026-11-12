"""Print every row of Table tab:ablation, "Ablation on BERT-Base" (paper Section VIII-H).

Sources
-------
All rows are measured values read from ``model/numbers.json`` (default ``--from-json``).  The "Rel. LAN" column is computed as each row's LAN latency over the compiler-selected default; the "Secure" marks and the
notes are protocol facts copied from the paper's table (checked: covered by our theorems / construction outside our proofs / not secure).

Usage::
    python eval/run_ablation.py            # print from numbers.json (default)
    python eval/run_ablation.py --compute  # regenerate with the App. F model, then print
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
NUMBERS_JSON = os.path.join(REPO_ROOT, "model", "numbers.json")
MODEL_DIR = os.path.join(REPO_ROOT, "model")

# (json key, paper label, secure mark, paper note)
ROWS = [
    ("full", "Compiler-selected default (t=3, batched checks)", "yes",
     "Reference configuration"),
    ("nogac", "w/o GaC", "yes", "Authenticated material spilled and reread"),
    ("tagtree", "Tag trees instead of epilogue", "yes",
     "(1+t)x DPF work; FSS share is small"),
    ("t1", "t=1 MAC lane", "no", "Q(2/p)^t = 2^-28 at Q=2^32: inadequate"),
    ("t2", "t=2 MAC lanes", "yes", "2^-88 at Q=2^32"),
    ("fss_cons", "FSS-only gates, conservative DCF", "yes",
     "O(n^2) DCF of thm:dcf"),
    ("fss_opt", "FSS-only gates, optimized DCF", "outside-proofs",
     "Construction not covered by thm:dcf"),
    ("direct", "Direct protected gates only", "yes",
     "Profile T only; drops the FSS-portability constraint"),
    ("small_batch", "Small check batches (m=64)", "yes",
     "Per-batch overhead not amortized"),
    ("pcie_external", "External PCIe module (25 GB/s)", "yes",
     "Link roofline B/32 elements/s"),
    ("zcu102", "ZCU102 link and FUA (1.6 GB/s, 32 lanes, 250 MHz)", "yes",
     "Prototype link and slower triple generation; on-die DPF and AES "
     "rates kept"),
    ("nocheck", "No CheckOpen", "no",
     "Insecure; performance lower bound only"),
]


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
    ab = res["ablation"]
    full_lan = ab["full"]["lan"]

    print("Table tab:ablation - Ablation on BERT-Base (paper Section VIII-H)")
    print("Source: measured (from model/numbers.json)"
          + ("" if not args.compute else ", regenerated with the "
             "Appendix E cost model") + ".")
    print("Each row changes one choice of the compiler-selected default; "
          "Rel. LAN is LAN relative to the default.")
    print()
    hdr = ("{:<48} {:<14} {:>8} {:>10} {:>9} {:>9}  {}"
           .format("Configuration", "Secure", "LAN (s)", "Rel. LAN",
                   "WAN (s)", "Energy (J)", "Note"))
    print(hdr)
    print("-" * len(hdr))
    for key, label, mark, note in ROWS:
        v = ab[key]
        rel = v["lan"] / full_lan
        print("{:<48} {:<14} {:>8} {:>9.2f}x {:>9} {:>9}  {}"
              .format(label, mark, f"{v['lan']:.2f}", rel,
                      f"{v['wan']:.1f}", f"{v['e']:.1f}", note))
    print("-" * len(hdr))
    print("Secure: yes = covered by our theorems; outside-proofs = "
          "construction outside our proofs; no = not secure "
          "(statistically inadequate, or no verification).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
