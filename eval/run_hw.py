"""Print the hardware-cost tables of paper Section VIII-G: Table
tab:hwcost (Hardware Cost of One VIGOR-DFA Module) and Table tab:fpga
(ZCU102 Functional Prototype).

Sources
-------
Post-synthesis results measured in the paper's 28 nm flow, scaled to
7 nm with DeepScaleTool as in DFA (paper Section VIII-A); the DFA blocks
are the synthesis results of the DFA paper (dfa2026trusted).  These
tables are not outputs of the compiler cost model, so they are recorded
here verbatim from the paper tables (they have no numbers.json entry).

Usage::

    python eval/run_hw.py
"""

import argparse

# Table tab:hwcost: component, (28 nm mm^2, 28 nm mW, 7 nm mm^2, 7 nm mW)
HWCOST_DFA = [
    ("16 DPF units (64 AES-128)", 1.73, 29, 0.054, 11),
    ("SRAM buffers", 3.06, 585, 0.096, 219),
    ("VPU (16-lane Ara)", 1.97, 794, 0.062, 298),
    ("All DFA (incl. control core)", 7.67, 1683.5, 0.239, 631),
]
HWCOST_ADD = [
    ("Field unit array (128 lanes)", 2.80, 1000, 0.088, 375),
    ("Check engine", 0.18, 45, 0.006, 17),
    ("AEAD/GHASH (freezer, peer channel)", 0.21, 60, 0.007, 23),
    ("Ledger, guard, parser", 0.09, 12, 0.003, 5),
    ("Ledger SRAM (32 KB)", 0.25, 35, 0.008, 13),
    ("Freeze SRAM (256 KB)", 1.07, 200, 0.033, 75),
]

# Table tab:fpga: resource, used, available, utilization
FPGA = [
    ("LUT", 168_000, 274_000, "61%"),
    ("Flip-flop", 201_000, 548_000, "37%"),
    ("BRAM36", 412, 912, "45%"),
    ("DSP", 356, 2_520, "14%"),
]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.parse_args(argv)

    print("Table tab:hwcost - Hardware Cost of One VIGOR-DFA Module "
          "(paper Section VIII-G, measured post-synthesis results)")
    print()
    hdr = "{:<38} {:>8} {:>8} {:>8} {:>8}".format(
        "Component", "28nm mm2", "28nm mW", "7nm mm2", "7nm mW")
    print(hdr)
    print("-" * len(hdr))
    print("DFA blocks reused by VIGOR-DFA (dfa2026trusted):")
    for name, a28, p28, a7, p7 in HWCOST_DFA:
        print("{:<38} {:>8} {:>8} {:>8} {:>8}".format(
            name, f"{a28:.2f}", f"{p28:,.1f}".rstrip("0").rstrip("."),
            f"{a7:.3f}", f"{p7:.0f}"))
    print("Blocks added by VIGOR-DFA:")
    for name, a28, p28, a7, p7 in HWCOST_ADD:
        print("{:<38} {:>8} {:>8} {:>8} {:>8}".format(
            name, f"{a28:.2f}", f"{p28:,.1f}".rstrip("0").rstrip("."),
            f"{a7:.3f}", f"{p7:.0f}"))
    print("-" * len(hdr))
    print("{:<38} {:>8} {:>8} {:>8} {:>8}".format(
        "VIGOR-DFA additions", "4.60", "1,352", "0.145", "508"))
    print("{:<38} {:>8} {:>8} {:>8} {:>8}".format(
        "All VIGOR-DFA", "12.27", "3,036", "0.384", "1,139"))
    print()
    print("At 7 nm one complete module occupies 0.384 mm^2, i.e. 0.046% "
          "of the 826 mm^2 A100 die.  The FUA dominates the additions "
          "with 61% of the added area and 74% of the added power at "
          "7 nm, followed by the 256 KB freeze SRAM with 23% of the "
          "added area; the security-policy logic (ledger, release "
          "guard, parser and check engine) takes only 0.009 mm^2, 6% of "
          "the additions.  No AES engines are added: challenge "
          "derivation and AEAD freezing time-share the 64 engines with "
          "PRG expansion, occupying the AES array and the FUA for about "
          "2.8 ms per BERT-Base query (<0.1% of its latency).")

    print()
    print("Table tab:fpga - ZCU102 Functional Prototype (XCZU9EG-2FFVB1156)")
    print()
    hdr2 = "{:<14} {:>10} {:>12} {:>13}".format("Resource", "Used",
                                                "Available", "Utilization")
    print(hdr2)
    print("-" * len(hdr2))
    for name, used, avail, util in FPGA:
        print("{:<14} {:>10,} {:>12,} {:>13}".format(name, used, avail,
                                                     util))
    print("-" * len(hdr2))
    print("Datapath: 4 DPF units (16 AES-128), 32 field lanes, 250 MHz")
    print("DPF throughput: 1.0 G expansions/s, measured at 50% of the "
          "2.0 G expansions/s peak of 16 AES engines at 250 MHz (one "
          "block per engine and cycle, two blocks per expansion)")
    print("Board power: 9.8 W")
    print("Host link: 1.6 GB/s, i.e. 50 M authenticated elements/s at "
          "32 bytes each")
    print()
    print("The ZCU102 prototype is a pessimistic functional point (one "
          "board with an emulated peer), not a performance target and "
          "not a Profile T deployment target (paper Section VIII-G).")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
