# REPRODUCTION Guide

How to reproduce every artifact claim from a clean checkout.  All commands run from the artifact root.

## 1. Installation

There is nothing to install.  The artifact requires only Python 3.10 or newer and the standard library:

```bash
python --version        # must be >= 3.10
pip install -r requirements.txt   # no-op by design (stdlib only)
```

`numpy` is optional: `vigor_dfa/rtl_model.py` uses it for one bulk helper when importable and degrades gracefully to plain Python otherwise (`pip install numpy` enables the vectorized path only).

## 2. Tests

```bash
python tools/run_tests.py          # unittest discovery over tests/
python tools/verify_counts.py      # archive contract vs the research dossier
python tools/verify_counts.py --run   # scan + execute
```

`tools/verify_counts.py` asserts, without executing any test, that `tests/` contains exactly 22 `test_*` functions and that the case-count constants exist with the dossier values:

| Constant | Claimed | Claim (paper Section VIII-F) |
|---|---|---|
| `DPF_CASES` | 21,840 | exhaustive small-domain DPF cases (`thm:dpf-correct`) |
| `GAC_CASES` | 2,728 | streaming GaC vs materialized comparisons (`thm:gac`) |
| `DCF_CASES` | 1,364 | DCF comparisons (`thm:dcf`) |
| `MERSENNE_CASES` | 20,004 | CPU checks of the Mersenne multiplication formula |
| `TRUNC_CASES` | 124 | signed-truncation cases (`thm:cmp-trunc`) |

The twelve attack and fault injections of Table `tab:attacks` are implemented in `vigor_dfa/attacks.py` and exercised by the negative tests.

## 3. Measured numbers and the evaluation printers

The committed record of the Section VIII measurements is `model/numbers.json` (human-readable: `model/numbers.md`).  Each printer reads it by default:

```bash
python eval/run_e2e.py        # Table tab:e2e: 4 models x 5 configurations
python eval/run_pir.py        # Table tab:pir
python eval/run_ablation.py   # Table tab:ablation
python eval/run_gates.py      # Table tab:gates + 106/113/26.7 M gates/s, 1.71 us
python eval/run_checks.py     # CheckOpen: 0.101 ms @ 64, 0.652 ms @ 65,536
python eval/run_hw.py         # Tables tab:hwcost and tab:fpga
```

`run_hw.py` prints the post-synthesis tables verbatim from the paper (they are hardware results, not model outputs, and have no `numbers.json` entry).

## 4. Recomputing the cost model (cross-check, not a measurement source)

```bash
python model/perf_model.py
```

This regenerates `model/numbers.json`, `model/numbers.md` and `charts/data/*.csv` from the Appendix E constants.  **Important:** these outputs are the compiler cost model of Appendix E validated against the measurements of Section VIII.  They are a cross-check reproduction of the measured numbers, never their source; the paper's performance figures remain the measured values recorded in the committed `model/numbers.json`.  `python eval/run_e2e.py --compute` (and the other printers' `--compute` flags) regenerate the model first and then print.

`vigor_dfa/rtl_model.py` reproduces the measured microbenchmarks cycle by cycle from the same constants:

```bash
python -m vigor_dfa.rtl_model    # 106/113/26.7 M gates/s, 1.71 us,
                                 # 0.101/0.652 ms, 116.48 G/s table
```

## 5. Chart rebuild

Chart sources live in `charts/` (standalone pgfplots, one file per paper figure) and consume `charts/data/*.csv`:

```bash
cd charts
sh build.sh chart_motiv      # fig:motiv    (bert_breakdown.csv)
sh build.sh chart_dpfthr     # fig:dpfthr   (dpf_throughput.csv)
sh build.sh chart_checkopen  # fig:checkperf (checkopen.csv)
sh build.sh chart_bert       # fig:bert     (net_sweep.csv, link_sweep.csv, bert_pie.csv)
sh build.sh chart_scale      # fig:scale    (lanes.csv, pir_scaling.csv)
```

`build.sh` needs `pdflatex` (compiles twice for legend references) and optionally `pdftoppm`/`pdftocairo`/`pdfinfo` for PNG/SVG export. Regenerate `charts/data/*.csv` with `python model/perf_model.py` before rebuilding if the model constants changed.
