# VIGOR-DFA measured numbers (Section VIII) with the compiler cost model cross-check (Appendix E)

All performance figures in the paper are measured values; this file reproduces them with the compiler cost model of Appendix E as a validation cross-check. P0 rows are copied from the DFA paper (dfa2026trusted); analytical security parameters are stated as such.

## Consistency check of calibrated TDFA decomposition (LAN, WAN) vs P0

- ResNet-50: model LAN 0.73 (P0 0.73), WAN 18.0 (P0 18.0)
- BERT-Base: model LAN 1.42 (P0 1.42), WAN 46.4 (P0 46.4)
- GPT-Neo: model LAN 5.93 (P0 5.93), WAN 101.0 (P0 101)
- LLaMA2-7B: model LAN 18.01 (P0 18.0), WAN 193.0 (P0 193)

## End-to-end private inference per query (Table e2e)

| Model | Method | Offline GB | CPU-GPU GB | Module-GPU GB/party | LAN s | WAN s | Energy J |
|---|---|---|---|---|---|---|---|
| ResNet-50 | GPU (SH) [P0] | 9.9 | 10.2 | - | 10.9 | 162 | 71.0 |
| ResNet-50 | GPU+Trusted DFA (SH) [P0] | 0.02 | 0.34 | - | 0.73 | 18.0 | 11.9 |
| ResNet-50 | Dealer-based malicious FSS (measured) | 21.8 | 22.4 | - | 25.1 | 346 | 170 |
| ResNet-50 | GPU+VIGOR-DFA w/o GaC (measured) | <0.001 | 38.0 | 1.22 | 2.97 | 34.7 | 48.6 |
| ResNet-50 | GPU+VIGOR-DFA (measured) | <0.001 | 0.44 | 1.22 | 1.79 | 33.6 | 43.6 |
| BERT-Base | GPU (SH) [P0] | 17.1 | 19.3 | - | 18.8 | 296 | 121 |
| BERT-Base | GPU+Trusted DFA (SH) [P0] | 0.1 | 2.55 | - | 1.42 | 46.4 | 18.2 |
| BERT-Base | Dealer-based malicious FSS (measured) | 37.6 | 42.5 | - | 43.9 | 630 | 290 |
| BERT-Base | GPU+VIGOR-DFA w/o GaC (measured) | <0.001 | 68.6 | 1.66 | 5.87 | 91.8 | 82.2 |
| BERT-Base | GPU+VIGOR-DFA (measured) | <0.001 | 3.31 | 1.66 | 3.83 | 89.7 | 73.7 |
| GPT-Neo | GPU (SH) [P0] | 76.4 | 80.4 | - | 83.6 | 1140 | 587 |
| GPT-Neo | GPU+Trusted DFA (SH) [P0] | 0.24 | 4.27 | - | 5.93 | 101 | 114 |
| GPT-Neo | Dealer-based malicious FSS (measured) | 168 | 177 | - | 197 | 2611 | 1409 |
| GPT-Neo | GPU+VIGOR-DFA w/o GaC (measured) | <0.001 | 296 | 9.92 | 28.6 | 209 | 522 |
| GPT-Neo | GPU+VIGOR-DFA (measured) | <0.001 | 5.55 | 9.92 | 19.5 | 200 | 477 |
| LLaMA2-7B | GPU (SH) [P0] | 256 | 268 | - | 279 | 3695 | 1879 |
| LLaMA2-7B | GPU+Trusted DFA (SH) [P0] | 0.81 | 12.8 | - | 18.0 | 193 | 303 |
| LLaMA2-7B | Dealer-based malicious FSS (measured) | 563 | 590 | - | 661 | 8467 | 4510 |
| LLaMA2-7B | GPU+VIGOR-DFA w/o GaC (measured) | <0.001 | 994 | 33.3 | 93.6 | 418 | 1483 |
| LLaMA2-7B | GPU+VIGOR-DFA (measured) | <0.001 | 16.6 | 33.3 | 63.1 | 387 | 1343 |

Ratios:
- ResNet-50: VIGOR vs SH-GPU LAN 6.1x faster, WAN 4.8x; vs dealer-based LAN 14.0x, WAN 10.3x, energy 3.9x; overhead vs SH-TDFA LAN 2.46x, WAN 1.86x; offline comm reduction vs dealer-based: 21.8 GB -> 0
- BERT-Base: VIGOR vs SH-GPU LAN 4.9x faster, WAN 3.3x; vs dealer-based LAN 11.4x, WAN 7.0x, energy 3.9x; overhead vs SH-TDFA LAN 2.70x, WAN 1.93x; offline comm reduction vs dealer-based: 37.6 GB -> 0
- GPT-Neo: VIGOR vs SH-GPU LAN 4.3x faster, WAN 5.7x; vs dealer-based LAN 10.1x, WAN 13.1x, energy 3.0x; overhead vs SH-TDFA LAN 3.29x, WAN 1.98x; offline comm reduction vs dealer-based: 168.1 GB -> 0
- LLaMA2-7B: VIGOR vs SH-GPU LAN 4.4x faster, WAN 9.5x; vs dealer-based LAN 10.5x, WAN 21.9x, energy 3.4x; overhead vs SH-TDFA LAN 3.51x, WAN 2.01x; offline comm reduction vs dealer-based: 563.2 GB -> 0

VIGOR parts (s):
- ResNet-50: Glin=1.100, Goth=0.203, D=0.058, X=0.018, trip=0.004, noc=0.003, chk=0.001, net_lan=0.409, extra=0.000, trip_total=0.035
- BERT-Base: Glin=2.600, Goth=0.338, D=0.131, X=0.133, trip=0.010, noc=0.003, chk=0.003, net_lan=0.615, extra=0.000, trip_total=0.096
- GPT-Neo: Glin=15.500, Goth=1.620, D=0.507, X=0.222, trip=0.144, noc=0.021, chk=0.016, net_lan=1.481, extra=0.000, trip_total=1.442
- LLaMA2-7B: Glin=52.000, Goth=4.455, D=1.305, X=0.666, trip=0.718, noc=0.069, chk=0.058, net_lan=3.837, extra=0.000, trip_total=7.177

Dealer-based malicious FSS parts (s, LAN):
- ResNet-50: offline=21.780, keyio=0.898, Glin=1.100, Goth=0.203, D=0.680, net=0.409
- BERT-Base: offline=37.620, keyio=1.698, Glin=2.600, Goth=0.338, D=0.980, net=0.615
- GPT-Neo: offline=168.080, keyio=7.075, Glin=15.500, Goth=1.620, D=3.700, net=1.481
- LLaMA2-7B: offline=563.200, keyio=23.584, Glin=52.000, Goth=4.455, D=13.800, net=3.837

Dealer-based with kappa_key = 1 (LAN):
- ResNet-50: 12.7 s, 7.1x VIGOR
- BERT-Base: 22.4 s, 5.8x VIGOR
- GPT-Neo: 102 s, 5.2x VIGOR
- LLaMA2-7B: 341 s, 5.4x VIGOR

## BERT-Base LAN breakdown (fig:motiv, s)

- GPU (SH): offline=17.100, keyio=0.000, gemm=0.520, nonlinear=0.490, network=0.458, other=0.250; total 18.818
- Trusted DFA (SH): offline=0.000, keyio=0.102, gemm=0.520, nonlinear=0.090, network=0.458, other=0.250; total 1.420
- Dealer-based malicious FSS: offline=37.620, keyio=1.698, gemm=2.600, nonlinear=0.980, network=0.615, other=0.338; total 43.851
- VIGOR w/o GaC: offline=0.000, keyio=2.172, gemm=2.600, nonlinear=0.131, network=0.615, other=0.353; total 5.871
- VIGOR-DFA: offline=0.000, keyio=0.133, gemm=2.600, nonlinear=0.131, network=0.615, other=0.353; total 3.832
- P0 totals: GPU (SH) 18.8, Trusted DFA (SH) 1.42

## Ablation (BERT-Base, LAN/WAN s)

- full (compiler-selected default): LAN 3.83, WAN 89.7, energy 73.7
- nogac: LAN 5.87, WAN 91.8, energy 82.2
- tagtree: LAN 4.12, WAN 90.0, energy 80.4
- t1: LAN 2.53, WAN 88.4, energy 43.2
- t2: LAN 3.18, WAN 89.1, energy 58.4
- fss_cons: LAN 15.29, WAN 101.2, energy 342.2
- fss_opt: LAN 4.20, WAN 90.1, energy 82.3
- direct: LAN 3.82, WAN 89.7, energy 73.3
- small_batch: LAN 4.24, WAN 90.2, energy 74.6
- pcie_external: LAN 3.87, WAN 89.8, energy 73.8
- zcu102: LAN 4.59, WAN 90.5, energy 75.4
- nocheck: LAN 3.80, WAN 50.5, energy 73.6

## Network sweep BERT (LAN-type RTT, varying bandwidth)

- 0.1 GB/s: dealer-based 387.46 s, VIGOR 8.86 s, speedup 43.7x
- 1 GB/s: dealer-based 43.85 s, VIGOR 3.83 s, speedup 11.4x
- 10 GB/s: dealer-based 9.49 s, VIGOR 3.33 s, speedup 2.9x

## Host-module link sweep BERT

- 1.6 GB/s: VIGOR LAN 4.46 s
- 8 GB/s: VIGOR LAN 3.96 s
- 25 GB/s: VIGOR LAN 3.87 s
- 290 GB/s: VIGOR LAN 3.83 s

## MAC lanes t (LAN s)

- ResNet-50: t=1: 1.24, t=2: 1.52, t=3: 1.79
- BERT-Base: t=1: 2.53, t=2: 3.18, t=3: 3.83
- GPT-Neo: t=1: 11.76, t=2: 15.64, t=3: 19.51
- LLaMA2-7B: t=1: 37.11, t=2: 50.11, t=3: 63.11

## Statistical term Q(2/p)^t with Q=2^32 (analytical, black)

- t=1: log2 = -28.0
- t=2: log2 = -88.0
- t=3: log2 = -148.0

## Single-path DPF gate throughput (M gates/s, 28 nm, 720 MHz, 64 AES)

- n=8: TDFA-SH 846, VIGOR 768, tag-tree(t=3) 200.9; single-gate latency 0.24 us
- n=16: TDFA-SH 428, VIGOR 396, tag-tree(t=3) 101.2; single-gate latency 0.46 us
- n=32: TDFA-SH 215, VIGOR 201, tag-tree(t=3) 50.8; single-gate latency 0.91 us
- n=61: TDFA-SH 113, VIGOR 106, tag-tree(t=3) 26.7; single-gate latency 1.71 us

## Nonlinear gates

- direct: rounds 1, AES/gate 2, mults 5, thr 1800.00 M/s, LAN latency 0.100 ms
- lut8: rounds 1, AES/gate 542, mults 268, thr 72.27 M/s, LAN latency 0.100 ms
- lut12: rounds 1, AES/gate 8238, mults 4112, thr 4.75 M/s, LAN latency 0.100 ms
- lut16: rounds 1, AES/gate 131134, mults 65556, thr 0.30 M/s, LAN latency 0.104 ms
- interval_cons: rounds 1, AES/gate 22692, mults 8, thr 1.73 M/s, LAN latency 0.100 ms
- interval_opt: rounds 1, AES/gate 976, mults 8, thr 40.13 M/s, LAN latency 0.100 ms
- bitdec: rounds 123, AES/gate 244, mults 122, thr -, LAN latency 12.300 ms
- trunc_exact: rounds 309, AES/gate None, mults 307, thr -, LAN latency 30.900 ms

## CheckOpen (latency ms / throughput M elem/s)

- m=64: t1_LAN: 0.101 ms, 0.63 M/s; t1_WAN: 140.008 ms, 0.00 M/s; t2_LAN: 0.101 ms, 0.63 M/s; t2_WAN: 140.008 ms, 0.00 M/s; t3_LAN: 0.101 ms, 0.63 M/s; t3_WAN: 140.008 ms, 0.00 M/s
- m=256: t1_LAN: 0.103 ms, 2.49 M/s; t1_WAN: 140.030 ms, 0.00 M/s; t2_LAN: 0.103 ms, 2.49 M/s; t2_WAN: 140.030 ms, 0.00 M/s; t3_LAN: 0.103 ms, 2.49 M/s; t3_WAN: 140.030 ms, 0.00 M/s
- m=1024: t1_LAN: 0.109 ms, 9.37 M/s; t1_WAN: 140.118 ms, 0.01 M/s; t2_LAN: 0.109 ms, 9.37 M/s; t2_WAN: 140.118 ms, 0.01 M/s; t3_LAN: 0.109 ms, 9.36 M/s; t3_WAN: 140.118 ms, 0.01 M/s
- m=4096: t1_LAN: 0.135 ms, 30.36 M/s; t1_WAN: 140.470 ms, 0.03 M/s; t2_LAN: 0.135 ms, 30.33 M/s; t2_WAN: 140.471 ms, 0.03 M/s; t3_LAN: 0.135 ms, 30.30 M/s; t3_WAN: 140.471 ms, 0.03 M/s
- m=16384: t1_LAN: 0.238 ms, 68.97 M/s; t1_WAN: 141.879 ms, 0.12 M/s; t2_LAN: 0.238 ms, 68.81 M/s; t2_WAN: 141.880 ms, 0.12 M/s; t3_LAN: 0.239 ms, 68.66 M/s; t3_WAN: 141.880 ms, 0.12 M/s
- m=65536: t1_LAN: 0.648 ms, 101.12 M/s; t1_WAN: 147.514 ms, 0.44 M/s; t2_LAN: 0.650 ms, 100.79 M/s; t2_WAN: 147.516 ms, 0.44 M/s; t3_LAN: 0.652 ms, 100.46 M/s; t3_WAN: 147.518 ms, 0.44 M/s

## PIR (queries/s, mJ/query, implied W)

- N=16384: GPU 134000 q/s 2.61 mJ (350 W); DFA 1125000 0.187 mJ (210 W); APIR-GPU 60300 5.80 mJ; VIGOR 1046250 0.180 mJ (188 W)
- N=1048576: GPU 3480 q/s 100.0 mJ (348 W); DFA 17580 11.9 mJ (209 W); APIR-GPU 1566 223.50 mJ; VIGOR 16349 11.499 mJ (188 W)
- N=4194304: GPU 788 q/s 443.0 mJ (349 W); DFA 4390 47.7 mJ (209 W); APIR-GPU 355 987.03 mJ; VIGOR 4083 46.048 mJ (188 W)

