# rtl/ — representative RTL of the VIGOR-DFA protected datapath

## `fu_mersenne61.v`

A 61-bit Mersenne-prime field multiply unit with exact reduction, in a two-stage pipeline:

* stage 1: 61×61 → 122-bit product and the first fold `x = (x & p) + (x >> 61)`;
* stage 2: second fold (only the top bit of the 62-bit intermediate can be set) and one conditional subtraction of `p`.

### Position of this file in the artifact

* **Behavioural twin of `vigor_dfa/field.py`.** The two-stage fold-then-subtract rule is the exact Python `mersenne_reduce()` sequence (`while x >= 2**61: x = (x & p) + (x >> 61)`, then `if x >= p: x -= p`), which itself implements the fixed reduction of the exact field kernels in the paper's implementation contract (technical specification Sec. 15, "Exact A100 Mersenne arithmetic"). The CUDA form expresses the 122-bit shift through 64-bit words, `(lo >> 61) | (hi << 3)`; in RTL the shift of the full 122-bit product is written directly.
* **Corresponds to the paper's field unit (Paper Sec. VI).** The paper places a Mersenne-61 field unit array inside the DPF units, where the lanes serve epilogues, triples, reductions and check residuals; this file is the representative multiply-and-reduce lane of that array. Inputs are canonical elements (`< p`), outputs are canonical, and the unit accepts one pair per cycle with a two-cycle result latency (`out_valid` framing).
* **Representative component, not a synthesis report.** This file is written in synthesis-style Verilog-2001 but has **not been synthesized or simulated** in this environment (no RTL toolchain is available there); it demonstrates the exact datapath logic and its one-to-one correspondence with the Python reference, not a hardware implementation claim. Any synthesis or equivalence checking is future work, exactly as the paper's proof-boundary table lists "constant-time, bit-exact CUDA/RTL refinement" as a deployment obligation.
