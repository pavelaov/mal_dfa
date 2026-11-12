// ===================================================================== fu_mersenne61.v 61-bit Mersenne-prime field multiply unit with exact reduction, two-stage pipeline.  Representative hardware component of the VIGOR-DFA Mersenne-61 field unit array (Paper Sec. VI, sec:arch; field unit lanes sit inside each DPF unit).   stage 1:  61x61 -> 122-bit product;  first fold  x = (x & p) + (x >> 61)   stage 2:  second fold (adds only the top bit of the 62-bit             intermediate) and one conditional subtraction of p This is the behavioural twin of mersenne_reduce() in vigor_dfa/field.py:   Python:  while x >= (1 << 61): x = (x & P) + (x >> 61)            if x >= P:           x = x - P A 122-bit product needs exactly two folds: the first fold adds two 61-bit halves (result < 2^62), the second fold reduces to adding the single bit above position 60 (result <= 2^61), and the conditional subtraction maps the single noncanonical value 2^61 to 1.  The same two-fold sequence is the implementation contract for the exact GPU field kernels, which express the 122-bit shift through 64-bit words ((lo >> 61) | (hi << 3)); in RTL the shift of the full 122-bit product is explicit. Inputs must be canonical (a, b < p).  The output is canonical, in [0, p).  The unit is independent of in_valid framing: it consumes one (a, b) pair per cycle while in_valid is asserted and produces the result two cycles later with out_valid. Status: representative, synthesis-style RTL (Verilog-2001); not synthesized or simulated in this environment (no RTL toolchain available there). =====================================================================

module fu_mersenne61 #(
    parameter [60:0] P61 = 61'h1FFFFFFFFFFFFFFF   // p = 2^61 - 1
) (
    input  wire        clk,
    input  wire        rst_n,        // asynchronous reset, active low
    input  wire        in_valid,
    input  wire [60:0] in_a,         // canonical: in_a < p
    input  wire [60:0] in_b,         // canonical: in_b < p
    output wire        out_valid,
    output wire [60:0] out_z         // canonical product: in [0, p)
);

    // ---- stage 1: 61x61 product + first fold, then register ----------
    wire [121:0] prod_c  = in_a * in_b;                // 61x61 -> 122 bits
    wire [61:0]  fold1_c = prod_c[60:0] + prod_c[121:61];  // first fold

    reg [61:0] fold1_r;
    reg        valid1_r;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fold1_r  <= 62'b0;
            valid1_r <= 1'b0;
        end else begin
            fold1_r  <= fold1_c;
            valid1_r <= in_valid;
        end
    end

    // ---- stage 2: second fold of the REGISTERED first fold ------------ second fold: (fold1_r & p) + (fold1_r >> 61); only bit 61 can be set
    wire [61:0]  fold2_c = fold1_r[60:0] + {61'b0, fold1_r[61]};
    // conditional subtraction of p; fold2_c == 2^61 maps to 1
    wire [61:0]  sub_c   = fold2_c - {1'b0, P61};
    wire         ge_p    = fold2_c >= {1'b0, P61};

    reg [60:0] out_z_r;
    reg        valid2_r;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            out_z_r  <= 61'b0;
            valid2_r <= 1'b0;
        end else begin
            valid2_r <= valid1_r;
            out_z_r  <= ge_p ? sub_c[60:0] : fold2_c[60:0];
        end
    end

    assign out_valid = valid2_r;
    assign out_z     = out_z_r;

endmodule
