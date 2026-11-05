/* ==================================================================================================== */
/* FILE: alu8_cycle_sim.c | Cycle-Accurate 8-Bit Synchronous ALU RTL Co-Simulation Engine (ISO C99)     */
/* ==================================================================================================== */
#include <stdio.h>    /* Provides standard I/O stream routines for printing RTL waveform telemetry.     */
#include <stdint.h>   /* Defines exact-width integer types (uint8_t, uint16_t) matching hardware buses. */
#include <stdbool.h>  /* Introduces boolean data type to model single-bit digital logic nets cleanly.   */

#define WORD_MASK     0x00FFU /* 8-bit datapath mask (8'hFF) isolating architectural register width.    */
#define EXT9_MASK     0x01FFU /* 9-bit extended mask (9'h1FF) retaining carry/borrow bit [8] post-ALU.  */
#define SIGN_BIT_POS  7U      /* Bit index of the Most Significant Bit (MSB) for Two's Complement sign. */
#define CARRY_BIT_POS 8U      /* Bit index of the carry-out/borrow bit inside the 9-bit arithmetic bus. */
#define OPCODE_MASK   0x07U   /* 3-bit mask (3'b111) constraining operation selector to 8 valid opcodes.*/
#define SHIFT_MASK    0x07U   /* 3-bit mask (3'b111) limiting barrel shifter distance to 0..7 bit lanes.*/

typedef enum {                /* Enumerates the 3-bit binary control encodings for the 8-to-1 ALU mux.  */
    OP_ADD = 0x00U,           /* 3'b000: 8-bit binary addition (A + B) with carry-out & overflow sense. */
    OP_SUB = 0x01U,           /* 3'b001: 8-bit subtraction (A - B) via Two's Complement borrow logic.   */
    OP_AND = 0x02U,           /* 3'b010: Bitwise logical AND (A & B) for selective bit-lane masking.    */
    OP_OR  = 0x03U,           /* 3'b011: Bitwise logical OR  (A | B) for bit-lane assertion merging.    */
    OP_XOR = 0x04U,           /* 3'b100: Bitwise exclusive-OR (A ^ B) for parity and equality checks.   */
    OP_INV = 0x05U,           /* 3'b101: Bitwise unary inversion (~A) computing One's Complement of A.  */
    OP_SHL = 0x06U,           /* 3'b110: Logical shift left  (A << B[2:0]) capturing last shifted MSB.  */
    OP_SHR = 0x07U            /* 3'b111: Logical shift right (A >> B[2:0]) capturing last shifted LSB.  */
} AluOpcode_t;                /* Completes strongly-typed 3-bit opcode enumeration for control decoder. */

typedef struct {              /* Models the synchronous D-Flip-Flop (DFF) architectural state registers.*/
    uint8_t  alu_out;         /* 8-bit registered datapath output bus alu_out[7:0] latched on posedge.  */
    uint8_t  flag_c;          /* 1-bit Carry/Borrow status flip-flop (CCR[3]) capturing unsigned carry. */
    uint8_t  flag_z;          /* 1-bit Zero status flip-flop (CCR[2]) asserted via 8-input NOR gate.    */
    uint8_t  flag_n;          /* 1-bit Negative status flip-flop (CCR[1]) reflecting sign bit alu_out[7]*/
    uint8_t  flag_v;          /* 1-bit Overflow status flip-flop (CCR[0]) detecting signed 2's comp ovf.*/
    uint32_t clk_ticks;       /* Monotonic clock cycle counter tracking sequential state transitions.   */
} AluRegState_t;              /* Completes sequential register bank representation of the ALU core.     */

typedef struct {              /* Bundles pin-level input stimuli driven onto the ALU interface per tick.*/
    uint8_t op_a;             /* 8-bit primary operand bus op_a[7:0] driven before setup-time window.   */
    uint8_t op_b;             /* 8-bit secondary operand bus op_b[7:0] driven before setup-time window. */
    uint8_t alu_sel;          /* 3-bit operation control bus alu_sel[2:0] selecting functional unit.    */
    bool    rst_n;            /* Active-low asynchronous reset pin (0 = reset asserted, 1 = normal op). */
} AluStimulus_t;              /* Completes pin-level test vector structure for hardware verification.   */

static inline void step_alu_clock_cycle( /* Models one rising clock edge (posedge clk) of RTL module.  */
    AluRegState_t * restrict reg,        /* Pointer to sequential DFF state bank; restrict aids opt.    */
    const AluStimulus_t * restrict pin   /* Pointer to current cycle input pin stimulus bundle.         */
) {                                      /* Opens sequential always_ff @(posedge clk or negedge rst_n). */
    reg->clk_ticks++;                    /* Increments master simulation clock counter on rising edge.  */
    if (!pin->rst_n) {                   /* Checks active-low asynchronous reset condition (!rst_n).    */
        reg->alu_out = 0x00U;            /* Clears 8-bit output register bank to 8'h00 immediately.     */
        reg->flag_c  = 0x00U;            /* Clears Carry status flip-flop to logic 1'b0 on reset.       */
        reg->flag_z  = 0x01U;            /* Asserts Zero status flip-flop to 1'b1 as output is 8'h00.   */
        reg->flag_n  = 0x00U;            /* Clears Negative status flip-flop to logic 1'b0 on reset.    */
        reg->flag_v  = 0x00U;            /* Clears Signed Overflow flip-flop to logic 1'b0 on reset.    */
        return;                          /* Exits early because asynchronous reset overrides clocking.  */
    }                                    /* Closes asynchronous reset branch; begins combinational path.*/

    const uint8_t a8  = pin->op_a & WORD_MASK;       /* Clamps operand A to 8 bits matching wire width. */
    const uint8_t b8  = pin->op_b & WORD_MASK;       /* Clamps operand B to 8 bits matching wire width. */
    const uint8_t sel = pin->alu_sel & OPCODE_MASK;  /* Masks control selector to 3 bits (8 opcodes).   */
    const uint8_t shamt = b8 & SHIFT_MASK;           /* Extracts 3-bit shift count B[2:0] for shifters. */
    uint16_t wide_res = 0x0000U;                     /* Models 9-bit internal combinational bus [8:0].  */
    uint8_t  comb_v   = 0x00U;                       /* Models combinational overflow net before DFF.   */
    uint8_t  comb_c   = 0x00U;                       /* Models combinational carry-out net before DFF.  */

    switch (sel) {                                   /* Implements 8-to-1 combinational ALU multiplexer.*/
        case OP_ADD:                                 /* Branch 3'b000: 8-bit unsigned/signed addition.  */
            wide_res = (uint16_t)(a8 + b8) & EXT9_MASK; /* Computes 9-bit sum capturing carry in bit 8. */
            comb_c   = (uint8_t)((wide_res >> CARRY_BIT_POS) & 1U); /* Extracts unsigned carry-out C.   */
            comb_v   = (uint8_t)(((~(a8 ^ b8)) & (a8 ^ (uint8_t)wide_res)) >> SIGN_BIT_POS) & 1U; /* V. */
            break;                                   /* Completes addition combinational path.          */
        case OP_SUB:                                 /* Branch 3'b001: 8-bit Two's Complement subtract. */
            wide_res = (uint16_t)(a8 - b8) & EXT9_MASK; /* Computes 9-bit difference; bit 8 is borrow.  */
            comb_c   = (uint8_t)((wide_res >> CARRY_BIT_POS) & 1U); /* Extracts unsigned borrow flag C. */
            comb_v   = (uint8_t)(((a8 ^ b8) & (a8 ^ (uint8_t)wide_res)) >> SIGN_BIT_POS) & 1U; /* V.    */
            break;                                   /* Completes subtraction combinational path.       */
        case OP_AND:                                 /* Branch 3'b010: 8-bit bitwise AND gate array.    */
            wide_res = (uint16_t)(a8 & b8) & WORD_MASK; /* Evaluates bit-by-bit conjunction A & B.      */
            break;                                   /* Leaves C=0 and V=0 for logical AND operation.   */
        case OP_OR:                                  /* Branch 3'b011: 8-bit bitwise OR gate array.     */
            wide_res = (uint16_t)(a8 | b8) & WORD_MASK; /* Evaluates bit-by-bit disjunction A | B.      */
            break;                                   /* Leaves C=0 and V=0 for logical OR operation.    */
        case OP_XOR:                                 /* Branch 3'b100: 8-bit bitwise XOR gate array.    */
            wide_res = (uint16_t)(a8 ^ b8) & WORD_MASK; /* Evaluates bitwise exclusive-OR A ^ B.        */
            break;                                   /* Leaves C=0 and V=0 for logical XOR operation.   */
        case OP_INV:                                 /* Branch 3'b101: 8-bit unary inverter array.      */
            wide_res = (uint16_t)(~a8) & WORD_MASK;  /* Inverts each bit of operand A (~A & 0xFF).      */
            break;                                   /* Leaves C=0 and V=0 for unary NOT operation.     */
        case OP_SHL:                                 /* Branch 3'b110: 8-bit logical left barrel shift. */
            wide_res = (uint16_t)((uint16_t)a8 << shamt) & EXT9_MASK; /* Shifts left by B[2:0] lanes.   */
            comb_c   = (shamt > 0U) ? (uint8_t)((a8 >> (8U - shamt)) & 1U) : 0U; /* Last shifted-out bit*/
            break;                                   /* Completes logical shift left combinational path.*/
        case OP_SHR:                                 /* Branch 3'b111: 8-bit logical right barrel shift.*/
            wide_res = (uint16_t)(a8 >> shamt) & WORD_MASK; /* Shifts operand A right by B[2:0] lanes.  */
            comb_c   = (shamt > 0U) ? (uint8_t)((a8 >> (shamt - 1U)) & 1U) : 0U; /* Last shifted-out bit*/
            break;                                   /* Completes logical shift right combinational mux.*/
        default:                                     /* Defensive default preventing latch inference.   */
            wide_res = 0x0000U;                      /* Forces internal bus to known zero state.        */
            break;                                   /* Exits combinational multiplexer evaluation.     */
    }                                                /* Ends always_comb functional datapath block.     */

    reg->alu_out = (uint8_t)(wide_res & WORD_MASK);           /* Latches lower 8 bits into alu_out DFFs.*/
    reg->flag_c  = comb_c;                                    /* Latches Carry/Borrow net into flag_c.  */
    reg->flag_z  = (uint8_t)(reg->alu_out == 0x00U);          /* Latches 8-bit NOR zero detect into Z.  */
    reg->flag_n  = (uint8_t)((reg->alu_out >> SIGN_BIT_POS) & 1U); /* Latches MSB sign bit [7] into N.  */
    reg->flag_v  = comb_v;                                    /* Latches signed overflow net into V.    */
}                                                             /* Ends posedge clk synchronous update.   */

static void print_byte_bin(uint8_t val) {            /* Formats an 8-bit byte as a binary bitstring.    */
    for (int bit = 7; bit >= 0; --bit) {             /* Loops from MSB (bit 7) down to LSB (bit 0).     */
        putchar(((val >> bit) & 1U) ? '1' : '0');    /* Prints ASCII '1' or '0' for each bit position.  */
    }                                                /* Completes 8-bit binary character emission loop. */
}                                                    /* Exits binary waveform formatting helper.        */

int main(void) {                                     /* Entry point for the RTL verification testbench. */
    AluRegState_t dut = {0U, 0U, 1U, 0U, 0U, 0U};    /* Initializes DUT state registers to power-on.    */
    const char *op_names[8] = {                      /* Defines lookup table of 3-character op labels.  */
        "ADD", "SUB", "AND", "OR ", "XOR", "INV", "SHL", "SHR" /* Indexed directly by 3-bit alu_sel.    */
    };                                               /* Completes mnemonic string array initialization. */

    const AluStimulus_t test_vectors[] = {           /* Declares 10-cycle directed verification suite.  */
        { .op_a = 0xFFU, .op_b = 0xFFU, .alu_sel = OP_ADD, .rst_n = false }, /* Cyc 1: Async Reset test.*/
        { .op_a = 0xC8U, .op_b = 0x64U, .alu_sel = OP_ADD, .rst_n = true  }, /* Cyc 2: 200+100=44 (C=1).*/
        { .op_a = 0x50U, .op_b = 0x40U, .alu_sel = OP_ADD, .rst_n = true  }, /* Cyc 3: 80+64=144 (V=1). */
        { .op_a = 0x10U, .op_b = 0x20U, .alu_sel = OP_SUB, .rst_n = true  }, /* Cyc 4: 16-32=240 (C=1). */
        { .op_a = 0xAAU, .op_b = 0x0FU, .alu_sel = OP_AND, .rst_n = true  }, /* Cyc 5: 0xAA & 0x0F=0x0A.*/
        { .op_a = 0xA0U, .op_b = 0x05U, .alu_sel = OP_OR,  .rst_n = true  }, /* Cyc 6: 0xA0 | 0x05=0xA5.*/
        { .op_a = 0x5AU, .op_b = 0x5AU, .alu_sel = OP_XOR, .rst_n = true  }, /* Cyc 7: 0x5A ^ 0x5A=0x00.*/
        { .op_a = 0x0FU, .op_b = 0x00U, .alu_sel = OP_INV, .rst_n = true  }, /* Cyc 8: ~0x0F = 0xF0.    */
        { .op_a = 0x81U, .op_b = 0x01U, .alu_sel = OP_SHL, .rst_n = true  }, /* Cyc 9: 0x81 << 1 = 0x02.*/
        { .op_a = 0x81U, .op_b = 0x01U, .alu_sel = OP_SHR, .rst_n = true  }  /* Cyc 10: 0x81 >> 1 = 0x40*/
    };                                               /* Ends deterministic stimulus vector array.       */

    const size_t total_cycles = sizeof(test_vectors) / sizeof(test_vectors[0]); /* Counts test vectors. */

    printf("====================================================================================================\n"); /* Banner. */
    printf("      8-BIT SYNCHRONOUS ALU CYCLE-ACCURATE RTL CO-SIMULATION ENGINE (ISO C99 GOLDEN MODEL)          \n"); /* Title.  */
    printf("====================================================================================================\n"); /* Rule.   */
    printf(" Cyc | RST_N | OP  |     OP_A (Bin / Hex / Dec) |     OP_B (Bin / Hex / Dec) ||  ALU_OUT (Bin / Hex / Dec) | C Z N V\n"); /* Hdr.*/
    printf("----------------------------------------------------------------------------------------------------\n"); /* Sep.    */

    for (size_t i = 0; i < total_cycles; ++i) {      /* Iterates across each clock cycle in testbench.  */
        step_alu_clock_cycle(&dut, &test_vectors[i]);/* Triggers rising clock edge on the ALU model.    */
        printf("  %2u |   %u   | %s | ",             /* Prints cycle number, reset pin, and op string.  */
               dut.clk_ticks, test_vectors[i].rst_n ? 1U : 0U, /* Passes tick count and rst_n level.    */
               test_vectors[i].rst_n ? op_names[test_vectors[i].alu_sel & OPCODE_MASK] : "RST"); /* Op. */
        print_byte_bin(test_vectors[i].op_a);        /* Prints 8-bit binary representation of op_a.     */
        printf(" (0x%02X/%3u) | ", test_vectors[i].op_a, test_vectors[i].op_a); /* Prints A hex/dec.    */
        print_byte_bin(test_vectors[i].op_b);        /* Prints 8-bit binary representation of op_b.     */
        printf(" (0x%02X/%3u) || ", test_vectors[i].op_b, test_vectors[i].op_b);/* Prints B hex/dec.    */
        print_byte_bin(dut.alu_out);                 /* Prints 8-bit binary registered output alu_out.  */
        printf(" (0x%02X/%3u) | %u %u %u %u\n",      /* Formats output hex/dec and 4 status flags.      */
               dut.alu_out, dut.alu_out, dut.flag_c, dut.flag_z, dut.flag_n, dut.flag_v); /* CCR flags. */
    }                                                /* Ends cycle-by-cycle simulation loop.            */

    printf("====================================================================================================\n"); /* Footer. */
    return 0;                                        /* Returns 0 indicating clean simulation exit.     */
}                                                    /* Terminates main verification program.           */
