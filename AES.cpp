#include <stdio.h>    // Loads standard I/O; provides printf() used in main() for final output
#include <stdlib.h>   // Loads standard utilities; supports underlying OS memory handling
#include <string.h>   // Loads string utilities; supports underlying array structures
#include <stdint.h>   // Loads precise integer types (uint8_t); essential for strict 8-bit AES math

// --- HARDWARE TIMER SETUP --- // Prepares CPU tick reading; feeds into main() benchmark phase
#if defined(_WIN32) || defined(_MSC_VER) // Checks if OS is Windows; dictates compiler intrinsic choice
#include <intrin.h>                      // Loads Windows intrinsics; enables __rdtsc() instruction below
static inline uint64_t get_ticks() {     // Defines inline timer function; called immediately before/after AES blocks
    return __rdtsc();                    // Returns exact CPU cycles; feeds start and end benchmark variables
}                                        // Ends Windows timer setup; proceeds to fallback definitions
#else                                    // Handles non-Windows edge cases; prevents compile failure
static inline uint64_t get_ticks() { return 0; } // Returns 0 if unsupported; allows safe compilation
#endif                                   // Ends timer setup; proceeds to cryptographic substitution tables

// --- AES LOOKUP TABLES --- // Pre-calculated mathematical mappings; feeds into Substitution algorithms
static const uint8_t sbox[256] = { // Forward S-box array; maps input byte to output byte; used by sub_bytes() and key_expansion()
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // S-box Row 0: Feeds non-linear diffusion
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // S-box Row 1: Breaks linear math patterns
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // S-box Row 2: Derived from GF(2^8) inverses
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // S-box Row 3: Scrambles AddRoundKey output
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // S-box Row 4: Prepares data for ShiftRows
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // S-box Row 5: Evaluated per-byte independently
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // S-box Row 6: Used 16 times per encryption round
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // S-box Row 7: Defends against differential cryptanalysis
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // S-box Row 8: Applies affine transformation bits
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // S-box Row 9: Fully symmetrical generation
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // S-box Row 10: Prevents algebraic attacks
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // S-box Row 11: Replaces state bytes directly
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // S-box Row 12: Outputs strictly 8-bit values
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // S-box Row 13: Used in key schedule every 4 words
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // S-box Row 14: Finalizes sub_bytes phase
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // S-box Row 15: Ends S-box lookup array
}; // Ends forward S-box array initialization

static const uint8_t rsbox[256] = { // Reverse S-box array; mathematically inverses the forward S-box; used by inv_sub_bytes()
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // Rev S-box Row 0: Restores original byte values
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // Rev S-box Row 1: Takes input from inv_shift_rows
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // Rev S-box Row 2: Feeds output into add_round_key
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // Rev S-box Row 3: Pre-calculated to save CPU time
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // Rev S-box Row 4: Exact mathematical reflection of S-box
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // Rev S-box Row 5: Ensures flawless lossless decryption
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // Rev S-box Row 6: Applied 160 times per full block decryption
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // Rev S-box Row 7: Neutralizes the non-linear substitution
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // Rev S-box Row 8: Decrypts ciphered data bytes
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // Rev S-box Row 9: Required only for decryption phase
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // Rev S-box Row 10: Never used during encryption phase
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // Rev S-box Row 11: Converts 8-bit index to 8-bit value
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // Rev S-box Row 12: Reconstructs state matrix integrity
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // Rev S-box Row 13: Finalizes the reverse substitution step
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // Rev S-box Row 14: Precedes inv_mix_columns logically
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // Rev S-box Row 15: Ends Reverse S-box lookup array
}; // Ends reverse S-box array initialization

static const uint8_t rcon[11] = { // Round constants array; prevents symmetries during key generation; used by key_expansion()
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 // Hex values representing x^(i-1) in GF(2^8); feeds XOR in Key Schedule
}; // Ends round constant array

// --- GALOIS FIELD MATH --- // Helper for MixColumns; provides bitwise multiplication over GF(2^8)
static uint8_t multiply(uint8_t x, uint8_t y) { // Takes 2 bytes to multiply; feeds product into MixColumns state matrix
    return (((y & 1) * x) ^                     // Checks bit 0 of y; if set, XOR x into result; feeds to next check
            ((y >> 1 & 1) * ((x << 1) ^ (((x >> 7) & 1) * 0x1b))) ^ // Checks bit 1; shifts x and XORs polynomial 0x1b if overflowed; combines
            ((y >> 2 & 1) * ((x << 2) ^ (((x >> 6) & 1) * 0x1b))) ^ // Checks bit 2; shifts x further; combines with accumulated XOR total
            ((y >> 3 & 1) * ((x << 3) ^ (((x >> 5) & 1) * 0x1b))) ^ // Checks bit 3; shifts x again; AES only requires multiplying up to 0x0E (4 bits)
            ((y >> 4 & 1) * ((x << 4) ^ (((x >> 4) & 1) * 0x1b)))); // Checks bit 4; final bit check; returns fully mixed product to caller
}                                               // Ends GF multiplication function; returns control to mix_columns()

// --- SHARED KEY EXPANSION --- // Derives 11 round keys from 1 master key; feeds add_round_key()
static void key_expansion(const uint8_t *key, uint8_t *round_keys) { // Takes 16-byte raw key; outputs 176-byte expanded key schedule
    for (int i = 0; i < 16; i++) round_keys[i] = key[i];             // Copies original key into first 16 bytes; forms Round 0 Key
    uint8_t temp[4];                                                 // Allocates 4-byte buffer; holds previous column to generate next column
    for (int i = 4; i < 44; i++) {                                   // Loops 40 times; generates remaining 40 columns (4 bytes each)
        for (int j = 0; j < 4; j++) temp[j] = round_keys[(i - 1) * 4 + j]; // Reads immediately preceding column into temp; feeds transformation
        if (i % 4 == 0) {                                            // Checks if current column is a multiple of 4; triggers non-linear rotation
            uint8_t t = temp[0];                                     // Temporarily stores top byte; feeds cyclical shift (RotWord)
            temp[0] = sbox[temp[1]] ^ rcon[i / 4];                   // Shifts 2nd byte up, runs S-box, XORs round constant; replaces 1st byte
            temp[1] = sbox[temp[2]];                                 // Shifts 3rd byte up, runs S-box; replaces 2nd byte
            temp[2] = sbox[temp[3]];                                 // Shifts 4th byte up, runs S-box; replaces 3rd byte
            temp[3] = sbox[t];                                       // Wraps stored top byte to bottom, runs S-box; replaces 4th byte
        }                                                            // Ends non-linear rotation; temp now holds transformed column
        for (int j = 0; j < 4; j++) round_keys[i * 4 + j] = round_keys[(i - 4) * 4 + j] ^ temp[j]; // XORs 4-columns-back with temp; outputs new column
    }                                                                // Ends column generation loop; all 11 round keys are now ready
}                                                                    // Ends key_expansion; returns control to main()

// XORs 16-byte state matrix with 16-byte round key; bridges steps between rounds
static void add_round_key(uint8_t state[4][4], const uint8_t *round_key) { // Takes 4x4 matrix and current round's key segment
    for (int c = 0; c < 4; c++)                                            // Loops over 4 columns of the state
        for (int r = 0; r < 4; r++)                                        // Loops over 4 rows of the state
            state[r][c] ^= round_key[c * 4 + r];                           // XORs matrix byte with corresponding key byte; modifies state in-place
}                                                                          // Ends add_round_key; feeds modified state to next step

// --- ENCRYPTION OPERATIONS --- // Core forward transformations
static void sub_bytes(uint8_t state[4][4]) {                         // Substitutes all 16 state bytes; takes input from add_round_key
    for (int r = 0; r < 4; r++)                                      // Loops over 4 rows
        for (int c = 0; c < 4; c++)                                  // Loops over 4 columns
            state[r][c] = sbox[state[r][c]];                         // Replaces byte with S-box lookup; feeds modified state to shift_rows
}                                                                    // Ends sub_bytes

static void shift_rows(uint8_t state[4][4]) {                        // Cyclically shifts state rows left; takes input from sub_bytes
    uint8_t t;                                                       // Temporary byte holder; supports swaps
    t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t; // Row 1: Shifts left by 1
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;                                                       // Row 2: Shifts left by 2 (swaps evens)
    t = state[3][0]; state[3][0] = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = t; // Row 3: Shifts left by 3 (right by 1)
}                                                                    // Ends shift_rows; feeds scrambled state to mix_columns

static void mix_columns(uint8_t state[4][4]) {                       // Mathematically diffuses bytes in each column; takes input from shift_rows
    for (int c = 0; c < 4; c++) {                                    // Loops over the 4 columns individually
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c]; // Reads original column bytes; prevents overwritten data interference
        state[0][c] = multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3;   // Calculates new row 0 byte; relies on GF(2^8) math
        state[1][c] = a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3;   // Calculates new row 1 byte; diffuses bits
        state[2][c] = a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3);   // Calculates new row 2 byte; diffuses bits
        state[3][c] = multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2);   // Calculates new row 3 byte; finishes column mix
    }                                                                // Ends column loop
}                                                                    // Ends mix_columns; feeds heavily diffused state to add_round_key

static void aes_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_keys) { // Orchestrates 10 encryption rounds; takes plaintext
    uint8_t state[4][4];                                             // Allocates 4x4 working state matrix
    for (int r = 0; r < 4; r++)                                      // Loops rows
        for (int c = 0; c < 4; c++)                                  // Loops columns
            state[r][c] = in[c * 4 + r];                             // Loads linear 16-byte input into column-major state matrix
    
    add_round_key(state, round_keys);                                // Round 0: Initial Key Addition; preps state for main loops
    for (int round = 1; round < 10; round++) {                       // Rounds 1 to 9: Main processing loop
        sub_bytes(state);                                            // Step 1: Substitute bytes
        shift_rows(state);                                           // Step 2: Scramble rows
        mix_columns(state);                                          // Step 3: Diffuse columns
        add_round_key(state, round_keys + round * 16);               // Step 4: Inject round key (offset by round number)
    }                                                                // Ends main loop; state proceeds to final round
    sub_bytes(state);                                                // Round 10: Final byte substitution
    shift_rows(state);                                               // Round 10: Final row scramble (skips MixColumns per AES spec)
    add_round_key(state, round_keys + 160);                          // Round 10: Final Key Injection (uses very last 16 bytes of round_keys)
    
    for (int r = 0; r < 4; r++)                                      // Loops rows
        for (int c = 0; c < 4; c++)                                  // Loops columns
            out[c * 4 + r] = state[r][c];                            // Unloads column-major state matrix back into linear 16-byte output array
}                                                                    // Ends block encryption; yields ciphertext

// --- DECRYPTION OPERATIONS --- // Core reverse transformations
static void inv_sub_bytes(uint8_t state[4][4]) {                     // Inverses the byte substitution; takes input from inv_shift_rows
    for (int r = 0; r < 4; r++)                                      // Loops rows
        for (int c = 0; c < 4; c++)                                  // Loops columns
            state[r][c] = rsbox[state[r][c]];                        // Replaces byte with Reverse S-box lookup; feeds state to add_round_key
}                                                                    // Ends inv_sub_bytes

static void inv_shift_rows(uint8_t state[4][4]) {                    // Cyclically shifts state rows right; takes input from main decrypt loop
    uint8_t t;                                                       // Temporary byte holder; supports swaps
    t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t; // Row 1: Shifts right by 1
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;                                                       // Row 2: Shifts right by 2 (identical to left by 2)
    t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;                                                       // Row 2: Finishes right by 2 swap
    t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t; // Row 3: Shifts right by 3 (left by 1)
}                                                                    // Ends inv_shift_rows; feeds state to inv_sub_bytes

static void inv_mix_columns(uint8_t state[4][4]) {                   // Mathematically undoes column diffusion; takes input from add_round_key
    for (int c = 0; c < 4; c++) {                                    // Loops over the 4 columns individually
        uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c]; // Reads current column bytes
        state[0][c] = multiply(a0, 0x0e) ^ multiply(a1, 0x0b) ^ multiply(a2, 0x0d) ^ multiply(a3, 0x09); // Undoes Row 0 math using inverse polynomials
        state[1][c] = multiply(a0, 0x09) ^ multiply(a1, 0x0e) ^ multiply(a2, 0x0b) ^ multiply(a3, 0x0d); // Undoes Row 1 math
        state[2][c] = multiply(a0, 0x0d) ^ multiply(a1, 0x09) ^ multiply(a2, 0x0e) ^ multiply(a3, 0x0b); // Undoes Row 2 math
        state[3][c] = multiply(a0, 0x0b) ^ multiply(a1, 0x0d) ^ multiply(a2, 0x09) ^ multiply(a3, 0x0e); // Undoes Row 3 math
    }                                                                // Ends column loop
}                                                                    // Ends inv_mix_columns; feeds state to next round's inv_shift_rows

static void aes_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *round_keys) { // Orchestrates 10 decryption rounds; takes ciphertext
    uint8_t state[4][4];                                             // Allocates 4x4 working state matrix
    for (int r = 0; r < 4; r++)                                      // Loops rows
        for (int c = 0; c < 4; c++)                                  // Loops columns
            state[r][c] = in[c * 4 + r];                             // Loads linear 16-byte input (ciphertext) into state matrix
    
    add_round_key(state, round_keys + 160);                          // Round 10 (Start): Inject very last key segment first
    for (int round = 9; round >= 1; round--) {                       // Rounds 9 down to 1: Main reverse processing loop
        inv_shift_rows(state);                                       // Step 1 (Reverse): Unscramble rows
        inv_sub_bytes(state);                                        // Step 2 (Reverse): Un-substitute bytes
        add_round_key(state, round_keys + round * 16);               // Step 3 (Reverse): Inject corresponding round key (going backwards)
        inv_mix_columns(state);                                      // Step 4 (Reverse): Undo column diffusion
    }                                                                // Ends main reverse loop; state proceeds to Round 0
    inv_shift_rows(state);                                           // Round 0: Final unscramble of rows
    inv_sub_bytes(state);                                            // Round 0: Final un-substitution of bytes
    add_round_key(state, round_keys);                                // Round 0: Inject very first master key segment to yield plaintext
    
    for (int r = 0; r < 4; r++)                                      // Loops rows
        for (int c = 0; c < 4; c++)                                  // Loops columns
            out[c * 4 + r] = state[r][c];                            // Unloads restored state matrix back into linear 16-byte output array
}                                                                    // Ends block decryption; yields plaintext

// --- MAIN EXECUTION --- // Entry point; ties all functions together
int main(void) {                                                     // Starts program execution
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // Defines standard 128-bit test key; feeds key_expansion
    uint8_t round_keys[176];                                         // Allocates memory for 11 keys (16 bytes each); destination for key_expansion
    key_expansion(key, round_keys);                                  // Expands master key; provides necessary schedule for encrypt/decrypt

    uint8_t input[16] = "Hello Windows! ";                           // Defines exactly 16 bytes of plaintext (15 chars + null terminator); feeds encryption
    uint8_t encrypted[16];                                           // Allocates buffer for cipher output; destination for aes_encrypt_block
    uint8_t decrypted[16];                                           // Allocates buffer for recovered text; destination for aes_decrypt_block

    printf("--- Standalone AES-128 ---\n\n");                        // Prints header to console; formats user UI
    printf("Original Text  : %s\n", input);                          // Prints plaintext to console; provides visual baseline for success

    uint64_t start_enc = get_ticks();                                // Reads CPU clock; begins encryption speed benchmark
    aes_encrypt_block(input, encrypted, round_keys);                 // Encrypts plaintext using expanded keys; yields ciphertext in 'encrypted' buffer
    uint64_t end_enc = get_ticks();                                  // Reads CPU clock; concludes encryption speed benchmark
    
    printf("Ciphertext (Hex): ");                                    // Prints label for cipher output; prepares console for hex loop
    for (int i = 0; i < 16; i++) printf("%02x", encrypted[i]);       // Loops over encrypted buffer; formats and prints each byte as hex string
    printf("\n");                                                    // Prints newline; separates cipher from decryption phase

    uint64_t start_dec = get_ticks();                                // Reads CPU clock; begins decryption speed benchmark
    aes_decrypt_block(encrypted, decrypted, round_keys);             // Decrypts ciphertext using expanded keys; yields plaintext in 'decrypted' buffer
    uint64_t end_dec = get_ticks();                                  // Reads CPU clock; concludes decryption speed benchmark

    printf("Decrypted Text : %s\n\n", decrypted);                    // Prints successfully recovered text (relies on null terminator); confirms logic is sound

    printf("Encryption Ticks : %llu\n", (unsigned long long)(end_enc - start_enc)); // Calculates elapsed ticks; outputs encryption benchmark to user
    printf("Decryption Ticks : %llu\n", (unsigned long long)(end_dec - start_dec)); // Calculates elapsed ticks; outputs decryption benchmark to user

    return 0;                                                        // Signals successful execution to Windows OS; safely closes program
}                                                                    // Ends program
