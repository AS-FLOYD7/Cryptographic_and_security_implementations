#include <stdio.h>      // Standard library for formatted console I/O
#include <stdint.h>     // Standard library for fixed-width integer types
#include <stdlib.h>     // Standard library for general purpose utilities
#include <string.h>     // Standard library for memory manipulation operations

#ifdef _WIN32           // Check if we are compiling on a Windows OS
#include <intrin.h>     // Include MSVC intrinsics for CPU cycle counting (__rdtsc)
#else                   // If the OS is Linux or macOS
#include <x86intrin.h>  // Include x86 intrinsics for GCC/Clang (__rdtsc)
#endif                  // End OS architecture preprocessor check

// --- CRYSTALS-KYBER MATHEMATICAL PARAMETERS ---
#define KYBER_N 256     // The number of coefficients in a ring polynomial
#define KYBER_Q 3329    // The prime modulus Q used for all polynomial coefficients
#define KYBER_K 2       // The matrix dimension K for Kyber-512 (K=2)

// --- GLOBAL STATE VARIABLES ---
int16_t zetas[128];     // Array to hold 128 pre-calculated twiddle factors (roots of unity)
uint32_t s_rng[4] = { 123456789, 362436069, 521288629, 88675123 }; // Initial state for the Xoshiro128** PRNG

// --- UTILITY & PRNG FUNCTIONS ---
uint8_t bitrev7(uint8_t a) {        // Function to bit-reverse a 7-bit integer
    uint8_t r = 0;                  // Initialize the result byte to zero
    for (int i = 0; i < 7; i++) {   // Iterate through all 7 bits
        r |= ((a >> i) & 1) << (6 - i); // Shift the i-th bit to its mirror position (6-i) and OR it
    }                               // End bitwise loop
    return r;                       // Return the fully bit-reversed 7-bit integer
}                                   // End bit-reversal function

static inline uint32_t rotl(const uint32_t x, int k) { // Function to perform circular left bit rotation
    return (x << k) | (x >> (32 - k)); // Shift left by k bits OR shifted right by the remaining bits
}                                   // End circular rotation function

uint32_t prng32(void) {             // Generate a 32-bit random number (Xoshiro128** replacement for SHAKE)
    const uint32_t result = rotl(s_rng[1] * 5, 7) * 9; // Compute the output from current state
    const uint32_t t = s_rng[1] << 9; // Compute temporary state shift
    s_rng[2] ^= s_rng[0];             // Update PRNG state index 2 via XOR
    s_rng[3] ^= s_rng[1];             // Update PRNG state index 3 via XOR
    s_rng[1] ^= s_rng[2];             // Update PRNG state index 1 via XOR
    s_rng[0] ^= s_rng[3];             // Update PRNG state index 0 via XOR
    s_rng[2] ^= t;                    // Apply temporary shifted state back into index 2
    s_rng[3] = rotl(s_rng[3], 11);    // Rotate state index 3 to finalize update
    return result;                    // Return the highly uniform 32-bit pseudo-random result
}                                   // End PRNG iteration function

int prng_bit(void) {                // Function to extract a single random bit
    static uint32_t bits = 0;         // Static variable to store a pool of 32 generated bits
    static int count = 0;             // Static variable to track how many bits are left in the pool
    if(count == 0) {                  // If the pool is empty (no bits left)
        bits = prng32();              // Generate a brand new 32-bit pool
        count = 32;                   // Reset the available bit counter to 32
    }                                 // End empty check
    int bit = bits & 1;               // Extract the very last bit (Least Significant Bit)
    bits >>= 1;                       // Shift the pool to queue the next bit
    count--;                          // Decrement the available bits counter
    return bit;                       // Return the single extracted random bit
}                                   // End single-bit extraction function

// --- INITIALIZATION OPERATIONS ---
void init_zetas() {                 // Initialize twiddle factors for the Number Theoretic Transform
    int32_t zeta = 17;              // Kyber's primitive 256-th root of unity modulo 3329
    int32_t powers[128];            // Array to store consecutive powers of zeta
    powers[0] = 1;                  // Zeta to the power of 0 is mathematically 1
    for(int i = 1; i < 128; i++) {  // Loop to calculate all up to zeta^127
        powers[i] = (powers[i-1] * zeta) % KYBER_Q; // Multiply previous power by zeta and apply modulo Q
    }                               // End powers loop
    for(int i = 0; i < 128; i++) {  // Loop to convert powers into the array format required by Kyber
        int32_t m = (powers[bitrev7(i)] * 2285) % KYBER_Q; // Fetch bit-reversed index and convert to Montgomery domain
        if (m > KYBER_Q / 2) {      // If the resulting integer is in the upper half of modulus Q
            m -= KYBER_Q;           // Subtract Q to center the integer in the (-Q/2, Q/2) range
        }                           // End bounds check
        zetas[i] = (int16_t)m;      // Store the bounded Montgomery twiddle factor into the global array
    }                               // End array formatting loop
}                                   // End twiddle factor initialization

// --- MODULAR ARITHMETIC PRIMITIVES ---
int16_t montgomery_reduce(int32_t a) { // Optimize modular reduction using the Montgomery mechanism
    int16_t u = (int16_t)(a * 62209);  // Multiply the lower 16 bits by Q^-1 mod 2^16 to find the remainder
    int32_t t = (int32_t)u * KYBER_Q;  // Multiply the remainder by the prime Q to get a multiple
    t = a - t;                         // Subtract the exact multiple from the original input
    t >>= 16;                          // Bitwise shift right by 16 to essentially divide by 2^16
    return (int16_t)t;                 // Cast to a 16-bit signed integer and return the reduced value
}                                      // End Montgomery reduction function

int16_t barrett_reduce(int16_t a) {    // Optimize modular reduction using the Barrett approximation technique
    int16_t t;                         // Variable to hold the calculated quotient estimate
    const int16_t v = 20159;           // Constant v = floor((2^26 + Q/2) / Q), precomputed for 3329
    int32_t shift_val = (int32_t)v * a + (1 << 25); // Multiply input by v and add rounding bias (2^25)
    t = (int16_t)(shift_val >> 26);    // Arithmetic shift right by 26 to divide and isolate quotient
    t *= KYBER_Q;                      // Multiply quotient by Q to get nearest multiple of Q
    return a - t;                      // Subtract the multiple from the original input to get the remainder
}                                      // End Barrett reduction function

int16_t fqmul(int16_t a, int16_t b) {  // Execute finite field multiplication in the Montgomery domain
    return montgomery_reduce((int32_t)a * b); // Multiply elements and apply Montgomery reduction back to range
}                                      // End finite field multiplication function

// --- NTT & INVERSE NTT OPERATIONS ---
void ntt(int16_t r[256]) {             // Function to compute the in-place Number Theoretic Transform
    unsigned int len, start, j, k;     // Declare indexing variables and iterators
    int16_t t, zeta;                   // Declare a temporary mathematical variable and twiddle factor
    k = 1;                             // Initialize the twiddle factor lookup counter to 1
    for(len = 128; len >= 2; len >>= 1) { // Iterate over tree layers, halving the sequence length each time
        for(start = 0; start < 256; start = j + len) { // Iterate over each block within the current layer
            zeta = zetas[k++];         // Fetch the corresponding twiddle factor for this specific block
            for(j = start; j < start + len; j++) { // Butterfly operation over the block's elements
                t = fqmul(zeta, r[j + len]); // Multiply the element in the upper half by the twiddle factor
                r[j + len] = r[j] - t; // Set new upper element by subtracting product from the lower element
                r[j] = r[j] + t;       // Set new lower element by adding product to the lower element
            }                          // End butterfly loop
        }                              // End block loop
    }                                  // End layer loop
}                                      // End NTT function

void invntt(int16_t r[256]) {          // Function to compute the in-place Inverse Number Theoretic Transform
    unsigned int start, len, j, k;     // Declare indexing variables and iterators
    int16_t t, zeta;                   // Declare a temporary mathematical variable and twiddle factor
    const int16_t f = 1441;            // Precomputed scaling factor (Montgomery square / 128) mod Q
    k = 127;                           // Initialize the twiddle factor lookup counter to its maximum
    for(len = 2; len <= 128; len <<= 1) { // Iterate backwards over tree layers, doubling sequence length
        for(start = 0; start < 256; start = j + len) { // Iterate over each block within the current layer
            zeta = zetas[k--];         // Fetch the twiddle factor in reverse lookup order (yields negative inverse)
            for(j = start; j < start + len; j++) { // Inverse butterfly operation over the block
                t = r[j];              // Temporarily save the current lower half element
                r[j] = barrett_reduce(t + r[j + len]); // Combine lower and upper, reduce, and store in lower
                
                // CRITICAL FIX: The backward traversal of the zetas array inherently produces the 
                // mathematical NEGATIVE inverse (-zeta^-1). To correct this, we must subtract in reverse 
                // order (B - A) so the negatives algebraically cancel out to produce the true inverted component.
                r[j + len] = r[j + len] - t; // Subtract original lower element from original upper element
                
                r[j + len] = fqmul(zeta, r[j + len]); // Multiply the resulting upper difference by the twiddle factor
            }                          // End inverse butterfly loop
        }                              // End block loop
    }                                  // End layer loop
    for(j = 0; j < 256; j++) {         // Final scaling phase for the inverse transform
        r[j] = fqmul(r[j], f);         // Multiply each resulting coefficient by the constant scaling factor f
    }                                  // End coefficient scaling loop
}                                      // End Inverse NTT function

// --- POLYNOMIAL MULTIPLICATION ---
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) { // Base polynomial cross-multiplication
    r[0] = fqmul(a[1], b[1]);          // Step 1: Multiply the high coefficients of a and b
    r[0] = fqmul(r[0], zeta);          // Step 2: Multiply the result by zeta to apply the modular wrap modulo (X^2 - zeta)
    r[0] += fqmul(a[0], b[0]);         // Step 3: Add the product of the low coefficients to finalize the resulting low
    r[1] = fqmul(a[0], b[1]);          // Step 4: Cross-multiply the low coefficient of a with the high of b
    r[1] += fqmul(a[1], b[0]);         // Step 5: Add the cross-product of a's high and b's low to finalize the resulting high
}                                      // End base multiplication function

void poly_basemul_montgomery(int16_t r[256], const int16_t a[256], const int16_t b[256]) { // Full NTT base multiplication
    for(int i = 0; i < 64; i++) {      // Loop 64 times, processing a cluster of 4 polynomial coefficients per pass
        basemul(&r[4*i], &a[4*i], &b[4*i], zetas[64 + i]); // Base-multiply the first sub-pair using a positive twiddle factor
        basemul(&r[4*i + 2], &a[4*i + 2], &b[4*i + 2], -zetas[64 + i]); // Base-multiply the second sub-pair using negative twiddle
    }                                  // End block clustering loop
}                                      // End full polynomial multiplication function

// --- POLYNOMIAL ALGEBRA & NOISE GENERATION ---
void poly_add(int16_t r[256], const int16_t a[256], const int16_t b[256]) { // Add two polynomials natively
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = a[i] + b[i];            // Compute and store the exact coefficient addition
    }                                  // End vector iteration
}                                      // End addition function

void poly_sub(int16_t r[256], const int16_t a[256], const int16_t b[256]) { // Subtract two polynomials natively
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = a[i] - b[i];            // Compute and store the exact coefficient subtraction
    }                                  // End vector iteration
}                                      // End subtraction function

void poly_reduce(int16_t r[256]) {     // Vector wrapper to apply Barrett reduction to the whole polynomial
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = barrett_reduce(r[i]);   // Apply Barrett algorithm bounds to the specific coefficient
    }                                  // End vector iteration
}                                      // End vector reduction function

void poly_tomont(int16_t r[256]) {     // Convert polynomial to Montgomery domain by multiplying by constant R
    const int16_t f = 1353;            // Constant denoting R^2 mod Q, used mathematically as the conversion factor
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = montgomery_reduce((int32_t)r[i] * f); // Scale the raw coefficient directly into the Montgomery domain
    }                                  // End vector iteration
}                                      // End domain conversion function

void poly_getnoise_eta3(int16_t r[256]) { // Sample a small-noise polynomial from Centered Binomial Distribution (eta=3)
    for(int i = 0; i < 256; i++) {     // Loop to generate all 256 noisy coefficients
        int a = 0, b = 0;              // Initialize accumulators for the coin tosses
        for(int j = 0; j < 3; j++) {   // Run exactly 3 coin tosses (eta = 3)
            a += prng_bit();           // Accumulate positive statistical mass
            b += prng_bit();           // Accumulate negative statistical mass
        }                              // End coin toss phase
        r[i] = a - b;                  // The noise coefficient is the algebraic difference yielding [-3, 3] distribution
    }                                  // End noise generation loop
}                                      // End eta-3 sampling function

void poly_getnoise_eta2(int16_t r[256]) { // Sample a tighter small-noise polynomial from CBD (eta=2)
    for(int i = 0; i < 256; i++) {     // Loop to generate all 256 noisy coefficients
        int a = 0, b = 0;              // Initialize accumulators for the coin tosses
        for(int j = 0; j < 2; j++) {   // Run exactly 2 coin tosses (eta = 2)
            a += prng_bit();           // Accumulate positive statistical mass
            b += prng_bit();           // Accumulate negative statistical mass
        }                              // End coin toss phase
        r[i] = a - b;                  // The noise coefficient is the algebraic difference yielding [-2, 2] distribution
    }                                  // End noise generation loop
}                                      // End eta-2 sampling function

// --- COMPRESSION AND MESSAGE ENCODING ---
void compress_poly(uint16_t *out, const int16_t *in, int d) { // Lossy compression of a polynomial into 'd' bits
    for(int i = 0; i < 256; i++) {     // Iterate over every coefficient
        int32_t val = in[i];           // Extract the coefficient as a 32-bit integer
        if (val < 0) { val += KYBER_Q; } // If the value is negative from reduction, offset by Q to make it strictly positive
        uint32_t c = (((uint32_t)val << d) + KYBER_Q / 2) / KYBER_Q; // Execute mathematically perfect proportional scaling to 2^d
        out[i] = c & ((1 << d) - 1);   // Apply a bitmask exactly equal to 'd' bits to ensure bounds and assign to output
    }                                  // End compression iteration
}                                      // End compression function

void decompress_poly(int16_t *out, const uint16_t *in, int d) { // Decompression of a 'd' bit polynomial back to modulo Q
    for(int i = 0; i < 256; i++) {     // Iterate over every compressed coefficient
        uint32_t val = in[i];          // Extract the lossy 'd' bit segment
        uint32_t c = (val * KYBER_Q + (1 << (d - 1))) >> d; // Proportionally expand it back towards modulo Q bounds
        out[i] = (int16_t)c;           // Cast the mathematically expanded output back to signed 16-bit
    }                                  // End decompression iteration
}                                      // End decompression function

void poly_frommsg(int16_t r[256], const uint8_t msg[32]) { // Encode a raw 32-byte message into a high-error-resistant polynomial
    for(int i = 0; i < 32; i++) {      // Iterate over the 32 message bytes
        for(int j = 0; j < 8; j++) {   // Iterate over the 8 bits inside each byte
            int16_t bit = (msg[i] >> j) & 1; // Extract the specific underlying bit
            r[8*i + j] = bit ? ((KYBER_Q + 1) / 2) : 0; // Encode a 1-bit as exactly Q/2 to resist LWE algebraic error noise
        }                              // End bit manipulation
    }                                  // End byte manipulation
}                                      // End message encoder function

void poly_tomsg(uint8_t msg[32], const int16_t r[256]) { // Decode a noisy polynomial directly back to a raw 32-byte message
    for(int i = 0; i < 32; i++) {      // Iterate precisely over the 32 designated bytes
        msg[i] = 0;                    // Explicitly initialize the current byte's buffer to zero
        for(int j = 0; j < 8; j++) {   // Iterate through all 8 individual polynomial components comprising the byte
            int32_t val = r[8*i + j];  // Extract the raw coefficient
            if (val < 0) { val += KYBER_Q; } // Mathematically align negative residues inside the positive boundary
            int16_t t = (((val << 1) + KYBER_Q / 2) / KYBER_Q) & 1; // Round towards binary integer extremes to destroy LWE noise
            msg[i] |= (t << j);        // Inject the securely extracted pristine bit back into its correct location
        }                              // End bit deduction
    }                                  // End byte deduction
}                                      // End message decoder function

// --- GLOBAL KEY STORAGES (For standalone simulation clarity) ---
int16_t pk_A[KYBER_K][KYBER_K][KYBER_N]; // Natively stored structured Public Key Matrix A (already uniformly distributed in NTT domain)
int16_t pk_t[KYBER_K][KYBER_N];          // Native Public Key Vector 't', generated mathematically
int16_t sk_s[KYBER_K][KYBER_N];          // Extremely guarded Secret Key Vector 's', kept in the NTT domain

// --- KYBER PKE OPERATIONS ---
void Kyber_PKE_KeyGen() {                // Generate mathematically correlated IND-CPA Public and Secret Keys
    for(int i = 0; i < KYBER_K; i++) {   // Iterate over the Matrix row dimensions
        for(int j = 0; j < KYBER_K; j++) { // Iterate over the Matrix column dimensions
            for(int x = 0; x < KYBER_N; x++) { // Iterate over every coefficient space within the Matrix node
                uint32_t val;            // Variable to capture PRNG output
                do {                     // Begin strict Rejection Sampling loop
                    val = prng32() & 0x1FFF; // Generate a random sequence up to 13-bits maximum
                } while(val >= KYBER_Q); // Aggressively reject any number outside the Prime Q limits
                pk_A[i][j][x] = val;     // Matrix A is successfully assigned a uniformly random number
            }                            // End coefficient assignment loop
        }                                // End column loop
    }                                    // End row loop

    int16_t e[KYBER_K][KYBER_N];         // Temporary buffer structure for generated Secret Error 'e'
    for(int i = 0; i < KYBER_K; i++) {   // Iterate over vector columns
        poly_getnoise_eta3(sk_s[i]);     // Sample the fundamental secret polynomial via binomial distribution
        poly_getnoise_eta3(e[i]);        // Sample the secret error polynomial identically
    }                                    // End sampling generation loop

    for(int i = 0; i < KYBER_K; i++) {   // Iterate over vector columns
        ntt(sk_s[i]);                    // Swiftly transform Secret polynomial into the algebraic NTT domain
        ntt(e[i]);                       // Swiftly transform Error polynomial into the algebraic NTT domain
    }                                    // End domain transformation loop

    for(int i = 0; i < KYBER_K; i++) {   // Iterate linearly to compute Public Vector mathematically: t = A * s + e
        int16_t temp[KYBER_N];           // Internal calculation buffer required for inner products
        poly_basemul_montgomery(pk_t[i], pk_A[i][0], sk_s[0]); // Conduct initial base multiplication array pass
        for(int j = 1; j < KYBER_K; j++) { // Iterate horizontally across matrix vectors
            poly_basemul_montgomery(temp, pk_A[i][j], sk_s[j]); // Perform subsequent baseline multiplications
            poly_add(pk_t[i], pk_t[i], temp); // Perform a polynomial addition of the resulting factors
        }                                // End algebraic vector inner product iteration
        poly_tomont(pk_t[i]);            // Translate result from R^-1 offset back to operational Montgomery status
        poly_add(pk_t[i], pk_t[i], e[i]);// Finally add the natively transformed error factor
        poly_reduce(pk_t[i]);            // Guarantee boundaries via a rapid Barrett reduction pass
    }                                    // End vector computation loop
}                                        // End PKE KeyGen process

// Transmit variables (Ciphertext structures)
uint16_t u_comp[KYBER_K][KYBER_N];       // The primary matrix-multiplied Ciphertext component 'u', compressed directly to 10 bits
uint16_t v_comp[KYBER_N];                // The secondary offset Ciphertext component 'v', aggressively compressed to 4 bits

void Kyber_PKE_Encrypt(const uint8_t msg[32]) { // Encrypt an embedded 32-byte physical payload safely via PKE
    int16_t r[KYBER_K][KYBER_N];         // Buffer dedicated solely to ephemeral encryption randomness polynomial
    int16_t e1[KYBER_K][KYBER_N];        // Buffer tracking structural error accumulation polynomial 'e1'
    int16_t e2[KYBER_N];                 // Buffer identifying subsequent error component 'e2'

    for(int i = 0; i < KYBER_K; i++) {   // Traverse sequence bounds
        poly_getnoise_eta3(r[i]);        // Build random binomial sequence using eta3 variance logic
        poly_getnoise_eta2(e1[i]);       // Generate secondary structural noise tightly bounding limits via eta2
    }                                    // End vector generator loop
    poly_getnoise_eta2(e2);              // Supply solitary error variance needed strictly for trailing calculation

    for(int i = 0; i < KYBER_K; i++) {   // Traverse sequentially
        ntt(r[i]);                       // Transpose operational random element dynamically to NTT scope
    }                                    // End generator transformation process

    int16_t u[KYBER_K][KYBER_N];         // Internal calculation buffer to isolate part one of target Ciphertext
    for(int i = 0; i < KYBER_K; i++) {   // Initiate core routine to mathematically solve: u = InvNTT(A^T * r) + e1
        int16_t temp[KYBER_N];           // Required intermediary tracking variable for additions
        poly_basemul_montgomery(u[i], pk_A[0][i], r[0]); // Begin initial transposed matrix multiplication element operation
        for(int j = 1; j < KYBER_K; j++) { // Walk sequence against inner limits
            poly_basemul_montgomery(temp, pk_A[j][i], r[j]); // Perform consecutive sequence transposed operations
            poly_add(u[i], u[i], temp);  // Logically sum operations natively
        }                                // End algebraic inner transposition loop
        invntt(u[i]);                    // Rapidly collapse the transformed domain back naturally to standard form
        poly_add(u[i], u[i], e1[i]);     // Factor in the previously established error polynomial e1
        poly_reduce(u[i]);               // Restrict values safely behind limits utilizing Barrett optimization
        compress_poly(u_comp[i], u[i], 10); // Dynamically apply severe precision reduction simulating actual 10-bit packet storage
    }                                    // End generation loop for Ciphertext U

    int16_t v[KYBER_N];                  // Internal calculation buffer to isolate part two of target Ciphertext
    int16_t temp2[KYBER_N];              // Secondary calculation placeholder for V sequence logic
    poly_basemul_montgomery(v, pk_t[0], r[0]); // Initiate calculation matching public parameter T directly with R
    for(int j = 1; j < KYBER_K; j++) {   // Advance pointer
        poly_basemul_montgomery(temp2, pk_t[j], r[j]); // Execute matching inner baseline functions
        poly_add(v, v, temp2);           // Progressively combine baseline computations sequentially
    }                                    // End baseline summation
    invntt(v);                           // Perform final inverse calculation collapsing domain explicitly

    poly_add(v, v, e2);                  // Interject terminal error logic into matrix stream mathematically

    int16_t m_poly[KYBER_N];             // Standalone allocation structure designed for message assimilation
    poly_frommsg(m_poly, msg);           // Invoke algebraic expansion allocating individual bits squarely into Q/2 peaks
    poly_add(v, v, m_poly);              // Superimpose mathematical signal directly atop noise and structure boundaries
    poly_reduce(v);                      // Lock sequence bounds definitively to modulus Q parameters
    compress_poly(v_comp, v, 4);         // Severely strip mathematical detail retaining bare minimum 4 bits of precision tracking
}                                        // End PKE Encryption process

void Kyber_PKE_Decrypt(uint8_t msg_out[32]) { // Algorithmically unseal previously encrypted structural payload
    int16_t u[KYBER_K][KYBER_N];         // Recover calculation sequence buffer to capture unpacked elements
    int16_t v[KYBER_N];                  // Secondary sequence structure to maintain decoupled variables

    for(int i = 0; i < KYBER_K; i++) {   // Iterate cleanly over sequences
        decompress_poly(u[i], u_comp[i], 10); // Predictably inflate precision structures attempting to reform modulus
        ntt(u[i]);                       // Accelerate the recovered baseline into calculation NTT domain instantly
    }                                    // End structure reconstruction bounds
    decompress_poly(v, v_comp, 4);       // Perform critical decompression heavily rounding component V toward logical modulo Q

    int16_t w[KYBER_N];                  // Target isolated component buffering final stage logical subtraction
    int16_t temp3[KYBER_N];              // Standard calculation intermediary
    poly_basemul_montgomery(w, sk_s[0], u[0]); // Core decryption process multiplying secret structure implicitly
    for(int j = 1; j < KYBER_K; j++) {   // Advance sequentially
        poly_basemul_montgomery(temp3, sk_s[j], u[j]); // Expand core logic horizontally across variables
        poly_add(w, w, temp3);           // Amalgamate outcomes reliably
    }                                    // End algebraic multiplication stream
    invntt(w);                           // Break domain formatting transforming logically aligned outputs natively

    int16_t m_out_poly[KYBER_N];         // Prepare finalized mathematical vector isolation component
    poly_sub(m_out_poly, v, w);          // Subjugate structure v mathematically against structured outcome w resulting in M+Noise
    poly_reduce(m_out_poly);             // Ensure absolute bounds limit adherence avoiding standard arithmetic overflow scenarios

    poly_tomsg(msg_out, m_out_poly);     // Resolve and scrape structural layout cleanly producing perfect binary message string
}                                        // End PKE Decryption process

// --- BENCHMARKING SYSTEM ---
uint64_t get_cycles() {                  // Read system-level High Precision hardware clock timestamp counter
#ifdef _WIN32                            // Preprocessor verify windows logic
    return __rdtsc();                    // Trigger native underlying CPU read directive for cycles
#else                                    // Ensure fallback
    return __rdtsc();                    // Trigger comparable external compiler native read mechanism
#endif                                   // Conclude compilation logic
}                                        // End cycle reading function

void print_hex(const char* label, const uint8_t* data, size_t len) { // Dedicated visual byte output formatting logic
    printf("%-15s: ", label);            // Neatly pad spacing for textual strings ensuring uniform column display
    for(size_t i = 0; i < len; i++) {    // Traverse payload boundaries sequentially
        printf("%02X", data[i]);         // Dump underlying binary explicitly to strict 2-character hex architecture
    }                                    // End dump processing
    printf("\n");                        // Terminate line cleanly for subsequent processing logs
}                                        // End visual alignment processing

int main() {                             // Primary operational controller initiating program stream execution
    printf("========================================================\n"); // Print bold structural formatting header top
    printf("     Kyber-512 PKE Implementation in C using NTT        \n"); // Display precise descriptive title structure clearly
    printf("========================================================\n\n"); // Print bold structural formatting header bottom

    init_zetas();                        // Calculate natively generated precalculated roots of unity mathematically early

    uint8_t original_msg[32] = {0};      // Instantiate explicitly zeroed source message staging buffer
    uint8_t decrypted_msg[32] = {0};     // Instantiate explicitly zeroed destination message return staging buffer

    for(int i = 0; i < 32; i++) {        // Build out sequence iterations defining exactly 256 bits inherently
        original_msg[i] = (uint8_t)(prng32() & 0xFF); // Load uniformly randomized mathematical elements into strict underlying binary block
    }                                    // Resolve block structure build

    printf("[*] Starting Kyber Operations...\n\n"); // Emit process stage initialization message indicating execution activity

    // Warm-up to guarantee exact hardware cache alignments
    Kyber_PKE_KeyGen();                  // Complete preliminary test execution strictly forcing sequence memory loading
    Kyber_PKE_Encrypt(original_msg);     // Complete preliminary load execution testing processing branches intrinsically
    Kyber_PKE_Decrypt(decrypted_msg);    // Subjugate testing components avoiding lazy branch evaluations

    // Configuration constraints
    uint64_t start, end;                 // Define high level variables recording tracking outcomes
    int RUNS = 1000;                     // Prescribe a robust operational benchmarking sequence loop boundary limit natively

    start = get_cycles();                // Initiate precise internal tracking recording starting stamp definitively
    for(int i = 0; i < RUNS; i++) {      // Loop continuously maintaining strictly rigid constraints
        Kyber_PKE_KeyGen();              // Enforce PKE primary baseline component generation strictly
    }                                    // Exit execution constraint logic
    end = get_cycles();                  // Terminate block effectively sealing cycle metric values instantly
    uint64_t cycles_keygen = (end - start) / RUNS; // Normalize outcome logically deriving average timing cost fundamentally

    start = get_cycles();                // Initiate tracking specifically isolating target bounds precisely
    for(int i = 0; i < RUNS; i++) {      // Traverse explicitly through exact configuration limits repeatedly
        Kyber_PKE_Encrypt(original_msg); // Fire component logic generating complex structural output consistently
    }                                    // Ensure full conclusion operation iteration sequence gracefully
    end = get_cycles();                  // Register resulting counter natively extracting precision time metrics
    uint64_t cycles_encrypt = (end - start) / RUNS; // Extract median scale calculating accurate execution impact fundamentally

    start = get_cycles();                // Reset monitoring variable preparing clean operational metrics reliably
    for(int i = 0; i < RUNS; i++) {      // Propagate execution loop repeatedly demanding steady state logic execution
        Kyber_PKE_Decrypt(decrypted_msg);// Call logic natively converting structural math cleanly back to primitive states
    }                                    // Halt cyclic progression smoothly
    end = get_cycles();                  // Finalize marker establishing endpoint constraint exactly
    uint64_t cycles_decrypt = (end - start) / RUNS; // Reduce bulk tracking into easily evaluated baseline averages 

    int16_t dummy_poly[256] = {0};       // Declare synthetic isolated structural array eliminating overhead latency
    start = get_cycles();                // Register primary NTT bounds evaluating primitive algebra operations logically
    for(int i = 0; i < RUNS; i++) {      // Enter rapid iteration state natively running highly constrained limits
        ntt(dummy_poly);                 // Exploit fundamental in-place limits proving operational calculation cost definitively
    }                                    // Conclude loop execution effectively
    end = get_cycles();                  // Stop metrics safely acquiring strict timeline difference measurements
    uint64_t cycles_ntt = (end - start) / RUNS; // Assess timing metrics cleanly yielding single primitive baseline calculation

    start = get_cycles();                // Instantiate tracking specific strictly targeting reverse algorithmic calculations natively
    for(int i = 0; i < RUNS; i++) {      // Revert into isolated execution boundaries
        invntt(dummy_poly);              // Demand execution validating exact cost differences specifically identifying logical limits
    }                                    // Quit routine normally
    end = get_cycles();                  // Grab trailing index capturing bounds definitively
    uint64_t cycles_invntt = (end - start) / RUNS; // Evaluate outcomes rationally

    int success = 1;                     // Prime verification logic explicitly defaulting assumption positively intuitively
    for(int i = 0; i < 32; i++) {        // Sweep natively across 32 sequential byte thresholds completely
        if (original_msg[i] != decrypted_msg[i]) { // Scrutinize outputs logically proving decryption viability fundamentally
            success = 0;                 // Override baseline actively if mismatch condition strikes logic critically
            break;                       // Drop iteration completely discarding excessive verification overheads efficiently
        }                                // Conclude logical block natively
    }                                    // Wrap iteration logic

    printf("--- Output Validation ---\n"); // Print textual barrier
    print_hex("Original Msg", original_msg, 32); // Print pristine original parameters safely mapping outputs visually
    print_hex("Decrypted Msg", decrypted_msg, 32); // Correlate retrieved payload visually validating against previous logs essentially
    
    if(success) {                        // Process success flag logically evaluating positive condition
        printf("\n[+] SUCCESS! The decrypted message matches the original exactly.\n\n"); // Announce positive mathematically proven operational results dynamically
    } else {                             // Assume alternative failure condition logically handling edge-cases smoothly
        printf("\n[-] ERROR! Decryption failed to recover the message.\n\n"); // Print robust warning clearly emphasizing execution failure dynamically
    }                                    // Complete conditional output structures effectively

    printf("--- Performance Benchmark (Average CPU Cycles over %d runs) ---\n", RUNS); // Header introducing complex mathematical benchmarking averages explicitly
    printf(" | NTT Operation        : %10llu cycles |\n", cycles_ntt); // Map scalar primitive metrics distinctly reporting logical constraints natively
    printf(" | InvNTT Operation     : %10llu cycles |\n", cycles_invntt); // Emphasize inverse arithmetic calculations definitively reporting scalar boundaries
    printf(" | PKE Key Generation   : %10llu cycles |\n", cycles_keygen); // Output Key Generation scale clearly highlighting process depth visibly
    printf(" | PKE Encryption       : %10llu cycles |\n", cycles_encrypt); // Display fundamental Encryption operational timings inherently validating performance rationally
    printf(" | PKE Decryption       : %10llu cycles |\n", cycles_decrypt); // Ensure robust documentation displaying resulting decryption complexity reliably
    printf("--------------------------------------------------------------\n"); // Provide cleanly aligned layout border visually cementing overall architecture clearly

    return 0;                            // Resolve standard program flow accurately completing execution strictly within system expectations naturally
}                                        // Finish absolute code boundary reliably
