#include <stdio.h>      // Standard library for formatted console I/O
#include <stdint.h>     // Standard library for fixed-width integer types
#include <stdlib.h>     // Standard library for general purpose utilities
#include <string.h>     // Standard library for memory manipulation operations

#ifdef _WIN32           // Check if we are compiling on a Windows OS
#include <intrin.h>     // Include MSVC intrinsics for CPU cycle counting (__rdtsc)
#else                   // If the OS is Linux or macOS
#include <x86intrin.h>  // Include x86 intrinsics for GCC/Clang (__rdtsc)
#endif                  // End OS architecture preprocessor check

#define DILITHIUM_N 256                         // The number of coefficients in a ring polynomial
#define DILITHIUM_Q 8380417                     // The prime modulus Q = 2^23 - 2^13 + 1
#define DILITHIUM_K 4                           // The matrix row dimension K for Dilithium-2 (K=4)
#define DILITHIUM_L 4                           // The matrix column dimension L for Dilithium-2 (L=4)
#define DILITHIUM_ETA 2                         // Secret key noise bound [-2, 2]
#define DILITHIUM_TAU 39                        // Number of +/-1 coefficients in challenge polynomial c
#define DILITHIUM_BETA 78                       // Rejection threshold beta = TAU * ETA = 39 * 2 = 78
#define DILITHIUM_GAMMA1 (1 << 17)              // Masking vector y coefficient range bound (2^17 = 131072)
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1)/88) // Low-order rounding range ((Q - 1) / 88 = 95232)

int32_t zetas[256];     // Array to hold 256 pre-calculated 512-th roots of unity in Montgomery domain
uint32_t s_rng[4] = { 123456789, 362436069, 521288629, 88675123 }; // Initial state for the Xoshiro128** PRNG
int32_t pk_A[DILITHIUM_K][DILITHIUM_L][DILITHIUM_N]; // Public Matrix A stored directly in the NTT domain
int32_t pk_t[DILITHIUM_K][DILITHIUM_N];              // Public Key Vector t = A * s1 + s2
int32_t sk_s1_ntt[DILITHIUM_L][DILITHIUM_N];         // Secret Key Vector s1 stored in the NTT domain
int32_t sk_s2_ntt[DILITHIUM_K][DILITHIUM_N];         // Secret Key Vector s2 stored in the NTT domain
int32_t sig_z[DILITHIUM_L][DILITHIUM_N];             // Signature response vector z = y + c * s1
int32_t sig_c[DILITHIUM_N];                          // Signature challenge polynomial c
uint64_t total_rejections = 0;                       // Diagnostic counter tracking Fiat-Shamir rejections

uint8_t bitrev8(uint8_t a) {        // Function to bit-reverse an 8-bit integer for 256 NTT layers
    uint8_t r = 0;                  // Initialize the result byte to zero
    for (int i = 0; i < 8; i++) {   // Iterate through all 8 bits
        r |= ((a >> i) & 1) << (7 - i); // Shift the i-th bit to its mirror position (7-i) and OR it
    }                               // End bitwise loop
    return r;                       // Return the fully bit-reversed 8-bit integer
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

void init_zetas() {                 // Initialize twiddle factors for the 256-element Number Theoretic Transform
    int64_t zeta = 1753;            // Dilithium's primitive 512-th root of unity modulo 8380417
    int64_t powers[256];            // Array to store consecutive powers of zeta
    powers[0] = 1;                  // Zeta to the power of 0 is mathematically 1
    for(int i = 1; i < 256; i++) {  // Loop to calculate all powers up to zeta^255
        powers[i] = (powers[i-1] * zeta) % DILITHIUM_Q; // Multiply previous power by zeta modulo Q
    }                               // End powers loop
    for(int i = 0; i < 256; i++) {  // Loop to convert powers into bit-reversed Montgomery form (R = 2^32)
        int64_t m = (powers[bitrev8(i)] * 4193792LL) % DILITHIUM_Q; // Scale by 2^32 mod Q = 4193792
        if (m > DILITHIUM_Q / 2) {  // If the resulting integer is in the upper half of modulus Q
            m -= DILITHIUM_Q;       // Subtract Q to center the integer in the (-Q/2, Q/2) range
        }                           // End bounds check
        zetas[i] = (int32_t)m;      // Store the bounded 32-bit Montgomery twiddle factor into the global array
    }                               // End array formatting loop
}                                   // End twiddle factor initialization

int32_t montgomery_reduce(int64_t a) { // Optimize 64-bit modular reduction using the 32-bit Montgomery mechanism
    int32_t t = (int32_t)((uint64_t)a * 58728449ULL); // Multiply lower 32 bits by Q^-1 mod 2^32 (58728449)
    t = (int32_t)((a - (int64_t)t * DILITHIUM_Q) >> 32); // Subtract multiple of Q and arithmetic shift right by 32
    return t;                          // Return the reduced 32-bit signed integer in (-Q, Q)
}                                      // End Montgomery reduction function

int32_t reduce32(int32_t a) {          // Fast Barrett-style centered reduction modulo Q = 2^23 - 2^13 + 1
    int32_t t = (a + (1 << 22)) >> 23; // Estimate quotient by shifting right by 23 with rounding bias 2^22
    return a - t * DILITHIUM_Q;        // Subtract quotient multiple of Q to isolate centered remainder
}                                      // End fast 32-bit reduction function

int32_t caddq(int32_t a) {             // Conditionally add prime Q if coefficient is negative
    a += (a >> 31) & DILITHIUM_Q;      // Arithmetic shift right creates all-1s mask if negative, adding Q
    return a;                          // Return positive representative in [0, Q)
}                                      // End conditional addition function

int32_t freeze(int32_t a) {            // Full canonical reduction to standard range [0, Q-1]
    a = reduce32(a);                   // First compress into (-Q, Q) via fast shift reduction
    a = caddq(a);                      // Map negative values cleanly into positive [0, Q-1] range
    return a;                          // Return canonical positive residue
}                                      // End canonical freeze function

int32_t fqmul(int32_t a, int32_t b) {  // Execute finite field multiplication in the 32-bit Montgomery domain
    return montgomery_reduce((int64_t)a * b); // Multiply 32-bit operands into 64-bit product and Montgomery reduce
}                                      // End finite field multiplication function

void ntt(int32_t r[256]) {             // Function to compute the complete 8-layer in-place Number Theoretic Transform
    unsigned int len, start, j, k;     // Declare indexing variables and iterators
    int32_t t, zeta;                   // Declare temporary butterfly variable and twiddle factor
    k = 0;                             // Initialize the twiddle factor lookup counter to 0 (k++ starts at 1)
    for(len = 128; len >= 1; len >>= 1) { // Iterate over all 8 tree layers, halving length down to 1
        for(start = 0; start < 256; start = j + len) { // Iterate over each independent block in the layer
            zeta = zetas[++k];         // Fetch the corresponding 512-th root twiddle factor
            for(j = start; j < start + len; j++) { // Gentleman-Sande / Cooley-Tukey butterfly operation
                t = fqmul(zeta, r[j + len]); // Multiply the upper half element by the twiddle factor
                r[j + len] = r[j] - t; // Set new upper element by subtracting product from lower element
                r[j] = r[j] + t;       // Set new lower element by adding product to lower element
            }                          // End butterfly loop
        }                              // End block loop
    }                                  // End layer loop
}                                      // End NTT function

void invntt(int32_t r[256]) {          // Function to compute the complete 8-layer in-place Inverse NTT
    unsigned int start, len, j, k;     // Declare indexing variables and iterators
    int32_t t, zeta;                   // Declare temporary butterfly variable and twiddle factor
    const int32_t f = 41978;           // Precomputed scaling factor (2^64 / 256) mod Q = 41978
    k = 256;                           // Initialize twiddle factor counter to end of array
    for(len = 1; len < 256; len <<= 1) { // Iterate backwards over all 8 layers, doubling length from 1 to 128
        for(start = 0; start < 256; start = j + len) { // Iterate over each block within the current layer
            zeta = -zetas[--k];        // Fetch negated twiddle factor in reverse order (yields +zeta^-1)
            for(j = start; j < start + len; j++) { // Gentleman-Sande inverse butterfly operation
                t = r[j];              // Temporarily save the current lower half element
                r[j] = t + r[j + len]; // Combine lower and upper elements into the lower slot
                r[j + len] = t - r[j + len]; // Subtract upper from lower to pair with negated twiddle factor
                r[j + len] = fqmul(zeta, r[j + len]); // Multiply difference by inverted twiddle factor
            }                          // End inverse butterfly loop
        }                              // End block loop
    }                                  // End layer loop
    for(j = 0; j < 256; j++) {         // Final scaling phase to divide by N=256 and convert out of Montgomery
        r[j] = fqmul(r[j], f);         // Multiply each coefficient by f = 2^64 / 256 mod Q
    }                                  // End coefficient scaling loop
}                                      // End Inverse NTT function

void poly_pointwise_montgomery(int32_t r[256], const int32_t a[256], const int32_t b[256]) { // Pointwise NTT multiplication
    for(int i = 0; i < 256; i++) {     // Because X^256 + 1 splits into 256 linear factors in Z_8380417
        r[i] = fqmul(a[i], b[i]);      // Polynomial multiplication is pureed coordinate-wise multiplication
    }                                  // End pointwise loop
}                                      // End pointwise multiplication function

void poly_add(int32_t r[256], const int32_t a[256], const int32_t b[256]) { // Add two polynomials natively
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = a[i] + b[i];            // Compute and store the exact coefficient addition
    }                                  // End vector iteration
}                                      // End addition function

void poly_sub(int32_t r[256], const int32_t a[256], const int32_t b[256]) { // Subtract two polynomials natively
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = a[i] - b[i];            // Compute and store the exact coefficient subtraction
    }                                  // End vector iteration
}                                      // End subtraction function

void poly_reduce(int32_t r[256]) {     // Vector wrapper to apply centered reduction across a polynomial
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = reduce32(r[i]);         // Apply fast 32-bit reduction to each coefficient
    }                                  // End vector iteration
}                                      // End vector reduction function

void poly_freeze(int32_t r[256]) {     // Vector wrapper to canonically map coefficients to [0, Q-1]
    for(int i = 0; i < 256; i++) {     // Loop over all 256 indices
        r[i] = freeze(r[i]);           // Freeze each coefficient into [0, Q-1]
    }                                  // End vector iteration
}                                      // End vector freeze function

void poly_uniform_eta(int32_t r[256]) { // Sample secret polynomial with coefficients uniformly in [-ETA, ETA]
    for(int i = 0; i < 256; i++) {     // Loop to populate all 256 small secret coefficients
        uint32_t t;                    // Variable to hold candidate random nibble
        do {                           // Rejection sampling loop over 4-bit values [0, 15]
            t = prng32() & 0x0F;       // Extract 4 random bits
        } while(t >= 15);              // Reject 15 so t is uniform in [0, 14] (since 15 is 3 * 5)
        r[i] = (int32_t)DILITHIUM_ETA - (int32_t)(t % 5); // Map uniformly to [-2, 2]
    }                                  // End secret noise generation loop
}                                      // End uniform eta sampling function

void poly_uniform_gamma1(int32_t r[256]) { // Sample masking polynomial y in [-(GAMMA1 - 1), GAMMA1]
    for(int i = 0; i < 256; i++) {     // Loop over all 256 coefficients
        uint32_t t = prng32() & 0x3FFFF; // Extract 18 random bits in [0, 2*GAMMA1 - 1]
        r[i] = DILITHIUM_GAMMA1 - (int32_t)t; // Shift into [-(GAMMA1 - 1), GAMMA1]
    }                                  // End masking generation loop
}                                      // End gamma1 sampling function

void decompose(int32_t *r1, int32_t *r0, int32_t a) { // Split element a into HighBits r1 and LowBits r0 mod 2*GAMMA2
    int32_t a_pos = freeze(a);         // Ensure input coefficient is canonically in [0, Q-1]
    int32_t r1_val = (a_pos + 127) >> 7; // Divide by 128 as first step toward dividing by 2*GAMMA2 = 190464
    r1_val = (r1_val * 11275 + (1 << 23)) >> 24; // Multiply by reciprocal approximation of 1488 to get quotient
    r1_val ^= ((43 - r1_val) >> 31) & r1_val; // Handle corner case wrap-around when r1_val == 44 (since Q-1 = 44 * 2*GAMMA2)
    int32_t r0_val = a_pos - r1_val * 2 * DILITHIUM_GAMMA2; // Compute exact remainder r0 = a - r1 * (2*GAMMA2)
    r0_val -= (((DILITHIUM_Q - 1) / 2 - r0_val) >> 31) & DILITHIUM_Q; // Adjust r0 by -Q when wrapping around 0
    *r1 = r1_val;                      // Output HighBits r1 in [0, 43]
    *r0 = r0_val;                      // Output centered LowBits r0 in [-GAMMA2, GAMMA2]
}                                      // End decomposition function

void poly_decompose(int32_t r1[256], int32_t r0[256], const int32_t a[256]) { // Decompose an entire polynomial
    for(int i = 0; i < 256; i++) {     // Loop through all 256 coefficients
        decompose(&r1[i], &r0[i], a[i]); // Split each coefficient into HighBits and LowBits
    }                                  // End polynomial decomposition loop
}                                      // End polynomial decomposition wrapper

int poly_chknorm(const int32_t a[256], int32_t B) { // Check if infinity norm ||a||_inf >= B (returns 1 if rejected)
    for(int i = 0; i < 256; i++) {     // Inspect every coefficient in the polynomial
        int32_t t = a[i] >> 31;        // Create sign mask (0 if positive, -1 if negative)
        t = a[i] - (t & 2 * a[i]);     // Constant-time absolute value |a[i]|
        if (t >= B) {                  // If any coefficient reaches or exceeds bound B
            return 1;                  // Return 1 to trigger Fiat-Shamir rejection
        }                              // End bound comparison
    }                                  // End coefficient inspection loop
    return 0;                          // All coefficients strictly satisfy ||a||_inf < B
}                                      // End infinity norm check function

void challenge_poly(int32_t c[256], const uint8_t msg[32], const int32_t w1[DILITHIUM_K][DILITHIUM_N]) { // Fiat-Shamir Hash H(msg, w1)
    uint32_t hash_state[4] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A }; // Initialize deterministic sponge state
    for(int i = 0; i < 32; i++) {      // Absorb all 32 message bytes into the sponge state
        hash_state[i & 3] ^= ((uint32_t)msg[i] << ((i & 3) * 8)); // XOR message byte into state word
        hash_state[0] = rotl(hash_state[0] + hash_state[1], 7);   // Mix state words via ARX round
        hash_state[2] ^= hash_state[0];                           // Propagate diffusion across sponge
    }                                  // End message absorption loop
    for(int i = 0; i < DILITHIUM_K; i++) { // Absorb HighBits vector w1 into the sponge state
        for(int j = 0; j < DILITHIUM_N; j++) { // Iterate over every HighBits coefficient
            hash_state[(i + j) & 3] ^= (uint32_t)w1[i][j] + (uint32_t)(j << 8); // Mix w1[i][j] into sponge
            hash_state[1] = rotl(hash_state[1] + hash_state[2], 11); // Diffuse state word 1
            hash_state[3] = rotl(hash_state[3] ^ hash_state[1], 17); // Diffuse state word 3
        }                              // End coefficient absorption
    }                                  // End vector absorption

    for(int i = 0; i < 256; i++) {     // Initialize challenge polynomial c to all zeros
        c[i] = 0;                      // Zero out index i
    }                                  // End zero initialization
    for(int i = 256 - DILITHIUM_TAU; i < 256; i++) { // Fisher-Yates sample exactly TAU = 39 +/-1 positions
        uint32_t j;                    // Target index variable
        do {                           // Reject indices > i to ensure uniform permutation
            hash_state[0] = rotl(hash_state[0] * 5, 7) * 9 + 0x9E3779B9; // Squeeze next pseudo-random word
            hash_state[1] ^= hash_state[0]; // Update internal sponge state
            hash_state[2] = rotl(hash_state[2] + hash_state[1], 13); // Mix internal sponge state
            j = hash_state[2] & 0xFF;  // Extract candidate index in [0, 255]
        } while(j > (uint32_t)i);      // Repeat until j <= i
        c[i] = c[j];                   // Move existing value at index j to index i
        c[j] = (hash_state[0] & 1) ? 1 : -1; // Assign +1 or -1 to position j based on squeezed sign bit
    }                                  // End Fisher-Yates challenge sampling loop
}                                      // End challenge generation function

void Dilithium_KeyGen() {              // Generate ML-LWE / MSIS Public and Secret Keys for Dilithium-2
    for(int i = 0; i < DILITHIUM_K; i++) { // Iterate over Matrix A row dimensions
        for(int j = 0; j < DILITHIUM_L; j++) { // Iterate over Matrix A column dimensions
            for(int x = 0; x < DILITHIUM_N; x++) { // Iterate over all 256 polynomial coefficients
                uint32_t val;          // Variable to capture PRNG output
                do {                   // Begin strict 23-bit Rejection Sampling loop
                    val = prng32() & 0x7FFFFF; // Mask to 23 bits [0, 8388607]
                } while(val >= DILITHIUM_Q); // Reject values >= 8380417 to guarantee uniform distribution
                pk_A[i][j][x] = (int32_t)val; // Store uniform coefficient directly in NTT domain
            }                          // End coefficient loop
        }                              // End column loop
    }                                  // End row loop

    int32_t s2[DILITHIUM_K][DILITHIUM_N]; // Temporary buffer for standard-domain secret error s2
    for(int i = 0; i < DILITHIUM_L; i++) { // Sample L secret polynomials for vector s1
        poly_uniform_eta(sk_s1_ntt[i]); // Sample coefficients in [-2, 2]
        ntt(sk_s1_ntt[i]);             // Transform s1 into the NTT domain for fast signing
    }                                  // End s1 sampling loop
    for(int i = 0; i < DILITHIUM_K; i++) { // Sample K secret error polynomials for vector s2
        poly_uniform_eta(s2[i]);       // Sample coefficients in [-2, 2]
        memcpy(sk_s2_ntt[i], s2[i], sizeof(int32_t) * DILITHIUM_N); // Copy s2 before NTT transform
        ntt(sk_s2_ntt[i]);             // Transform s2 copy into NTT domain for fast signing
    }                                  // End s2 sampling loop

    for(int i = 0; i < DILITHIUM_K; i++) { // Compute public vector t = InvNTT(A * NTT(s1)) + s2
        int32_t temp[DILITHIUM_N];     // Temporary accumulator for matrix-vector inner product
        poly_pointwise_montgomery(pk_t[i], pk_A[i][0], sk_s1_ntt[0]); // Multiply first column of row i
        for(int j = 1; j < DILITHIUM_L; j++) { // Accumulate remaining columns of row i
            poly_pointwise_montgomery(temp, pk_A[i][j], sk_s1_ntt[j]); // Pointwise multiply A[i][j] * s1[j]
            poly_add(pk_t[i], pk_t[i], temp); // Add product into accumulator
        }                              // End row inner product loop
        invntt(pk_t[i]);               // Transform inner product back to standard polynomial domain and remove R^-1
        poly_add(pk_t[i], pk_t[i], s2[i]); // Add secret error vector s2[i]
        poly_freeze(pk_t[i]);          // Canonically reduce public key vector t into [0, Q-1]
    }                                  // End public vector t computation
}                                      // End Dilithium KeyGen process

int Dilithium_Sign(const uint8_t msg[32]) { // Sign a 32-byte message using Fiat-Shamir with Aborts
    int32_t y[DILITHIUM_L][DILITHIUM_N];    // Masking vector y in [-(GAMMA1-1), GAMMA1]
    int32_t y_ntt[DILITHIUM_L][DILITHIUM_N];// NTT representation of masking vector y
    int32_t w[DILITHIUM_K][DILITHIUM_N];    // Commitment vector w = A * y
    int32_t w1[DILITHIUM_K][DILITHIUM_N];   // HighBits of commitment w
    int32_t w0[DILITHIUM_K][DILITHIUM_N];   // LowBits of commitment w
    int32_t c_ntt[DILITHIUM_N];             // NTT representation of challenge polynomial c
    int attempts = 0;                       // Track number of Fiat-Shamir iterations for this signature

rej:                                   // Label for Fiat-Shamir rejection restart
    attempts++;                        // Increment attempt counter
    for(int i = 0; i < DILITHIUM_L; i++) { // Sample fresh masking vector y
        poly_uniform_gamma1(y[i]);     // Populate y[i] uniformly in [-(GAMMA1-1), GAMMA1]
        memcpy(y_ntt[i], y[i], sizeof(int32_t) * DILITHIUM_N); // Copy y[i] to NTT buffer
        ntt(y_ntt[i]);                 // Transform y_ntt[i] into NTT domain
    }                                  // End masking vector preparation

    for(int i = 0; i < DILITHIUM_K; i++) { // Compute commitment w = InvNTT(A * NTT(y))
        int32_t temp[DILITHIUM_N];     // Temporary polynomial for inner product accumulation
        poly_pointwise_montgomery(w[i], pk_A[i][0], y_ntt[0]); // Multiply first column
        for(int j = 1; j < DILITHIUM_L; j++) { // Accumulate remaining columns
            poly_pointwise_montgomery(temp, pk_A[i][j], y_ntt[j]); // Pointwise multiply in NTT domain
            poly_add(w[i], w[i], temp);// Add into commitment row
        }                              // End inner product loop
        invntt(w[i]);                  // Inverse NTT to return w[i] to standard representation
        poly_decompose(w1[i], w0[i], w[i]); // Split w[i] into HighBits w1[i] and LowBits w0[i]
    }                                  // End commitment decomposition loop

    challenge_poly(sig_c, msg, w1);    // Derive sparse challenge c = H(msg, w1) with 39 +/-1 entries
    memcpy(c_ntt, sig_c, sizeof(int32_t) * DILITHIUM_N); // Copy challenge c for NTT transformation
    ntt(c_ntt);                        // Transform challenge c into NTT domain

    for(int i = 0; i < DILITHIUM_L; i++) { // Compute signature response z = y + InvNTT(c_ntt * s1_ntt)
        poly_pointwise_montgomery(sig_z[i], c_ntt, sk_s1_ntt[i]); // Multiply c_ntt * s1_ntt[i] (scales by R^-1)
        invntt(sig_z[i]);              // Inverse NTT removes R^-1 because c_ntt was unscaled and f has R^2
        poly_add(sig_z[i], sig_z[i], y[i]); // Add masking polynomial y[i]
        poly_reduce(sig_z[i]);         // Reduce coefficients into centered interval
        if (poly_chknorm(sig_z[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA)) { // Security check: ||z||_inf < GAMMA1 - BETA
            total_rejections++;        // Record rejection event
            goto rej;                  // Abort and restart with fresh y to prevent secret key leakage!
        }                              // End z norm check
    }                                  // End response vector z computation

    for(int i = 0; i < DILITHIUM_K; i++) { // Check LowBits security condition: ||LowBits(w - c*s2)||_inf < GAMMA2 - BETA
        int32_t cs2[DILITHIUM_N], r1[DILITHIUM_N], r0[DILITHIUM_N]; // Buffers for c*s2 and decomposition
        poly_pointwise_montgomery(cs2, c_ntt, sk_s2_ntt[i]); // Compute c_ntt * s2_ntt[i] in NTT domain
        invntt(cs2);                   // Transform c * s2 back to standard polynomial domain
        poly_sub(r0, w[i], cs2);       // Compute w[i] - c * s2[i]
        poly_decompose(r1, r0, r0);    // Decompose w - c*s2 into HighBits r1 and LowBits r0
        if (poly_chknorm(r0, DILITHIUM_GAMMA2 - DILITHIUM_BETA)) { // Check if ||r0||_inf >= GAMMA2 - BETA
            total_rejections++;        // Record rejection event
            goto rej;                  // Abort and restart if carry boundary could fail
        }                              // End r0 norm check
        for(int j = 0; j < DILITHIUM_N; j++) { // Verify exact HighBits invariance: HighBits(w - c*s2) == w1
            if (r1[j] != w1[i][j]) {   // If HighBits shifted despite r0 bound
                total_rejections++;    // Record rejection event
                goto rej;              // Restart signing loop
            }                          // End HighBits check
        }                              // End coefficient loop
    }                                  // End LowBits verification loop
    return attempts;                   // Return number of attempts required to produce valid signature
}                                      // End Dilithium Sign process

int Dilithium_Verify(const uint8_t msg[32]) { // Verify a Dilithium signature (sig_z, sig_c) on msg
    for(int i = 0; i < DILITHIUM_L; i++) { // Step 1: Verify response vector z satisfies infinity norm bound
        if (poly_chknorm(sig_z[i], DILITHIUM_GAMMA1 - DILITHIUM_BETA)) { // Check ||z[i]||_inf < GAMMA1 - BETA
            return 0;                  // Reject immediately if z is out of bounds
        }                              // End norm check
    }                                  // End z bound verification loop

    int32_t z_ntt[DILITHIUM_L][DILITHIUM_N]; // Buffer for NTT(z)
    for(int i = 0; i < DILITHIUM_L; i++) { // Transform response vector z into NTT domain
        memcpy(z_ntt[i], sig_z[i], sizeof(int32_t) * DILITHIUM_N); // Copy sig_z[i]
        ntt(z_ntt[i]);                 // Execute forward NTT
    }                                  // End z NTT loop

    int32_t c_ntt[DILITHIUM_N];        // Buffer for NTT(c)
    memcpy(c_ntt, sig_c, sizeof(int32_t) * DILITHIUM_N); // Copy challenge polynomial sig_c
    ntt(c_ntt);                        // Transform challenge polynomial into NTT domain

    int32_t w1_prime[DILITHIUM_K][DILITHIUM_N]; // Reconstructed HighBits vector w1'
    int32_t w0_dummy[DILITHIUM_K][DILITHIUM_N]; // Dummy LowBits buffer
    for(int i = 0; i < DILITHIUM_K; i++) { // Reconstruct w' = InvNTT(A * NTT(z) - NTT(c) * NTT(t))
        int32_t az[DILITHIUM_N], temp[DILITHIUM_N], t_ntt[DILITHIUM_N], ct[DILITHIUM_N]; // Working polynomials
        poly_pointwise_montgomery(az, pk_A[i][0], z_ntt[0]); // Multiply first column A[i][0] * z_ntt[0]
        for(int j = 1; j < DILITHIUM_L; j++) { // Accumulate remaining columns
            poly_pointwise_montgomery(temp, pk_A[i][j], z_ntt[j]); // Pointwise multiply A[i][j] * z_ntt[j]
            poly_add(az, az, temp);    // Add into az accumulator
        }                              // End A * z inner product
        invntt(az);                    // Transform A * z back to standard representation

        memcpy(t_ntt, pk_t[i], sizeof(int32_t) * DILITHIUM_N); // Copy public key polynomial t[i]
        ntt(t_ntt);                    // Transform t[i] into NTT domain
        poly_pointwise_montgomery(ct, c_ntt, t_ntt); // Multiply c_ntt * t_ntt
        invntt(ct);                    // Transform c * t back to standard representation

        poly_sub(az, az, ct);          // Compute A*z - c*t = w - c*s2
        poly_decompose(w1_prime[i], w0_dummy[i], az); // Extract HighBits(A*z - c*t, 2*GAMMA2) = w1'
    }                                  // End w1' reconstruction loop

    int32_t c_prime[DILITHIUM_N];      // Recomputed challenge polynomial c'
    challenge_poly(c_prime, msg, w1_prime); // Recompute c' = H(msg, w1')
    for(int i = 0; i < DILITHIUM_N; i++) { // Compare recomputed challenge c' against signature challenge c
        if (c_prime[i] != sig_c[i]) {  // If any coefficient mismatches
            return 0;                  // Signature verification fails!
        }                              // End coefficient comparison
    }                                  // End challenge comparison loop
    return 1;                          // Signature is mathematically valid!
}                                      // End Dilithium Verify process

uint64_t get_cycles() {                // Read system-level High Precision hardware clock timestamp counter
#ifdef _WIN32                          // Preprocessor verify windows logic
    return __rdtsc();                  // Trigger native underlying CPU read directive for cycles
#else                                  // Ensure fallback
    return __rdtsc();                  // Trigger comparable external compiler native read mechanism
#endif                                 // Conclude compilation logic
}                                      // End cycle reading function

void print_hex(const char* label, const uint8_t* data, size_t len) { // Dedicated visual byte output formatting logic
    printf("%-18s: ", label);          // Neatly pad spacing for textual strings ensuring uniform column display
    for(size_t i = 0; i < len; i++) {  // Traverse payload boundaries sequentially
        printf("%02X", data[i]);       // Dump underlying binary explicitly to strict 2-character hex architecture
    }                                  // End dump processing
    printf("\n");                      // Terminate line cleanly for subsequent processing logs
}                                      // End visual alignment processing

int main() {                           // Primary operational controller initiating program stream execution
    printf("==============================================================\n"); // Print bold structural header top
    printf("   Dilithium-2 (ML-DSA-44) Implementation in C using NTT      \n"); // Display descriptive title clearly
    printf("==============================================================\n\n"); // Print bold structural header bottom

    init_zetas();                      // Precalculate 256 bit-reversed 512-th roots of unity in Montgomery form

    uint8_t message[32] = {0};         // Instantiate 32-byte message buffer to be signed
    for(int i = 0; i < 32; i++) {      // Populate message with pseudo-random bytes
        message[i] = (uint8_t)(prng32() & 0xFF); // Assign random byte from Xoshiro128** PRNG
    }                                  // End message initialization

    printf("[*] Starting Dilithium-2 Operations...\n\n"); // Emit process stage initialization message

    Dilithium_KeyGen();                // Warm up Key Generation pipeline
    Dilithium_Sign(message);           // Warm up Fiat-Shamir Signing pipeline
    int valid_initial = Dilithium_Verify(message); // Verify initial warm-up signature

    message[0] ^= 0x01;                // Flip Least Significant Bit of byte 0 to simulate tampering
    int forged_check = Dilithium_Verify(message); // Attempt verification on tampered message
    message[0] ^= 0x01;                // Restore original message byte

    uint64_t start, end;               // Cycle counter variables
    int RUNS = 1000;                   // Number of iterations for statistically stable cycle averages

    start = get_cycles();              // Record starting timestamp for KeyGen
    for(int i = 0; i < RUNS; i++) {    // Execute KeyGen RUNS times
        Dilithium_KeyGen();            // Run Key Generation
    }                                  // End KeyGen benchmark loop
    end = get_cycles();                // Record ending timestamp for KeyGen
    uint64_t cycles_keygen = (end - start) / RUNS; // Compute average KeyGen cycles

    total_rejections = 0;              // Reset rejection counter before signing benchmark
    start = get_cycles();              // Record starting timestamp for Sign
    for(int i = 0; i < RUNS; i++) {    // Execute Sign RUNS times
        Dilithium_Sign(message);       // Run Fiat-Shamir with Aborts signing
    }                                  // End Sign benchmark loop
    end = get_cycles();                // Record ending timestamp for Sign
    uint64_t cycles_sign = (end - start) / RUNS; // Compute average Sign cycles

    start = get_cycles();              // Record starting timestamp for Verify
    for(int i = 0; i < RUNS; i++) {    // Execute Verify RUNS times
        Dilithium_Verify(message);     // Run Signature Verification
    }                                  // End Verify benchmark loop
    end = get_cycles();                // Record ending timestamp for Verify
    uint64_t cycles_verify = (end - start) / RUNS; // Compute average Verify cycles

    int32_t dummy_poly[256] = {0};     // Isolated polynomial array for primitive NTT benchmarking
    start = get_cycles();              // Record starting timestamp for 8-layer NTT
    for(int i = 0; i < RUNS; i++) {    // Execute NTT RUNS times
        ntt(dummy_poly);               // Run in-place 256-point NTT
    }                                  // End NTT benchmark loop
    end = get_cycles();                // Record ending timestamp for NTT
    uint64_t cycles_ntt = (end - start) / RUNS; // Compute average NTT cycles

    start = get_cycles();              // Record starting timestamp for 8-layer InvNTT
    for(int i = 0; i < RUNS; i++) {    // Execute InvNTT RUNS times
        invntt(dummy_poly);            // Run in-place 256-point Inverse NTT
    }                                  // End InvNTT benchmark loop
    end = get_cycles();                // Record ending timestamp for InvNTT
    uint64_t cycles_invntt = (end - start) / RUNS; // Compute average InvNTT cycles

    printf("--- Signature Validation ---\n"); // Print validation section header
    print_hex("Signed Message", message, 32); // Print the 32-byte message in hex
    printf("Valid Signature   : %s\n", valid_initial ? "VERIFIED (ACCEPT)" : "FAILED"); // Report valid check
    printf("Tampered Message  : %s\n", !forged_check ? "REJECTED (FORGERY BLOCKED)" : "ERROR"); // Report tamper check
    printf("Avg FS Attempts   : %.2f attempts/sig (%.2f rejections/sig)\n\n",
           1.0 + (double)total_rejections / RUNS, (double)total_rejections / RUNS); // Report rejection rate

    printf("--- Performance Benchmark (Average CPU Cycles over %d runs) ---\n", RUNS); // Print benchmark header
    printf(" | NTT Operation        : %10llu cycles |\n", (unsigned long long)cycles_ntt); // Print NTT cycles
    printf(" | InvNTT Operation     : %10llu cycles |\n", (unsigned long long)cycles_invntt); // Print InvNTT cycles
    printf(" | Dilithium KeyGen     : %10llu cycles |\n", (unsigned long long)cycles_keygen); // Print KeyGen cycles
    printf(" | Dilithium Sign       : %10llu cycles |\n", (unsigned long long)cycles_sign); // Print Sign cycles
    printf(" | Dilithium Verify     : %10llu cycles |\n", (unsigned long long)cycles_verify); // Print Verify cycles
    printf("--------------------------------------------------------------\n"); // Print footer border

    return 0;                          // Exit cleanly
}                                      // End main function
