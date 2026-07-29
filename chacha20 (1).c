/* =========================================================================
 * chacha20.c
 *
 * A fast, portable, single-file C implementation of the ChaCha20 stream
 * cipher as specified in RFC 8439 (obsoletes RFC 7539):
 *   "ChaCha20 and Poly1305 for IETF Protocols"
 *
 * Parameters used here (RFC 8439 variant):
 *   - 256-bit (32-byte) key
 *   - 96-bit  (12-byte) nonce
 *   - 32-bit  block counter (starts at a caller-supplied value)
 *   - 20 rounds (10 "double rounds": column round + diagonal round)
 *
 * Contents:
 *   1. Core primitives   (rotate, little-endian load/store)
 *   2. ChaCha20 block function (register-optimized, RFC 8439 section 2.3)
 *   3. Stream cipher API (encryption == decryption, since it's XOR-based)
 *   4. Self-test against the official RFC 8439 section 2.4.2 test vector
 *   5. Worked encryption/decryption example
 *   6. Cycle-accurate benchmark (RDTSC/RDTSCP) + throughput measurement
 *
 * Build (Linux/x86_64, GCC or Clang):
 *   gcc -O3 -march=native -funroll-loops -o chacha20 chacha20.c
 *   ./chacha20
 *
 * Portability:
 *   The cipher core is standard C99 and portable to any platform.
 *   Only the cycle counter (Section 6) uses x86 RDTSC/RDTSCP intrinsics;
 *   on non-x86 platforms it automatically falls back to a
 *   nanosecond wall-clock timer (clock_gettime), so the file still
 *   builds and runs everywhere.
 *
 * Security note:
 *   This is a reference-quality, constant-structure software
 *   implementation intended for correctness, clarity, and performance
 *   measurement. It does not claim side-channel (timing/cache) hardened
 *   guarantees at the level of formally verified or hardware-accelerated
 *   (AES-NI/AVX512-style) production libraries. For production use,
 *   prefer/compare against an audited library (e.g., libsodium,
 *   BoringSSL) unless you have reviewed this code for your threat model.
 * ========================================================================= */

/* Needed so <time.h> exposes clock_gettime()/CLOCK_MONOTONIC under a
 * strict ISO C standard (e.g. -std=c99), not just under GNU extensions.
 * Must be defined before any system header is included. */
#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ---- x86 cycle-counter intrinsics (falls back gracefully elsewhere) ---- */
#if defined(__x86_64__) || defined(__i386__)
    #define HAVE_RDTSC 1
    #include <immintrin.h>
#else
    #define HAVE_RDTSC 0
#endif

/* =========================================================================
 * 1. CORE PRIMITIVES
 * ========================================================================= */

/* 32-bit left rotation. On any modern compiler with -O2/-O3 this compiles
 * down to a single ROL/ROTL instruction (idiom recognized by GCC/Clang). */
static inline uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

/* Load 4 bytes from memory as a little-endian uint32_t.
 * Written byte-wise so the code is endianness-agnostic and has no
 * unaligned-access / strict-aliasing issues on any platform. */
static inline uint32_t load32_le(const uint8_t *p)
{
    return  (uint32_t)p[0]        |
            ((uint32_t)p[1] << 8) |
            ((uint32_t)p[2] << 16)|
            ((uint32_t)p[3] << 24);
}

/* Store a uint32_t into memory as little-endian bytes. */
static inline void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* =========================================================================
 * 2. CHACHA20 BLOCK FUNCTION  (RFC 8439, Section 2.3)
 * ========================================================================= */

/* The ChaCha quarter-round. Operates on four 32-bit words held in local
 * (register) variables — not array elements — so the compiler can keep
 * the entire working state in CPU registers for the whole block
 * transform instead of repeatedly loading/storing to memory. This is the
 * single biggest scalar-performance win available before resorting to
 * SIMD (SSE2/AVX2), and is the technique used by fast reference
 * implementations (e.g., libsodium's "ref" core). */
#define QUARTERROUND(a, b, c, d)          \
    do {                                  \
        a += b; d ^= a; d = rotl32(d,16); \
        c += d; b ^= c; b = rotl32(b,12); \
        a += b; d ^= a; d = rotl32(d, 8); \
        c += d; b ^= c; b = rotl32(b, 7); \
    } while (0)

/* The 4x4 ChaCha20 state matrix, indices 0..15, laid out as:
 *
 *   [ const  const  const  const ]   ("expa" "nd 3" "2-by" "te k")
 *   [ key0   key1   key2   key3  ]
 *   [ key4   key5   key6   key7  ]
 *   [ counter nonce0 nonce1 nonce2 ]
 *
 * chacha20_block() runs the 20-round permutation on a copy of the input
 * state, adds the original state back in (Davies-Meyer-style
 * feed-forward, which is what makes it a PRF suitable for a stream
 * cipher rather than a bare permutation), and serializes the result to
 * 64 bytes of keystream, little-endian per RFC 8439 Section 2.3. */
static void chacha20_block(const uint32_t state[16], uint8_t out[64])
{
    /* Copy state into local variables -> compiler keeps these in
     * registers (x86_64 has 16 GP registers; this fits comfortably,
     * especially with -O3). */
    uint32_t x0  = state[0],  x1  = state[1],  x2  = state[2],  x3  = state[3];
    uint32_t x4  = state[4],  x5  = state[5],  x6  = state[6],  x7  = state[7];
    uint32_t x8  = state[8],  x9  = state[9],  x10 = state[10], x11 = state[11];
    uint32_t x12 = state[12], x13 = state[13], x14 = state[14], x15 = state[15];

    /* 10 double-rounds = 20 rounds total. Loop is small and fully
     * unrolled by GCC/Clang at -O2/-O3 (verified in generated asm);
     * -funroll-loops / #pragma below reinforce that if the optimizer
     * declines for any reason. */
#if defined(__GNUC__) || defined(__clang__)
    #pragma GCC unroll 10
#endif
    for (int i = 0; i < 10; i++) {
        /* Odd round: operate on columns of the 4x4 matrix */
        QUARTERROUND(x0, x4, x8,  x12);
        QUARTERROUND(x1, x5, x9,  x13);
        QUARTERROUND(x2, x6, x10, x14);
        QUARTERROUND(x3, x7, x11, x15);
        /* Even round: operate on diagonals of the 4x4 matrix */
        QUARTERROUND(x0, x5, x10, x15);
        QUARTERROUND(x1, x6, x11, x12);
        QUARTERROUND(x2, x7, x8,  x13);
        QUARTERROUND(x3, x4, x9,  x14);
    }

    /* Feed-forward: add the original input words to the permuted words
     * (mod 2^32), per RFC 8439 Section 2.3 step "add the original
     * input words". */
    x0  += state[0];  x1  += state[1];  x2  += state[2];  x3  += state[3];
    x4  += state[4];  x5  += state[5];  x6  += state[6];  x7  += state[7];
    x8  += state[8];  x9  += state[9];  x10 += state[10]; x11 += state[11];
    x12 += state[12]; x13 += state[13]; x14 += state[14]; x15 += state[15];

    /* Serialize the 16 words to 64 bytes, little-endian. */
    store32_le(out +  0, x0);  store32_le(out +  4, x1);
    store32_le(out +  8, x2);  store32_le(out + 12, x3);
    store32_le(out + 16, x4);  store32_le(out + 20, x5);
    store32_le(out + 24, x6);  store32_le(out + 28, x7);
    store32_le(out + 32, x8);  store32_le(out + 36, x9);
    store32_le(out + 40, x10); store32_le(out + 44, x11);
    store32_le(out + 48, x12); store32_le(out + 52, x13);
    store32_le(out + 56, x14); store32_le(out + 60, x15);
}

/* =========================================================================
 * 3. STREAM CIPHER API
 * ========================================================================= */

/* ChaCha20 constants: ASCII "expand 32-byte k" split into 4 little-endian
 * 32-bit words, per RFC 8439 Section 2.3. Fixed for the 256-bit-key
 * variant used here. */
static const uint32_t CHACHA20_CONSTANTS[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

/* Build the initial 16-word ChaCha20 state from key/nonce/counter. */
static void chacha20_init_state(uint32_t state[16],
                                 const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter)
{
    state[0] = CHACHA20_CONSTANTS[0];
    state[1] = CHACHA20_CONSTANTS[1];
    state[2] = CHACHA20_CONSTANTS[2];
    state[3] = CHACHA20_CONSTANTS[3];

    state[4]  = load32_le(key + 0);
    state[5]  = load32_le(key + 4);
    state[6]  = load32_le(key + 8);
    state[7]  = load32_le(key + 12);
    state[8]  = load32_le(key + 16);
    state[9]  = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);

    state[12] = counter;

    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);
}

/*
 * chacha20_xor()
 * ---------------
 * Encrypts OR decrypts `len` bytes from `in` into `out` (in-place safe,
 * i.e. in == out is allowed) by XOR-ing with the ChaCha20 keystream.
 *
 * Because ChaCha20 is a synchronous stream cipher, encryption and
 * decryption are the *identical* operation:
 *     ciphertext = plaintext  XOR keystream
 *     plaintext  = ciphertext XOR keystream   (same keystream, same key/nonce/counter)
 * so a single function correctly implements both directions — this is
 * intentional, not a simplification.
 *
 * key      : 32-byte (256-bit) secret key
 * nonce    : 12-byte (96-bit) number used once per (key, message)
 * counter  : initial 32-bit block counter (RFC 8439 recommends starting
 *            at 1 when a protocol reserves block 0 for something else,
 *            e.g. a Poly1305 key; plain ChaCha20 typically starts at 0)
 * in, out  : input/output buffers of length `len`
 * len      : number of bytes to process (may be any length, including
 *            lengths not aligned to the 64-byte block size)
 */
void chacha20_xor(const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter,
                   const uint8_t *in,
                   uint8_t *out,
                   size_t len)
{
    uint32_t state[16];
    uint8_t  keystream[64];

    chacha20_init_state(state, key, nonce, counter);

    while (len > 0) {
        chacha20_block(state, keystream);
        state[12]++;                 /* advance the 32-bit block counter */

        size_t chunk = (len < 64) ? len : 64;

        /* XOR this block's keystream with the input. Compilers vectorize
         * this simple byte loop well at -O3 (SSE2/AVX2 auto-vectorization
         * on x86_64); it is also branch-free per iteration. */
        for (size_t i = 0; i < chunk; i++)
            out[i] = in[i] ^ keystream[i];

        in  += chunk;
        out += chunk;
        len -= chunk;
    }
}

/* =========================================================================
 * 4. SELF-TEST  (RFC 8439, Section 2.4.2 official test vector)
 * ========================================================================= */

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i & 15) == 15) printf("\n%*s", (int)strlen(label), "");
    }
    printf("\n");
}

/* Returns 1 on success (implementation matches the RFC), 0 on failure. */
static int chacha20_self_test(void)
{
    /* RFC 8439 Section 2.4.2 "Example and Test Vector for the ChaCha20
     * Cipher": Key = 00..1f, Nonce = 00:00:00:00:00:00:00:4a:00:00:00:00,
     * Initial Counter = 1, plaintext = the "sunscreen" passage. */
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t plaintext[114] =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    static const uint8_t expected_ciphertext[114] = {
        0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
        0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
        0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
        0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
        0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
        0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
        0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
        0x87,0x4d
    };

    uint8_t ciphertext[114];
    uint8_t decrypted[114];

    /* Encrypt: plaintext -> ciphertext, starting block counter = 1 */
    chacha20_xor(key, nonce, 1, plaintext, ciphertext, sizeof(plaintext));

    int ok = (memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) == 0);

    /* Decrypt: ciphertext -> recovered plaintext, same key/nonce/counter */
    chacha20_xor(key, nonce, 1, ciphertext, decrypted, sizeof(ciphertext));
    ok = ok && (memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);

    printf("=== RFC 8439 Section 2.4.2 self-test ===\n");
    printf("Result: %s\n", ok ? "PASS (ciphertext matches RFC 8439 exactly)"
                               : "FAIL (implementation does not match the RFC)");
    if (!ok) {
        print_hex("  got     : ", ciphertext, sizeof(ciphertext));
        print_hex("  expected: ", expected_ciphertext, sizeof(expected_ciphertext));
    }
    printf("\n");
    return ok;
}

/* =========================================================================
 * 5. WORKED ENCRYPTION / DECRYPTION EXAMPLE
 * ========================================================================= */

static void demo_encrypt_decrypt(void)
{
    /* --- In real use: generate `key` and `nonce` with a CSPRNG, e.g.
     *     getrandom(2) on Linux or /dev/urandom. NEVER reuse the same
     *     (key, nonce) pair to encrypt two different messages. --- */
    static const uint8_t key[32] = {
        0x1c,0x92,0x40,0xa5,0xeb,0x55,0xd3,0x8a,0xf3,0x33,0x88,0x86,0x04,0xf6,0xb5,0xf0,
        0x47,0x39,0x17,0xc1,0x40,0x2b,0x80,0x09,0x9d,0xca,0x5c,0xbc,0x20,0x70,0x75,0xc0
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
    };
    const uint32_t initial_counter = 0;

    const char *message = "The quick brown fox jumps over the lazy dog. "
                           "ChaCha20 demo: confidentiality via stream XOR.";
    size_t len = strlen(message);

    uint8_t *ciphertext = malloc(len);
    uint8_t *recovered  = malloc(len);
    if (!ciphertext || !recovered) { fprintf(stderr, "OOM\n"); exit(1); }

    printf("=== Encryption / decryption example ===\n");
    printf("Plaintext (%zu bytes): \"%s\"\n\n", len, message);

    /* Encrypt */
    chacha20_xor(key, nonce, initial_counter,
                 (const uint8_t *)message, ciphertext, len);
    print_hex("Ciphertext (hex): ", ciphertext, len);
    printf("\n");

    /* Decrypt (same function, same key/nonce/counter) */
    chacha20_xor(key, nonce, initial_counter, ciphertext, recovered, len);

    printf("Decrypted: \"%.*s\"\n", (int)len, recovered);
    printf("Round-trip check: %s\n\n",
           memcmp(recovered, message, len) == 0 ? "OK (matches original)"
                                                 : "FAILED");

    free(ciphertext);
    free(recovered);
}

/* =========================================================================
 * 6. PERFORMANCE BENCHMARK
 *    Measures both CPU clock cycles (RDTSC/RDTSCP, x86) and wall-clock
 *    throughput (clock_gettime), then reports cycles/byte and MB/s —
 *    the standard metrics used to compare stream-cipher implementations.
 * ========================================================================= */

#if HAVE_RDTSC
/* Serializing timestamp read at the *start* of a measured region:
 * LFENCE before RDTSC prevents earlier instructions from being reordered
 * past the timestamp read. */
static inline uint64_t rdtsc_begin(void)
{
    _mm_lfence();
    return __rdtsc();
}

/* Serializing timestamp read at the *end* of a measured region:
 * RDTSCP itself waits for prior instructions to retire before reading the
 * counter, and the trailing LFENCE stops later instructions from being
 * reordered before it. This begin/end pairing is the standard Intel-
 * recommended pattern for benchmarking short code regions. */
static inline uint64_t rdtsc_end(void)
{
    unsigned int aux;
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}
#endif /* HAVE_RDTSC */

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void run_benchmark(void)
{
    static const uint8_t key[32]   = { 0x42 }; /* rest zero-initialized */
    static const uint8_t nonce[12] = { 0x24 }; /* rest zero-initialized */

    const size_t buf_len = 1u << 20;      /* 1 MiB payload per trial */
    const int    trials  = 200;           /* repetitions for stable timing */

    uint8_t *src = malloc(buf_len);
    uint8_t *dst = malloc(buf_len);
    if (!src || !dst) { fprintf(stderr, "OOM\n"); exit(1); }
    memset(src, 0xA5, buf_len);

    printf("=== Performance benchmark ===\n");
    printf("Payload size : %zu bytes (%.2f MiB) per trial\n",
           buf_len, buf_len / (1024.0 * 1024.0));
    printf("Trials       : %d\n", trials);

    /* --- Warm-up: bring code/data into L1 cache, let CPU reach steady
     *     clock state, before any measurement is taken. --- */
    for (int i = 0; i < 5; i++)
        chacha20_xor(key, nonce, 0, src, dst, buf_len);

#if HAVE_RDTSC
    /* --- CPU-cycle measurement (RDTSC/RDTSCP) --- */
    uint64_t best_cycles = UINT64_MAX, total_cycles = 0;
    for (int t = 0; t < trials; t++) {
        uint64_t c0 = rdtsc_begin();
        chacha20_xor(key, nonce, 0, src, dst, buf_len);
        uint64_t c1 = rdtsc_end();
        uint64_t d = c1 - c0;
        total_cycles += d;
        if (d < best_cycles) best_cycles = d;
    }
    double avg_cycles = (double)total_cycles / trials;
    double best_cpb    = (double)best_cycles / buf_len;
    double avg_cpb      = avg_cycles / buf_len;

    printf("\n-- CPU cycles (RDTSC/RDTSCP) --\n");
    printf("Best  : %10llu cycles  (%.3f cycles/byte)\n",
           (unsigned long long)best_cycles, best_cpb);
    printf("Average: %10.0f cycles  (%.3f cycles/byte)\n",
           avg_cycles, avg_cpb);
#else
    printf("\n(RDTSC not available on this architecture; skipping cycle count)\n");
#endif

    /* --- Wall-clock throughput measurement (architecture-independent) --- */
    double t0 = now_seconds();
    for (int t = 0; t < trials; t++)
        chacha20_xor(key, nonce, 0, src, dst, buf_len);
    double t1 = now_seconds();

    double seconds       = t1 - t0;
    double total_bytes   = (double)buf_len * trials;
    double mb_per_second = (total_bytes / (1024.0 * 1024.0)) / seconds;
    double gb_per_second  = (total_bytes / (1024.0*1024.0*1024.0)) / seconds;

    printf("\n-- Wall-clock throughput --\n");
    printf("Total data processed : %.2f MiB\n", total_bytes / (1024.0*1024.0));
    printf("Elapsed time          : %.6f s\n", seconds);
    printf("Throughput             : %.1f MB/s  (%.3f GB/s)\n",
           mb_per_second, gb_per_second);

#if HAVE_RDTSC
    /* Approximate core clock (GHz) implied by cycles vs wall time, useful
     * as a sanity check that RDTSC and clock_gettime agree with each
     * other (RDTSC ticks at a fixed reference frequency on modern x86,
     * not the current dynamic core frequency, so this is an estimate). */
    double implied_ghz = (avg_cycles * trials) / seconds / 1e9;
    printf("Implied clock (sanity check): ~%.2f GHz\n", implied_ghz);
#endif

    printf("\n");
    free(src);
    free(dst);
}

/* =========================================================================
 * MAIN
 * ========================================================================= */
int main(void)
{
    int ok = chacha20_self_test();
    demo_encrypt_decrypt();
    run_benchmark();
    return ok ? 0 : 1;
}
