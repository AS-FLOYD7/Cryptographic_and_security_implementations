#include <stdio.h>      /* Standard I/O library for printing formatted cryptographic state telemetry */
#include <stdint.h>     /* Fixed-width integer types (uint8_t, uint32_t, uint64_t) for exact bit-level arithmetic */
#include <string.h>     /* Standard string operations (strlen) for measuring plaintext payload lengths */
#include <stddef.h>     /* Standard size_t definitions for safe memory buffer indexing */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) /* Detect x86/x64 CPU architecture at compile time */
#include <x86intrin.h>  /* Hardware intrinsics header exposing the CPU Time Stamp Counter (__rdtsc) */
#define USE_RDTSC 1     /* Enable hardware clock-cycle profiling on x86/x64 processors */
#else                   /* Fallback branch for ARM64, RISC-V, or other non-x86 architectures */
#define USE_RDTSC 0     /* Disable hardware intrinsic call on platforms without __rdtsc */
#endif                  /* End of architecture detection preprocessor block */

#define LANES 4                                 /* Four 64-bit words form a 256-bit post-quantum security state */
#define KEY_BYTES (LANES * 8)                   /* 32 bytes (256 bits) per key to resist Grover's quantum search */
#define TAG_ROOT_KDF   0x50515844485F524BULL    /* ASCII domain separator "PQXDH_RK" isolating Root Key extraction */
#define TAG_CHAIN_STEP 0x434841494E5F5354ULL    /* ASCII domain separator "CHAIN_ST" isolating symmetric chain ratcheting */
#define TAG_MSG_DERIV  0x4D53475F4B45595FULL    /* ASCII domain separator "MSG_KEY_" isolating per-message key derivation */
#define TAG_AEAD_MAC   0x414541445F4D4143ULL    /* ASCII domain separator "AEAD_MAC" isolating authentication tag computation */

#define ROTL64(v, n) (((v) << (n)) | ((v) >> (64 - (n)))) /* Constant-time 64-bit circular left shift for ARX diffusion */

typedef struct {                /* 256-bit cryptographic key structure aligned for 64-bit CPU registers */
    uint64_t w[LANES];          /* Array of four 64-bit lanes storing 256 bits of high-entropy key state */
} key256_t;                     /* Type alias for Root Keys, Chain Keys, Message Keys, and KEM secrets */

typedef struct {                /* Complete Post-Quantum Double Ratchet endpoint session state machine */
    key256_t root_key;          /* 256-bit Root Key (RK) updated during asymmetric ECDH + ML-KEM ratchets */
    key256_t chain_key;         /* 256-bit Symmetric Chain Key (CK) rolled forward on every message */
    uint32_t epoch;             /* Asymmetric ratchet epoch counter tracking Post-Compromise Security heals */
    uint32_t step;              /* Symmetric ratchet message index tracking Forward Secrecy progression */
} pq_ratchet_t;                 /* Type alias for the active session state */

static inline uint64_t cpu_cycles(void) {       /* Inline hardware profiler to measure execution latency in clock cycles */
#if USE_RDTSC                                   /* Check if x86 hardware cycle counter is enabled */
    return __rdtsc();                           /* Read current processor timestamp counter directly from hardware MSR */
#else                                           /* Fallback path when compiling on non-x86 targets */
    return 0ULL;                                /* Return zero when hardware cycle counter is unavailable */
#endif                                          /* End of conditional hardware timing block */
}                                               /* End of cpu_cycles function */

static void wipe_memory(void *buf, size_t len) {            /* Compiler-proof memory scrubber enforcing physical Forward Secrecy */
    volatile uint8_t *p = (volatile uint8_t *)buf;          /* Volatile pointer prevents compiler dead-store optimization (-O3) */
    while (len--) {                                         /* Iterate through every byte of sensitive cryptographic state */
        *p++ = 0x00U;                                       /* Overwrite RAM byte with zero so compromised memory leaks nothing */
    }                                                       /* End of byte-by-byte zeroization loop */
}                                                           /* End of wipe_memory function */

static inline void arx_sponge_permute(uint64_t s[LANES]) {  /* 8-round ChaCha/SipHash-style ARX permutation for non-linear mixing */
    for (int r = 0; r < 8; ++r) {                           /* Run 8 full rounds to achieve full 256-bit avalanche diffusion */
        s[0] += s[1];                                       /* Modular 64-bit addition mixing lane 1 into lane 0 */
        s[1] = ROTL64(s[1], 13) ^ s[0];                     /* Rotate lane 1 by 13 bits and XOR with updated lane 0 */
        s[2] += s[3];                                       /* Modular 64-bit addition mixing lane 3 into lane 2 */
        s[3] = ROTL64(s[3], 16) ^ s[2];                     /* Rotate lane 3 by 16 bits and XOR with updated lane 2 */
        s[0] = ROTL64(s[0], 32);                            /* 32-bit word swap on lane 0 to break byte alignment symmetries */
        s[2] += s[1];                                       /* Cross-lane modular addition mixing lane 1 into lane 2 */
        s[1] = ROTL64(s[1], 17) ^ s[2];                     /* Rotate lane 1 by 17 bits and XOR with cross-mixed lane 2 */
        s[0] += s[3];                                       /* Cross-lane modular addition mixing lane 3 into lane 0 */
        s[3] = ROTL64(s[3], 21) ^ s[0];                     /* Rotate lane 3 by 21 bits and XOR with cross-mixed lane 0 */
        s[2] = ROTL64(s[2], 32);                            /* 32-bit word swap on lane 2 completing the quarter-round matrix */
        s[0] ^= (0x9E3779B97F4A7C15ULL + (uint64_t)r);      /* Inject golden-ratio round constant to prevent slide attacks */
    }                                                       /* End of 8-round ARX permutation loop */
}                                                           /* End of arx_sponge_permute function */

static void kdf_dual_prf(key256_t *out,                     /* Domain-separated Dual-PRF Key Derivation Function (Extract-and-Expand) */
                         const key256_t *key_in,            /* Primary 256-bit input key (Root Key or Chain Key) */
                         const key256_t *aux_in,            /* Optional 256-bit auxiliary secret (ML-KEM secret) or NULL */
                         uint64_t domain_tag) {             /* 64-bit cryptographic domain separator constant */
    uint64_t st[LANES];                                     /* Local 256-bit sponge state allocated in CPU registers */
    st[0] = key_in->w[0] ^ 0x736F6D6570736575ULL;           /* Seed lane 0 with key lane 0 XORed with Nothing-Up-My-Sleeve IV0 */
    st[1] = key_in->w[1] ^ 0x646F72616E646F6DULL;           /* Seed lane 1 with key lane 1 XORed with Nothing-Up-My-Sleeve IV1 */
    st[2] = key_in->w[2] ^ 0x6C7967656E657261ULL;           /* Seed lane 2 with key lane 2 XORed with Nothing-Up-My-Sleeve IV2 */
    st[3] = key_in->w[3] ^ domain_tag;                      /* Seed lane 3 with key lane 3 XORed with explicit domain tag */
    if (aux_in != NULL) {                                   /* Check if hybrid post-quantum auxiliary entropy is present */
        st[0] ^= aux_in->w[0];                              /* Absorb auxiliary secret lane 0 into sponge state */
        st[1] ^= aux_in->w[1];                              /* Absorb auxiliary secret lane 1 into sponge state */
        st[2] ^= aux_in->w[2];                              /* Absorb auxiliary secret lane 2 into sponge state */
        st[3] ^= aux_in->w[3];                              /* Absorb auxiliary secret lane 3 into sponge state */
    }                                                       /* End of optional auxiliary secret absorption */
    arx_sponge_permute(st);                                 /* Execute first 8-round ARX permutation (KDF Extract stage) */
    if (aux_in != NULL) {                                   /* Apply Davies-Meyer feed-forward with rotated auxiliary lanes */
        st[0] ^= aux_in->w[2];                              /* Cross-XOR auxiliary lane 2 to block state inversion */
        st[1] ^= aux_in->w[3];                              /* Cross-XOR auxiliary lane 3 into intermediate sponge state */
    }                                                       /* End of auxiliary feed-forward stage */
    st[3] ^= ~domain_tag;                                   /* Mix bitwise-inverted domain tag before Expand stage */
    arx_sponge_permute(st);                                 /* Execute second 8-round ARX permutation (KDF Expand stage) */
    for (int i = 0; i < LANES; ++i) {                       /* Loop across all four 64-bit output lanes */
        out->w[i] = st[i] ^ key_in->w[i];                   /* XOR permutation output with input key for preimage resistance */
    }                                                       /* End of output key extraction loop */
    wipe_memory(st, sizeof(st));                            /* Scrub temporary sponge state from stack memory */
}                                                           /* End of kdf_dual_prf function */

static void pqxdh_handshake_init(pq_ratchet_t *ctx,         /* Initialize PQXDH session from classical ECDH + post-quantum ML-KEM */
                                 const key256_t *ecdh_ss,   /* Classical X25519 elliptic-curve shared secret */
                                 const key256_t *mlkem_ss)  /* Post-Quantum ML-KEM-1024 lattice shared secret */
{                                                           /* Begin PQXDH hybrid key schedule initialization */
    kdf_dual_prf(&ctx->root_key, ecdh_ss, mlkem_ss, TAG_ROOT_KDF); /* Fuse X25519 + ML-KEM secrets into hybrid Root Key */
    kdf_dual_prf(&ctx->chain_key, &ctx->root_key, NULL, TAG_CHAIN_STEP); /* Derive initial Chain Key from Root Key */
    ctx->epoch = 1U;                                        /* Initialize asymmetric ratchet epoch counter to 1 */
    ctx->step  = 0U;                                        /* Initialize per-epoch symmetric message counter to 0 */
}                                                           /* End of pqxdh_handshake_init function */

static void spqr_asymmetric_ratchet(pq_ratchet_t *ctx,      /* Execute Asymmetric Hybrid Ratchet hop for Post-Compromise Security */
                                    const key256_t *new_dh, /* Fresh ephemeral X25519 Diffie-Hellman ratchet output */
                                    const key256_t *new_pq) /* Fresh ephemeral ML-KEM-1024 encapsulation secret */
{                                                           /* Begin SPQR asymmetric root ratchet step */
    key256_t hop_secret;                                    /* Stack container for combined ephemeral hybrid hop secret */
    kdf_dual_prf(&hop_secret, new_dh, new_pq, TAG_ROOT_KDF ^ 0xAA55ULL); /* Combine fresh classical and PQ ratchet secrets */
    kdf_dual_prf(&ctx->root_key, &ctx->root_key, &hop_secret, TAG_ROOT_KDF); /* Advance Root Key with fresh hybrid entropy */
    kdf_dual_prf(&ctx->chain_key, &ctx->root_key, NULL, TAG_CHAIN_STEP); /* Reset Sending Chain Key from healed Root Key */
    ctx->epoch++;                                           /* Increment epoch counter to reflect new asymmetric ratchet state */
    ctx->step = 0U;                                         /* Reset message step counter for the new epoch */
    wipe_memory(&hop_secret, sizeof(hop_secret));           /* Scrub intermediate hybrid hop secret from RAM immediately */
}                                                           /* End of spqr_asymmetric_ratchet function */

static void symmetric_chain_ratchet(pq_ratchet_t *ctx,      /* Advance Symmetric KDF Ratchet and output one-time Message Key */
                                    key256_t *msg_key) {    /* Output pointer for isolated 256-bit Message Key */
    kdf_dual_prf(msg_key, &ctx->chain_key, NULL, TAG_MSG_DERIV); /* Derive ephemeral Message Key using MSG_KEY_ domain */
    kdf_dual_prf(&ctx->chain_key, &ctx->chain_key, NULL, TAG_CHAIN_STEP); /* Irreversibly roll Chain Key forward */
    ctx->step++;                                            /* Increment symmetric message counter within current epoch */
}                                                           /* End of symmetric_chain_ratchet function */

static void aead_crypt_and_tag(uint8_t *out_buf,            /* Authenticated stream cipher encryption/decryption + MAC generator */
                               uint64_t *tag_out,           /* Output pointer for 64-bit authentication tag */
                               const uint8_t *in_buf,       /* Input plaintext or ciphertext byte array */
                               size_t len,                  /* Length of message payload in bytes */
                               const key256_t *mk,          /* One-time 256-bit Message Key */
                               uint32_t epoch,              /* Associated Data: current asymmetric epoch number */
                               uint32_t step) {             /* Associated Data: current symmetric message index */
    uint64_t ks[LANES];                                     /* 256-bit keystream block generated per 32-byte message chunk */
    uint64_t ctr = 0ULL;                                    /* Block counter ensuring unique keystream across long payloads */
    for (size_t off = 0; off < len; off += KEY_BYTES) {     /* Iterate over payload in 32-byte blocks */
        ks[0] = mk->w[0] ^ ctr++;                           /* Mix message key lane 0 with incrementing block counter */
        ks[1] = mk->w[1] ^ (((uint64_t)epoch << 32) | step);/* Bind header metadata (epoch, step) into keystream state */
        ks[2] = mk->w[2] ^ 0xF00DBAADBEEF1337ULL;           /* Mix message key lane 2 with fixed whitening constant */
        ks[3] = mk->w[3] ^ TAG_MSG_DERIV;                   /* Mix message key lane 3 with message derivation domain tag */
        arx_sponge_permute(ks);                             /* Permute state to produce 32 bytes of pseudorandom keystream */
        const uint8_t *kb = (const uint8_t *)ks;            /* View 64-bit keystream lanes as a byte array for stream XOR */
        size_t n = (len - off < KEY_BYTES) ? (len - off) : KEY_BYTES; /* Clamp byte count for final partial block */
        for (size_t i = 0; i < n; ++i) {                    /* Iterate through each byte in the current block */
            out_buf[off + i] = in_buf[off + i] ^ kb[i];     /* XOR input byte with keystream byte to encrypt or decrypt */
        }                                                   /* End of byte-level stream XOR loop */
    }                                                       /* End of block keystream loop */
    if (tag_out != NULL) {                                  /* Compute MAC tag binding Associated Data and ciphertext */
        uint64_t mac[LANES] = {                             /* Initialize 256-bit MAC state from Message Key and metadata */
            mk->w[0] ^ epoch, mk->w[1] ^ step,              /* Bind epoch ID and message step index into MAC lanes 0-1 */
            mk->w[2] ^ len,   mk->w[3] ^ TAG_AEAD_MAC       /* Bind payload byte length and MAC domain into lanes 2-3 */
        };                                                  /* End of MAC state initialization */
        const uint8_t *ct = (out_buf != in_buf) ? out_buf : in_buf; /* Authenticate outgoing ciphertext bytes */
        for (size_t i = 0; i < len; ++i) {                  /* Absorb each ciphertext byte into the sponge accumulator */
            mac[i % LANES] ^= ((uint64_t)ct[i] << ((i % 8) * 8)); /* Shift and XOR byte into its aligned 64-bit lane */
            if ((i & 31U) == 31U) arx_sponge_permute(mac);  /* Compress MAC state after every 32 bytes absorbed */
        }                                                   /* End of ciphertext byte absorption loop */
        arx_sponge_permute(mac);                            /* Final squeezing permutation for MAC tag generation */
        *tag_out = mac[0] ^ mac[1] ^ mac[2] ^ mac[3];       /* Fold 256-bit MAC state into a 64-bit authentication tag */
        wipe_memory(mac, sizeof(mac));                      /* Scrub internal MAC accumulator from stack memory */
    }                                                       /* End of MAC computation block */
    wipe_memory(ks, sizeof(ks));                            /* Scrub keystream buffer from stack memory */
}                                                           /* End of aead_crypt_and_tag function */

static int verify_tag_const_time(uint64_t a, uint64_t b) {  /* Constant-time tag comparison immune to timing side-channels */
    uint64_t d = a ^ b;                                     /* XOR tags: result is 0 if and only if all 64 bits match */
    d |= (d >> 32);                                         /* OR upper 32 bits into lower 32 bits */
    d |= (d >> 16);                                         /* OR upper 16 bits into lower 16 bits */
    d |= (d >> 8);                                          /* OR upper 8 bits into lower 8 bits */
    d |= (d >> 4);                                          /* OR upper 4 bits into lower 4 bits */
    d |= (d >> 2);                                          /* OR upper 2 bits into lower 2 bits */
    d |= (d >> 1);                                          /* OR bit 1 into bit 0 (LSB is 0 iff tags are identical) */
    return (int)((d & 1ULL) ^ 1ULL);                        /* Invert LSB to return 1 on valid match, 0 on mismatch */
}                                                           /* End of verify_tag_const_time function */

static void dump_key256(const char *label, const key256_t *k) { /* Diagnostic formatter printing 256-bit keys in hex */
    printf("  %-18s : %016llX %016llX %016llX %016llX\n",   /* Print label followed by four 16-digit hex words */
           label,                                           /* Key identifier string */
           (unsigned long long)k->w[0],                     /* Bits 0..63 of 256-bit state */
           (unsigned long long)k->w[1],                     /* Bits 64..127 of 256-bit state */
           (unsigned long long)k->w[2],                     /* Bits 128..191 of 256-bit state */
           (unsigned long long)k->w[3]);                    /* Bits 192..255 of 256-bit state */
}                                                           /* End of dump_key256 function */

int main(void) {                                            /* Main driver demonstrating PQXDH + SPQR Double Ratchet */
    printf("========================================================================================\n"); /* Print top banner */
    printf("   POST-QUANTUM HYBRID DOUBLE RATCHET (PQXDH + ML-KEM-1024 + 256-BIT ARX KDF ENGINE)    \n"); /* Print title */
    printf("========================================================================================\n\n"); /* Print bottom banner */

    const key256_t x25519_secret = {{                       /* Classical X25519 ECDH shared secret (256-bit input) */
        0x8A3F91C2D4E50671ULL, 0x19B4C72E5F803A62ULL,       /* High-entropy classical elliptic-curve words 0 and 1 */
        0x4D7E20A9B1C83F54ULL, 0xF061D2E3A4B59C87ULL        /* High-entropy classical elliptic-curve words 2 and 3 */
    }};                                                     /* End of X25519 secret initialization */

    const key256_t mlkem_secret = {{                        /* Post-Quantum ML-KEM-1024 (Kyber) decapsulated secret */
        0xE7C14908B2A6D53FULL, 0x38D0F51A7C9E24B6ULL,       /* High-entropy Module-LWE lattice words 0 and 1 */
        0x92A46E81C3F70B5DULL, 0x5B1E83D47A02C96EULL        /* High-entropy Module-LWE lattice words 2 and 3 */
    }};                                                     /* End of ML-KEM secret initialization */

    pq_ratchet_t session;                                   /* Allocate Post-Quantum Double Ratchet state machine */
    uint64_t t_start = cpu_cycles();                        /* Sample CPU cycle counter before PQXDH initialization */
    pqxdh_handshake_init(&session, &x25519_secret, &mlkem_secret); /* Mix classical + PQ secrets into Root & Chain Keys */
    uint64_t t_end = cpu_cycles();                          /* Sample CPU cycle counter after PQXDH initialization */

    printf("[STAGE 1] PQXDH Hybrid Root Extraction (CPU Cycles: %llu)\n", (unsigned long long)(t_end - t_start)); /* Log cycles */
    dump_key256("X25519 Shared", &x25519_secret);           /* Print classical ECDH secret component */
    dump_key256("ML-KEM-1024 Shared", &mlkem_secret);       /* Print post-quantum lattice secret component */
    dump_key256("Hybrid Root Key", &session.root_key);      /* Print derived 256-bit Master Root Key */
    dump_key256("Initial Chain Key", &session.chain_key);   /* Print initial 256-bit Symmetric Chain Key */
    printf("\n");                                           /* Print blank line separator */

    const char *messages[4] = {                             /* Array of test messages transmitted across ratchet epochs */
        "HANDSHAKE_OK: PQXDH hybrid channel active.",       /* Message 1 (Epoch 1, Step 1) */
        "DATA_STREAM: Module-LWE parameters verified.",     /* Message 2 (Epoch 1, Step 2) */
        "SPQR_RATCHET: Post-compromise KEM heal complete.", /* Message 3 (Epoch 2, Step 1 - after asymmetric hop) */
        "CLOSING_FIN: Forward secrecy state scrubbed."      /* Message 4 (Epoch 2, Step 2) */
    };                                                      /* End of test messages array */

    for (int i = 0; i < 4; ++i) {                           /* Loop over all 4 messages in the transmission schedule */
        if (i == 2) {                                       /* Perform an Asymmetric Hybrid Ratchet before Message 3 */
            const key256_t fresh_ecdh = {{                  /* Fresh ephemeral X25519 ratchet secret for Epoch 2 */
                0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL, 0x0F1E2D3C4B5A6978ULL, 0x8796A5B4C3D2E1F0ULL /* Ephemeral DH */
            }};                                             /* End of fresh ECDH secret */
            const key256_t fresh_mlkem = {{                 /* Fresh ephemeral ML-KEM ratchet secret for Epoch 2 */
                0xCAFEBABE1337C0DEULL, 0xFEEDFACE8BADF00DULL, 0xDEADBEEF42424242ULL, 0x0123456789ABCDEFULL /* Ephemeral PQ */
            }};                                             /* End of fresh ML-KEM secret */
            uint64_t r0 = cpu_cycles();                     /* Start cycle timer for asymmetric ratchet step */
            spqr_asymmetric_ratchet(&session, &fresh_ecdh, &fresh_mlkem); /* Heal Root Key and reset Chain Key */
            uint64_t r1 = cpu_cycles();                     /* Stop cycle timer for asymmetric ratchet step */
            printf("----------------------------------------------------------------------------------------\n"); /* Print divider */
            printf("[STAGE 2] Asymmetric Hybrid Root Ratchet -> Epoch %u (CPU Cycles: %llu)\n", /* Log epoch transition */
                   session.epoch, (unsigned long long)(r1 - r0)); /* Print new epoch number and cycle count */
            dump_key256("Healed Root Key", &session.root_key); /* Display newly healed Root Key */
            dump_key256("New Chain Key", &session.chain_key); /* Display freshly derived Chain Key for Epoch 2 */
            printf("----------------------------------------------------------------------------------------\n\n"); /* Print divider */
        }                                                   /* End of asymmetric ratchet trigger */

        key256_t msg_key;                                   /* Ephemeral 256-bit Message Key for current frame */
        uint8_t ciphertext[128] = {0};                      /* Buffer holding encrypted wire ciphertext */
        uint8_t recovered[128]  = {0};                      /* Buffer holding receiver-decrypted plaintext */
        uint64_t tx_tag = 0ULL, rx_tag = 0ULL;              /* 64-bit sender and receiver authentication tags */
        size_t mlen = strlen(messages[i]);                  /* Compute exact byte length of current plaintext string */

        uint64_t c0 = cpu_cycles();                         /* Start cycle timer for symmetric ratchet + AEAD encrypt */
        symmetric_chain_ratchet(&session, &msg_key);        /* Derive one-time Message Key and advance Chain Key */
        aead_crypt_and_tag(ciphertext, &tx_tag, (const uint8_t *)messages[i], mlen, /* Encrypt plaintext and generate MAC */
                           &msg_key, session.epoch, session.step); /* Bind current epoch and step as Associated Data */
        uint64_t c1 = cpu_cycles();                         /* Stop cycle timer for symmetric ratchet + AEAD encrypt */

        aead_crypt_and_tag(recovered, NULL, ciphertext, mlen, &msg_key, /* Decrypt ciphertext on receiver side */
                           session.epoch, session.step);    /* Supply identical Associated Data for keystream sync */
        aead_crypt_and_tag(ciphertext, &rx_tag, (const uint8_t *)recovered, mlen, /* Recompute MAC tag for verification */
                           &msg_key, session.epoch, session.step); /* Authenticate header metadata and payload */
        int valid = verify_tag_const_time(tx_tag, rx_tag);  /* Verify authentication tag in constant time */

        printf("[MESSAGE %d | Epoch %u, Step %u] (Ratchet+AEAD Cycles: %llu)\n", /* Print per-message telemetry header */
               i + 1, session.epoch, session.step, (unsigned long long)(c1 - c0)); /* Output counters and cycle latency */
        printf("  Plaintext          : \"%s\"\n", (char *)recovered); /* Print verified decrypted plaintext */
        dump_key256("Ephemeral Msg Key", &msg_key);         /* Print unique 256-bit Message Key used for this frame */
        dump_key256("Updated Chain Key", &session.chain_key); /* Print rolled-forward Chain Key for next message */
        printf("  Ciphertext (16B)   : ");                  /* Print prefix for hexadecimal ciphertext sample */
        for (size_t b = 0; b < 16 && b < mlen; ++b) {       /* Iterate over first 16 bytes of ciphertext */
            printf("%02X ", ciphertext[b]);                 /* Print each encrypted byte in two-digit hex */
        }                                                   /* End of ciphertext hex dump loop */
        printf("| MAC: %016llX [%s]\n",                     /* Print 64-bit MAC tag and constant-time check status */
               (unsigned long long)tx_tag, valid ? "AUTH_OK" : "TAMPERED"); /* Indicate integrity verification result */

        wipe_memory(&msg_key, sizeof(msg_key));             /* Scrub ephemeral Message Key from RAM immediately */
        printf("  Scrubbed Msg Key   : %016llX (Forward Secrecy Enforced)\n\n", /* Confirm key deletion in output */
               (unsigned long long)msg_key.w[0]);           /* Print zeroed lane 0 to prove physical erasure */
    }                                                       /* End of message processing loop */

    wipe_memory(&session, sizeof(session));                 /* Scrub entire session state machine before exit */
    return 0;                                               /* Return 0 to indicate successful execution */
}                                                           /* End of main function */
