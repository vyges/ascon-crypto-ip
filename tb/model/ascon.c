// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// Ascon-AEAD128 (NIST SP 800-232) — C golden reference model.
// See ascon.h. Clean-room from the spec; parameters: rate = 128 bits,
// init/final permutation p^12, data permutation p^8, 128-bit key/nonce/tag.

#include "ascon.h"
#include <string.h>

// Ascon-AEAD128 IV (little-endian load of the parameter bytes
// [ver=1, 0, (b<<4)|a=0x8c, taglen=0x0080 LE, rate=0x10, 0, 0]).
#define ASCON_IV 0x00001000808c0001ULL

#define ASCON_RATE_BYTES 16
#define ROUNDS_A 12
#define ROUNDS_B 8

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

// Little-endian load/store of a 64-bit word from/to a byte buffer.
static inline uint64_t load64(const uint8_t *b) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= (uint64_t)b[i] << (8 * i);
    return x;
}
static inline void store64(uint8_t *b, uint64_t x) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(x >> (8 * i));
}

void ascon_permutation(uint64_t s[5], int rounds) {
    uint64_t x0 = s[0], x1 = s[1], x2 = s[2], x3 = s[3], x4 = s[4];
    for (int r = 12 - rounds; r < 12; r++) {
        // round constant into x2
        x2 ^= (uint64_t)(0xf0 - r * 0x0f);
        // substitution layer (bitsliced 5-bit S-box)
        uint64_t t0, t1, t2, t3, t4;
        x0 ^= x4; x4 ^= x3; x2 ^= x1;
        t0 = ~x0; t1 = ~x1; t2 = ~x2; t3 = ~x3; t4 = ~x4;
        t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;
        // linear diffusion layer
        x0 ^= rotr64(x0, 19) ^ rotr64(x0, 28);
        x1 ^= rotr64(x1, 61) ^ rotr64(x1, 39);
        x2 ^= rotr64(x2, 1)  ^ rotr64(x2, 6);
        x3 ^= rotr64(x3, 10) ^ rotr64(x3, 17);
        x4 ^= rotr64(x4, 7)  ^ rotr64(x4, 41);
    }
    s[0] = x0; s[1] = x1; s[2] = x2; s[3] = x3; s[4] = x4;
}

// Initialize the state from key+nonce and run the init permutation + key XOR.
static void init_state(uint64_t s[5], const uint8_t *key, const uint8_t *nonce) {
    uint64_t k0 = load64(key), k1 = load64(key + 8);
    s[0] = ASCON_IV;
    s[1] = k0;
    s[2] = k1;
    s[3] = load64(nonce);
    s[4] = load64(nonce + 8);
    ascon_permutation(s, ROUNDS_A);
    s[3] ^= k0;
    s[4] ^= k1;
}

// Absorb associated data (with 10* padding); domain-separation bit is applied
// by the caller after this returns.
static void absorb_ad(uint64_t s[5], const uint8_t *ad, size_t ad_len) {
    if (ad_len == 0) return;
    while (ad_len >= ASCON_RATE_BYTES) {
        s[0] ^= load64(ad);
        s[1] ^= load64(ad + 8);
        ascon_permutation(s, ROUNDS_B);
        ad += ASCON_RATE_BYTES;
        ad_len -= ASCON_RATE_BYTES;
    }
    // final padded block: remaining bytes + 0x01 + zeros
    uint8_t blk[ASCON_RATE_BYTES] = {0};
    memcpy(blk, ad, ad_len);
    blk[ad_len] = 0x01;
    s[0] ^= load64(blk);
    s[1] ^= load64(blk + 8);
    ascon_permutation(s, ROUNDS_B);
}

void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_TAG_BYTES],
                           const uint8_t key[ASCON_KEY_BYTES],
                           const uint8_t nonce[ASCON_NONCE_BYTES],
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t *pt, size_t pt_len) {
    uint64_t s[5];
    uint64_t k0 = load64(key), k1 = load64(key + 8);
    init_state(s, key, nonce);
    absorb_ad(s, ad, ad_len);
    s[4] ^= 0x8000000000000000ULL; // domain separation

    // plaintext: full blocks (squeeze ciphertext), then padded final block
    while (pt_len >= ASCON_RATE_BYTES) {
        s[0] ^= load64(pt);
        s[1] ^= load64(pt + 8);
        store64(ct, s[0]);
        store64(ct + 8, s[1]);
        ascon_permutation(s, ROUNDS_B);
        pt += ASCON_RATE_BYTES;
        ct += ASCON_RATE_BYTES;
        pt_len -= ASCON_RATE_BYTES;
    }
    uint8_t blk[ASCON_RATE_BYTES] = {0};
    memcpy(blk, pt, pt_len);
    blk[pt_len] = 0x01;
    s[0] ^= load64(blk);
    s[1] ^= load64(blk + 8);
    uint8_t out[ASCON_RATE_BYTES];
    store64(out, s[0]);
    store64(out + 8, s[1]);
    memcpy(ct, out, pt_len); // only the real bytes

    // finalization
    s[2] ^= k0;
    s[3] ^= k1;
    ascon_permutation(s, ROUNDS_A);
    store64(tag, s[3] ^ k0);
    store64(tag + 8, s[4] ^ k1);
}

int ascon_aead128_decrypt(uint8_t *pt,
                          const uint8_t key[ASCON_KEY_BYTES],
                          const uint8_t nonce[ASCON_NONCE_BYTES],
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t *ct, size_t ct_len,
                          const uint8_t tag[ASCON_TAG_BYTES]) {
    uint64_t s[5];
    uint64_t k0 = load64(key), k1 = load64(key + 8);
    init_state(s, key, nonce);
    absorb_ad(s, ad, ad_len);
    s[4] ^= 0x8000000000000000ULL;

    while (ct_len >= ASCON_RATE_BYTES) {
        uint64_t c0 = load64(ct), c1 = load64(ct + 8);
        store64(pt, s[0] ^ c0);
        store64(pt + 8, s[1] ^ c1);
        s[0] = c0;
        s[1] = c1;
        ascon_permutation(s, ROUNDS_B);
        pt += ASCON_RATE_BYTES;
        ct += ASCON_RATE_BYTES;
        ct_len -= ASCON_RATE_BYTES;
    }
    // final partial block: recover plaintext, then inject c || pad into rate
    uint8_t sr[ASCON_RATE_BYTES];
    store64(sr, s[0]);
    store64(sr + 8, s[1]);
    for (size_t i = 0; i < ct_len; i++) pt[i] = sr[i] ^ ct[i];
    // rebuild the rate lanes: real ct bytes, padding bit, keep state elsewhere
    uint8_t blk[ASCON_RATE_BYTES];
    memcpy(blk, sr, ASCON_RATE_BYTES);   // start from current rate bytes
    for (size_t i = 0; i < ct_len; i++) blk[i] = ct[i];
    blk[ct_len] ^= 0x01;                 // flip padding bit relative to sr
    s[0] = load64(blk);
    s[1] = load64(blk + 8);

    s[2] ^= k0;
    s[3] ^= k1;
    ascon_permutation(s, ROUNDS_A);
    uint8_t t[ASCON_TAG_BYTES];
    store64(t, s[3] ^ k0);
    store64(t + 8, s[4] ^ k1);

    // constant-time-ish tag compare
    uint8_t diff = 0;
    for (int i = 0; i < ASCON_TAG_BYTES; i++) diff |= t[i] ^ tag[i];
    return diff ? -1 : 0;
}
