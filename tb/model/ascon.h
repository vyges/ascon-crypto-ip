// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// Ascon-AEAD128 (NIST SP 800-232) — C golden reference model.
//
// This is the software reference against which the SystemVerilog RTL
// (rtl/ascon_*.sv) is differentially fuzzed and known-answer tested. Written
// clean-room from the NIST SP 800-232 specification; the algorithm and its
// constants are a public standard (reference implementations are CC0).

#ifndef VYGES_ASCON_H
#define VYGES_ASCON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASCON_KEY_BYTES   16
#define ASCON_NONCE_BYTES 16
#define ASCON_TAG_BYTES   16

// Authenticated encryption. Writes ciphertext (same length as plaintext) to
// `ct` and the 16-byte authentication tag to `tag`.
void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_TAG_BYTES],
                           const uint8_t key[ASCON_KEY_BYTES],
                           const uint8_t nonce[ASCON_NONCE_BYTES],
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t *pt, size_t pt_len);

// Authenticated decryption. Writes plaintext to `pt`. Returns 0 on tag
// success, -1 on tag mismatch (in which case `pt` must be discarded).
int ascon_aead128_decrypt(uint8_t *pt,
                          const uint8_t key[ASCON_KEY_BYTES],
                          const uint8_t nonce[ASCON_NONCE_BYTES],
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t *ct, size_t ct_len,
                          const uint8_t tag[ASCON_TAG_BYTES]);

// Bare 320-bit permutation over 5x64-bit words, `rounds` rounds (12 or 8).
// Exposed so the RTL permutation datapath can be KAT'd against it directly.
void ascon_permutation(uint64_t s[5], int rounds);

#ifdef __cplusplus
}
#endif

#endif // VYGES_ASCON_H
