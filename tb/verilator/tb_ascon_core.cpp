// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// Differential fuzzer + KAT harness for ascon_core (Ascon-AEAD128).
// Drives the SystemVerilog DUT and compares every ciphertext/plaintext/tag
// against the C golden model (model/ascon.c), across randomized AD/PT lengths
// (including empty, partial, and multi-block), for both encrypt and decrypt,
// plus a corrupted-tag rejection check and a hard-coded NIST vector.

#include "Vascon_core.h"
#include "verilated.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" {
#include "ascon.h"
}

using std::vector;

static uint64_t ld64(const uint8_t *b) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= (uint64_t)b[i] << (8 * i);
    return x;
}
static void st64(uint8_t *b, uint64_t x) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(x >> (8 * i));
}
template <class W> static void put128(W &w, uint64_t lo, uint64_t hi) {
    w[0] = (uint32_t)lo; w[1] = (uint32_t)(lo >> 32);
    w[2] = (uint32_t)hi; w[3] = (uint32_t)(hi >> 32);
}
template <class W> static void get128(const W &w, uint64_t &lo, uint64_t &hi) {
    lo = ((uint64_t)w[1] << 32) | w[0];
    hi = ((uint64_t)w[3] << 32) | w[2];
}

struct Blk { uint64_t lo, hi; uint8_t bytes; bool last; };

// Segment a byte stream into rate blocks per the Ascon 10* rule: a final block
// (bytes = len%16) is always appended, so a multiple-of-16 length ends in a
// pad-only block (bytes=0). Empty streams yield one such block; the caller
// drops the AD list entirely when AD is empty.
static vector<Blk> segment(const uint8_t *d, size_t len) {
    vector<Blk> v;
    size_t off = 0;
    size_t full = len / 16;
    for (size_t i = 0; i < full; i++, off += 16) {
        uint8_t buf[16]; memcpy(buf, d + off, 16);
        v.push_back({ld64(buf), ld64(buf + 8), 16, false});
    }
    uint8_t buf[16] = {0};
    size_t rem = len - off;
    memcpy(buf, d + off, rem);
    v.push_back({ld64(buf), ld64(buf + 8), (uint8_t)rem, true});
    for (auto &b : v) b.last = false;
    v.back().last = true;
    return v;
}

static void tick(Vascon_core *d) {
    d->clk_i = 1; d->eval();
    d->clk_i = 0; d->eval();
}

// Run one AEAD op on the DUT. For encrypt, msg=PT and out=CT; for decrypt,
// msg=CT and out=PT. Returns tag (encrypt) or leaves tag_ok in *tok (decrypt).
static void run_dut(Vascon_core *d, bool decrypt,
                    const uint8_t key[16], const uint8_t nonce[16],
                    const uint8_t *ad, size_t adlen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t exp_tag[16],
                    uint8_t *out, size_t outlen, uint8_t out_tag[16], int *tok) {
    vector<Blk> adb = (adlen > 0) ? segment(ad, adlen) : vector<Blk>();
    vector<Blk> mgb = segment(msg, msglen);

    d->start_i = 0; d->ad_valid_i = 0; d->msg_valid_i = 0;
    d->decrypt_i = decrypt; d->ad_empty_i = (adlen == 0);
    put128(d->key_i, ld64(key), ld64(key + 8));
    put128(d->npub_i, ld64(nonce), ld64(nonce + 8));
    put128(d->exp_tag_i, exp_tag ? ld64(exp_tag) : 0, exp_tag ? ld64(exp_tag + 8) : 0);
    d->eval();
    // pulse start while in IDLE
    d->start_i = 1; tick(d); d->start_i = 0;

    size_t ai = 0, mi = 0, oo = 0;
    *tok = 0;
    for (int cyc = 0; cyc < 20000; cyc++) {
        d->eval(); // settle combinational for this cycle's decisions

        d->ad_valid_i = 0; d->msg_valid_i = 0;
        bool ad_fire = false, msg_fire = false;
        if (d->ad_ready_o && ai < adb.size()) {
            d->ad_valid_i = 1;
            put128(d->ad_data_i, adb[ai].lo, adb[ai].hi);
            d->ad_bytes_i = adb[ai].bytes; d->ad_last_i = adb[ai].last;
            ad_fire = true;
        }
        if (d->msg_ready_o && mi < mgb.size()) {
            d->msg_valid_i = 1;
            put128(d->msg_data_i, mgb[mi].lo, mgb[mi].hi);
            d->msg_bytes_i = mgb[mi].bytes; d->msg_last_i = mgb[mi].last;
            msg_fire = true;
        }
        d->eval(); // settle with valids asserted

        if (msg_fire && d->msg_valid_o) {
            uint64_t lo, hi; get128(d->msg_data_o, lo, hi);
            uint8_t b[16]; st64(b, lo); st64(b + 8, hi);
            for (int i = 0; i < d->msg_bytes_o && oo < outlen; i++) out[oo++] = b[i];
        }
        if (d->done_o) {
            uint64_t lo, hi; get128(d->tag_o, lo, hi);
            if (out_tag) { st64(out_tag, lo); st64(out_tag + 8, hi); }
            *tok = d->tag_ok_o;
            tick(d); // consume S_DONE
            return;
        }
        tick(d);
        if (ad_fire) ai++;
        if (msg_fire) mi++;
    }
    fprintf(stderr, "DUT timeout\n");
}

static uint32_t rng_state = 0x1234abcdu;
static uint32_t rnd() { rng_state = rng_state * 1664525u + 1013904223u; return rng_state; }

int main(int argc, char **argv) {
    Verilated::commandArgs(argc, argv);
    Vascon_core *d = new Vascon_core;

    // reset
    d->rst_ni = 0; d->clk_i = 0;
    d->start_i = 0; d->ad_valid_i = 0; d->msg_valid_i = 0;
    for (int i = 0; i < 5; i++) tick(d);
    d->rst_ni = 1; tick(d);

    int pass = 0, fail = 0;

    // Hard NIST SP 800-232 vector (Count 1): empty AD/PT.
    {
        uint8_t key[16], nonce[16], tag[16], ct[1]; int tok;
        for (int i = 0; i < 16; i++) { key[i] = i; nonce[i] = 0x10 + i; }
        uint8_t exp[16] = {0x4F,0x9C,0x27,0x82,0x11,0xBE,0xC9,0x31,
                           0x6B,0xF6,0x8F,0x46,0xEE,0x8B,0x2E,0xC6};
        run_dut(d, false, key, nonce, nullptr, 0, nullptr, 0, nullptr, ct, 0, tag, &tok);
        if (memcmp(tag, exp, 16) == 0) { pass++; printf("NIST Count 1 vector: PASS\n"); }
        else { fail++; printf("NIST Count 1 vector: FAIL\n"); }
    }

    // Randomized differential fuzz vs the golden model.
    const int N = 4000;
    for (int t = 0; t < N; t++) {
        uint8_t key[16], nonce[16], ad[80], pt[80];
        size_t adlen = rnd() % 49;   // 0..48 : empty, partial, multi-block
        size_t ptlen = rnd() % 49;
        for (int i = 0; i < 16; i++) { key[i] = rnd(); nonce[i] = rnd(); }
        for (size_t i = 0; i < adlen; i++) ad[i] = rnd();
        for (size_t i = 0; i < ptlen; i++) pt[i] = rnd();

        uint8_t ct_ref[80], tag_ref[16];
        ascon_aead128_encrypt(ct_ref, tag_ref, key, nonce, ad, adlen, pt, ptlen);

        // DUT encrypt
        uint8_t ct_dut[80], tag_dut[16]; int tok;
        run_dut(d, false, key, nonce, ad, adlen, pt, ptlen, nullptr, ct_dut, ptlen, tag_dut, &tok);
        bool ok = (memcmp(ct_dut, ct_ref, ptlen) == 0) && (memcmp(tag_dut, tag_ref, 16) == 0);

        // DUT decrypt of the reference ciphertext -> recover pt, tag must verify
        uint8_t pt_dut[80]; int dtok;
        run_dut(d, true, key, nonce, ad, adlen, ct_ref, ptlen, tag_ref, pt_dut, ptlen, nullptr, &dtok);
        if (!(dtok == 1 && memcmp(pt_dut, pt, ptlen) == 0)) ok = false;

        // corrupted tag must be rejected
        uint8_t bad[16]; memcpy(bad, tag_ref, 16); bad[0] ^= 1;
        int btok;
        run_dut(d, true, key, nonce, ad, adlen, ct_ref, ptlen, bad, pt_dut, ptlen, nullptr, &btok);
        if (btok != 0) ok = false;

        if (ok) pass++;
        else {
            fail++;
            if (fail <= 5)
                fprintf(stderr, "FAIL trial %d (adlen=%zu ptlen=%zu)\n", t, adlen, ptlen);
        }
    }

    printf("ascon_core differential fuzz: %d passed, %d failed\n", pass, fail);
    d->final();
    delete d;
    return fail ? 1 : 0;
}
