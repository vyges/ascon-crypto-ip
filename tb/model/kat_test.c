// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// Known-answer test for the Ascon-AEAD128 golden model. Parses the official
// NIST LWC KAT file (Count/Key/Nonce/PT/AD/CT) and checks, for every vector:
//   - encrypt(pt, ad) == expected ct||tag
//   - decrypt of our own ct||tag recovers pt with a valid tag
//   - a corrupted tag is rejected
// Usage: kat_test <LWC_AEAD_KAT_128_128.txt>

#include "ascon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Decode a hex field after "Name = " into buf; returns byte length.
static size_t hexdecode(const char *line, const char *key, uint8_t *buf) {
    const char *p = strstr(line, key);
    if (!p) return (size_t)-1;
    p += strlen(key);
    while (*p == ' ') p++;
    size_t n = 0;
    while (hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
        buf[n++] = (uint8_t)((hexval(p[0]) << 4) | hexval(p[1]));
        p += 2;
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <kat.txt>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("fopen"); return 2; }

    char line[8192];
    uint8_t key[16], nonce[16], pt[4096], ad[4096], ct_exp[4096 + 16];
    uint8_t ct[4096 + 16], tag[16], rec[4096];
    size_t pt_len = 0, ad_len = 0, ct_len = 0;
    int have_key = 0, have_nonce = 0, count = 0, pass = 0, fail = 0;

    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "Key = "))   { hexdecode(line, "Key = ", key);   have_key = 1; }
        else if (strstr(line, "Nonce = ")) { hexdecode(line, "Nonce = ", nonce); have_nonce = 1; }
        else if (strstr(line, "PT = "))    { pt_len = hexdecode(line, "PT = ", pt); }
        else if (strstr(line, "AD = "))    { ad_len = hexdecode(line, "AD = ", ad); }
        else if (strstr(line, "CT = ")) {
            ct_len = hexdecode(line, "CT = ", ct_exp);
            if (!have_key || !have_nonce) continue;
            count++;
            int ok = 1;

            // encrypt and compare against expected ct||tag
            ascon_aead128_encrypt(ct, tag, key, nonce, ad, ad_len, pt, pt_len);
            if (ct_len != pt_len + 16) ok = 0;
            if (ok && memcmp(ct, ct_exp, pt_len) != 0) ok = 0;
            if (ok && memcmp(tag, ct_exp + pt_len, 16) != 0) ok = 0;

            // decrypt our own output -> must recover pt with a valid tag
            if (ascon_aead128_decrypt(rec, key, nonce, ad, ad_len, ct, pt_len, tag) != 0) ok = 0;
            if (ok && memcmp(rec, pt, pt_len) != 0) ok = 0;

            // a flipped tag bit must be rejected
            uint8_t bad[16];
            memcpy(bad, tag, 16); bad[0] ^= 1;
            if (ascon_aead128_decrypt(rec, key, nonce, ad, ad_len, ct, pt_len, bad) == 0) ok = 0;

            if (ok) pass++;
            else { fail++; if (fail <= 5) fprintf(stderr, "FAIL vector near count %d (pt=%zu ad=%zu)\n", count, pt_len, ad_len); }
        }
    }
    fclose(f);
    printf("Ascon-AEAD128 golden-model KAT: %d/%d passed, %d failed\n", pass, count, fail);
    return fail ? 1 : 0;
}
