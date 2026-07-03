# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Vyges (https://vyges.com)
#
# Ascon-AEAD128 (NIST SP 800-232) Python golden reference. Mirrors the C model
# (tb/model/ascon.c) and is validated the same way — against the official NIST
# known-answer vectors. Used by the cocotb testbench as the differential oracle.

MASK = (1 << 64) - 1
IV = 0x00001000808C0001
RATE = 16


def _rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def permutation(s, rounds):
    x0, x1, x2, x3, x4 = s
    for r in range(12 - rounds, 12):
        x2 ^= (0xF0 - r * 0x0F)
        # substitution layer
        x0 ^= x4; x4 ^= x3; x2 ^= x1
        t0 = (~x0 & MASK) & x1
        t1 = (~x1 & MASK) & x2
        t2 = (~x2 & MASK) & x3
        t3 = (~x3 & MASK) & x4
        t4 = (~x4 & MASK) & x0
        x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0
        x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 ^= MASK
        # linear diffusion
        x0 ^= _rotr(x0, 19) ^ _rotr(x0, 28)
        x1 ^= _rotr(x1, 61) ^ _rotr(x1, 39)
        x2 ^= _rotr(x2, 1) ^ _rotr(x2, 6)
        x3 ^= _rotr(x3, 10) ^ _rotr(x3, 17)
        x4 ^= _rotr(x4, 7) ^ _rotr(x4, 41)
    return [x0 & MASK, x1 & MASK, x2 & MASK, x3 & MASK, x4 & MASK]


def _ld(b):
    return int.from_bytes(b, "little")


def _st(x):
    return int(x & MASK).to_bytes(8, "little")


def _init(key, nonce):
    k0, k1 = _ld(key[0:8]), _ld(key[8:16])
    s = [IV, k0, k1, _ld(nonce[0:8]), _ld(nonce[8:16])]
    s = permutation(s, 12)
    s[3] ^= k0
    s[4] ^= k1
    return s, k0, k1


def _absorb_ad(s, ad):
    if not ad:
        return
    off = 0
    while len(ad) - off >= RATE:
        s[0] ^= _ld(ad[off:off + 8]); s[1] ^= _ld(ad[off + 8:off + 16])
        s[:] = permutation(s, 8)
        off += RATE
    blk = bytearray(RATE)
    blk[:len(ad) - off] = ad[off:]
    blk[len(ad) - off] = 0x01
    s[0] ^= _ld(blk[0:8]); s[1] ^= _ld(blk[8:16])
    s[:] = permutation(s, 8)


def encrypt(key, nonce, ad, pt):
    s, k0, k1 = _init(key, nonce)
    _absorb_ad(s, ad)
    s[4] ^= 1 << 63  # domain separation
    ct = bytearray()
    off = 0
    while len(pt) - off >= RATE:
        s[0] ^= _ld(pt[off:off + 8]); s[1] ^= _ld(pt[off + 8:off + 16])
        ct += _st(s[0]) + _st(s[1])
        s[:] = permutation(s, 8)
        off += RATE
    rem = len(pt) - off
    blk = bytearray(RATE)
    blk[:rem] = pt[off:]
    blk[rem] = 0x01
    s[0] ^= _ld(blk[0:8]); s[1] ^= _ld(blk[8:16])
    ct += (_st(s[0]) + _st(s[1]))[:rem]
    s[2] ^= k0; s[3] ^= k1
    s[:] = permutation(s, 12)
    tag = _st(s[3] ^ k0) + _st(s[4] ^ k1)
    return bytes(ct), bytes(tag)
