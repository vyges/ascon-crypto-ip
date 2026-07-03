# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Vyges (https://vyges.com)
#
# cocotb testbench for ascon_core (Ascon-AEAD128). Two verification modes,
# matching the simon-cipher methodology:
#   - NIST known-answer conformance: drive the DUT with official SP 800-232
#     vectors (tb/vectors/) and check ciphertext+tag byte-for-byte.
#   - Randomized differential: compare DUT encrypt/decrypt against the Python
#     golden reference (ascon_ref.py) across empty/partial/multi-block lengths,
#     plus corrupted-tag rejection.

import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

import ascon_ref

VEC = os.path.join(os.path.dirname(__file__), "..", "vectors", "LWC_AEAD_KAT_128_128.txt")


def segment(data):
    """Split a byte stream into rate blocks: (data128, nbytes, last). A final
    block (nbytes = len%16) is always appended per the Ascon 10* rule."""
    blocks = []
    full = len(data) // 16
    for i in range(full):
        b = data[i * 16:(i + 1) * 16]
        blocks.append((int.from_bytes(b, "little"), 16, False))
    rem = data[full * 16:]
    b = bytes(rem) + bytes(16 - len(rem))
    blocks.append((int.from_bytes(b, "little"), len(rem), False))
    v, n, _ = blocks[-1]
    blocks[-1] = (v, n, True)
    return blocks


async def reset(dut):
    dut.rst_ni.value = 0
    dut.start_i.value = 0
    dut.ad_valid_i.value = 0
    dut.msg_valid_i.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk_i)
    dut.rst_ni.value = 1
    await RisingEdge(dut.clk_i)


async def run_op(dut, decrypt, key, nonce, ad, msg, exp_tag=b"\x00" * 16):
    """Drive one AEAD operation; return (output_bytes, tag_int, tag_ok)."""
    adb = segment(ad) if len(ad) > 0 else []
    mgb = segment(msg)

    dut.decrypt_i.value = 1 if decrypt else 0
    dut.ad_empty_i.value = 1 if len(ad) == 0 else 0
    dut.key_i.value = int.from_bytes(key, "little")
    dut.npub_i.value = int.from_bytes(nonce, "little")
    dut.exp_tag_i.value = int.from_bytes(exp_tag, "little")
    dut.ad_valid_i.value = 0
    dut.msg_valid_i.value = 0

    await RisingEdge(dut.clk_i)
    dut.start_i.value = 1
    await RisingEdge(dut.clk_i)
    dut.start_i.value = 0

    ai = mi = 0
    out = bytearray()
    for _ in range(30000):
        await Timer(1, "ns")  # settle combinational after the edge
        if int(dut.done_o.value) == 1:
            tag = int(dut.tag_o.value)
            tok = int(dut.tag_ok_o.value)
            return bytes(out), tag, tok

        ad_fire = msg_fire = False
        if int(dut.ad_ready_o.value) == 1 and ai < len(adb):
            v, nb, last = adb[ai]
            dut.ad_valid_i.value = 1
            dut.ad_data_i.value = v
            dut.ad_bytes_i.value = nb
            dut.ad_last_i.value = 1 if last else 0
            ad_fire = True
        else:
            dut.ad_valid_i.value = 0

        if int(dut.msg_ready_o.value) == 1 and mi < len(mgb):
            v, nb, last = mgb[mi]
            dut.msg_valid_i.value = 1
            dut.msg_data_i.value = v
            dut.msg_bytes_i.value = nb
            dut.msg_last_i.value = 1 if last else 0
            msg_fire = True
        else:
            dut.msg_valid_i.value = 0

        await Timer(1, "ns")  # settle with valids asserted
        if msg_fire and int(dut.msg_valid_o.value) == 1:
            word = int(dut.msg_data_o.value).to_bytes(16, "little")
            out += word[:int(dut.msg_bytes_o.value)]
        if ad_fire:
            ai += 1
        if msg_fire:
            mi += 1

        await RisingEdge(dut.clk_i)  # consuming edge for the block just driven
    raise cocotb.result.TestFailure("run_op timeout")


def parse_kat(path):
    recs, cur = [], {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("Count"):
                cur = {}
            elif "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                cur[k] = bytes.fromhex(v) if v else b""
                if k == "CT":
                    recs.append(cur)
    return recs


@cocotb.test()
async def test_nist_kat(dut):
    """Official NIST SP 800-232 Ascon-AEAD128 known-answer conformance."""
    cocotb.start_soon(Clock(dut.clk_i, 10, units="ns").start())
    await reset(dut)
    recs = parse_kat(VEC)
    # stride across the full file so all AD/PT length shapes are exercised
    sample = recs[::25]
    for i, r in enumerate(sample):
        pt, ad, exp = r["PT"], r["AD"], r["CT"]
        ct_exp, tag_exp = exp[:len(pt)], exp[len(pt):]
        out, tag, _ = await run_op(dut, False, r["Key"], r["Nonce"], ad, pt)
        tag_b = tag.to_bytes(16, "little")
        assert out == ct_exp, f"KAT {i}: ct {out.hex()} != {ct_exp.hex()}"
        assert tag_b == tag_exp, f"KAT {i}: tag {tag_b.hex()} != {tag_exp.hex()}"
        # decrypt our own ciphertext -> recover pt, tag must verify
        rec, _, tok = await run_op(dut, True, r["Key"], r["Nonce"], ad, ct_exp, tag_exp)
        assert tok == 1 and rec == pt, f"KAT {i}: decrypt/tag failed"
    dut._log.info(f"NIST KAT: {len(sample)} vectors passed")


@cocotb.test()
async def test_random_diff(dut):
    """Randomized differential vs the Python golden reference."""
    cocotb.start_soon(Clock(dut.clk_i, 10, units="ns").start())
    await reset(dut)
    rng = random.Random(0xA5C0)
    N = 300
    for t in range(N):
        adlen = rng.randint(0, 48)
        ptlen = rng.randint(0, 48)
        key = bytes(rng.randrange(256) for _ in range(16))
        nonce = bytes(rng.randrange(256) for _ in range(16))
        ad = bytes(rng.randrange(256) for _ in range(adlen))
        pt = bytes(rng.randrange(256) for _ in range(ptlen))
        ct_ref, tag_ref = ascon_ref.encrypt(key, nonce, ad, pt)

        out, tag, _ = await run_op(dut, False, key, nonce, ad, pt)
        assert out == ct_ref, f"trial {t}: ct mismatch (ad={adlen} pt={ptlen})"
        assert tag.to_bytes(16, "little") == tag_ref, f"trial {t}: tag mismatch"

        rec, _, tok = await run_op(dut, True, key, nonce, ad, ct_ref, tag_ref)
        assert tok == 1 and rec == pt, f"trial {t}: decrypt mismatch"
    dut._log.info(f"Random differential: {N} trials passed")


@cocotb.test()
async def test_tag_reject(dut):
    """A corrupted tag must be rejected on decrypt (tag_ok = 0)."""
    cocotb.start_soon(Clock(dut.clk_i, 10, units="ns").start())
    await reset(dut)
    key = bytes(range(16))
    nonce = bytes(range(0x10, 0x20))
    ad = b"\x30\x31\x32"
    pt = b"hello ascon vyges!!"
    ct, tag = ascon_ref.encrypt(key, nonce, ad, pt)
    bad = bytearray(tag)
    bad[0] ^= 0x01
    _, _, tok = await run_op(dut, True, key, nonce, ad, ct, bytes(bad))
    assert tok == 0, "corrupted tag was accepted"
    dut._log.info("Tag rejection: OK")
