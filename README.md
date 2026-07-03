# ascon-crypto-ip — Ascon-AEAD128 (NIST SP 800-232)

A clean-room, silicon-targeted implementation of **Ascon-AEAD128**, the
authenticated-encryption mode of the NIST lightweight cryptography standard
([SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final)). Ascon is NIST's
selected lightweight AEAD for constrained devices — IoT, embedded, and low-power
sensor SoCs — making it a natural fit for secure boot, firmware confidentiality,
and on-die data protection.

- **Cipher:** Ascon-AEAD128 — 128-bit key, nonce, and tag; 128-bit rate;
  init/final permutation `p^12`, data permutation `p^8`.
- **RTL:** parameterized SystemVerilog, single-round iterative permutation
  datapath (area-efficient), streaming block interface for arbitrary-length
  associated data and message.
- **License:** Apache-2.0. The algorithm is a public standard; this RTL and the
  models are an independent clean-room implementation.

## Verification

Verified with the **golden-model + differential-fuzz** methodology — a C/Python
reference cross-checked against the official NIST vectors, and the RTL
differentially compared against it:

| Harness | What it checks | Result |
| --- | --- | --- |
| C golden model KAT (`make model-kat`) | Reference vs **all 1089 official NIST vectors** (encrypt, decrypt, tag reject) | 1089/1089 |
| Verilator differential fuzz (`make fuzz`) | RTL vs golden model, 4000 randomized trials + NIST Count 1 | 4001 pass, 0 fail |
| cocotb (`make cocotb`) | RTL vs NIST KAT sample + 300 random-diff + tag rejection | 3/3 tests pass |

Every trial exercises encrypt, decrypt round-trip, and corrupted-tag rejection
across empty, partial, and multi-block associated-data / message lengths.

```sh
make test     # golden-model KAT + Verilator differential fuzz + lint
make cocotb   # cocotb testbench (needs cocotb + a simulator, e.g. Verilator)
```

## Interface (`rtl/ascon_core.sv`)

Data is presented as 128-bit rate blocks `{lane1, lane0}` (lane0 = the first 8
bytes, little-endian). The driver segments associated data and message into
blocks and, per the Ascon 10\* padding rule, appends a final block with
`bytes = 0` when a stream length is a multiple of 16 (an empty message still has
one such block; empty AD has none — signalled by `ad_empty_i`). The core applies
padding and partial-block masking internally from each block's `bytes` count.

| Signal | Dir | Description |
| --- | --- | --- |
| `clk_i`, `rst_ni` | in | clock, active-low reset |
| `start_i`, `decrypt_i`, `ad_empty_i` | in | start pulse; mode; no-AD flag (latched) |
| `key_i[127:0]`, `npub_i[127:0]` | in | key `{key1,key0}`, nonce `{n1,n0}` |
| `exp_tag_i[127:0]` | in | expected tag (decrypt verification) |
| `ad_*`, `msg_*` | in/out | AD and message block streams (valid/ready/data/bytes/last) |
| `msg_data_o`, `msg_bytes_o`, `msg_valid_o` | out | ciphertext (enc) / plaintext (dec) |
| `done_o`, `tag_o[127:0]`, `tag_ok_o` | out | completion, computed tag, decrypt tag-match |

## Structure

```
rtl/          ascon_pkg.sv, ascon_perm.sv, ascon_core.sv   — synthesizable RTL
tb/cocotb/    test_ascon_core.py, ascon_ref.py, Makefile   — cocotb testbench
tb/model/     ascon.c/.h, kat_test.c                        — C golden model + KAT
tb/verilator/ tb_ascon_core.cpp                             — C++ differential fuzzer
tb/vectors/   LWC_AEAD_KAT_128_128.txt                      — official NIST vectors
flow/         synthesis / FPGA / simulation flows
docs/         design and architecture notes
```

## Roadmap

- Ascon-Hash256 / Ascon-XOF128 / Ascon-CXOF128 (share the permutation datapath).
- Register/bus wrapper (APB/AXI-Lite) for drop-in SoC integration.
- Throughput variants: unrolled 2- and 4-rounds/cycle permutation.
- Side-channel-hardened (masked) permutation option.

## References

- NIST SP 800-232, *Ascon-Based Lightweight Cryptography Standards for
  Constrained Devices* — <https://csrc.nist.gov/pubs/sp/800/232/final>
- Ascon reference distribution — <https://github.com/ascon/ascon-c>
