# Ascon-AEAD128 — design notes

Implementation of Ascon-AEAD128 (NIST SP 800-232) targeting ASIC/FPGA.

## Algorithm parameters

| Parameter | Value |
| --- | --- |
| Key / nonce / tag | 128 bits each |
| State | 320 bits (5 × 64-bit lanes `x0..x4`) |
| Rate | 128 bits (`x0`, `x1`) |
| Init / finalize permutation | `p^12` (12 rounds) |
| Data permutation | `p^8` (8 rounds) |
| IV (loaded into `x0`) | `0x00001000808c0001` |

Bytes are little-endian within a lane (`byte 0 = bits [7:0]`), matching the
golden models' `load64`/`store64`.

## Microarchitecture

- **`ascon_pkg`** — the round function `ascon_round` (constant addition, bitsliced
  5-bit S-box, linear diffusion), round-constant and rotate helpers.
- **`ascon_perm`** — iterative permutation: one round per clock over a single
  round datapath, with a `start`/`done` handshake. An `n`-round run starts at
  global round index `12 - n` so the last round always uses constant `0x4b`.
  Area-efficient (one round of combinational logic) at ~`n` cycles per call.
- **`ascon_core`** — the AEAD control FSM and datapath. Sequences:
  `INIT (p^12) → key-XOR → [absorb AD, p^8]* → domain-sep → [process msg, p^8]* →
  key-XOR → finalize (p^12) → tag`. Padding (`10*`) and partial-block masking for
  the final block are applied internally from each block's `bytes` count; encrypt
  squeezes ciphertext from the rate, decrypt recovers plaintext and reconstructs
  the rate from the ciphertext bytes.

The single-round datapath trades throughput for area; the roadmap includes
unrolled 2-/4-rounds-per-cycle variants for higher throughput.

## Latency (approximate, cycles)

| Phase | Cost |
| --- | --- |
| Init | ~13 (p^12 + key-XOR) |
| Each AD block | ~9 (absorb + p^8) |
| Each message block | ~9 (process + p^8) |
| Finalize | ~13 (key-XOR + p^12) |

## Verification

Golden-model + differential methodology (see README):
- C and Python golden models, each validated against the official NIST vectors.
- RTL differentially fuzzed against the golden model (Verilator, C++) and driven
  against NIST vectors + random inputs (cocotb).
- Every case checks encrypt, decrypt round-trip, and corrupted-tag rejection over
  empty / partial / multi-block AD and message lengths.

## References

- NIST SP 800-232 — <https://csrc.nist.gov/pubs/sp/800/232/final>
- Ascon reference distribution — <https://github.com/ascon/ascon-c>
