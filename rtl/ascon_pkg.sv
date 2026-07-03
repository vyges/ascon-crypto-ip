// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// ascon_pkg — shared parameters and the Ascon permutation round function for
// the Ascon-AEAD128 core (NIST SP 800-232).
//
// State packing: the 320-bit state is {x4, x3, x2, x1, x0} with x0 in the low
// 64 bits. Each xN is a 64-bit lane; bytes are little-endian within a lane
// (byte 0 = bits [7:0]), matching the golden model's load64/store64.

package ascon_pkg;

  // Ascon-AEAD128 initialization vector (little-endian load of the NIST
  // parameter bytes {ver=1, 0, (b<<4)|a=0x8c, taglen=0x0080 LE, rate=0x10,0,0}).
  localparam logic [63:0] ASCON_IV = 64'h00001000808c0001;

  localparam int unsigned ASCON_A_ROUNDS  = 12; // init / finalization
  localparam int unsigned ASCON_B_ROUNDS  = 8;  // associated data / message
  localparam int unsigned ASCON_RATE_BYTES = 16;

  // Round constant added to x2 in global round `idx` (0..11): 0xf0 - 0x0f*idx.
  function automatic logic [7:0] ascon_rc(input logic [3:0] idx);
    ascon_rc = 8'hf0 - (idx * 8'h0f);
  endfunction

  // 64-bit rotate right.
  function automatic logic [63:0] ascon_rotr(input logic [63:0] x, input int unsigned n);
    ascon_rotr = (x >> n) | (x << (64 - n));
  endfunction

  // One Ascon permutation round: add round constant, substitution layer
  // (bitsliced 5-bit S-box), linear diffusion layer.
  function automatic logic [319:0] ascon_round(input logic [319:0] state,
                                               input logic [7:0]   rc);
    logic [63:0] x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;
    {x4, x3, x2, x1, x0} = state;

    // p_C : add round constant to x2
    x2 ^= {56'b0, rc};

    // p_S : substitution (bitsliced S-box)
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    t0 = ~x0; t1 = ~x1; t2 = ~x2; t3 = ~x3; t4 = ~x4;
    t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

    // p_L : linear diffusion
    x0 ^= ascon_rotr(x0, 19) ^ ascon_rotr(x0, 28);
    x1 ^= ascon_rotr(x1, 61) ^ ascon_rotr(x1, 39);
    x2 ^= ascon_rotr(x2, 1)  ^ ascon_rotr(x2, 6);
    x3 ^= ascon_rotr(x3, 10) ^ ascon_rotr(x3, 17);
    x4 ^= ascon_rotr(x4, 7)  ^ ascon_rotr(x4, 41);

    ascon_round = {x4, x3, x2, x1, x0};
  endfunction

endpackage
