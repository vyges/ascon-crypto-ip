// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// ascon_core — Ascon-AEAD128 (NIST SP 800-232) authenticated encryption /
// decryption core. Rate = 128 bits, init/final p^12, data p^8, 128-bit
// key/nonce/tag.
//
// Data is presented as 128-bit rate blocks {lane1, lane0}, lane0 = the first 8
// bytes (little-endian). The driver segments AD and message into blocks and,
// per the Ascon 10* padding rule, appends a final block with `bytes`=0 when a
// stream length is a multiple of 16 (an empty message still has one such
// block; empty AD has none — signal that with ad_empty_i). The core applies
// padding / partial-block masking internally from the per-block `bytes` count.

module ascon_core
  import ascon_pkg::*;
(
  input  logic         clk_i,
  input  logic         rst_ni,

  // Operation start (single-cycle pulse). Inputs latched on start.
  input  logic         start_i,
  input  logic         decrypt_i,   // 0 = encrypt, 1 = decrypt
  input  logic         ad_empty_i,  // 1 = no associated data at all
  input  logic [127:0] key_i,       // {key1, key0}
  input  logic [127:0] npub_i,      // {n1, n0}
  input  logic [127:0] exp_tag_i,   // expected tag (decrypt tag check)
  output logic         ready_o,     // high in IDLE

  // Associated-data block stream.
  input  logic         ad_valid_i,
  input  logic [127:0] ad_data_i,
  input  logic [4:0]   ad_bytes_i,  // 16 = full, 0..15 = last partial
  input  logic         ad_last_i,
  output logic         ad_ready_o,

  // Message block stream (pt for encrypt, ct for decrypt).
  input  logic         msg_valid_i,
  input  logic [127:0] msg_data_i,
  input  logic [4:0]   msg_bytes_i,
  input  logic         msg_last_i,
  output logic         msg_ready_o,
  output logic [127:0] msg_data_o,  // ct for encrypt, pt for decrypt
  output logic [4:0]   msg_bytes_o,
  output logic         msg_valid_o,

  // Result.
  output logic         done_o,      // pulse: tag_o / tag_ok_o valid
  output logic [127:0] tag_o,
  output logic         tag_ok_o
);

  // ---- byte-oriented helpers (little-endian within the 128-bit rate) --------

  // Encrypt padding of a partial/last plaintext block: real bytes kept, a 0x01
  // byte at position `nb`, zeros above.
  function automatic logic [127:0] pad_pt(input logic [127:0] d, input logic [4:0] nb);
    for (int i = 0; i < 16; i++) begin
      if (i < int'(nb))       pad_pt[8*i +: 8] = d[8*i +: 8];
      else if (i == int'(nb)) pad_pt[8*i +: 8] = 8'h01;
      else                    pad_pt[8*i +: 8] = 8'h00;
    end
  endfunction

  // Decrypt last block: recovered plaintext bytes (real bytes only, else 0).
  function automatic logic [127:0] dec_pt(input logic [127:0] rate,
                                          input logic [127:0] ct, input logic [4:0] nb);
    for (int i = 0; i < 16; i++)
      dec_pt[8*i +: 8] = (i < int'(nb)) ? (rate[8*i +: 8] ^ ct[8*i +: 8]) : 8'h00;
  endfunction

  // Decrypt last block: reconstructed rate lanes (real ct bytes, padding bit,
  // kept keystream above).
  function automatic logic [127:0] dec_rate(input logic [127:0] rate,
                                            input logic [127:0] ct, input logic [4:0] nb);
    for (int i = 0; i < 16; i++) begin
      if (i < int'(nb))       dec_rate[8*i +: 8] = ct[8*i +: 8];
      else if (i == int'(nb)) dec_rate[8*i +: 8] = rate[8*i +: 8] ^ 8'h01;
      else                    dec_rate[8*i +: 8] = rate[8*i +: 8];
    end
  endfunction

  // ---- state ----------------------------------------------------------------

  typedef enum logic [3:0] {
    S_IDLE, S_INIT, S_KEYX, S_AD, S_AD_PERM, S_SEP,
    S_MSG, S_MSG_PERM, S_FINX, S_FIN_PERM, S_DONE
  } state_e;

  state_e       state_q;
  logic [319:0] st_q;              // full 320-bit ascon state
  logic         dec_q;             // latched decrypt
  logic         adempty_q;
  logic [63:0]  k0_q, k1_q;        // latched key lanes
  logic [127:0] exptag_q;
  logic         last_q;            // last block seen (for perm return path)

  // shared permutation instance
  logic         p_start, p_done;
  logic [4:0]   p_nrounds;
  logic [319:0] p_state_in, p_state_out;

  ascon_perm u_perm (
    .clk_i, .rst_ni,
    .start_i  (p_start),
    .nrounds_i(p_nrounds),
    .state_i  (p_state_in),
    .done_o   (p_done),
    .state_o  (p_state_out)
  );

  // convenient views of the current rate lanes {x1, x0}
  logic [63:0] x0, x1, x2, x3, x4;
  assign {x4, x3, x2, x1, x0} = st_q;
  logic [127:0] rate;
  assign rate = {x1, x0};

  // combinational message datapath (encrypt / decrypt of the presented block)
  logic [127:0] pt_padded, new_rate_enc, ct_out;
  assign pt_padded    = (msg_bytes_i == 5'(ASCON_RATE_BYTES)) ? msg_data_i : pad_pt(msg_data_i, msg_bytes_i);
  assign new_rate_enc = rate ^ pt_padded;                 // encrypt: ct = new rate
  assign ct_out       = new_rate_enc;

  logic [127:0] pt_out_dec, new_rate_dec;
  assign new_rate_dec = (msg_bytes_i == 5'(ASCON_RATE_BYTES)) ? msg_data_i
                                               : dec_rate(rate, msg_data_i, msg_bytes_i);
  assign pt_out_dec   = (msg_bytes_i == 5'(ASCON_RATE_BYTES)) ? (rate ^ msg_data_i)
                                               : dec_pt(rate, msg_data_i, msg_bytes_i);

  // rate lanes after the current message block (encrypt or decrypt)
  logic [127:0] msg_new_rate;
  assign msg_new_rate = dec_q ? new_rate_dec : new_rate_enc;

  // AD absorb (padding for a partial last block)
  logic [127:0] ad_padded, ad_new_rate;
  assign ad_padded   = (ad_bytes_i == 5'(ASCON_RATE_BYTES)) ? ad_data_i : pad_pt(ad_data_i, ad_bytes_i);
  assign ad_new_rate = rate ^ ad_padded;

  // ---- outputs --------------------------------------------------------------

  assign ready_o     = (state_q == S_IDLE);
  assign ad_ready_o  = (state_q == S_AD);
  assign msg_ready_o = (state_q == S_MSG);

  always_comb begin
    msg_valid_o = 1'b0;
    msg_data_o  = dec_q ? pt_out_dec : ct_out;
    msg_bytes_o = msg_bytes_i;
    if (state_q == S_MSG && msg_valid_i) msg_valid_o = 1'b1;
  end

  assign tag_o    = {x4 ^ k1_q, x3 ^ k0_q};
  assign tag_ok_o = (state_q == S_DONE) ? (tag_o == exptag_q) : 1'b0;
  assign done_o   = (state_q == S_DONE);

  // ---- control / datapath ---------------------------------------------------

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q  <= S_IDLE;
      st_q     <= '0;
      dec_q    <= 1'b0;
      adempty_q<= 1'b0;
      k0_q     <= '0; k1_q <= '0;
      exptag_q <= '0;
      last_q   <= 1'b0;
      p_start  <= 1'b0;
      p_nrounds<= 5'(ASCON_A_ROUNDS);
      p_state_in <= '0;
    end else begin
      p_start <= 1'b0;

      unique case (state_q)
        S_IDLE: if (start_i) begin
          dec_q     <= decrypt_i;
          adempty_q <= ad_empty_i;
          k0_q      <= key_i[63:0];
          k1_q      <= key_i[127:64];
          exptag_q  <= exp_tag_i;
          // initial state {n1, n0, key1, key0, IV}
          p_state_in <= {npub_i[127:64], npub_i[63:0], key_i[127:64], key_i[63:0], ASCON_IV};
          p_nrounds  <= 5'(ASCON_A_ROUNDS);
          p_start    <= 1'b1;
          state_q    <= S_INIT;
        end

        S_INIT: if (p_done) begin
          st_q    <= p_state_out;
          state_q <= S_KEYX;
        end

        S_KEYX: begin
          // XOR key into x3, x4 after init permutation
          st_q[255:192] <= x3 ^ k0_q;
          st_q[319:256] <= x4 ^ k1_q;
          state_q       <= adempty_q ? S_SEP : S_AD;
        end

        S_AD: if (ad_valid_i) begin
          // absorb AD block into rate, then p^8
          st_q[127:0] <= ad_new_rate;
          last_q      <= ad_last_i;
          p_state_in  <= {x4, x3, x2, ad_new_rate[127:64], ad_new_rate[63:0]};
          p_nrounds   <= 5'(ASCON_B_ROUNDS);
          p_start     <= 1'b1;
          state_q     <= S_AD_PERM;
        end

        S_AD_PERM: if (p_done) begin
          st_q    <= p_state_out;
          state_q <= last_q ? S_SEP : S_AD;
        end

        S_SEP: begin
          st_q[319:256] <= x4 ^ 64'h8000_0000_0000_0000; // domain separation
          state_q       <= S_MSG;
        end

        S_MSG: if (msg_valid_i) begin
          // update rate (encrypt: ct=new rate; decrypt: rate=ct-derived)
          st_q[127:0] <= msg_new_rate;
          last_q      <= msg_last_i;
          if (msg_last_i) begin
            state_q <= S_FINX;      // no p^8 after the last message block
          end else begin
            p_state_in <= {x4, x3, x2, msg_new_rate[127:64], msg_new_rate[63:0]};
            p_nrounds  <= 5'(ASCON_B_ROUNDS);
            p_start    <= 1'b1;
            state_q    <= S_MSG_PERM;
          end
        end

        S_MSG_PERM: if (p_done) begin
          st_q    <= p_state_out;
          state_q <= S_MSG;
        end

        S_FINX: begin
          // XOR key into x2, x3, then p^12
          p_state_in <= {x4, x3 ^ k1_q, x2 ^ k0_q, x1, x0};
          p_nrounds  <= 5'(ASCON_A_ROUNDS);
          p_start    <= 1'b1;
          state_q    <= S_FIN_PERM;
        end

        S_FIN_PERM: if (p_done) begin
          st_q    <= p_state_out;
          state_q <= S_DONE;
        end

        S_DONE: state_q <= S_IDLE;

        default: state_q <= S_IDLE;
      endcase
    end
  end

endmodule
