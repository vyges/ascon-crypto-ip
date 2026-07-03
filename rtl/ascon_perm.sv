// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Vyges (https://vyges.com)
//
// ascon_perm — iterative Ascon permutation: applies `nrounds_i` (12 or 8)
// rounds of ascon_pkg::ascon_round, one round per clock. Single-round
// datapath (area-efficient) with a start/done handshake. The last round of a
// 12- or 8-round permutation always uses round constant 0x4b, so an n-round
// run starts at global round index (12 - n).

module ascon_perm
  import ascon_pkg::*;
(
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic         start_i,     // pulse: capture state_i, begin
  input  logic [4:0]   nrounds_i,   // 12 or 8
  input  logic [319:0] state_i,
  output logic         done_o,      // pulse: state_o valid
  output logic [319:0] state_o
);

  logic [319:0] st;
  logic [3:0]   rnd;
  logic         busy;

  assign state_o = st;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      busy   <= 1'b0;
      done_o <= 1'b0;
      rnd    <= '0;
      st     <= '0;
    end else begin
      done_o <= 1'b0;
      if (start_i && !busy) begin
        st   <= state_i;
        rnd  <= 4'(5'd12 - nrounds_i); // first global round index
        busy <= 1'b1;
      end else if (busy) begin
        st <= ascon_round(st, ascon_rc(rnd));
        if (rnd == 4'd11) begin
          busy   <= 1'b0;
          done_o <= 1'b1;
        end else begin
          rnd <= rnd + 4'd1;
        end
      end
    end
  end

endmodule
