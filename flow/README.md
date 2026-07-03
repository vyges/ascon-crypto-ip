# flow/

Build, synthesis, and simulation flows for `ascon-crypto-ip`.

- `simulation/` — simulation entry points (see also the top-level `Makefile` and
  `tb/cocotb/Makefile`).

Planned:
- `fpga/` — FPGA synthesis (Yosys + nextpnr; Vivado project for Xilinx targets).
- `asic/` — ASIC synthesis / place-and-route (OpenLane / Vyges Loom sign-off).

The RTL is technology-independent; these directories will hold per-target scripts
and constraints as the IP moves through synthesis and timing closure.
