# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Vyges (https://vyges.com)
#
# Build + verification entry points for the Ascon-AEAD128 IP.
#   make test        # golden-model KAT + Verilator differential fuzz + lint
#   make model-kat   # C golden model vs all 1089 official NIST vectors
#   make fuzz        # Verilator RTL vs golden model, randomized
#   make lint        # Verilator RTL lint
#   make cocotb      # cocotb testbench (NIST KAT + random diff); needs cocotb
#   make clean

RTL       := rtl/ascon_pkg.sv rtl/ascon_perm.sv rtl/ascon_core.sv
MODEL_DIR := tb/model
VEC       := tb/vectors/LWC_AEAD_KAT_128_128.txt
BUILD     := build

.PHONY: test model-kat fuzz lint cocotb clean

test: model-kat fuzz lint

model-kat:
	@mkdir -p $(BUILD)
	cc -O2 -Wall -Wextra -o $(BUILD)/kat_test $(MODEL_DIR)/ascon.c $(MODEL_DIR)/kat_test.c
	$(BUILD)/kat_test $(VEC)

fuzz:
	verilator --cc --exe --build -j 0 --top-module ascon_core -Wno-fatal \
	  --Mdir $(BUILD)/obj_fuzz --CFLAGS "-I$(abspath $(MODEL_DIR))" -o sim_ascon \
	  $(RTL) tb/verilator/tb_ascon_core.cpp $(MODEL_DIR)/ascon.c
	$(BUILD)/obj_fuzz/sim_ascon

lint:
	verilator --lint-only -Wall -Wno-fatal --top-module ascon_core $(RTL)

cocotb:
	$(MAKE) -C tb/cocotb

clean:
	rm -rf $(BUILD) tb/cocotb/sim_build tb/cocotb/dump.fst tb/cocotb/results.xml
