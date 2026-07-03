# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Vyges (https://vyges.com)
#
# cocotb testbench for ascon_core (Ascon-AEAD128). Default simulator: Verilator.
#   make            # run all cocotb tests
#   make SIM=icarus # run under Icarus Verilog instead
#
# cocotb-config is auto-detected in PATH or common install locations.

COCOTB_CONFIG := $(shell which cocotb-config 2>/dev/null || echo $(HOME)/.local/bin/cocotb-config)
export PATH := $(HOME)/.local/bin:$(PATH)

TOPLEVEL_LANG ?= verilog
SIM ?= verilator

RTL := $(abspath $(PWD)/../../rtl)
VERILOG_SOURCES := $(RTL)/ascon_pkg.sv $(RTL)/ascon_perm.sv $(RTL)/ascon_core.sv

TOPLEVEL := ascon_core
MODULE   := test_ascon_core

ifeq ($(SIM),verilator)
    EXTRA_ARGS += -Wno-fatal
    # add --trace for VCD waveforms when debugging
endif

include $(shell $(COCOTB_CONFIG) --makefiles)/Makefile.sim
