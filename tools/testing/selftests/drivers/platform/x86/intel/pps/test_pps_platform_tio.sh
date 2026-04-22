#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test the functionality of the Intel Timed IO (TIO) platform driver.
#
# Tests include:
#   - Module verification for pps_tio_plat
#   - Platform device discovery (INTC1023/INTC1024)
#   - tio_mode sysfs attribute: default value, switching, invalid values
#
# Copyright (C) 2026 Intel Corporation

source "$(dirname "$0")/pps_tio_common.sh"

# Module names
readonly MOD_PLAT="pps_tio_plat"

PPS_LOG_FILE="/tmp/pps_platform_tio_test_logs.$$"
PPS_TEST_NAME="PPS platform"
TIO_PLAT_PATH=""
TIO_MODE_PATH=""
ORIGIN_PLAT_LOADED=""

pps_cleanup()
{
	append_log "[$INFO] Restore environment after PPS platform test"

	# If we switched mode, try to restore to generator (default)
	if [ -n "$TIO_MODE_PATH" ] && [ -f "$TIO_MODE_PATH" ]; then
		echo 0 > "$TIO_MODE_PATH" 2>/dev/null
	fi

	# Unload module if we loaded it
	if [ "$ORIGIN_PLAT_LOADED" = "false" ]; then
		lsmod | grep -q "$MOD_PLAT" && modprobe -r "$MOD_PLAT" 2>/dev/null
	fi

	pps_cleanup_finish
}

# ===================== Test Cases =====================

# Test: Load Intel TIO platform module
test_load_module()
{
	if lsmod | grep -q "$MOD_PLAT"; then
		append_log "[$INFO] Module $MOD_PLAT is already loaded"
		ORIGIN_PLAT_LOADED="true"
	else
		ORIGIN_PLAT_LOADED="false"
		modprobe "$MOD_PLAT" 2>/dev/null
		if lsmod | grep -q "$MOD_PLAT"; then
			append_log "[$PASS] Loaded module $MOD_PLAT"
		else
			append_log "[$SKIP] Cannot load module $MOD_PLAT (no hardware?)"
		fi
	fi
}

# Test: Verify Intel TIO platform device exists in sysfs
test_tio_platform_device()
{
	TIO_PLAT_PATH=$(find_tio_platform_device 2>/dev/null)
	if [ -n "$TIO_PLAT_PATH" ] && [ -d "$TIO_PLAT_PATH" ]; then
		append_log "[$PASS] Intel TIO platform device found: $TIO_PLAT_PATH"
	else
		test_exit "Intel TIO platform device not found (no INTC1023/INTC1024 ACPI device). \
Requires Intel TIO hardware." "$KSFT_SKIP"
	fi
}

# Test: Read tio_mode sysfs attribute (default should be 'generator')
test_tio_mode_read_default()
{
	local mode_val

	TIO_MODE_PATH="${TIO_PLAT_PATH}/tio_mode"
	if [ ! -f "$TIO_MODE_PATH" ]; then
		append_log "[$FAIL] tio_mode sysfs attribute not found at $TIO_MODE_PATH"
		return
	fi

	mode_val=$(cat "$TIO_MODE_PATH" 2>/dev/null)
	if [ "$mode_val" = "generator" ]; then
		append_log "[$PASS] tio_mode default is 'generator' (as documented)"
	else
		append_log "[$FAIL] tio_mode default is '$mode_val', expected 'generator'"
	fi
}

# Test: Switch tio_mode from generator to client (echo 1 > tio_mode)
test_tio_mode_switch_to_client()
{
	local mode_val

	if [ ! -f "$TIO_MODE_PATH" ]; then
		append_log "[$FAIL] tio_mode path not found"
		return
	fi

	echo 1 > "$TIO_MODE_PATH" 2>/dev/null
	if [ $? -ne 0 ]; then
		append_log "[$FAIL] Failed to switch tio_mode to client (echo 1)"
		return
	fi

	mode_val=$(cat "$TIO_MODE_PATH" 2>/dev/null)
	if [ "$mode_val" = "client" ]; then
		append_log "[$PASS] tio_mode switched to 'client' successfully"
	else
		append_log "[$FAIL] tio_mode is '$mode_val' after switch, expected 'client'"
	fi
}

# Test: Switch tio_mode back from client to generator (echo 0 > tio_mode)
test_tio_mode_switch_to_generator()
{
	local mode_val

	if [ ! -f "$TIO_MODE_PATH" ]; then
		append_log "[$FAIL] tio_mode path not found"
		return
	fi

	echo 0 > "$TIO_MODE_PATH" 2>/dev/null
	if [ $? -ne 0 ]; then
		append_log "[$FAIL] Failed to switch tio_mode to generator (echo 0)"
		return
	fi

	mode_val=$(cat "$TIO_MODE_PATH" 2>/dev/null)
	if [ "$mode_val" = "generator" ]; then
		append_log "[$PASS] tio_mode switched back to 'generator' successfully"
	else
		append_log "[$FAIL] tio_mode is '$mode_val' after switch, expected 'generator'"
	fi
}

# Test: Verify tio_mode rejects invalid mode values
test_tio_mode_invalid()
{
	if [ ! -f "$TIO_MODE_PATH" ]; then
		append_log "[$FAIL] tio_mode path not found"
		return
	fi

	echo 2 > "$TIO_MODE_PATH" 2>/dev/null
	if [ $? -ne 0 ]; then
		append_log "[$PASS] tio_mode correctly rejected invalid value 2"
	else
		append_log "[$FAIL] tio_mode accepted invalid value 2"
	fi
}

# ===================== Main Test Sequence =====================

test_pps_platform_tio()
{
	append_log "[$INFO] === Intel Timed IO (TIO) PPS Platform Test ==="
	append_log "[$INFO] Test started at $(date)"

	# Phase 1: Module verification
	append_log "[$INFO] --- Phase 1: Module Verification ---"
	check_modinfo "$MOD_PLAT"
	test_load_module

	# Phase 2: Platform device tests
	append_log "[$INFO] --- Phase 2: Platform Device Tests ---"
	test_tio_platform_device
	test_tio_mode_read_default

	# Phase 3: Mode switching tests
	append_log "[$INFO] --- Phase 3: Mode Switching Tests ---"
	test_tio_mode_switch_to_client
	test_tio_mode_switch_to_generator
	test_tio_mode_invalid

	append_log "[$INFO] === Test Complete ==="
}

trap pps_cleanup SIGTERM SIGINT
test_pps_platform_tio
pps_cleanup
