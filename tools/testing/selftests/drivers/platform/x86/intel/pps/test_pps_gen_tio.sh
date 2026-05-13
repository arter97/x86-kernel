#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test the functionality of the Intel Timed IO (TIO) PPS Generator driver.
#
# This script covers the following:
#   - Module verification for pps_gen_tio
#   - PPS generator device discovery under /sys/class/pps-gen/
#   - Sysfs attribute verification (dev, enable, system, time, uevent)
#   - System clock usage check
#   - Time readback validation
#   - Enable/disable generation via sysfs
#
# Copyright (C) 2026 Intel Corporation

source "$(dirname "$0")/pps_tio_common.sh"

# Module name
readonly MOD_GEN="pps_gen_tio"

# Sysfs paths
readonly PPS_GEN_CLASS="/sys/class/pps-gen"

PPS_LOG_FILE="/tmp/pps_gen_tio_test_logs.$$"
PPS_TEST_NAME="PPS generator"
GEN_DEV=""
ORIGIN_GEN_LOADED=""

pps_cleanup()
{
	append_log "[$INFO] Restore environment after PPS generator test"

	# Disable generator if we enabled it
	if [ -n "$GEN_DEV" ] && [ -f "${PPS_GEN_CLASS}/${GEN_DEV}/enable" ]; then
		echo 0 > "${PPS_GEN_CLASS}/${GEN_DEV}/enable" 2>/dev/null
	fi

	# Unload module if we loaded it
	if [ "$ORIGIN_GEN_LOADED" = "false" ]; then
		lsmod | grep -q "$MOD_GEN" && modprobe -r "$MOD_GEN" 2>/dev/null
	fi

	pps_cleanup_finish
}

# ===================== Test Cases =====================

# Test: Load Intel TIO PPS generator module
test_load_modules()
{
	if lsmod | grep -q "$MOD_GEN"; then
		append_log "[$INFO] Module $MOD_GEN is already loaded"
		ORIGIN_GEN_LOADED="true"
	else
		ORIGIN_GEN_LOADED="false"
		modprobe "$MOD_GEN" 2>/dev/null
		if lsmod | grep -q "$MOD_GEN"; then
			append_log "[$PASS] Loaded module $MOD_GEN"
		else
			append_log "[$SKIP] Cannot load module $MOD_GEN (no hardware?)"
			return 1
		fi
	fi
}

# Test: PPS generator class exists and pps-gen device is created
test_pps_gen_device_exists()
{
	if [ ! -d "$PPS_GEN_CLASS" ]; then
		append_log "[$FAIL] PPS generator class $PPS_GEN_CLASS not found"
		return
	fi

	GEN_DEV=$(find_pps_gen_device "$PPS_GEN_CLASS" 2>/dev/null)
	if [ -n "$GEN_DEV" ]; then
		append_log "[$PASS] PPS generator device found: $GEN_DEV"
	else
		append_log "[$SKIP] No PPS generator device found under $PPS_GEN_CLASS"
	fi
}

# Test: Verify PPS generator sysfs attributes (enable, time, system)
test_pps_gen_sysfs_attrs()
{
	local attr missing=""

	if [ -z "$GEN_DEV" ]; then
		append_log "[$SKIP] No generator device, skipping sysfs attr check"
		return
	fi

	for attr in dev enable system time uevent; do
		if [ ! -e "${PPS_GEN_CLASS}/${GEN_DEV}/${attr}" ]; then
			missing="$missing $attr"
		fi
	done

	if [ -z "$missing" ]; then
		append_log "[$PASS] PPS generator sysfs attributes present (dev, enable, system, time, uevent)"
	else
		append_log "[$FAIL] PPS generator missing sysfs attributes:$missing"
	fi
}

# Test: Read PPS generator 'system' attribute (TIO sets use_system_clock=true)
test_pps_gen_system_clock()
{
	local val

	if [ -z "$GEN_DEV" ]; then
		append_log "[$SKIP] No generator device, skipping system clock check"
		return
	fi

	val=$(cat "${PPS_GEN_CLASS}/${GEN_DEV}/system" 2>/dev/null)
	if [ "$val" = "1" ]; then
		append_log "[$PASS] PPS generator use_system_clock=1 (expected for TIO)"
	elif [ "$val" = "0" ]; then
		append_log "[$PASS] PPS generator use_system_clock=0"
	else
		append_log "[$FAIL] PPS generator system attribute unexpected value: '$val'"
	fi
}

# Test: Read PPS generator 'time' attribute
test_pps_gen_time()
{
	local val sec nsec

	if [ -z "$GEN_DEV" ]; then
		append_log "[$SKIP] No generator device, skipping time check"
		return
	fi

	val=$(cat "${PPS_GEN_CLASS}/${GEN_DEV}/time" 2>/dev/null)
	if echo "$val" | grep -qE '^[0-9]+ [0-9]+$'; then
		sec=$(echo "$val" | awk '{print $1}')
		nsec=$(echo "$val" | awk '{print $2}')
		# Sanity: time should be after year 2000 (946684800)
		if [ "$sec" -gt 946684800 ]; then
			append_log "[$PASS] PPS generator time=${sec}.${nsec} (valid)"
		else
			append_log "[$FAIL] PPS generator time=${sec}.${nsec} (too old)"
		fi
	else
		append_log "[$FAIL] PPS generator time format invalid: '$val'"
	fi
}

# Test: Enable PPS generation via sysfs
test_pps_gen_enable()
{
	local ret

	if [ -z "$GEN_DEV" ]; then
		append_log "[$SKIP] No generator device, skipping enable test"
		return
	fi

	echo 1 > "${PPS_GEN_CLASS}/${GEN_DEV}/enable" 2>/dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		append_log "[$PASS] PPS generator enabled (echo 1 > enable)"
		# Wait briefly to let generation start
		sleep 2
	else
		append_log "[$FAIL] PPS generator enable failed with ret=$ret"
	fi
}

# Test: Disable PPS generation via sysfs
test_pps_gen_disable()
{
	local ret

	if [ -z "$GEN_DEV" ]; then
		append_log "[$SKIP] No generator device, skipping disable test"
		return
	fi

	echo 0 > "${PPS_GEN_CLASS}/${GEN_DEV}/enable" 2>/dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		append_log "[$PASS] PPS generator disabled (echo 0 > enable)"
	else
		append_log "[$FAIL] PPS generator disable failed with ret=$ret"
	fi
}

# ===================== Main Test Sequence =====================

test_pps_gen_tio()
{
	append_log "[$INFO] === Intel Timed IO (TIO) PPS Generator Test ==="
	append_log "[$INFO] Test started at $(date)"

	# Phase 1: Module verification
	# Phase 2 is skipped only when both modinfo and module load fail.
	local modinfo_failed=0 load_failed=0

	append_log "[$INFO] --- Phase 1: Module Verification ---"
	check_modinfo "$MOD_GEN" || modinfo_failed=1
	test_load_modules || load_failed=1

	if [ "$modinfo_failed" -ne 0 ] && [ "$load_failed" -ne 0 ]; then
		append_log "[$SKIP] Phase 1 failed: module not available and cannot be loaded, skipping Phase 2"
		return
	fi

	# Phase 2: PPS Generator tests
	append_log "[$INFO] --- Phase 2: PPS Generator Tests ---"
	test_pps_gen_device_exists
	test_pps_gen_sysfs_attrs
	test_pps_gen_system_clock
	test_pps_gen_time
	test_pps_gen_enable
	test_pps_gen_disable

	append_log "[$INFO] === Test Complete ==="
}

trap pps_cleanup SIGTERM SIGINT
test_pps_gen_tio
pps_cleanup
