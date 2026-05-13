#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Common test framework for Intel Timed IO (TIO) PPS self-tests.
#
# Provides shared constants, logging, result summary, cleanup helpers,
# and device discovery utilities used by all TIO PPS test scripts.
#
# Copyright (C) 2026 Intel Corporation

# kselftest return codes
readonly KSFT_PASS=0
readonly KSFT_FAIL=1
readonly KSFT_SKIP=4

# Log level tags
readonly PASS="PASS"
readonly FAIL="FAIL"
readonly SKIP="SKIP"
readonly INFO="INFO"

# ACPI device IDs for Intel TIO
readonly ACPI_IDS="INTC1023 INTC1024"

# Global state - must be set by each test script before calling common functions:
#   PPS_LOG_FILE  - path to the test log file
#   PPS_TEST_NAME - human-readable test name for messages
RESULT=$KSFT_PASS

# Append a message to the test log and stdout
append_log()
{
	echo -e "$1" | tee -a "$PPS_LOG_FILE"
}

# Print result summary from the log file
pps_result_summary()
{
	local fail_num pass_num skip_num

	if [ -e "$PPS_LOG_FILE" ]; then
		fail_num=$(grep -c "^\[${FAIL}\]" "$PPS_LOG_FILE")
		pass_num=$(grep -c "^\[${PASS}\]" "$PPS_LOG_FILE")
		skip_num=$(grep -c "^\[${SKIP}\]" "$PPS_LOG_FILE")

		if [ "$fail_num" -ne 0 ]; then
			RESULT=$KSFT_FAIL
			echo "[$INFO] $PPS_TEST_NAME test failure summary:"
			grep "^\[${FAIL}\]" "$PPS_LOG_FILE"
		elif [ "$skip_num" -ne 0 ] && [ "$pass_num" -eq 0 ]; then
			RESULT=$KSFT_SKIP
		fi
		echo "[$INFO] $PPS_TEST_NAME test pass:$pass_num, skip:$skip_num, fail:$fail_num"
	fi
}

# Common cleanup finish: print summary, remove log file, and exit.
# Each test script should define pps_cleanup() that performs test-specific
# teardown and then calls this function.
pps_cleanup_finish()
{
	pps_result_summary
	[ -e "$PPS_LOG_FILE" ] && rm -rf "$PPS_LOG_FILE"

	echo "[RESULT] $PPS_TEST_NAME test exit with $RESULT"
	exit "$RESULT"
}

# Exit early with SKIP and invoke cleanup.
# Requires pps_cleanup() to be defined by the test script.
test_exit()
{
	local info=$1
	RESULT=$2
	append_log "[$SKIP] $info"
	pps_cleanup
}

# Find the first PPS generator device under the given class path
find_pps_gen_device()
{
	local pps_gen_class="$1"
	local gen_dev

	for gen_dev in ${pps_gen_class}/pps-gen*; do
		[ -d "$gen_dev" ] || continue
		basename "$gen_dev"
		return 0
	done
	return 1
}

# Find the Intel TIO platform device sysfs path
find_tio_platform_device()
{
	local acpi_id dev_path

	for acpi_id in $ACPI_IDS; do
		for dev_path in /sys/devices/platform/${acpi_id}*/; do
			if [ -d "$dev_path" ]; then
				echo "$dev_path"
				return 0
			fi
		done
	done
	return 1
}


# Find a PPS device whose name matches a pattern
find_pps_by_name()
{
	local pattern="$1"
	local pps_class="$2"
	local pps_dev name

	for pps_dev in ${pps_class}/pps*; do
		[ -d "$pps_dev" ] || continue
		[ -f "$pps_dev/name" ] || continue
		name=$(cat "$pps_dev/name" 2>/dev/null)
		if echo "$name" | grep -qi "$pattern"; then
			basename "$pps_dev"
			return 0
		fi
	done
	return 1
}

# Check module info for a given module
check_modinfo()
{
	local mod="$1"
	local desc

	desc=$(modinfo "$mod" 2>/dev/null | grep "^description:" | head -1)
	if [ -n "$desc" ]; then
		append_log "[$PASS] modinfo $mod: $desc"
		return 0
	else
		append_log "[$SKIP] modinfo $mod: module not available"
		return 1
	fi
}
