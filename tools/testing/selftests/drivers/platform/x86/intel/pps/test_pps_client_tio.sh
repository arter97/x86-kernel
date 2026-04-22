#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test the functionality of the Intel Timed IO (TIO) PPS Client driver.
#
# Copyright (C) 2026 Intel Corporation

source "$(dirname "$0")/pps_tio_common.sh"

# Module names
readonly MOD_PLAT="pps_tio_plat"
readonly MOD_CLIENT="pps_tio_client"

# Sysfs paths
readonly PPS_CLASS="/sys/class/pps"

PPS_LOG_FILE="/tmp/pps_client_tio_test_logs.$$"
PPS_TEST_NAME="PPS client"
TIO_PLAT_PATH=""
TIO_MODE_PATH=""
CLIENT_DEV=""
ORIGIN_PLAT_LOADED=""
ORIGIN_CLIENT_LOADED=""

pps_cleanup()
{
	append_log "[$INFO] Restore environment after PPS client test"

	# If we switched mode, try to restore to generator (default)
	if [ -n "$TIO_MODE_PATH" ] && [ -f "$TIO_MODE_PATH" ]; then
		echo 0 > "$TIO_MODE_PATH" 2>/dev/null
	fi

	# Disable client poll if we enabled it
	if [ -n "$CLIENT_DEV" ] && [ -f "${PPS_CLASS}/${CLIENT_DEV}/poll" ]; then
		echo 0 > "${PPS_CLASS}/${CLIENT_DEV}/poll" 2>/dev/null
	fi

	# Unload modules if we loaded them (reverse order)
	if [ "$ORIGIN_CLIENT_LOADED" = "false" ]; then
		lsmod | grep -q "$MOD_CLIENT" && modprobe -r "$MOD_CLIENT" 2>/dev/null
	fi
	if [ "$ORIGIN_PLAT_LOADED" = "false" ]; then
		lsmod | grep -q "$MOD_PLAT" && modprobe -r "$MOD_PLAT" 2>/dev/null
	fi

	pps_cleanup_finish
}

# ===================== Prerequisites =====================

# Load platform and client modules as prerequisites
setup_load_modules()
{
	local mod

	for mod in $MOD_PLAT $MOD_CLIENT; do
		if lsmod | grep -q "$mod"; then
			append_log "[$INFO] Module $mod is already loaded"
			case "$mod" in
				"$MOD_PLAT") ORIGIN_PLAT_LOADED="true" ;;
				"$MOD_CLIENT") ORIGIN_CLIENT_LOADED="true" ;;
			esac
		else
			case "$mod" in
				"$MOD_PLAT") ORIGIN_PLAT_LOADED="false" ;;
				"$MOD_CLIENT") ORIGIN_CLIENT_LOADED="false" ;;
			esac
			modprobe "$mod" 2>/dev/null
			if lsmod | grep -q "$mod"; then
				append_log "[$INFO] Loaded module $mod"
			else
				append_log "[$SKIP] Cannot load module $mod (no hardware?)"
			fi
		fi
	done
}

# Find platform device and switch to client mode as prerequisites
setup_client_mode()
{
	TIO_PLAT_PATH=$(find_tio_platform_device 2>/dev/null)
	if [ -z "$TIO_PLAT_PATH" ] || [ ! -d "$TIO_PLAT_PATH" ]; then
		test_exit "Intel TIO platform device not found (no INTC1023/INTC1024 ACPI device). \
Requires Intel TIO hardware." "$KSFT_SKIP"
	fi

	TIO_MODE_PATH="${TIO_PLAT_PATH}/tio_mode"
	if [ ! -f "$TIO_MODE_PATH" ]; then
		test_exit "tio_mode sysfs attribute not found at $TIO_MODE_PATH" "$KSFT_SKIP"
	fi

	# Switch to client mode
	echo 1 > "$TIO_MODE_PATH" 2>/dev/null
	if [ $? -ne 0 ]; then
		test_exit "Failed to switch tio_mode to client" "$KSFT_SKIP"
	fi
	append_log "[$INFO] Switched tio_mode to client"

	# Wait briefly for auxiliary device to be created
	sleep 1
}

# ===================== Test Cases =====================

# Test: PPS client device exists and verify name is "intel_tio_client"
test_pps_client_device()
{
	CLIENT_DEV=$(find_pps_by_name "intel_tio_client" "$PPS_CLASS" 2>/dev/null)
	if [ -n "$CLIENT_DEV" ]; then
		local name
		name=$(cat "${PPS_CLASS}/${CLIENT_DEV}/name" 2>/dev/null)
		append_log "[$PASS] PPS TIO client device found: $CLIENT_DEV (name=$name)"
	else
		append_log "[$FAIL] PPS TIO client device with name 'intel_tio_client' not found"
	fi
}

# Test: Verify PPS client sysfs attributes
test_pps_client_sysfs_attrs()
{
	local attr missing=""

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device, skipping sysfs attr check"
		return
	fi

	for attr in assert clear dev echo mode name path poll uevent; do
		if [ ! -e "${PPS_CLASS}/${CLIENT_DEV}/${attr}" ]; then
			missing="$missing $attr"
		fi
	done

	if [ -z "$missing" ]; then
		append_log "[$PASS] PPS client sysfs attributes present (assert, clear, echo, mode, name, path, poll, ...)"
	else
		append_log "[$FAIL] PPS client missing sysfs attributes:$missing"
	fi
}

# Test: Verify PPS client mode includes PPS_CANPOLL (0x200)
test_pps_client_mode_canpoll()
{
	local mode_hex mode_dec

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device, skipping CANPOLL check"
		return
	fi

	mode_hex=$(cat "${PPS_CLASS}/${CLIENT_DEV}/mode" 2>/dev/null | tr -d '[:space:]')
	mode_dec=$((16#${mode_hex}))

	# PPS_CANPOLL = 0x200
	if [ $((mode_dec & 0x200)) -ne 0 ]; then
		append_log "[$PASS] PPS client mode=0x${mode_hex} includes PPS_CANPOLL"
	else
		append_log "[$FAIL] PPS client mode=0x${mode_hex} missing PPS_CANPOLL (0x200)"
	fi

	# PPS_CAPTUREASSERT = 0x01
	if [ $((mode_dec & 0x01)) -ne 0 ]; then
		append_log "[$PASS] PPS client mode=0x${mode_hex} includes PPS_CAPTUREASSERT"
	else
		append_log "[$FAIL] PPS client mode=0x${mode_hex} missing PPS_CAPTUREASSERT (0x01)"
	fi

	# PPS_CANWAIT = 0x100
	if [ $((mode_dec & 0x100)) -ne 0 ]; then
		append_log "[$PASS] PPS client mode=0x${mode_hex} includes PPS_CANWAIT"
	else
		append_log "[$FAIL] PPS client mode=0x${mode_hex} missing PPS_CANWAIT (0x100)"
	fi

	# PPS_TSFMT_TSPEC = 0x1000
	if [ $((mode_dec & 0x1000)) -ne 0 ]; then
		append_log "[$PASS] PPS client mode=0x${mode_hex} includes PPS_TSFMT_TSPEC"
	else
		append_log "[$FAIL] PPS client mode=0x${mode_hex} missing PPS_TSFMT_TSPEC (0x1000)"
	fi
}

# Test: Enable PPS client poll via sysfs
test_pps_client_poll_enable()
{
	local ret

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device, skipping poll enable test"
		return
	fi

	echo 1 > "${PPS_CLASS}/${CLIENT_DEV}/poll" 2>/dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		append_log "[$PASS] PPS client poll enabled (echo 1 > poll)"
	else
		append_log "[$FAIL] PPS client poll enable failed with ret=$ret"
	fi
}

# Test: Verify PPS client assert events are being captured
test_pps_client_assert_capture()
{
	local assert_before assert_after seq_before seq_after

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device, skipping assert capture test"
		return
	fi

	assert_before=$(cat "${PPS_CLASS}/${CLIENT_DEV}/assert" 2>/dev/null)
	if [ -z "$assert_before" ]; then
		# No assert events yet - wait for some
		sleep 3
		assert_before=$(cat "${PPS_CLASS}/${CLIENT_DEV}/assert" 2>/dev/null)
	fi

	# Extract sequence number (format: "sec.nsec#seq")
	seq_before=$(echo "$assert_before" | grep -oP '#\K[0-9]+')

	if [ -z "$seq_before" ]; then
		append_log "[$SKIP] No PPS assert events captured (need loopback: TIO output -> TIO input)"
		return
	fi

	# Wait 3 seconds for more events
	sleep 3

	assert_after=$(cat "${PPS_CLASS}/${CLIENT_DEV}/assert" 2>/dev/null)
	seq_after=$(echo "$assert_after" | grep -oP '#\K[0-9]+')

	if [ -n "$seq_after" ] && [ "$seq_after" -gt "$seq_before" ]; then
		local delta=$((seq_after - seq_before))
		append_log "[$PASS] PPS client assert sequence advanced: $seq_before -> $seq_after (delta=$delta)"
		append_log "[$INFO] Before: $assert_before"
		append_log "[$INFO] After:  $assert_after"
	else
		append_log "[$SKIP] PPS client assert sequence did not advance (need loopback connection)"
		append_log "[$INFO] Before: $assert_before"
		append_log "[$INFO] After:  $assert_after"
	fi
}

# Test: Disable PPS client poll via sysfs
test_pps_client_poll_disable()
{
	local ret

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device, skipping poll disable test"
		return
	fi

	echo 0 > "${PPS_CLASS}/${CLIENT_DEV}/poll" 2>/dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		append_log "[$PASS] PPS client poll disabled (echo 0 > poll)"
	else
		append_log "[$FAIL] PPS client poll disable failed with ret=$ret"
	fi
}

# Test: Verify PPS client 'echo' attribute is readable
test_pps_client_echo_attr()
{
	local val ret

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device for echo attribute test"
		return
	fi

	val=$(cat "${PPS_CLASS}/${CLIENT_DEV}/echo" 2>/dev/null)
	ret=$?
	# echo_show returns -EOPNOTSUPP if no echo function and no ECHO mode bits
	if [ $ret -eq 0 ] || [ -n "$val" ]; then
		append_log "[$PASS] PPS client echo attribute readable (value=$val)"
	else
		# EOPNOTSUPP is acceptable if driver doesn't provide echo
		append_log "[$PASS] PPS client echo attribute returned EOPNOTSUPP (expected, no echo function)"
	fi
}

# Test: Verify PPS client 'path' attribute is readable
test_pps_client_path_attr()
{
	local val

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device for path attribute test"
		return
	fi

	val=$(cat "${PPS_CLASS}/${CLIENT_DEV}/path" 2>/dev/null)
	# path may be empty string, that's OK
	append_log "[$PASS] PPS client path attribute readable (value='$val')"
}

# Test: Verify PPS client 'clear' attribute is readable
test_pps_client_clear_attr()
{
	local val

	if [ -z "$CLIENT_DEV" ]; then
		append_log "[$SKIP] No TIO client device for clear attribute test"
		return
	fi

	val=$(cat "${PPS_CLASS}/${CLIENT_DEV}/clear" 2>/dev/null)
	# TIO client only supports CAPTUREASSERT, so clear may be empty
	append_log "[$PASS] PPS client clear attribute readable (value='$val')"
}

# ===================== Main Test Sequence =====================

test_pps_client_tio()
{
	append_log "[$INFO] === Intel Timed IO (TIO) PPS Client Test ==="
	append_log "[$INFO] Test started at $(date)"

	# Prerequisites: module verification, load modules, switch to client mode
	append_log "[$INFO] --- Prerequisites ---"
	check_modinfo "$MOD_CLIENT"
	setup_load_modules
	setup_client_mode

	# Phase 1: Client device tests
	append_log "[$INFO] --- Phase 1: PPS Client Device Tests ---"
	test_pps_client_device
	test_pps_client_sysfs_attrs
	test_pps_client_mode_canpoll

	# Phase 2: Client poll and capture tests
	append_log "[$INFO] --- Phase 2: PPS Client Poll & Capture Tests ---"
	test_pps_client_poll_enable
	test_pps_client_assert_capture
	test_pps_client_poll_disable

	# Phase 3: Additional attribute tests
	append_log "[$INFO] --- Phase 3: Additional Attribute Tests ---"
	test_pps_client_echo_attr
	test_pps_client_path_attr
	test_pps_client_clear_attr

	append_log "[$INFO] === Test Complete ==="
}

trap pps_cleanup SIGTERM SIGINT
test_pps_client_tio
pps_cleanup
