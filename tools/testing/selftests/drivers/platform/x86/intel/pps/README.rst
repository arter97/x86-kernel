.. SPDX-License-Identifier: GPL-2.0

==========================================
Intel Timed IO (TIO) PPS Self-Tests
==========================================

Overview
========

This directory contains self-tests for the Intel Timed IO (TIO) PPS drivers.
The common test framework is provided by ``pps_tio_common.sh``.

Prerequisites
=============

Hardware
--------

Intel platform with Timed GPIO (TGPIO) support.

BIOS Configuration
------------------

To enable TGPIO, configure the following BIOS options:

- ``Intel Advanced Menu > PCH-IO Configuration > Enable Timed GPIO0`` → **Enabled**
- ``Intel Advanced Menu > PCH-IO Configuration > Enable Timed GPIO1`` → **Enabled**

Kernel Configuration
--------------------

The following kernel configuration options must be enabled (as modules or
built-in)::

  CONFIG_PPS=m

Running the Tests
=================

Run individual tests as root using the kselftest framework::

  $ cd tools/testing/selftests/drivers/platform/x86/intel/pps
  $ sudo ./<test_script>.sh

Or using the kselftest runner from the kernel tree::

  $ make -C tools/testing/selftests TARGETS=drivers/platform/x86/intel/pps run_tests

Output
======

Test results are printed to stdout with the following prefixes:

- ``[PASS]`` - Test passed
- ``[FAIL]`` - Test failed
- ``[SKIP]`` - Test skipped (e.g., hardware not present)
- ``[INFO]`` - Informational message

The script exits with the kselftest return codes:

- ``0`` (KSFT_PASS) - All tests passed
- ``1`` (KSFT_FAIL) - One or more tests failed
- ``4`` (KSFT_SKIP) - All tests were skipped
