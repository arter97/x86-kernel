.. SPDX-License-Identifier: GPL-2.0

==========================================
Intel Timed IO (TIO) PPS Self-Tests
==========================================

Overview
========

This directory contains self-tests for the Intel Timed IO (TIO) PPS drivers.
The common test framework is provided by ``pps_tio_common.sh``.

- **PPS Generator** (``pps_gen_tio``) - The test script ``test_pps_gen_tio.sh``
  verifies the PPS generator functionality including module loading, sysfs
  attribute validation, time readback, and enable/disable operations.

- **PPS Platform** (``pps_tio_plat``) - The test script
  ``test_pps_platform_tio.sh`` verifies the PPS platform driver functionality
  including module loading, platform device discovery (INTC1023/INTC1024), and
  ``tio_mode`` sysfs attribute validation (default value, mode switching, and
  invalid value rejection).

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
  CONFIG_PPS_GENERATOR=m
  CONFIG_PPS_GENERATOR_TIO=m
  CONFIG_INTEL_TIO_PLAT=m

Running the Tests
=================

Run individual tests as root using the kselftest framework::

  $ cd tools/testing/selftests/drivers/platform/x86/intel/pps
  $ sudo ./test_pps_gen_tio.sh
  $ sudo ./test_pps_platform_tio.sh

Or using the kselftest runner from the kernel tree::

  $ make -C tools/testing/selftests TARGETS=drivers/platform/x86/intel/pps run_tests

Test Cases
==========

PPS Generator Tests (test_pps_gen_tio.sh)
------------------------------------------

The script runs the following test cases:

1. **Module info verification** - Checks ``modinfo pps_gen_tio`` is available.
2. **Module loading** - Loads the ``pps_gen_tio`` module if not already loaded.
3. **PPS generator device existence** - Verifies a ``pps-gen*`` device appears
   under ``/sys/class/pps-gen/``.
4. **Sysfs attribute verification** - Checks for expected attributes: ``dev``,
   ``enable``, ``system``, ``time``, ``uevent``.
5. **System clock check** - Reads the ``system`` attribute to verify clock
   configuration.
6. **Time readback** - Reads the ``time`` attribute and validates the timestamp.
7. **Enable PPS generation** - Writes ``1`` to the ``enable`` attribute.
8. **Disable PPS generation** - Writes ``0`` to the ``enable`` attribute.

PPS Platform Tests (test_pps_platform_tio.sh)
----------------------------------------------

The script runs the following test cases:

1. **Module info verification** - Checks ``modinfo pps_tio_plat`` is available.
2. **Module loading** - Loads the ``pps_tio_plat`` module if not already loaded.
3. **Platform device discovery** - Verifies an Intel TIO platform device
   (INTC1023/INTC1024) exists in sysfs.
4. **tio_mode default value** - Reads the ``tio_mode`` sysfs attribute and
   verifies the default value is ``generator``.
5. **Switch tio_mode to client** - Writes ``1`` to ``tio_mode`` and verifies
   the mode switches to ``client``.
6. **Switch tio_mode to generator** - Writes ``0`` to ``tio_mode`` and verifies
   the mode switches back to ``generator``.
7. **Reject invalid tio_mode** - Writes an invalid value (``2``) to ``tio_mode``
   and verifies it is rejected.

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
