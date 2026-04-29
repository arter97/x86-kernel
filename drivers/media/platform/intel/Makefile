# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2010 - 2025 Intel Corporation.

obj-$(CONFIG_VIDEO_PXA27x) += pxa_camera.o

is_kernel_lt_6_10 = $(shell if [ $$(printf "6.10\n$(KERNELVERSION)" | sort -V | head -n1) != "6.10" ]; then echo 1; fi)
ifeq ($(is_kernel_lt_6_10), 1)
ifneq ($(EXTERNAL_BUILD), 1)
src := $(srctree)/$(src)
endif
endif

ccflags-y += -I$(src)/../../../staging/media/ipu7/

# Comment: For checking purposes if this is needed for kernel compilation
# ifneq ($(filter y m, $(CONFIG_VIDEO_INTEL_IPU7)),)
# ccflags-y += -I$(src)/../../pci/intel/ipu7/
# endif

ifneq ($(filter y m, $(CONFIG_VIDEO_INTEL_IPU6)),)
ccflags-y += -I$(src)/../../pci/intel/ipu6/
endif

ifneq ($(filter y m, $(CONFIG_INTEL_IPU_ACPI)),)
obj-$(CONFIG_INTEL_IPU_ACPI) += ipu-acpi.o \
                                 ipu-acpi-pdata.o \
                                 ipu-acpi-common.o
else
obj-y += ipu7-fpga-pdata.o
endif