# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_VIDEO_PXA27x) += pxa_camera.o

ccflags-y += -I$(src)/../../pci/intel/ipu6/
obj-$(CONFIG_INTEL_IPU6_ACPI)         += ipu6-acpi.o \
                                         ipu6-acpi-pdata.o \
                                         ipu6-acpi-common.o
