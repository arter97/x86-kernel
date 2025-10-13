# SPDX-License-Identifier: GPL-2.0-only
obj-$(CONFIG_VIDEO_PXA27x) += pxa_camera.o

ifneq ($(filter y m, $(CONFIG_VIDEO_INTEL_IPU7)),)
ccflags-y += -I$(src)/../../pci/intel/ipu7/
endif

ifneq ($(filter y m, $(CONFIG_VIDEO_INTEL_IPU6)),)
ccflags-y += -I$(src)/../../pci/intel/ipu6/
endif
obj-$(CONFIG_INTEL_IPU6_ADLRVP_PDATA) += ipu6-adlrvp-pdata.o
obj-$(CONFIG_INTEL_IPU_ACPI)         += ipu-acpi.o \
                                         ipu-acpi-pdata.o \
                                         ipu-acpi-common.o
