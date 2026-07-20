# Out-of-tree wrapper Makefile

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Default target: build module(s)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Optional: install (requires root)
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
