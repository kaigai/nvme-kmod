KERNEL_UNAME := $(shell uname -r)
KERNEL_SOURCE := /lib/modules/$(KERNEL_UNAME)/build

NVIDIA_SOURCE := $(shell ls -drSt /usr/src/nvidia-* | grep -E '.*/nvidia-[0-9\.]+$$' | head -1)

obj-m := nvme-strom.o
ccflags-y := -I. -I$(NVIDIA_SOURCE)

default: modules

%:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

.PHONY: default
