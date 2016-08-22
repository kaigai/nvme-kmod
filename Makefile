KERNEL_UNAME := $(shell uname -r)
KERNEL_SOURCE := /lib/modules/$(KERNEL_UNAME)/build

NVIDIA_SOURCE := $(shell ls -St /usr/src/nvidia-*/nv-p2p.h | \
                         sed 's/\/nv-p2p\.h$$//g' | head -1)

CUDA_PATH_LIST := /usr/local/cuda /usr/local/cuda-*
CUDA_PATH := $(shell for x in $(CUDA_PATH_LIST);    \
	do test -e "$$x/include/cuda.h" && echo $$x; done | head -1)
USERSPACE_FLAGS := -I $(CUDA_PATH)/include -L $(CUDA_PATH)/lib64 -lcuda

EXTRA_CLEAN := nvme_test

obj-m := nvme_strom.o
ccflags-y := -I. -I$(NVIDIA_SOURCE)

default: modules nvme_test

nvme_test: nvme_test.c nvme_strom.h
	$(CC) -o $@ $(USERSPACE_FLAGS) -DBUILD_AS_DRIVERTEST $<

clean:
	rm -f $(EXTRA_CLEAN)
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

%:
	$(MAKE) -C $(KERNEL_SOURCE) \
	KBUILD_EXTRA_SYMBOLS=$(NVIDIA_SOURCE)/Module.symvers \
	NVIDIA_SOURCE=$(NVIDIA_SOURCE) M=$(PWD) $@

.PHONY: default
