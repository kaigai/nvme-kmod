NVME_STROM_VERSION := 0.1
NVME_STROM_VERSION_NUM=$(shell echo $(NVME_STROM_VERSION)	\
    | sed -e 's/\./ /g' -e 's/[A-Za-z].*$$//g'				\
    | awk '{printf "%d%02d%02d", $$1, $$2, (NF >=3) ? $$3 : 0}')
NVME_STROM_BUILD_TIMESTAMP = $(shell date --utc)

KERNEL_UNAME := $(shell uname -r)
KERNEL_SOURCE := /lib/modules/$(KERNEL_UNAME)/build
# MEMO: Older version of CUDA driver provided the kernel header files
# at '/usr/src/nvidia-*/nv-p2p.h'.
NVIDIA_SOURCE := $(shell ls -St /usr/src/nvidia-*/nv-p2p.h \
                                /usr/src/nvidia-*/nvidia/nv-p2p.h 2>/dev/null \
                       | sed 's/\/nv-p2p\.h$$//g' | head -1)

CUDA_PATH_LIST := /usr/local/cuda /usr/local/cuda-*
CUDA_PATH := $(shell for x in $(CUDA_PATH_LIST);    \
	do test -e "$$x/include/cuda.h" && echo $$x; done | head -1)
USERSPACE_FLAGS := -g -I $(CUDA_PATH)/include -L $(CUDA_PATH)/lib64

EXTRA_CLEAN := nvme_test

obj-m := nvme_strom.o
ccflags-y := -I. -I$(NVIDIA_SOURCE) 					\
	-DNVME_STROM_VERSION='"$(NVME_STROM_VERSION)"'		\
	-DNVME_STROM_VERSION_NUM=$(NVME_STROM_VERSION_NUM)	\
	-DNVME_STROM_BUILD_TIMESTAMP='"$(NVME_STROM_BUILD_TIMESTAMP)"'

default: modules nvme_test

nvme_test: nvme_test.c nvme_strom.h
	$(CC) -Wall nvme_test.c -o $@ $(USERSPACE_FLAGS) -lcuda -lpthread

clean:
	rm -f $(EXTRA_CLEAN)
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

%:
	$(MAKE) -C $(KERNEL_SOURCE) \
	KBUILD_EXTRA_SYMBOLS=$(NVIDIA_SOURCE)/Module.symvers \
	NVIDIA_SOURCE=$(NVIDIA_SOURCE) M=$(PWD) $@

.PHONY: default

