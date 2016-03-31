KERNEL_UNAME := $(shell uname -r)
KERNEL_SOURCE := /lib/modules/$(KERNEL_UNAME)/build

NVIDIA_SOURCE := $(shell ls -drSt /usr/src/nvidia-* | grep -E '.*/nvidia-[0-9\.]+$$' | head -1)

CUDA_PATH_LIST := /usr/local/cuda /usr/local/cuda-*
CUDA_PATH := $(shell for x in $(CUDA_PATH_LIST);    \
	do test -e "$$x/include/cuda.h" && echo $$x; done | head -1)
USERSPACE_FLAGS := -I $(CUDA_PATH)/include -L $(CUDA_PATH)/lib64 -lcuda

EXTRA_CLEAN := driver_test libnvme-strom.so

obj-m := nvme-strom.o
ccflags-y := -I. -I$(NVIDIA_SOURCE)

default: modules driver_test libnvme-strom.so

driver_test: libnvme-strom.c nvme-strom.h
	$(CC) -o $@ $(USERSPACE_FLAGS) -DBUILD_AS_DRIVERTEST $<

libnvme-strom.so: libnvme-strom.c nvme-strom.h
	$(CC) -o $@ -c -fpic $(USERSPACE_FLAGS) $<

clean:
	rm -f $(EXTRA_CLEAN)
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

%:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

.PHONY: default
