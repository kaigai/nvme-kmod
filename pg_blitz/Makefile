PG_BLITZ_VERSION := 1.0devel
PG_BLITZ_VERSION_NUM=$(shell echo $(PG_BLITZ_VERSION)	\
    | sed -e 's/\./ /g' -e 's/[A-Za-z].*$$//g'		\
    | awk '{printf "%d%02d%02d", $$1, $$2, (NF >=3) ? $$3 : 0}')

KERNEL_UNAME := $(shell uname -r)
KERNEL_SOURCE := /lib/modules/$(KERNEL_UNAME)/build

obj-m := pg_blitz.o
ccflags-y := -I.									\
	-DPG_BLITZ_VERSION='"$(PG_BLITZ_VERSION)"'		\
	-DPG_BLITZ_VERSION_NUM=$(PG_BLITZ_VERSION_NUM)	\
	-DPG_BLITZ_BUILD_TIMESTAMP='"$(PG_BLITZ_BUILD_TIMESTAMP=)"'

default: modules blitz_test

blitz_test: blitz_test.c pg_blitz.h
	$(CC) -O2 -g -Wall -o $@ blitz_test.c

%:
	$(MAKE) -C $(KERNEL_SOURCE) M=$(PWD) $@

.PHONY:	default
