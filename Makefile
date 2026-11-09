
ifneq ($(KERNELRELEASE),)
obj-m := kernel_extractor.o
ccflags-y := -I$(src) -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
else
.RECIPEPREFIX = >
KDIR ?= /lib/modules/$(shell uname -r)/build
CC   ?= gcc
SIMD ?= -mavx2 $(shell $(CC) -mvaes -x c -E /dev/null >/dev/null 2>&1 && echo -mvaes)
UCFLAGS := -O3 -std=gnu11 -Wall -Wextra -D_GNU_SOURCE $(SIMD) -I. -pthread
# CPU gate runs before main(): must not itself use AVX (no $(SIMD))
BASEFLAGS := -O2 -std=gnu11 -Wall -Wextra -D_GNU_SOURCE -I.

all: module ingestion_daemon test_extractor

module:
> $(MAKE) -C $(KDIR) M=$(CURDIR) modules

kim_cpu.o: kim_cpu.c kim_cpu.h
> $(CC) $(BASEFLAGS) -c -o $@ kim_cpu.c

ingestion_daemon: ingestion_daemon.c ingestion_daemon.h kim_uapi.h kim_cpu.o
> $(CC) $(UCFLAGS) -o $@ ingestion_daemon.c kim_cpu.o

ingestion_lib.o: ingestion_daemon.c ingestion_daemon.h kim_uapi.h
> $(CC) $(UCFLAGS) -DKIM_LIB_ONLY -c -o $@ ingestion_daemon.c

test_extractor: test_extractor.c ingestion_lib.o kim_cpu.o
> $(CC) $(UCFLAGS) -o $@ test_extractor.c ingestion_lib.o kim_cpu.o -lm

load: module
> insmod kernel_extractor.ko
unload:
> rmmod kernel_extractor
test: module test_extractor
> -rmmod kernel_extractor 2>/dev/null
> insmod kernel_extractor.ko
> ./test_extractor; rc=$$?; rmmod kernel_extractor; exit $$rc

clean:
> $(MAKE) -C $(KDIR) M=$(CURDIR) clean
> rm -f ingestion_daemon test_extractor ingestion_lib.o kim_cpu.o

.PHONY: all module load unload test clean
endif