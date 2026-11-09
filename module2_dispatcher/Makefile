.RECIPEPREFIX = >
# Module 2: cache-aware hybrid core dispatcher (user space only).
# Uses the Module-1 ingestion library and ABI from the parent directory.
CC   ?= gcc
SIMD ?= -mavx2 $(shell $(CC) -mvaes -x c -E /dev/null >/dev/null 2>&1 && echo -mvaes)
UCFLAGS := -O2 -g -std=gnu11 -Wall -Wextra -D_GNU_SOURCE $(SIMD) -I. -I.. -I../module3_verifier -I../module4_enforcer -pthread
BASEFLAGS := -O2 -std=gnu11 -Wall -Wextra -D_GNU_SOURCE -I..   # CPU gate: no $(SIMD)
KV_LIB  := ../module3_verifier/libkv.a
KE_LIB  := ../module4_enforcer/libke.a

KD_SRC := kd_topology.c kd_power.c kd_dispatcher.c
KD_HDR := kd_topology.h kd_power.h kd_dispatcher.h ../ingestion_daemon.h ../kim_uapi.h ../kim_cpu.h

all: kd_daemon test_dispatcher

kim_lib.o: ../ingestion_daemon.c ../ingestion_daemon.h ../kim_uapi.h
> $(CC) $(UCFLAGS) -DKIM_LIB_ONLY -c -o $@ $<

kim_cpu.o: ../kim_cpu.c ../kim_cpu.h
> $(CC) $(BASEFLAGS) -c -o $@ $<

$(KV_LIB): FORCE
> $(MAKE) -C ../module3_verifier libkv.a

$(KE_LIB): FORCE
> $(MAKE) -C ../module4_enforcer libke.a

kd_daemon: kd_daemon.c $(KD_SRC) $(KD_HDR) kim_lib.o kim_cpu.o $(KV_LIB) $(KE_LIB)
> $(CC) $(UCFLAGS) -o $@ kd_daemon.c $(KD_SRC) kim_lib.o kim_cpu.o $(KE_LIB) $(KV_LIB)

test_dispatcher: test_dispatcher.c $(KD_SRC) $(KD_HDR) kim_lib.o kim_cpu.o
> $(CC) $(UCFLAGS) -o $@ test_dispatcher.c $(KD_SRC) kim_lib.o kim_cpu.o -lm

# No root or kernel module needed.
test: test_dispatcher
> ./test_dispatcher

# Same tests under ThreadSanitizer (catches missing barriers in the pipeline).
tsan: kim_cpu.o
> $(CC) $(UCFLAGS) -O1 -fsanitize=thread -DKIM_LIB_ONLY -c -o kim_lib_tsan.o ../ingestion_daemon.c
> $(CC) $(UCFLAGS) -O1 -fsanitize=thread -o test_dispatcher_tsan test_dispatcher.c $(KD_SRC) kim_lib_tsan.o kim_cpu.o -lm
> ./test_dispatcher_tsan

clean:
> rm -f kd_daemon test_dispatcher test_dispatcher_tsan kim_lib.o kim_lib_tsan.o kim_cpu.o

.PHONY: all test tsan clean FORCE
FORCE:
