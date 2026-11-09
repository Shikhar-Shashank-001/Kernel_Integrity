.RECIPEPREFIX = >
# Module 4: lockdown & action enforcement (user space).
# libke.a is linked by the Module 2 daemon together with Module 3's libkv.a.
CC   ?= gcc
CFLAGS_COMMON := -O2 -g -std=gnu11 -Wall -Wextra -D_GNU_SOURCE -I. -I.. -I../module3_verifier
KV_LIB := ../module3_verifier/libkv.a

all: libke.a test_enforcer

ke.o: ke.c ke.h ../module3_verifier/kv_baseline.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

ke_io.o: ke_io.c ke.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

libke.a: ke.o ke_io.o
> $(AR) rcs $@ $^

$(KV_LIB): FORCE
> $(MAKE) -C ../module3_verifier libkv.a

test_enforcer: test_enforcer.c libke.a $(KV_LIB)
> $(CC) $(CFLAGS_COMMON) -o $@ test_enforcer.c libke.a $(KV_LIB) -pthread

# No root needed: all actions go to a mock backend.
test: test_enforcer
> ./test_enforcer

clean:
> rm -f *.o libke.a test_enforcer

.PHONY: all test clean FORCE
FORCE:
