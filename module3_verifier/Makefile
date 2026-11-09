.RECIPEPREFIX = >
# Module 3: per-frame integrity tag (AES-GCM-SIV, RFC 8452).
# libkv.a is linked by the Module 2 daemon; only kv_fast.c is built with the
# AES-NI/VPCLMULQDQ flags (it is entered only after a runtime CPUID check).
CC   ?= gcc
CFLAGS_COMMON := -O2 -g -std=gnu11 -Wall -Wextra -D_GNU_SOURCE -I. -I.. -pthread
FAST_FLAGS    := -mavx2 -mvpclmulqdq -mpclmul -maes

all: libkv.a test_verifier test_baseline

kv_ref.o: kv_ref.c kv_impl.h kv_tag.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

kv_tag.o: kv_tag.c kv_impl.h kv_tag.h ../kim_uapi.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

kv_fast.o: kv_fast.c kv_impl.h kv_tag.h
> $(CC) $(CFLAGS_COMMON) $(FAST_FLAGS) -c -o $@ $<

kv_explain.o: kv_explain.c kv_explain.h ../kim_uapi.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

kv_baseline.o: kv_baseline.c kv_baseline.h kv_explain.h ../kim_uapi.h
> $(CC) $(CFLAGS_COMMON) -c -o $@ $<

libkv.a: kv_ref.o kv_tag.o kv_fast.o kv_explain.o kv_baseline.o
> $(AR) rcs $@ $^

test_verifier: test_verifier.c kv_vectors.h libkv.a
> $(CC) $(CFLAGS_COMMON) -o $@ test_verifier.c libkv.a

test_baseline: test_baseline.c libkv.a
> $(CC) $(CFLAGS_COMMON) -o $@ test_baseline.c libkv.a

# Needs python3-cryptography; the generated header is kept in the tree.
vectors:
> python3 -I gen_vectors.py > kv_vectors.h

test: test_verifier test_baseline
> ./test_verifier
> ./test_baseline

clean:
> rm -f *.o libkv.a test_verifier test_baseline

.PHONY: all vectors test clean
