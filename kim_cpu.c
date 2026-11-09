// SPDX-License-Identifier: GPL-2.0
/*
 * kim_cpu.c - refuse to run on CPUs this build does not target (kim_cpu.h).
 * Must be compiled without -mavx2/-mvaes: it runs before any code that uses them.
 */
#include <cpuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kim_cpu.h"

/* Intel client parts from Alder Lake on (arch/x86/include/asm/intel-family.h). */
bool kim_cpu_model_ok(unsigned int family, unsigned int model)
{
	static const unsigned char fam6[] = {
		0x97, 0x9a,             /* Alder Lake, Alder Lake-L      */
		0xbe,                   /* Alder Lake-N (Gracemont)      */
		0xb7, 0xba, 0xbf,       /* Raptor Lake, -P, -S           */
		0xac, 0xaa,             /* Meteor Lake, -L               */
		0xc5, 0xc6, 0xb5,       /* Arrow Lake-H, Arrow Lake, -U  */
		0xbd,                   /* Lunar Lake-M                  */
		0xcc,                   /* Panther Lake-L                */
		0xd5,                   /* Wildcat Lake-L                */
	};
	unsigned int i;

	if (family == 18)               /* Nova Lake and later client cores */
		return true;
	if (family != 6)
		return false;
	for (i = 0; i < sizeof(fam6); i++)
		if (model == fam6[i])
			return true;
	return false;
}

static void brand(char *buf, size_t n)
{
	unsigned int r[12], i;

	buf[0] = '\0';
	if (__get_cpuid_max(0x80000000, NULL) < 0x80000004 || n < 49)
		return;
	for (i = 0; i < 3; i++)
		__get_cpuid(0x80000002 + i, &r[4 * i], &r[4 * i + 1], &r[4 * i + 2], &r[4 * i + 3]);
	memcpy(buf, r, 48);
	buf[48] = '\0';
}

__attribute__((constructor(101))) static void kim_cpu_gate(void)
{
	unsigned int a = 0, b = 0, c = 0, d = 0, fam, model;
	char vendor[13], name[64];
	const char *missing = NULL;
	const char *allow = getenv("KIM_ALLOW_ANY_CPU");

	__builtin_cpu_init();
	if (!__builtin_cpu_supports("avx2"))
		missing = "AVX2";
	else if (!__builtin_cpu_supports("vaes"))
		missing = "VAES";
	else if (!__builtin_cpu_supports("vpclmulqdq"))
		missing = "VPCLMULQDQ";
	else if (!__builtin_cpu_supports("aes"))
		missing = "AES-NI";
	else if (!__builtin_cpu_supports("pclmul"))
		missing = "PCLMULQDQ";

	__get_cpuid(0, &a, &b, &c, &d);
	memcpy(vendor, &b, 4);
	memcpy(vendor + 4, &d, 4);
	memcpy(vendor + 8, &c, 4);
	vendor[12] = '\0';
	__get_cpuid(1, &a, &b, &c, &d);
	fam = (a >> 8) & 0xf;
	model = (a >> 4) & 0xf;
	if (fam == 6 || fam == 15)
		model |= ((a >> 16) & 0xf) << 4;
	if (fam == 15)
		fam += (a >> 20) & 0xff;
	brand(name, sizeof(name));

	if (!missing && !strcmp(vendor, "GenuineIntel") && kim_cpu_model_ok(fam, model))
		return;
	fprintf(stderr, "kim: unsupported CPU: %s (%s family %u model 0x%x)\n"
		"kim: this build targets Intel Core 12th gen (Alder Lake) and newer",
		name[0] ? name : "?", vendor, fam, model);
	if (missing) {
		fprintf(stderr, "; this CPU lacks %s, which the code uses unconditionally\n", missing);
		exit(1);
	}
	if (allow && !strcmp(allow, "1")) {
		fprintf(stderr, "; KIM_ALLOW_ANY_CPU=1: running anyway (untested)\n");
		return;
	}
	fprintf(stderr, "\nkim: set KIM_ALLOW_ANY_CPU=1 to run anyway (it has the required "
		"instructions, but is untested)\n");
	exit(1);
}
