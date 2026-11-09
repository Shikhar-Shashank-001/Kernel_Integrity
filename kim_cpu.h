/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kim_cpu.h - supported-CPU gate for every user-space binary.
 *
 * The user space is built for Intel Core 12th gen (Alder Lake) and newer:
 * -mavx2 -mvaes everywhere, P/E hybrid scheduling, AES-GCM-SIV with VAES.
 * kim_cpu.c (compiled WITHOUT those flags) runs a constructor before main()
 * that exits with a clear message on any other CPU instead of dying later
 * with SIGILL. KIM_ALLOW_ANY_CPU=1 skips the model check (untested CPUs),
 * never the instruction check.
 */
#ifndef KIM_CPU_H
#define KIM_CPU_H

#include <stdbool.h>

/* family/model as the kernel's intel-family.h numbers them (IFM). */
bool kim_cpu_model_ok(unsigned int family, unsigned int model);

#endif /* KIM_CPU_H */
