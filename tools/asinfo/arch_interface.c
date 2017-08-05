/*
 * Copyright (c) 2017 Edgar A. Kaziakhmedov <edgar.kaziakhmedov@virtuozzo.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch_interface.h"
#include "defs.h"
#include "macros.h"
#include "xmalloc.h"

/* Define these shorthand notations to simplify the syscallent files. */
/* These flags could be useful to print group of syscalls */
#define DEFINE_SHORTHAND
#include "shorthand_def.h"

/*
 * For the current functionality there is no need
 * to use sen and (*sys_func)() fields in sysent struct
 */
#define SEN(syscall_name) 0, NULL

/* dummy_sysent is purposed to set syscall_list field in
 * inherited architectures */
struct_sysent dummy_sysent[] = {};

/* ARCH_blackfin */
struct_sysent blackfin_32bit_sysent[] = {
	#include "bfin/syscallent.h"
};
const int blackfin_32bit_usr1 = 0;
const int blackfin_32bit_usr2 = 0;
/* ARCH_ia64 */
struct_sysent ia64_64bit_sysent[] = {
	#include "ia64/syscallent.h"
};
const int ia64_64bit_usr1 = 0;
const int ia64_64bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_m68k */
struct_sysent m68k_32bit_sysent[] = {
	#include "m68k/syscallent.h"
};
const int m68k_32bit_usr1 = 0;
const int m68k_32bit_usr2 = 0;
/* ARCH_sparc64 64bit ABI */
struct_sysent sparc64_64bit_sysent[] = {
	#include "sparc64/syscallent.h"
};
const int sparc64_64bit_usr1 = 0;
const int sparc64_64bit_usr2 = 0;
/* ARCH_sparc64 32bit ABI */
struct_sysent sparc64_32bit_sysent[] = {
	#include "sparc64/syscallent1.h"
};
const int sparc64_32bit_usr1 = 0;
const int sparc64_32bit_usr2 = 0;
/* ARCH_sparc */
struct_sysent sparc_32bit_sysent[] = {
	#include "sparc/syscallent.h"
};
const int sparc_32bit_usr1 = 0;
const int sparc_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_metag */
struct_sysent metag_32bit_sysent[] = {
	#include "metag/syscallent.h"
};
const int metag_32bit_usr1 = 0;
const int metag_32bit_usr2 = 0;
/* ARCH_mips o32 ABI */
#ifndef LINUX_MIPSO32
# define LINUX_MIPSO32 1
# define NOW_DEFINED 1
#endif
struct_sysent mips_o32_sysent[] = {
	#include "dummy.h"
	#include "mips/syscallent-compat.h"
	#include "mips/syscallent-o32.h"
};
#ifdef NOW_DEFINED
# undef LINUX_MIPSO32
# undef NOW_DEFINED
#endif
const int mips_o32_usr1 = 0;
const int mips_o32_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_mips n32 ABI */
#ifndef LINUX_MIPSN32
# define LINUX_MIPSN32 1
# define NOW_DEFINED 1
#endif
struct_sysent mips_n32_sysent[] = {
	#include "dummy.h"
	#include "mips/syscallent-compat.h"
	#include "mips/syscallent-n32.h"
};
#ifdef NOW_DEFINED
# undef LINUX_MIPSN32
# undef NOW_DEFINED
#endif
const int mips_n32_usr1 = 0;
const int mips_n32_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_mips n64 ABI */
#ifndef LINUX_MIPSN64
# define LINUX_MIPSN64 1
# define NOW_DEFINED 1
#endif
struct_sysent mips_n64_sysent[] = {
	#include "dummy.h"
	#include "mips/syscallent-compat.h"
	#include "mips/syscallent-n64.h"
};
#ifdef NOW_DEFINED
# undef LINUX_MIPSN32
# undef NOW_DEFINED
#endif
const int mips_n64_usr1 = 0;
const int mips_n64_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_alpha */
struct_sysent alpha_64bit_sysent[] = {
	#include "alpha/syscallent.h"
};
const int alpha_64bit_usr1 = 0;
const int alpha_64bit_usr2 = 0;
/* ARCH_ppc */
struct_sysent ppc_32bit_sysent[] = {
	#include "powerpc/syscallent.h"
};
const int ppc_32bit_usr1 = 0;
const int ppc_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_ppc64 64bit ABI */
struct_sysent ppc64_64bit_sysent[] = {
	#include "powerpc64/syscallent.h"
};
const int ppc64_64bit_usr1 = 0;
const int ppc64_64bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_ppc64 32bit ABI */
struct_sysent ppc64_32bit_sysent[] = {
	#include "powerpc64/syscallent1.h"
};
const int ppc64_32bit_usr1 = 0;
const int ppc64_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_arm OABI*/
#ifdef __ARM_EABI__
# undef __ARM_EABI__
# define NOW_UNDEFINED 1
#endif
struct_sysent arm_oabi_sysent[] = {
	#include "arm/syscallent.h"
};
const int arm_oabi_usr1 = ARM_FIRST_SHUFFLED_SYSCALL;
const int arm_oabi_usr2 = ARM_LAST_SPECIAL_SYSCALL;
#undef ARM_FIRST_SHUFFLED_SYSCALL
#undef ARM_LAST_SPECIAL_SYSCALL
#undef SYS_socket_subcall
#ifdef NOW_UNDEFINED
# define __ARM_EABI__ 1
# undef NOW_UNDEFINED
#endif
/* ARCH_arm EABI*/
#ifndef __ARM_EABI__
# define __ARM_EABI__ 1
# define NOW_DEFINED 1
#endif
struct_sysent arm_eabi_sysent[] = {
	#include "arm/syscallent.h"
};
const int arm_eabi_usr1 = ARM_FIRST_SHUFFLED_SYSCALL;
const int arm_eabi_usr2 = ARM_LAST_SPECIAL_SYSCALL;
#undef ARM_FIRST_SHUFFLED_SYSCALL
#undef ARM_LAST_SPECIAL_SYSCALL
#ifdef NOW_DEFINED
# undef __ARM_EABI__
# undef NOW_DEFINED
#endif
/* ARCH_aarch64 64bit ABI */
struct_sysent aarch64_64bit_sysent[] = {
	#include "aarch64/syscallent.h"
};
const int aarch64_64bit_usr1 = 0;
const int aarch64_64bit_usr2 = 0;
/* ARCH_aarch64 32bit ABI */
#ifndef __ARM_EABI__
# define __ARM_EABI__ 1
# define NOW_DEFINED 1
#endif
struct_sysent aarch64_32bit_sysent[] = {
	#include "aarch64/syscallent1.h"
};
const int aarch64_32bit_usr1 = ARM_FIRST_SHUFFLED_SYSCALL;
const int aarch64_32bit_usr2 = ARM_LAST_SPECIAL_SYSCALL;
#undef ARM_FIRST_SHUFFLED_SYSCALL
#undef ARM_LAST_SPECIAL_SYSCALL
#ifdef NOW_DEFINED
# undef __ARM_EABI__
# undef NOW_DEFINED
#endif
/* ARCH_avr32 */
struct_sysent avr32_32bit_sysent[] = {
	#include "avr32/syscallent.h"
};
const int avr32_32bit_usr1 = 0;
const int avr32_32bit_usr2 = 0;
/* ARCH_arc */
struct_sysent arc_32bit_sysent[] = {
	#include "arc/syscallent.h"
};
const int arc_32bit_usr1 = 0;
const int arc_32bit_usr2 = 0;
/* ARCH_s390 */
struct_sysent s390_32bit_sysent[] = {
	#include "s390/syscallent.h"
};
const int s390_32bit_usr1 = 0;
const int s390_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_s390x */
struct_sysent s390x_64bit_sysent[] = {
	#include "s390x/syscallent.h"
};
const int s390x_64bit_usr1 = 0;
const int s390x_64bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_hppa */
struct_sysent hppa_32bit_sysent[] = {
	#include "hppa/syscallent.h"
};
const int hppa_32bit_usr1 = 0;
const int hppa_32bit_usr2 = 0;
/* ARCH_parisc */
#define parisc_32bit_sysent dummy_sysent
const int parisc_32bit_usr1 = 0;
const int parisc_32bit_usr2 = 0;
/* ARCH_sh */
struct_sysent sh_32bit_sysent[] = {
	#include "sh/syscallent.h"
};
const int sh_32bit_usr1 = 0;
const int sh_32bit_usr2 = 0;
/* ARCH_sh64 */
struct_sysent sh64_64bit_sysent[] = {
	#include "sh64/syscallent.h"
};
const int sh64_64bit_usr1 = 0;
const int sh64_64bit_usr2 = 0;
/* ARCH_x86 */
struct_sysent x86_32bit_sysent[] = {
	#include "i386/syscallent.h"
};
const int x86_32bit_usr1 = 0;
const int x86_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_i386 */
#define i386_32bit_sysent dummy_sysent
const int i386_32bit_usr1 = 0;
const int i386_32bit_usr2 = 0;
/* ARCH_i486 */
#define i486_32bit_sysent dummy_sysent
const int i486_32bit_usr1 = 0;
const int i486_32bit_usr2 = 0;
/* ARCH_i586 */
#define i586_32bit_sysent dummy_sysent
const int i586_32bit_usr1 = 0;
const int i586_32bit_usr2 = 0;
/* ARCH_i686 */
#define i686_32bit_sysent dummy_sysent
const int i686_32bit_usr1 = 0;
const int i686_32bit_usr2 = 0;
/* ARCH_x86_64 64bit ABI mode */
struct_sysent x86_64_64bit_sysent[] = {
	#include "x86_64/syscallent.h"
};
const int x86_64_64bit_usr1 = 0;
const int x86_64_64bit_usr2 = 0;
/* ARCH_x86_64 32bit ABI mode */
struct_sysent x86_64_32bit_sysent[] = {
	#include "x86_64/syscallent1.h"
};
const int x86_64_32bit_usr1 = 0;
const int x86_64_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_x86_64 x32 ABI mode */
struct_sysent x86_64_x32_sysent[] = {
	#include "x86_64/syscallent2.h"
};
const int x86_64_x32_usr1 = 0;
const int x86_64_x32_usr2 = 0;
/* ARCH_amd64 */
#define amd64_64bit_sysent dummy_sysent
const int amd64_64bit_usr1 = 0;
const int amd64_64bit_usr2 = 0;
/* ARCH_cris */
struct_sysent cris_32bit_sysent[] = {
	#include "crisv10/syscallent.h"
};
const int cris_32bit_usr1 = 0;
const int cris_32bit_usr2 = 0;
/* ARCH_crisv10 */
#define crisv10_32bit_sysent dummy_sysent
const int crisv10_32bit_usr1 = 0;
const int crisv10_32bit_usr2 = 0;
/* ARCH_crisv32 */
struct_sysent crisv32_32bit_sysent[] = {
	#include "crisv32/syscallent.h"
};
const int crisv32_32bit_usr1 = 0;
const int crisv32_32bit_usr2 = 0;
#undef SYS_socket_subcall
/* ARCH_tile 64bit ABI mode */
struct_sysent tile_64bit_sysent[] = {
	#include "tile/syscallent.h"
};
const int tile_64bit_usr1 = 0;
const int tile_64bit_usr2 = 0;
/* ARCH_tile 32bit ABI mode */
struct_sysent tile_32bit_sysent[] = {
	#include "tile/syscallent1.h"
};
const int tile_32bit_usr1 = 0;
const int tile_32bit_usr2 = 0;
/* ARCH_microblaze */
struct_sysent microblaze_32bit_sysent[] = {
	#include "microblaze/syscallent.h"
};
const int microblaze_32bit_usr1 = 0;
const int microblaze_32bit_usr2 = 0;
/* ARCH_nios2 */
struct_sysent nios2_32bit_sysent[] = {
	#include "nios2/syscallent.h"
};
const int nios2_32bit_usr1 = 0;
const int nios2_32bit_usr2 = 0;
/* ARCH_openrisc */
struct_sysent openrisc_32bit_sysent[] = {
	#include "or1k/syscallent.h"
};
const int openrisc_32bit_usr1 = 0;
const int openrisc_32bit_usr2 = 0;
/* ARCH_xtensa */
struct_sysent xtensa_32bit_sysent[] = {
	#include "xtensa/syscallent.h"
};
const int xtensa_32bit_usr1 = 0;
const int xtensa_32bit_usr2 = 0;
/* ARCH_riscv 64bit ABI mode */
struct_sysent riscv_64bit_sysent[] = {
	#include "riscv/syscallent.h"
};
const int riscv_64bit_usr1 = 0;
const int riscv_64bit_usr2 = 0;
/* ARCH_riscv 32bit ABI mode */
struct_sysent riscv_32bit_sysent[] = {
	#include "riscv/syscallent1.h"
};
const int riscv_32bit_usr1 = 0;
const int riscv_32bit_usr2 = 0;

#undef DEFINE_SYSCALLENT

#define DEFINE_SHORTHAND
#include "shorthand_def.h"

#define ARCH_DESC_DEFINE(arch, base_arch, mode) \
	[ARCH_##arch##_##mode] = { \
		.arch_num		= ARCH_##arch##_##mode, \
		.arch_name		= #arch, \
		.arch_name_len		= ARRAY_SIZE(#arch) - 1, \
		.arch_base_num		= ARCH_##base_arch##_##mode, \
		.abi_mode		= #mode, \
		.abi_mode_len		= ARRAY_SIZE(#arch) - 1, \
		.max_scn		= ARRAY_SIZE(arch##_##mode##_sysent), \
		.syscall_list		= arch##_##mode##_sysent, \
		.user_num1		= &arch##_##mode##_usr1, \
		.user_num2		= &arch##_##mode##_usr2, \
	}

/* Generate array of arch_descriptors for each architecture and mode */
struct arch_descriptor architectures[] = {
	ARCH_DESC_DEFINE(blackfin,	blackfin,	32bit	),
	ARCH_DESC_DEFINE(ia64,		ia64,		64bit	),
	ARCH_DESC_DEFINE(m68k,		m68k,		32bit	),
	ARCH_DESC_DEFINE(sparc64,	sparc64,	64bit	),
	ARCH_DESC_DEFINE(sparc64,	sparc64,	32bit	),
	ARCH_DESC_DEFINE(sparc,		sparc,		32bit	),
	ARCH_DESC_DEFINE(metag,		metag,		32bit	),
	ARCH_DESC_DEFINE(mips,		mips,		o32	),
	ARCH_DESC_DEFINE(mips,		mips,		n32	),
	ARCH_DESC_DEFINE(mips,		mips,		n64	),
	ARCH_DESC_DEFINE(alpha,		alpha,		64bit	),
	ARCH_DESC_DEFINE(ppc,		ppc,		32bit	),
	ARCH_DESC_DEFINE(ppc64,		ppc64,		64bit	),
	ARCH_DESC_DEFINE(ppc64,		ppc64,		32bit	),
	ARCH_DESC_DEFINE(arm,		arm,		oabi	),
	ARCH_DESC_DEFINE(arm,		arm,		eabi	),
	ARCH_DESC_DEFINE(aarch64,	aarch64,	64bit	),
	ARCH_DESC_DEFINE(aarch64,	aarch64,	32bit	),
	ARCH_DESC_DEFINE(avr32,		avr32,		32bit	),
	ARCH_DESC_DEFINE(arc,		arc,		32bit	),
	ARCH_DESC_DEFINE(s390,		s390,		32bit	),
	ARCH_DESC_DEFINE(s390x,		s390x,		64bit	),
	ARCH_DESC_DEFINE(hppa,		hppa,		32bit	),
	ARCH_DESC_DEFINE(parisc,	hppa,		32bit	),
	ARCH_DESC_DEFINE(sh,		sh,		32bit	),
	ARCH_DESC_DEFINE(sh64,		sh64,		64bit	),
	ARCH_DESC_DEFINE(x86,		x86,		32bit	),
	ARCH_DESC_DEFINE(i386,		x86,		32bit	),
	ARCH_DESC_DEFINE(i486,		x86,		32bit	),
	ARCH_DESC_DEFINE(i586,		x86,		32bit	),
	ARCH_DESC_DEFINE(i686,		x86,		32bit	),
	ARCH_DESC_DEFINE(x86_64,	x86_64,		64bit	),
	ARCH_DESC_DEFINE(x86_64,	x86_64,		32bit	),
	ARCH_DESC_DEFINE(x86_64,	x86_64,		x32	),
	ARCH_DESC_DEFINE(amd64,		x86_64,		64bit	),
	ARCH_DESC_DEFINE(cris,		cris,		32bit	),
	ARCH_DESC_DEFINE(crisv10,	cris,		32bit	),
	ARCH_DESC_DEFINE(crisv32,	crisv32,	32bit	),
	ARCH_DESC_DEFINE(tile,		tile,		64bit	),
	ARCH_DESC_DEFINE(tile,		tile,		32bit	),
	ARCH_DESC_DEFINE(microblaze,	microblaze,	32bit	),
	ARCH_DESC_DEFINE(nios2,		nios2,		32bit	),
	ARCH_DESC_DEFINE(openrisc,	openrisc,	32bit	),
	ARCH_DESC_DEFINE(xtensa,	xtensa,		32bit	),
	ARCH_DESC_DEFINE(riscv,		riscv,		64bit	),
	ARCH_DESC_DEFINE(riscv,		riscv,		32bit	)
};

/* To make architectures array usable for dispatchers.c */
const int architectures_size = ARRAY_SIZE(architectures);

#undef ARCH_DESC_DEFINE

struct arch_service *
al_create(unsigned int capacity)
{
	struct arch_service *as = NULL;

	if (!capacity)
		return NULL;
	as = xcalloc(sizeof(*as), 1);
	as->arch_list = xcalloc(sizeof(*(as->arch_list)), capacity);
	as->flag = xcalloc(sizeof(*(as->flag)), capacity);
	as->capacity = capacity;
	as->next_free = 0;
	return as;
}

int
al_push(struct arch_service *m, struct arch_descriptor *element)
{
	if (m->next_free >= m->capacity)
		return -1;
	m->arch_list[m->next_free] = element;
	m->flag[m->next_free] = AD_FLAG_EMPTY;
	m->next_free++;
	return 0;
}

static inline int
al_is_index_ok(struct arch_service *m, unsigned index) {
	if (index >= m->next_free)
		return -1;
	return 0;
}

int
al_set_flag(struct arch_service *m, unsigned index, int flag)
{
	if (al_is_index_ok(m, index) == 0) {
		m->flag[index] = flag;
		return 0;
	}
	return -1;
}

struct arch_descriptor *
al_get(struct arch_service *m, unsigned index)
{
	if (al_is_index_ok(m, index) != 0)
		return NULL;
	return m->arch_list[index];
}

unsigned int
al_size(struct arch_service *m)
{
	return m->next_free;
}

unsigned int
al_base_size(struct arch_service *m)
{
	int arch_size = al_size(m);
	int i = 0;
	unsigned count = 0;

	for (i = 0; i < arch_size; i++)
		if (m->arch_list[i]->arch_num ==
		    m->arch_list[i]->arch_base_num)
			count++;
	return count;
}

void
al_free(struct arch_service *m)
{
	free(m->arch_list);
	free(m);
}

enum arch_name_abi
al_arch_num(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->arch_num : ARCH_no_arch);
}

const char *
al_arch_name(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->arch_name : NULL);
}

int
al_arch_name_len(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->arch_name_len : -1);
}

enum arch_name_abi
al_arch_base_num(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->arch_base_num : ARCH_no_arch);
}

const char *
al_abi_mode(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->abi_mode : NULL);
}

int
al_abi_mode_len(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);

	return (elem ? elem->abi_mode_len : -1);
}

int
al_flag(struct arch_service *m, unsigned index)
{
	int status = al_is_index_ok(m, index);

	return (!status ? m->flag[index] : -1);
}

int
al_syscall_impl(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);
	int i = 0;
	int count = 0;

	if (elem == NULL)
		return -1;
	for (i = 0; i < elem->max_scn; i++) {
		if (elem->syscall_list[i].sys_name &&
		   !(elem->syscall_list[i].sys_flags &
		   TRACE_INDIRECT_SUBCALL))
			count++;
	}
	return count;
}

/* This method is purposed to find base arch
   NOTE: base arch is the arch, where arch_num is equal to arch_base_num
   with default ABI mode */
int
al_find_base_arch(struct arch_service *m, unsigned index)
{
	enum arch_name_abi base_arch = ARCH_no_arch;
	const char *arch_name = NULL;
	int mode = 0;
	int i = 0;

	if (al_is_index_ok(m, index) != 0)
		return -1;
	/* Is input arch ABI mode? */
	if (al_arch_base_num(m, index) == al_arch_num(m, index))
		mode = 1;
	/* Search base arch */
	base_arch = al_arch_base_num(m, index);
	arch_name = al_arch_name(m, index);
	for (i = index; i >= 0; i--) {
		if (!mode && (al_arch_num(m, i) != base_arch))
			continue;
		else {
			if (!mode)
				arch_name = al_arch_name(m, i);
			mode = 1;
		}
		if (mode && !strcmp(arch_name, al_arch_name(m, i)))
			continue;
		break;
	}
	return i + 1;
}

/* This method is purposed to count the supported ABI modes for the given
   arch */
int
al_get_abi_modes(struct arch_service *m, unsigned index)
{
	const char *arch_name = al_arch_name(m, index);
	int arch_size = al_size(m);
	int i = 0;
	int abi_count = 0;

	if (!arch_name)
		return -1;
	index = al_find_base_arch(m, index);
	for (i = index; i < arch_size; i++) {
		if (strcmp(arch_name, al_arch_name(m, i)) == 0) {
			abi_count++;
			continue;
		}
		break;
	}
	return abi_count;
}

/* If index is related to the first definition of arch in arch_list -> 0 */
int
al_is_arch_source(struct arch_service *m, unsigned index)
{
	int abi_modes = 0;
	unsigned base_index = 0;

	if (al_arch_num(m, index) != al_arch_base_num(m, index) ||
	    al_arch_num(m, index) == ARCH_no_arch)
		return -1;
	base_index = al_find_base_arch(m, index);
	abi_modes = al_get_abi_modes(m, index);
	if ((index >= base_index) && (index < base_index + abi_modes))
		return 0;
	return -1;
}

enum impl_type
al_ipc_syscall(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);
	int i;
	enum impl_type impl_buf = IMPL_int;

	for (i = 0; i < elem->max_scn; i++) {
		if (elem->syscall_list[i].sys_name == NULL)
			continue;
		/* It is enough to find just semop sybcall */
		if (!strcmp(elem->syscall_list[i].sys_name, "semop")) {
			if (!(elem->syscall_list[i].sys_flags &
			     TRACE_INDIRECT_SUBCALL))
				impl_buf = IMPL_ext;
			else if (impl_buf == IMPL_ext)
				impl_buf = IMPL_int_ext;
			else
				impl_buf = IMPL_int;
		}
	}
	return impl_buf;
}

enum impl_type
al_sck_syscall(struct arch_service *m, unsigned index)
{
	struct arch_descriptor *elem = al_get(m, index);
	int i;
	enum impl_type impl_buf = IMPL_int;

	for (i = 0; i < elem->max_scn; i++) {
		if (elem->syscall_list[i].sys_name == NULL)
			continue;
		/* It is enough to find just socket sybcall */
		if (!strcmp(elem->syscall_list[i].sys_name, "socket")) {
			if (!(elem->syscall_list[i].sys_flags &
			     TRACE_INDIRECT_SUBCALL))
				impl_buf = IMPL_ext;
			else if (impl_buf == IMPL_ext)
				impl_buf = IMPL_int_ext;
			else
				impl_buf = IMPL_int;
		}
	}
	return impl_buf;
}

int al_find_arch(struct arch_service *m, enum arch_name_abi a_type)
{
	int arch_size = al_size(m);
	int i;

	for (i = 0; i < arch_size; i++)
		if (al_arch_num(m, i) == a_type)
			return i;
	return -1;
}

/* This method is purposed to find next one name of the same architecture.
   For instance, x86_64 = amd64 */
int
al_next_arch_name(struct arch_service *m, unsigned index)
{
	static int next_arch = -1;
	int i = 0;
	int arch_size = al_size(m);

	if (next_arch == -1)
		next_arch = index;
	else
		next_arch++;
	if (al_arch_num(m, index) != al_arch_base_num(m, index) ||
	    al_arch_num(m, index) == ARCH_no_arch)
		return -1;
	for (i = next_arch; i < arch_size; i++) {
		next_arch = -1;
		if (strcmp(al_arch_name(m, index), al_arch_name(m, i)) == 0)
			continue;
		if (al_arch_base_num(m, index) == al_arch_base_num(m, i)) {
			next_arch = i;
			break;
		}
		break;
	}
	if (next_arch >= arch_size)
		next_arch = -1;
	return next_arch;
}

void
al_dump(struct arch_service *m)
{
	const char *title[] = {
		"N",
		"Architecture name",
		"ABI mode",
		/* Implemented syscalls */
		"IMPL syscalls",
		/* IPC implementation */
		"IPC IMPL",
		/* SOCKET implementation */
		"SOCKET IMPL"
	};
	int title_len[] = {
		0,
		strlen(title[1]),
		strlen(title[2]),
		strlen(title[3]),
		strlen(title[4]),
		strlen(title[5]),
	};
	const char *impl_st[] = {
		"external",
		"internal",
		"int/ext"
	};
	int i = 0;
	int lbase_arch = 0;
	int temp_len = 0;
	int arch_size = al_size(m);
	int arch_base_size = al_base_size(m);
	int N = 0;
	int next_name = 0;
	char *arch_name_buf;

	/* Calculate length of the column with the number of architectures */
	for (i = 1; arch_base_size/i != 0; i *= 10)
		title_len[0]++;
	for (i = 0; i < arch_size; i++) {
		/* Calculate length of the column with the
		   architectures name */
		if (al_is_arch_source(m, i) == -1)
			continue;
		lbase_arch = al_find_base_arch(m, i);
		temp_len = al_arch_name_len(m, lbase_arch);
		while ((next_name = al_next_arch_name(m, lbase_arch)) != -1) {
			temp_len += al_arch_name_len(m, next_name);
			/* To take into account delim symbol */
			temp_len++;
		}
		if (temp_len > title_len[1])
			title_len[1] = temp_len;
		/* Calculate length of the column with the ABI mode */
		if (al_abi_mode_len(m, i) > title_len[2])
			title_len[2] = al_abi_mode_len(m, i);
	}

	arch_name_buf = xcalloc(title_len[1], sizeof(*arch_name_buf));
	/* Output title */
	printf("| %*s | %*s | %*s | %*s | %*s | %*s |\n",
		title_len[0], title[0], title_len[1], title[1],
		title_len[2], title[2], title_len[3], title[3],
		title_len[4], title[4], title_len[5], title[5]);
	/* Output architectures */
	for (i = 0; i < arch_size; i++) {
		if ((al_is_arch_source(m, i) == -1) ||
		    !(al_flag(m, i) & AD_FLAG_PRINT))
			continue;
		printf("| %*u | ", title_len[0], N + 1);
		/* Put all the same arch back together */
		strcat(arch_name_buf, al_arch_name(m, i));
		lbase_arch = al_find_base_arch(m, i);
		while ((next_name = al_next_arch_name(m, lbase_arch)) != -1) {
			strcat(arch_name_buf, "/");
			strcat(arch_name_buf, al_arch_name(m, next_name));
		}
		printf("%*s | ", title_len[1], arch_name_buf);
		printf("%*s | ", title_len[2], al_abi_mode(m, i));
		printf("%*d | ", title_len[3], al_syscall_impl(m, i));
		printf("%*s | ", title_len[4], impl_st[al_ipc_syscall(m, i)]);
		printf("%*s |\n", title_len[5], impl_st[al_sck_syscall(m, i)]);
		N++;
		memset(arch_name_buf, 0, title_len[1]);
	}
	free(arch_name_buf);
}
