/*
 * The arch_interface.h is purposed to interact with the basic data structure
 * based on arch_descriptor struct. Mainly this set of methods are used by
 * arch_dispatcher.
 *
 * Copyright (c) 2017 Edgar A. Kaziakhmedov <edgar.kaziakhmedv@virtuozzo.com>
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
#ifndef ASINFO_ARCH_INTERFACE
#define ASINFO_ARCH_INTERFACE

#include "sysent.h"

/* Type implementaion of syscall, internal means as a subcall,
   external means a separate syscall, this enum is purposed for
   well-known ipc and socket subcall group */
enum impl_type {
	IMPL_ext,
	IMPL_int,
	IMPL_int_ext
};

/* Names of architectures
 * arch_name_abi format name_arch = ARCH_ + kernel_kernel/other_name +
   abi_mode */
enum arch_name_abi {
	ARCH_blackfin_32bit,
	ARCH_ia64_64bit,
	ARCH_m68k_32bit,
	ARCH_sparc64_64bit,
	ARCH_sparc64_32bit,
	ARCH_sparc_32bit,
	ARCH_metag_32bit,
	ARCH_mips_o32,
	ARCH_mips_n32,
	ARCH_mips_n64,
	ARCH_alpha_64bit,
	ARCH_ppc_32bit,
	ARCH_ppc64_64bit,
	ARCH_ppc64_32bit,
	ARCH_arm_oabi,
	ARCH_arm_eabi,
	ARCH_aarch64_64bit,
	ARCH_aarch64_32bit,
	ARCH_avr32_32bit,
	ARCH_arc_32bit,
	ARCH_s390_32bit,
	ARCH_s390x_64bit,
	ARCH_hppa_32bit,
	ARCH_parisc_32bit,
	ARCH_sh_32bit,
	ARCH_sh64_64bit,
	ARCH_x86_32bit,
	ARCH_i386_32bit,
	ARCH_i486_32bit,
	ARCH_i586_32bit,
	ARCH_i686_32bit,
	ARCH_x86_64_64bit,
	ARCH_x86_64_32bit,
	ARCH_x86_64_x32,
	ARCH_amd64_64bit,
	ARCH_cris_32bit,
	ARCH_crisv10_32bit,
	ARCH_crisv32_32bit,
	ARCH_tile_64bit,
	ARCH_tile_32bit,
	ARCH_microblaze_32bit,
	ARCH_nios2_32bit,
	ARCH_openrisc_32bit,
	ARCH_xtensa_32bit,
	ARCH_riscv_64bit,
	ARCH_riscv_32bit,
	ARCH_no_arch
};

struct arch_descriptor {
	enum arch_name_abi arch_num;
	const char *arch_name;
	const int arch_name_len;
	enum arch_name_abi arch_base_num;
	const char *abi_mode;
	const int abi_mode_len;
	const int max_scn;
	struct_sysent *syscall_list;
	/* In the most cases these fields are purposed to store specific for
	   given arch constants, for instance, ARM_FIRST_SHUFFLED_SYSCALL */
	const int *user_num1;
	const int *user_num2;
};

#define AD_FLAG_EMPTY 0
/* Actually, this flag is purposed to hide some abi modes while printing in
   one arch group
   NOTE: arch group means base arch name + others */
#define AD_FLAG_PRINT 1

/* To provide push-back interface with arch_list */
struct arch_service {
	/* immutable field */
	struct arch_descriptor **arch_list;
	/* User flags for each arch_descriptor */
	int *flag;
	unsigned capacity;
	unsigned next_free;
};

#define ARCH_LIST_DEFINE(name) \
	struct arch_service *(name)

/* Push-back interface is purposed to simplify interaction with
   arch_service struct
   NOTE: al - architecture list */

/* base methods */
struct arch_service *al_create(unsigned int capacity);

int al_push(struct arch_service *m, struct arch_descriptor *element);

int al_set_flag(struct arch_service *m, unsigned index, int flag);

struct arch_descriptor *al_get(struct arch_service *m, unsigned index);

unsigned int al_size(struct arch_service *m);

unsigned int al_base_size(struct arch_service *m);

void al_free(struct arch_service *m);

/* methods returning fields with error check */
enum arch_name_abi al_arch_num(struct arch_service *m, unsigned index);

const char *al_arch_name(struct arch_service *m, unsigned index);

int al_arch_name_len(struct arch_service *m, unsigned index);

enum arch_name_abi al_arch_base_num(struct arch_service *m, unsigned index);

const char *al_abi_mode(struct arch_service *m, unsigned index);

int al_abi_mode_len(struct arch_service *m, unsigned index);

int al_flag(struct arch_service *m, unsigned index);

/* calculating methods */
int al_syscall_impl(struct arch_service *m, unsigned index);

int al_find_base_arch(struct arch_service *m, unsigned index);

int al_get_abi_modes(struct arch_service *m, unsigned index);

int al_is_arch_source(struct arch_service *m, unsigned index);

enum impl_type al_ipc_syscall(struct arch_service *m, unsigned index);

enum impl_type al_sck_syscall(struct arch_service *m, unsigned index);

int al_find_arch(struct arch_service *m, enum arch_name_abi a_type);

int al_next_arch_name(struct arch_service *m, unsigned index);

void al_dump(struct arch_service *m);

#endif /* !ASINFO_ARCH_INTERFACE */
