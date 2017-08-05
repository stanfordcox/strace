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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#include "arch_interface.h"
#include "dispatchers.h"
#include "macros.h"
#include "request_msgs.h"
#include "syscall_interface.h"
#include "sysent.h"
#include "xmalloc.h"

extern struct arch_descriptor architectures[];
extern const int architectures_size;

static int
lookup_arch(struct arch_service **arch, char *arch_str)
{
	ARCH_LIST_DEFINE(a_full_list) = al_create(architectures_size);
	int arch_match = -1;
	char *match_pointer = NULL;
	int al_size_ret = 0;
	int al_size_full = 0;
	int i;

	if (arch_str == NULL)
		return -1;
	/* Firstly, generate full list of arch to simplify further work */
	for (i = 0; i < architectures_size; i++)
		al_push(a_full_list, &architectures[i]);
	al_size_full = al_size(a_full_list);
	/* Here we find the best match for arch_str in architecture list.
	   Best match means here that we have to find the longest name of
	   architecture in a_full_list with arch_str substring, beginning
	   from the first letter */
	for (i = 0; i < al_size_full; i++) {
		match_pointer = strstr(arch_str, al_arch_name(a_full_list, i));
		if (match_pointer == NULL || match_pointer != arch_str)
			continue;
		if (arch_match == -1 ||
		    al_arch_name_len(a_full_list, i) >
		    al_arch_name_len(a_full_list, arch_match))
			arch_match = i;
	}
	if (arch_match == -1)
		goto fail;
	/* Now we find all ABI modes related to the architecture and its other
	   names */
	/* Firstly, find the base arch */
	arch_match = al_find_base_arch(a_full_list, arch_match);
	/* Secondly, it is necessary to calculate size of final arch_list */
	al_size_ret = al_get_abi_modes(a_full_list, arch_match);
	while ((i = al_next_arch_name(a_full_list, arch_match)) != -1)
		al_size_ret++;
	if (al_size_ret == 0)
		goto fail;
	/* Finally, Create arch_list and fill it */
	*arch = al_create(al_size_ret);
	for (i = arch_match; i < (arch_match + al_size_ret); i++)
		al_push(*arch, &architectures[i]);

	free(a_full_list);
	return 0;
fail:
	free(a_full_list);
	return -1;
}

struct arch_service *
arch_dispatcher(unsigned request_type, char *arch)
{
	struct utsname info_uname;
	int i;
	ARCH_LIST_DEFINE(arch_list) = NULL;

	/* If user don't type any option in ARCH_REQ group, it means
	   get current arch */
	if ((request_type & AD_REQ_GET_ARCH) ||
	    (!(request_type & AD_REQ_MASK))) {
		uname(&info_uname);
		if (lookup_arch(&arch_list, info_uname.machine) == -1)
			goto fail;
		goto done;
	}

	if (request_type & AD_REQ_SET_ARCH) {
		if (lookup_arch(&arch_list, arch) == -1)
			goto fail;
		goto done;
	}

	if ((request_type & AD_REQ_LIST_ARCH)) {
		arch_list = al_create(architectures_size);
		for (i = 0; i < architectures_size; i++) {
			al_push(arch_list, &(architectures[i]));
			al_set_flag(arch_list, i, AD_FLAG_PRINT);
		}
		goto done;
	}
fail:
	arch_list = NULL;
done:
	return arch_list;
}

int
abi_dispatcher(struct arch_service *a_serv, unsigned request_type, char *abi)
{
	int i = 0;
	enum arch_name_abi arch_num = ARCH_no_arch;
	int abi_modes = 0;
	int arch_size = 0;
	int flag = 0;

	if (a_serv == NULL)
		return -1;
	arch_size = al_size(a_serv);
	abi_modes = al_get_abi_modes(a_serv, 0);
	/* The strace package could be compiled as 32bit app on 64bit
	   architecture, therefore asinfo has to detect it and print out
	   corresponding personality. Frankly speaking, it is necessary to
	   detect strace package personality */
	if ((request_type & ABD_REQ_GET_ABI) ||
	    (!(request_type & ABD_REQ_MASK))) {
		arch_num = al_arch_num(a_serv, 0);
		switch (arch_num) {
		case ARCH_mips_o32:
			al_set_flag(a_serv, al_find_arch(a_serv,
#if defined(LINUX_MIPSO32)
				    ARCH_mips_o32
#elif defined(LINUX_MIPSN32)
				    ARCH_mips_n32
#else
				    ARCH_mips_n64
#endif
				    ), AD_FLAG_PRINT);
			break;
		case ARCH_arm_oabi:
			al_set_flag(a_serv, al_find_arch(a_serv,
#if defined(__ARM_EABI__)
				    ARCH_arm_eabi
#else
				    ARCH_arm_oabi
#endif
				    ), AD_FLAG_PRINT);
			break;
		case ARCH_aarch64_64bit:
			al_set_flag(a_serv, al_find_arch(a_serv,
#if defined(__ARM_EABI__)
				    ARCH_aarch64_32bit
#else
				    ARCH_aarch64_64bit
#endif
				    ), AD_FLAG_PRINT);
			break;
		case ARCH_x86_64_64bit:
			al_set_flag(a_serv, al_find_arch(a_serv,
#if defined(X86_64)
				    ARCH_x86_64_64bit
#elif defined(X32)
				    ARCH_x86_64_x32
#else
				    ARCH_x86_64_32bit
#endif
				    ), AD_FLAG_PRINT);
			break;
		case ARCH_tile_64bit:
			al_set_flag(a_serv, al_find_arch(a_serv,
#if defined(__tilepro__)
				    ARCH_tile_32bit
#else
				    ARCH_tile_64bit
#endif
				    ), AD_FLAG_PRINT);
			break;
		default:
			/* Other cases should be printed using default rule:
			   print main(first) ABI mode + other arch names */
			al_set_flag(a_serv, 0, AD_FLAG_PRINT);
			for (i = abi_modes; i < arch_size; i++)
				al_set_flag(a_serv, i, AD_FLAG_PRINT);
		}
		goto done;
	}

	if (request_type & ABD_REQ_LIST_ABI) {
		for (i = 0; i < abi_modes; i++)
			al_set_flag(a_serv, i, AD_FLAG_PRINT);
		goto done;
	}

	if (request_type & ABD_REQ_SET_ABI) {
		if (abi == NULL)
			goto fail;
		for (i = 0; i < abi_modes; i++)
			if (strcmp(abi, al_abi_mode(a_serv, i)) == 0) {
				al_set_flag(a_serv, i, AD_FLAG_PRINT);
				flag = 1;
			}
		if (!flag)
			goto fail;
	}
done:
	return 0;
fail:
	return -1;
}

struct syscall_service *
syscall_dispatcher(struct arch_service *arch, int request_type, char *arg)
{
	SYSCALL_LIST_DEFINE(syscall_list) = ss_create(arch, request_type);

	if (request_type & SD_REQ_MASK) {
		ss_update_sc_num(syscall_list);
		ss_mark_matches(syscall_list, arg);
	}

	return syscall_list;
}


