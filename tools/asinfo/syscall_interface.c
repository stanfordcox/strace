/*
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch_interface.h"
#include "syscall_interface.h"
#include "request_msgs.h"
#include "xmalloc.h"

struct syscall_service *
ss_create(struct arch_service *m, int request_type)
{
	int i;
	int arch_list_size = al_size(m);
	struct arch_descriptor *ad = NULL;
	struct syscall_service *ss = NULL;

	/* Function calling syscall_service should make sure,
	   that there is just one arch with AD_FLAG_PRINT flag */
	for (i = 0; i < arch_list_size; i++)
		if (al_flag(m, i) & AD_FLAG_PRINT)
			ad = al_get(m, i);
	ss = xcalloc(sizeof(*ss), 1);
	ss->flag = xcalloc(sizeof(*(ss->flag)), ad->max_scn);
	ss->real_sys_num = xcalloc(sizeof(*(ss->real_sys_num)), ad->max_scn);
	ss->arch = ad;
	ss->request_type = request_type;
	return ss;
}

int
ss_flag(struct syscall_service *s, int num)
{
	if (num >= s->arch->max_scn)
		return -1;
	return s->flag[num];
}

int
ss_set_flag(struct syscall_service *s, int num, int flag)
{
	if (num >= s->arch->max_scn)
		return -1;
	s->flag[num] = flag;
	return 0;
}

enum input_type
ss_it(struct syscall_service *s)
{
	return s->it;
}

void
ss_set_input(struct syscall_service *s, enum input_type it)
{
	s->it = it;
}

int
ss_max_scn(struct syscall_service *s)
{
	return s->arch->max_scn;
}

int
ss_real_num(struct syscall_service *s, int num)
{
	if (num >= s->arch->max_scn)
		return -1;
	return s->real_sys_num[num];
}

int
ss_set_real_num(struct syscall_service *s, int num, int real_num)
{
	if (num >= s->arch->max_scn)
		return -1;
	s->real_sys_num[num] = real_num;
	return 0;
}

const char *
ss_syscall_name(struct syscall_service *s, int num)
{
	return s->arch->syscall_list[num].sys_name;
}

int
ss_syscall_flag(struct syscall_service *s, int num)
{
	return s->arch->syscall_list[num].sys_flags;
}

unsigned
ss_syscall_nargs(struct syscall_service *s, int num)
{
	return s->arch->syscall_list[num].nargs;
}

int
ss_user_num1(struct syscall_service *s)
{
	return *(s->arch->user_num1);
}

int
ss_user_num2(struct syscall_service *s)
{
	return *(s->arch->user_num2);
}

void
ss_free(struct syscall_service *s)
{
	free(s->flag);
	free(s);
}

enum sc_error
ss_error(struct syscall_service *s)
{
	return s->last_error;
}

void
ss_set_error(struct syscall_service *s, enum sc_error se)
{
	s->last_error = se;
}

static const char *serrors[] = {
[SE_WRONG_NUMBER] = "wrong syscall number",
[SE_NUMBER_NON_EXIST] = "syscall with that number was not implemented",
[SE_NAME_NON_EXIST] = "syscall with that name doesn't exist"
};

const char *
ss_get_serror(struct syscall_service *s)
{
	return serrors[s->last_error];
}

int
ss_find_num(struct syscall_service *s, int real_num)
{
	int i;
	int max_scn = ss_max_scn(s);

	for (i = 0; i < max_scn; i++)
		if (ss_real_num(s, i) == real_num)
			return i;
	return -1;
}

bool
ss_is_syscall_valid(struct syscall_service *s, int num)
{
	if ((num >= s->arch->max_scn) || (num < 0))
		return 0;
	return ss_syscall_name(s, num) &&
	       !(ss_syscall_flag(s, num) & TRACE_INDIRECT_SUBCALL);
}

int
ss_mark_matches(struct syscall_service *s, char *arg)
{
	int sc_real_number;
	int sc_num;
	char sym = 0;
	char *sc_name = NULL;
	int sc_count = 0;
	int i = 0;
	int max_scn = ss_max_scn(s);

	/* In case of --list-sysc */
	if (arg == NULL) {
		for (i = 0; i < max_scn; i++)
			if (ss_is_syscall_valid(s, i))
				ss_set_flag(s, i, SS_FLAG_PRINT);
		return 0;
	}

	/* Is it a number? */
	if ((sscanf(arg, "%d%c", &sc_real_number, &sym) == 0) || sym != '\0')
		sc_name = arg;
	else if (sc_real_number < 0) {
		ss_set_error(s, SE_WRONG_NUMBER);
		return -1;
	}

	/* In case of name -> find arg as a substring and mark */
	if (sc_name != NULL) {
		for (i = 0; i < max_scn; i++)
			if (ss_is_syscall_valid(s, i) &&
			    strstr(ss_syscall_name(s, i), sc_name) != NULL) {
				ss_set_flag(s, i, SS_FLAG_PRINT);
				sc_count++;
			}
		if (sc_count == 0) {
			ss_set_error(s, SE_NAME_NON_EXIST);
			return -1;
		}
		ss_set_input(s, IT_STRING);
		return 0;
	}
	/* In case of number -> check and mark */
	sc_num = ss_find_num(s, sc_real_number);
	if (ss_is_syscall_valid(s, sc_num)) {
		ss_set_flag(s, sc_num, SS_FLAG_PRINT);
		ss_set_input(s, IT_NUMBER);
		return 0;
	}
	ss_set_error(s, SE_NUMBER_NON_EXIST);
	return -1;
}

#ifndef __X32_SYSCALL_BIT
# define __X32_SYSCALL_BIT	0x40000000
#endif

int
ss_update_sc_num(struct syscall_service *s)
{
	int i = 0;
	int max_scn = ss_max_scn(s);
	for (i = 0; i < max_scn; i++) {
		if (!ss_is_syscall_valid(s, i)) {
			ss_set_real_num(s, i, -1);
			continue;
		}
		switch (s->arch->arch_num) {
		case ARCH_x86_64_x32:
			ss_set_real_num(s, i, i + __X32_SYSCALL_BIT);
			break;
		case ARCH_arm_oabi:
		case ARCH_arm_eabi:
		case ARCH_aarch64_32bit:
			if (i == ss_user_num1(s))
				ss_set_real_num(s, i, 0x000ffff0);
			if ((i >= ss_user_num1(s) + 1) &&
			    (i <= ss_user_num1(s) + ss_user_num2(s) + 1))
				ss_set_real_num(s, i, i + 0x000f0000 -
						      ss_user_num1(s) - 1);
			if (i < ss_user_num1(s))
				ss_set_real_num(s, i, i);
			break;
		case ARCH_sh64_64bit:
			ss_set_real_num(s, i, i & 0xffff);
		default:
			ss_set_real_num(s, i, i);
		}
	}
	return 0;
}

void
ss_dump(struct syscall_service *s)
{
	const char *title[] = {
		"System call name",
		"Syscall num",
		"Nargs",
	};
	int title_len[] = {
		strlen(title[0]),
		strlen(title[1]),
		strlen(title[2]),
	};
	int i;
	int max_scn = ss_max_scn(s);
	int temp_len = 0;

	/* Update title_len[0] */
	for (i = 0; i < max_scn; i++) {
		if (!(ss_flag(s, i) & SS_FLAG_PRINT))
			continue;
		temp_len = strlen(ss_syscall_name(s, i));
		if (temp_len > title_len[0])
			title_len[0] = temp_len;
	}
	/* Print title */
	if (s->request_type & SD_REQ_GET_LIST)
		printf("| %*s | %*s | %*s |\n", title_len[0], title[0],
						title_len[1], title[1],
						title_len[2], title[2]);
	if (s->request_type & SD_REQ_GET_SYSC)
		printf("| %*s | %*s |\n", title_len[0], title[0],
					  title_len[1], title[1]);
	if (s->request_type & SD_REQ_GET_NARGS)
		printf("| %*s | %*s |\n", title_len[0], title[0],
					  title_len[2], title[2]);
	/* Print out syscall or list of syscalls */
	for (i = 0; i < max_scn; i++) {
		if (!(ss_flag(s, i) & SS_FLAG_PRINT))
			continue;
		if (s->request_type & SD_REQ_GET_LIST)
			printf("| %*s | %*d | %*u |\n",
				title_len[0], ss_syscall_name(s, i),
				title_len[1], ss_real_num(s, i),
				title_len[2], ss_syscall_nargs(s, i));
		if (s->request_type & SD_REQ_GET_SYSC)
			printf("| %*s | %*d |\n",
				title_len[0], ss_syscall_name(s, i),
				title_len[1], ss_real_num(s, i));
		if (s->request_type & SD_REQ_GET_NARGS)
			printf("| %*s | %*u |\n",
				title_len[0], ss_syscall_name(s, i),
				title_len[2], ss_syscall_nargs(s, i));
	}
}
