/*
 * The syscall_interface.h is purposed to interact with the basic data
 * structure based on arch_descriptor struct. Mainly this set of methods are
 * used by syscall_dispatcher.
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
#ifndef ASINFO_SYSCALL_INTERFACE
#define ASINFO_SYSCALL_INTERFACE

#include <stdbool.h>

#include "arch_interface.h"

#define SS_FLAG_EMPTY 0
#define SS_FLAG_PRINT 1

enum input_type {
	IT_STRING = 1,
	IT_NUMBER
};

enum sc_error {
	SE_WRONG_NUMBER = 1,
	SE_NUMBER_NON_EXIST,
	SE_NAME_NON_EXIST,
};

struct syscall_service {
	struct arch_descriptor *arch;
	/* Mutable user flags for each syscall */
	int *flag;
	int *real_sys_num;
	/* To choose the format while dumping */
	int request_type;
	/* To detect input type */
	enum input_type it;
	enum sc_error last_error;
};

#define SYSCALL_LIST_DEFINE(name) \
	struct syscall_service *(name)

/* base methods */
struct syscall_service *ss_create(struct arch_service *m, int request_type);

int ss_flag(struct syscall_service *s, int num);

int ss_set_flag(struct syscall_service *s, int num, int flag);

enum input_type ss_it(struct syscall_service *s);

void ss_set_input(struct syscall_service *s, enum input_type it);

int ss_max_scn(struct syscall_service *s);

int ss_real_num(struct syscall_service *s, int num);

int ss_set_real_num(struct syscall_service *s, int num, int real_num);

const char *ss_syscall_name(struct syscall_service *s, int num);

int ss_syscall_flag(struct syscall_service *s, int num);

unsigned ss_syscall_nargs(struct syscall_service *s, int num);

int ss_user_num1(struct syscall_service *s);

int ss_user_num2(struct syscall_service *s);

void ss_free(struct syscall_service *s);

/* error group methods */
enum sc_error ss_error(struct syscall_service *s);

void ss_set_error(struct syscall_service *s, enum sc_error se);

const char *ss_get_serror(struct syscall_service *s);

/* calculating methods */
int ss_find_num(struct syscall_service *s, int real_num);

bool ss_is_syscall_valid(struct syscall_service *s, int num);

int ss_mark_matches(struct syscall_service *s, char *arg);

int ss_update_sc_num(struct syscall_service *s);

void ss_dump(struct syscall_service *s);

#endif /* !ASINFO_SYSCALL_INTERFACE */
