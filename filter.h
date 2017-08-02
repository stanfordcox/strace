/*
 * Copyright (c) 2017 Nikolay Marchuk <marchuk.nikolay.a@gmail.com>
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
#ifndef STRACE_FILTER_H
# define STRACE_FILTER_H
# include "defs.h"

struct filter;

struct filter_action;

struct bool_expression;

typedef int (*string_to_uint_func)(const char *);
void parse_set(const char *const, struct number_set *const,
	       string_to_uint_func, const char *const);
void parse_inject_common_args(char *, struct inject_opts *, const char *delim,
			      const bool fault_tokens_only);
typedef bool (*match_fd_func)(struct tcb *, int, void *);
int match_fd_common(struct tcb *, match_fd_func, void *);

/* filter api */
struct filter* add_filter_to_array(struct filter **, unsigned int *nfilters,
				   const char *name);
void parse_filter(struct filter *, const char *str);
void run_filters(struct tcb *, struct filter *, unsigned int, bool *);
void free_filter(struct filter *);
void *get_filter_priv_data(struct filter *);
void set_filter_priv_data(struct filter *, void *);
void set_filters_qualify_mode(struct filter **, unsigned int *nfilters);

/* filter action api */
struct filter *create_filter(struct filter_action *, const char *name);
struct filter_action *find_or_add_action(const char *);
void parse_filter_action(const char *, const char *, const char *);
void *get_filter_action_priv_data(struct filter_action *);
void set_filter_action_priv_data(struct filter_action *, void *);
void set_qualify_mode(struct filter_action *);

/* filter expression api */
struct bool_expression *create_expression();
bool run_expression(struct bool_expression *, bool *, unsigned int);
void set_expression_qualify_mode(struct bool_expression *);
void parse_filter_expression(struct bool_expression *, const char *,
			     struct filter_action *, unsigned int);

void parse_qualify_action(const char *, const char *, const char *);

#endif
