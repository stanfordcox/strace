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

#include "defs.h"
#include "filter.h"

#define DECL_FILTER(name)						\
extern void *								\
parse_ ## name ## _filter(const char *);				\
extern bool								\
run_ ## name ## _filter(struct tcb *, void *);				\
extern void								\
free_ ## name ## _filter(void *)					\
/* End of DECL_FILTER definition. */

DECL_FILTER(syscall);
DECL_FILTER(fd);
DECL_FILTER(path);
#undef DECL_FILTER

#define FILTER_TYPE(name)						\
{#name, parse_ ## name ## _filter, run_ ## name ## _filter,		\
	free_ ## name ## _filter}

static const struct filter_type {
	const char *name;
	void *(*parse_filter)(const char *);
	bool (*run_filter)(struct tcb *, void *);
	void (*free_priv_data)(void *);
} filter_types[] = {
	FILTER_TYPE(syscall),
	FILTER_TYPE(fd),
	FILTER_TYPE(path),
};
#undef FILTER_TYPE

struct filter {
	const struct filter_type *type;
	void *_priv_data;
};

static const struct filter_type *
lookup_filter_type(const char *str)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(filter_types); i++) {
		if (!strcmp(filter_types[i].name, str))
			return &filter_types[i];
	}
	return NULL;
}

struct filter *
add_filter_to_array(struct filter **filters, unsigned int *nfilters,
		    const char *name)
{
	const struct filter_type *type = lookup_filter_type(name);
	struct filter *filter;

	if (!type)
		error_msg_and_die("invalid filter '%s'", name);
	*filters = xreallocarray(*filters, ++(*nfilters),
				 sizeof(struct filter));
	filter = &((*filters)[*nfilters - 1]);
	filter->type = type;
	return filter;
}

void
parse_filter(struct filter *filter, const char *str)
{
	filter->_priv_data = filter->type->parse_filter(str);
}

static bool
run_filter(struct tcb *tcp, struct filter *filter)
{
	return filter->type->run_filter(tcp, filter->_priv_data);
}

void
run_filters(struct tcb *tcp, struct filter *filters, unsigned int nfilters,
	    bool *variables_buf)
{
	unsigned int i;

	for (i = 0; i < nfilters; ++i)
		variables_buf[i] = run_filter(tcp, &filters[i]);
}

void
free_filter(struct filter *filter)
{
	if (!filter)
		return;
	filter->type->free_priv_data(filter->_priv_data);
}

void *
get_filter_priv_data(struct filter *filter)
{
	return filter ? filter->_priv_data : NULL;
}

void
set_filter_priv_data(struct filter *filter, void *_priv_data)
{
	if (filter)
		filter->_priv_data = _priv_data;
}

void
set_filters_qualify_mode(struct filter **filters, unsigned int *nfilters)
{
	unsigned int i;

	for (i = 0; i < *nfilters - 1; ++i)
		free_filter(*filters + i);
	(*filters)[0] = (*filters)[*nfilters - 1];
	*filters = xreallocarray(*filters, 1, sizeof(struct filter));
	*nfilters = 1;
}
