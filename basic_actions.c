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

bool
is_traced(struct tcb *tcp)
{
	return (tcp->qual_flg & QUAL_TRACE);
}

bool
not_injected(struct tcb *tcp)
{
	return !(tcp->qual_flg & QUAL_INJECT);
}

void *
parse_null(const char *str)
{
	return NULL;
}

void
free_null(void *_priv_data)
{
	return;
}

void
apply_trace(struct tcb *tcp, void *_priv_data)
{
	if (!tracing_paths || pathtrace_match(tcp))
		tcp->qual_flg |= QUAL_TRACE;
}

void
apply_inject(struct tcb *tcp, void *_priv_data)
{
	struct inject_opts *opts = _priv_data;

	tcp->qual_flg |= QUAL_INJECT;
	if (!tcp->inject_vec[current_personality])
		tcp->inject_vec[current_personality] =
			xcalloc(nsyscalls, sizeof(struct inject_opts));
	if (scno_in_range(tcp->scno)
	    && !tcp->inject_vec[current_personality][tcp->scno].init)
		tcp->inject_vec[current_personality][tcp->scno] = *opts;
}

static void *
parse_inject_common(const char *str, bool fault_tokens_only,
		    const char *description)
{
	struct inject_opts *opts = xmalloc(sizeof(struct inject_opts));
	char *buf = str ? xstrdup(str) : NULL;

	parse_inject_common_args(buf, opts, ";", fault_tokens_only);
	if (!opts->init)
		error_msg_and_die("invalid %s '%s'", description, str);
	free(buf);
	return opts;
}

void *
parse_inject(const char *str)
{
	return parse_inject_common(str, false, "inject argument");
}

void free_inject(void *_priv_data)
{
	free(_priv_data);
}

void
apply_fault(struct tcb *tcp, void *_priv_data)
{
	apply_inject(tcp, _priv_data);
}

void *
parse_fault(const char *str)
{
	return parse_inject_common(str, true, "fault argument");
}

void
free_fault(void *_priv_data)
{
	free_inject(_priv_data);
}

void
apply_read(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_READ;
}

void
apply_write(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_WRITE;
}

void
apply_raw(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_RAW;
}

void
apply_abbrev(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_ABBREV;
}

void
apply_verbose(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_VERBOSE;
}

void
apply_hook_entry(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_HOOK_ENTRY;
}

void
apply_hook_exit(struct tcb *tcp, void *_priv_data)
{
	tcp->qual_flg |= QUAL_HOOK_EXIT;
}
