/*
 * Copyright (c) 2016 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2016-2017 The strace developers.
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
#include "nsig.h"
#include "filter.h"

typedef unsigned int number_slot_t;

struct number_set {
	number_slot_t *vec;
	unsigned int nslots;
	bool not;
};

struct number_set signal_set;

static int
find_errno_by_name(const char *name)
{
	unsigned int i;

	for (i = 1; i < nerrnos; ++i) {
		if (errnoent[i] && (strcasecmp(name, errnoent[i]) == 0))
			return i;
	}

	return -1;
}

static int
sigstr_to_uint(const char *s)
{
	int i;

	if (*s >= '0' && *s <= '9')
		return string_to_uint_upto(s, 255);

	if (strncasecmp(s, "SIG", 3) == 0)
		s += 3;

	for (i = 0; i <= 255; ++i) {
		const char *name = signame(i);

		if (strncasecmp(name, "SIG", 3) != 0)
			continue;

		name += 3;

		if (strcasecmp(name, s) != 0)
			continue;

		return i;
	}

	return -1;
}

static bool
parse_inject_token(const char *const token, struct inject_opts *const fopts,
		   const bool fault_tokens_only)
{
	const char *val;
	int intval;

	if ((val = STR_STRIP_PREFIX(token, "when=")) != token) {
		/*
		 *	== 1+1
		 * F	== F+0
		 * F+	== F+1
		 * F+S
		 */
		char *end;
		intval = string_to_uint_ex(val, &end, 0xffff, "+");
		if (intval < 1)
			return false;

		fopts->first = intval;

		if (*end) {
			val = end + 1;
			if (*val) {
				/* F+S */
				intval = string_to_uint_upto(val, 0xffff);
				if (intval < 1)
					return false;
				fopts->step = intval;
			} else {
				/* F+ == F+1 */
				fopts->step = 1;
			}
		} else {
			/* F == F+0 */
			fopts->step = 0;
		}
	} else if ((val = STR_STRIP_PREFIX(token, "error=")) != token) {
		if (fopts->rval != INJECT_OPTS_RVAL_DEFAULT)
			return false;
		intval = string_to_uint_upto(val, MAX_ERRNO_VALUE);
		if (intval < 0)
			intval = find_errno_by_name(val);
		if (intval < 1)
			return false;
		fopts->rval = -intval;
	} else if (!fault_tokens_only
		   && (val = STR_STRIP_PREFIX(token, "retval=")) != token) {
		if (fopts->rval != INJECT_OPTS_RVAL_DEFAULT)
			return false;
		intval = string_to_uint(val);
		if (intval < 0)
			return false;
		fopts->rval = intval;
	} else if (!fault_tokens_only
		   && (val = STR_STRIP_PREFIX(token, "signal=")) != token) {
		intval = sigstr_to_uint(val);
		if (intval < 1 || intval > NSIG_BYTES * 8)
			return false;
		fopts->signo = intval;
	} else {
		return false;
	}

	return true;
}

void
parse_inject_common_args(char *str, struct inject_opts *const opts,
			 const char *delim, const bool fault_tokens_only)
{
	char *saveptr = NULL;
	char *token;

	opts->first = 1;
	opts->step = 1;
	opts->rval = INJECT_OPTS_RVAL_DEFAULT;
	opts->signo = 0;
	opts->init = false;

	for (token = strtok_r(str, delim, &saveptr); token;
	     token = strtok_r(NULL, delim, &saveptr)) {
		if (!parse_inject_token(token, opts, fault_tokens_only))
			return;
	}

	/* If neither of retval, error, or signal is specified, then ... */
	if (opts->rval == INJECT_OPTS_RVAL_DEFAULT && !opts->signo) {
		if (fault_tokens_only) {
			/* in fault= syntax the default error code is ENOSYS. */
			opts->rval = -ENOSYS;
		} else {
			/* in inject= syntax this is not allowed. */
			return;
		}
	}
	opts->init = true;
}

static void
parse_read(const char *const str)
{
	struct filter_action *action = find_or_add_action("read");
	struct filter *filter = create_filter(action, "fd");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
parse_write(const char *const str)
{
	struct filter_action *action = find_or_add_action("write");
	struct filter *filter = create_filter(action, "fd");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
qualify_signals(const char *const str)
{
	parse_set(str, &signal_set, sigstr_to_uint, "signal");
}

static void
parse_trace(const char *const str)
{
	struct filter_action *action = find_or_add_action("trace");
	struct filter *filter = create_filter(action, "syscall");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
parse_abbrev(const char *const str)
{
	struct filter_action *action = find_or_add_action("abbrev");
	struct filter *filter = create_filter(action, "syscall");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
parse_verbose(const char *const str)
{
	struct filter_action *action = find_or_add_action("verbose");
	struct filter *filter = create_filter(action, "syscall");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
parse_raw(const char *const str)
{
	struct filter_action *action = find_or_add_action("raw");
	struct filter *filter = create_filter(action, "syscall");

	parse_filter(filter, str);
	set_qualify_mode(action);
}

static void
parse_inject_common(const char *const str, const bool fault_tokens_only,
		    const char *const description)
{
	struct inject_opts *opts = xmalloc(sizeof(struct inject_opts));
	char *buf = xstrdup(str);
	struct filter_action *action;
	struct filter *filter;
	char *args = strchr(buf, ':');

	if (args)
		*(args++) = '\0';

	action = find_or_add_action(fault_tokens_only ? "fault" : "inject");
	filter = create_filter(action, "syscall");
	parse_filter(filter, buf);
	set_qualify_mode(action);
	parse_inject_common_args(args, opts, ":", fault_tokens_only);
	if (!opts->init)
		error_msg_and_die("invalid %s '%s'", description,
				  args ? args : "");
	free(buf);
	set_filter_action_priv_data(action, opts);
}

static void
parse_fault(const char *const str)
{
	parse_inject_common(str, true, "fault argument");
}

static void
parse_inject(const char *const str)
{
	parse_inject_common(str, false, "inject argument");
}

static const struct qual_options {
	const char *name;
	void (*qualify)(const char *);
} qual_options[] = {
	{ "trace",	parse_trace	},
	{ "t",		parse_trace	},
	{ "abbrev",	parse_abbrev	},
	{ "a",		parse_abbrev	},
	{ "verbose",	parse_verbose	},
	{ "v",		parse_verbose	},
	{ "raw",	parse_raw	},
	{ "x",		parse_raw	},
	{ "signal",	qualify_signals	},
	{ "signals",	qualify_signals	},
	{ "s",		qualify_signals	},
	{ "read",	parse_read	},
	{ "reads",	parse_read	},
	{ "r",		parse_read	},
	{ "write",	parse_write	},
	{ "writes",	parse_write	},
	{ "w",		parse_write	},
	{ "fault",	parse_fault	},
	{ "inject",	parse_inject	},
};

void
parse_qualify_filter(const char *str)
{
	const struct qual_options *opt = qual_options;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(qual_options); ++i) {
		const char *name = qual_options[i].name;
		const size_t len = strlen(name);
		const char *val = str_strip_prefix_len(str, name, len);

		if (val == str || *val != '=')
			continue;
		str = val + 1;
		opt = &qual_options[i];
		break;
	}

	opt->qualify(str);
}
