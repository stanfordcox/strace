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
is_space_ascii(char c)
{
	return (c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') ||
	       (c == '\v') || (c == '\f');
}

/*
 * Split expression into action name, filter expression or qualify set
 * and action arguments.
 */
void
filtering_parse(const char *str)
{
	enum parsing_states {
		F_EMPTY,
		F_BEGIN,
		F_QUAL_SET,
		F_FILT_EXPR,
		F_QUAL_ARGS,
		F_FILT_ARGS,
		F_END
	} state = F_EMPTY;
	const char *begin = NULL;
	const char *action_name = NULL;
	const char *main_part = NULL;
	const char *args = NULL;
	int parentheses_count = 0;
	/* Used to store position of last terminating parenthesis. */
	char *expression_end = NULL;
	/* Used to provide diagnostics. */
	unsigned int pos = 0;
	char *buf = xstrdup(str);
	char *p;

	for (p = buf; *p; ++p, ++pos) {
		switch (state) {
		case F_EMPTY:
			switch (*p) {
			/* trace(), action name omitted */
			case '(':
				parentheses_count++;
				action_name = "trace";
				main_part = buf;
				state = F_FILT_EXPR;
				break;
			case '=':
				error_msg_and_die("invalid filter action ''");
			default:
				if (!is_space_ascii(*p)) {
					begin = p;
					state = F_BEGIN;
				}
			}
			break;

		case F_BEGIN:
			switch (*p) {
			/* action(...) */
			case '(':
				parentheses_count++;
				action_name = begin;
				*p = '\0';
				main_part = p + 1;
				state = F_FILT_EXPR;
				break;
			/* action=... */
			case '=':
				action_name = begin;
				*p = '\0';
				main_part = p + 1;
				state = F_QUAL_SET;
				break;
			/* qualify set without action. */
			case ',':
			case '?':
			case '!':
			case '/':
			case '%':
			case '-':
				action_name = "trace";
				main_part = begin;
				state = F_QUAL_SET;
				break;
			default:
				/* new expression without action. */
				if (is_space_ascii(*p)) {
					action_name = "trace";
					main_part = begin;
					state = F_FILT_EXPR;
				}
			}
			break;

		case F_QUAL_SET:
			if (*p == ':') {
				*p = '\0';
				args = p + 1;
				state = F_QUAL_ARGS;
			}
			break;

		case F_FILT_EXPR:
			switch (*p) {
			case ';':
				*p = '\0';
				args = p + 1;
				state = F_FILT_ARGS;
				break;
			case '(':
				parentheses_count++;
				break;
			case ')':
				parentheses_count--;
				expression_end = p;
				break;
			}

		case F_QUAL_ARGS:
			break;
		case F_FILT_ARGS:
			if (*p == ')') {
				expression_end = p;
				state = F_END;
			}
			break;
		case F_END:
			if (!is_space_ascii(*p))
				error_msg_and_die("illegal character '%c' in "
						  "'%s':%u", *p, str, pos);
		}
	}

	switch (state) {
	case F_EMPTY:
		error_msg_and_die("invalid filter expression '%s'", str);
	case F_BEGIN:
		action_name = "trace";
		main_part = begin;
		/* Fallthrough */
	case F_QUAL_SET:
	case F_QUAL_ARGS:
		parse_qualify_action(action_name, main_part, args);
		break;
	case F_FILT_EXPR:
	case F_FILT_ARGS:
	case F_END:
		if (parentheses_count != 0) {
			error_msg_and_die("missing '%c' in '%s'",
					  parentheses_count > 0 ? ')' : '(',
					  str);
		}
		if (expression_end)
			*expression_end = '\0';
		parse_filter_action(action_name, main_part, args);
		break;
	}
}
