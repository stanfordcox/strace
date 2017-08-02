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

struct expression_token {
	enum token_type {
		TOK_VARIABLE,
		TOK_OPERATOR
	} type;
	union token_data {
		unsigned int variable_id;
		enum operator_type {
			OP_NOT,
			OP_AND,
			OP_OR
		} operator_id;
	} data;
};

struct bool_expression {
	unsigned int ntokens;
	struct expression_token *tokens;
};

struct bool_expression *
create_expression(void)
{
	struct bool_expression *expr = xmalloc(sizeof(struct bool_expression));

	memset(expr, 0, sizeof(struct bool_expression));
	return expr;
}

static void
reallocate_expression(struct bool_expression *const expr,
		      const unsigned int new_ntokens)
{
	if (new_ntokens <= expr->ntokens)
		return;
	expr->tokens = xreallocarray(expr->tokens, new_ntokens,
				     sizeof(*expr->tokens));
	memset(expr->tokens + expr->ntokens, 0,
	       sizeof(*expr->tokens) * (new_ntokens - expr->ntokens));
	expr->ntokens = new_ntokens;
}

void
set_expression_qualify_mode(struct bool_expression *expr)
{
	if (!expr)
		error_msg_and_die("invalid expression");
	reallocate_expression(expr, 1);
	expr->tokens[0].type = TOK_VARIABLE;
	expr->tokens[0].data.variable_id = 0;
}

/* Print full diagnostics for corrupted expression */
static void
handle_corrupted_expression(struct bool_expression *expr, bool *stack,
			    unsigned int stack_size, unsigned int current_pos,
			    bool *variables, unsigned int variables_num)
{
	char *buf, *pos;
	unsigned int buf_size;
	unsigned int i;

	error_msg("corrupted filter expression:");

	/* Print expression. */
	buf_size = sizeof("expression (ntokens = ):")
		    + 3 * sizeof(unsigned int)
		    + (sizeof("op_") + 3 * sizeof(int)) * expr->ntokens;
	buf = xcalloc(buf_size, sizeof(char));
	pos = buf;
	pos += sprintf(pos, "expression (ntokens = %u):", expr->ntokens);
	for (i = 0; i < expr->ntokens; ++i) {
		switch (expr->tokens[i].type) {
		case TOK_VARIABLE:
			pos += sprintf(pos, "v_%u",
				       expr->tokens[i].data.variable_id);
			break;
		case TOK_OPERATOR:
			switch (expr->tokens[i].data.operator_id) {
			case OP_NOT:
				pos += sprintf(pos, "not");
				break;
			case OP_AND:
				pos += sprintf(pos, "and");
				break;
			case OP_OR:
				pos += sprintf(pos, "or");
			default:
				pos += sprintf(pos, "op_%d",
					      expr->tokens[i].data.operator_id);
			}
		default:
			pos += sprintf(pos, "?_%d", expr->tokens[i].type);
		}
	}
	error_msg("%s\n", buf);
	free(buf);

	/* Print variables. */
	buf_size = sizeof("variables (nvariables = ):") + 3 * sizeof(int)
		    + sizeof("false") * variables_num;
	buf = xcalloc(buf_size, sizeof(char));
	pos = buf;
	pos += sprintf(pos, "variables (nvariables = %u):", variables_num);
	for (i = 0; i < variables_num; ++i)
		pos += sprintf(pos, variables[i] ? " true" : " false");
	error_msg("%s\n", buf);
	free(buf);

	error_msg("current position: %u\n", current_pos);

	/* Print current stack state. */
	buf_size = sizeof("stack (stack_size = ):") + 3 * sizeof(int);
	buf = xcalloc(buf_size, sizeof(char));
	pos = buf;
	pos += sprintf(pos, "stack (stack_size = %u):", stack_size);
	for (i = 0; i < stack_size; ++i)
		pos += sprintf(pos, stack[i] ? " true" : " false");
	error_msg_and_die("%s\n", buf);
}

#define MAX_STACK_SIZE 32

bool
run_expression(struct bool_expression *expr, bool *variables,
	       unsigned int variables_num)
{
	bool stack[MAX_STACK_SIZE];
	unsigned int stack_size = 0;
	unsigned int i;

	for (i = 0; i < expr->ntokens; ++i) {
		struct expression_token *tok = &expr->tokens[i];

		switch (tok->type) {
		case TOK_VARIABLE:
			if (stack_size == MAX_STACK_SIZE)
				error_msg_and_die("stack overflow");

			if (tok->data.variable_id >= variables_num)
				handle_corrupted_expression(expr, stack,
							    stack_size, i,
							    variables,
							    variables_num);
			stack[stack_size++] = variables[tok->data.variable_id];
			break;
		case TOK_OPERATOR:
			switch (tok->data.operator_id) {
			case OP_NOT:
				if (stack_size == 0)
					handle_corrupted_expression(expr, stack,
								stack_size, i,
								variables,
								variables_num);
				stack[stack_size - 1] = !stack[stack_size - 1];
				break;
			case OP_AND:
				if (stack_size < 2)
					handle_corrupted_expression(expr, stack,
								stack_size, i,
								variables,
								variables_num);
				stack[stack_size - 2] = stack[stack_size - 2]
						     && stack[stack_size - 1];
				--stack_size;
				break;
			case OP_OR:
				if (stack_size < 2)
					handle_corrupted_expression(expr, stack,
								stack_size, i,
								variables,
								variables_num);
				stack[stack_size - 2] = stack[stack_size - 2]
						     || stack[stack_size - 1];
				--stack_size;
				break;
			}
		}
	}

	if (stack_size != 1)
		handle_corrupted_expression(expr, stack, stack_size, i,
					    variables, variables_num);
	return stack[0];
}
