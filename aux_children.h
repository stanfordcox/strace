/*
 * Auxiliary children support declarations.
 *
 * Copyright (c) 2017 The strace developers.
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

#ifndef STRACE_AUX_CHILDREN_H
#define STRACE_AUX_CHILDREN_H

#include <stdbool.h>

enum aux_child_ret {
	ACR_NO_ACTION,
	ACR_REMOVE_ME,
};

enum aux_child_sig {
	ACS_NONE,
	ACS_CONTINUE,
	ACS_TERMINATE,
};

typedef enum aux_child_sig (*aux_child_signal_fn)(pid_t pid, int status,
						  void *data);
typedef enum aux_child_ret (*aux_child_exit_fn)(pid_t pid, int exit_code,
						void *data);

struct aux_child_handlers {
	aux_child_signal_fn signal_fn;
	aux_child_exit_fn exit_notify_fn;
	aux_child_exit_fn exit_wait_fn;
};


extern void register_aux_child(pid_t pid, const struct aux_child_handlers *h,
			       void *signal_fn_data, void *exit_notify_fn_data,
			       void *exit_wait_fn_data);
/* Do not remove other children from the aux_child handlers.  */
extern void remove_aux_child(pid_t pid);

extern bool have_aux_children(void);

extern enum aux_child_sig aux_children_signal(pid_t pid, int status);
extern void aux_children_exit_notify(int exit_code);
extern int aux_children_exit_wait(int exit_code);

/* Simple signal handler, removes */
extern enum aux_child_sig aux_child_sig_handler(pid_t pid, int status,
						void *data);

#endif /* !STRACE_AUX_CHILDREN_H */
