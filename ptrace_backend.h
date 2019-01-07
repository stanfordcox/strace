/*
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

#ifndef STRACE_PTRACE_BACKEND_H
#define STRACE_PTRACE_BACKEND_H

#include "defs.h"
#include "trace_event.h"

extern bool ptrace_init(int argc, char *argv[]);

extern void ptrace_startup_child(char **argv);
extern void ptrace_attach_tcb(struct tcb *const tcp);
extern void ptrace_detach(struct tcb *tcp);
extern void ptrace_cleanup(void);

extern void *ptrace_alloc_trace_loop_storage(void);
extern struct tcb_wait_data *ptrace_next_event(void);
extern void ptrace_handle_group_stop(unsigned int *restart_sig, void *data);
extern void ptrace_handle_exec(struct tcb **current_tcp, void *data);
extern void *ptrace_get_siginfo(void *data);
extern bool ptrace_restart_process(struct tcb *current_tcp,
				   unsigned int restart_sig, void *data);

extern void ptrace_clear_regs(struct tcb *tcp);
extern long ptrace_get_regs(struct tcb * const tcp);
extern int ptrace_get_scno(struct tcb *tcp);
extern int ptrace_set_scno(struct tcb *tcp, kernel_ulong_t scno);
extern int ptrace_set_error(struct tcb *tcp, unsigned long new_error);
extern int ptrace_set_success(struct tcb *tcp, kernel_long_t new_rval);
extern int ptrace_get_syscall_result(struct tcb *tcp);

extern int ptrace_umoven(struct tcb *const tcp, kernel_ulong_t addr,
			 unsigned int len, void *const our_addr);
extern int ptrace_umovestr(struct tcb *const tcp, kernel_ulong_t addr,
			   unsigned int len, char *laddr);
extern int ptrace_upeek(struct tcb *tcp, unsigned long off,
			kernel_ulong_t *res);
extern int ptrace_upoke(struct tcb *tcp, unsigned long off, kernel_ulong_t val);

extern int ptrace_open(struct tcb *tcp, const char *path, int flags, int mode);

#if ADDITIONAL_TRACING_BACKENDS

extern const struct tracing_backend ptrace_backend;

#endif /* ADDITIONAL_TRACING_BACKENDS */

#endif /* !STRACE_PTRACE_BACKEND_H */
