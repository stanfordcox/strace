/* Interface of strace features over the GDB remote protocol.
 *
 * Copyright (c) 2015-2020 Red Hat Inc.
 * Copyright (c) 2015 Josh Stone <cuviper@gmail.com>
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

#include "protocol.h"

extern char* gdbserver;

bool gdb_handle_arg(char arg, char *optarg);
bool gdb_start_init(int argc, char *argv[]);
void gdb_end_init(void);
void gdb_startup_child(char **argv);
void gdb_attach_tcb(struct tcb *tcp);
void gdb_detach(struct tcb *tcp);
void gdb_cleanup(int fatal_sig);
struct tcb_wait_data *gdb_next_event(void);
void * gdb_get_siginfo(void *data);
int gdb_restart_process(const unsigned int restart_op, struct tcb *current_tcp, unsigned int restart_sig);
long gdb_get_registers(struct tcb * const tcp);
int gdb_get_scno(struct tcb *tcp);
int gdb_set_scno(struct tcb *tcp, kernel_ulong_t scno);
int gdb_umoven(struct tcb *const tcp, kernel_ulong_t addr, unsigned int len, void *const our_addr);
int gdb_umovestr(struct tcb *const tcp, kernel_ulong_t addr, unsigned int len, char *laddr);
int gdb_upeek(struct tcb *tcp, unsigned long off, kernel_ulong_t *res);
int gdb_upoke(struct tcb *tcp, unsigned long off, kernel_ulong_t res);
