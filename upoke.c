/*
 * Copyright (c) 2016 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2016-2019 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include "ptrace.h"
#include "ptrace_pokeuser.c"
#ifdef ENABLE_GDBSERVER
#include "gdbserver.h"
#endif

int
upoke(struct tcb *tcp, unsigned long off, kernel_ulong_t val)
{
#ifdef ENABLE_GDBSERVER
	if (__builtin_expect(gdbserver != NULL, 0))
		return gdb_upoke(tcp, off, val);
#endif
	if (ptrace_pokeuser(tcp->pid, off, val) < 0) {
		if (errno != ESRCH)
			perror_func_msg("PTRACE_POKEUSER pid:%d @%#lx)",
					tcp->pid, off);
		return -1;
	}
	return 0;
}
