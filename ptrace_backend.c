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

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "ptrace_backend.h"

/* Simple syscall wrappers for local ptrace backend */

#if defined _LARGEFILE64_SOURCE && defined HAVE_OPEN64
# define open_file open64
#else
# define open_file open
#endif

int
ptrace_open(struct tcb *tcp, const char *path, int flags, int mode)
{
	return open_file(path, flags, mode);
}

#if ADDITIONAL_TRACING_PACKENDS

static char *
ptrace_realpath(struct tcb *tcp, const char *path, char *resolved_path)
{
	return realpath(path, resolved_path);
}

static int
ptrace_pread(struct tcb *tcp, int fd, void *buf, size_t count, off_t offset)
{
	return pread(fd, buf, count, offset);
}

static int
ptrace_close(struct tcb *tcp, int fd)
{
	return close(fd);
}

static ssize_t
ptrace_readlink(struct tcb *tcp, const char *path, char *buf, size_t buf_size)
{
	return readlink(path, buf, buf_size);
}

static ssize_t
ptrace_getxattr(struct tcb *tcp, const char *path, const char *name, void *buf,
		size_t buf_size)
{
	return getxattr(path, name, buf, buf_size);
}

static int
ptrace_socket(struct tcb *tcp, int domain, int type, int protocol)
{
	return socket(domain, type, protocol);
}

static ssize_t
ptrace_sendmsg(struct tcb *tcp, int fd, const struct msghdr *msg, int flags)
{
	return sendmsg(fd, msg, flags);
}

static ssize_t
ptrace_recvmsg(struct tcb *tcp, int fd, struct msghdr *msg, int flags)
{
	return recvmsg(fd, msg, flags);
}


const struct tracing_backend ptrace_backend = {
	.name               = "ptrace",

	.init               = ptrace_init,

	.startup_child      = ptrace_startup_child,
	.attach_tcb         = ptrace_attach_tcb,
	.detach             = ptrace_detach,
	.cleanup            = ptrace_cleanup,

	.alloc_tls          = ptrace_alloc_trace_loop_storage,
	.next_event         = ptrace_next_event,
	.handle_exec        = ptrace_handle_exec,
	.handle_group_stop  = ptrace_handle_group_stop,
	.get_siginfo        = ptrace_get_siginfo,
	.restart_process    = ptrace_restart_process,

	.clear_regs         = ptrace_clear_regs,
	.get_regs           = ptrace_get_regs,
	.get_scno           = ptrace_get_scno,
	.set_scno           = ptrace_set_scno,
	.set_error          = ptrace_set_error,
	.set_success        = ptrace_set_success,
	.get_syscall_result = ptrace_get_syscall_result,

	.umoven             = ptrace_umoven,
	.umovestr           = ptrace_umovestr,
	.upeek              = ptrace_upeek,
	.upoke              = ptrace_upoke,

	.realpath           = ptrace_realpath,
	.open               = ptrace_open,
	.pread              = ptrace_pread,
	.close              = ptrace_close,
	.readlink           = ptrace_readlink,
	.getxattr           = ptrace_getxattr,
	.socket             = ptrace_socket,
	.sendmsg            = ptrace_sendmsg,
	.recvmsg            = ptrace_recvmsg,
};

#endif /* ADDITIONAL_TRACING_PACKENDS */
