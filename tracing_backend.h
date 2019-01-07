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

#ifndef STRACE_TRACING_BACKEND_H
#define STRACE_TRACING_BACKEND_H

#include "defs.h"
#include "trace_event.h"

#if ADDITIONAL_TRACING_BACKENDS

struct msghdr;

/**
 * Structure that contains pointers to functions that deemed specific to
 * a tracing backend. Tracing backend is currently adsumed to be more or less
 * ptrace-like, as a result, it has some peculiarities.
 */
struct tracing_backend {
	const char *name;

	/* Parse tracing-backend-specific argument */
	bool (*handle_arg) (char arg, char *optarg);
	/* Initialisation of the tracing backend */
	bool (*init) (int argc, char *argv[]);
	/* Optional. Called at the final initialisation stage, after attach */
	void (*post_init) (void);

	/* XXX Merge these two in start_init */
        bool (*prog_pid_check) (char *exec_name, int nprocs);
	bool (*verify_args) (const char *username, bool daemon,
			     unsigned int *follow_fork);

	/* Tracee creation/reaping and attaching/detaching */

	void (*startup_child) (char **argv);
	void (*attach_tcb) (struct tcb *tcp);
	void (*detach) (struct tcb *tcp);
	void (*cleanup) (void);

	/*
	 * Group of functions related to the main tracing loop.
	 */

	/* Return new event */
	struct tcb_wait_data * (*next_event) (void);
	/* Additional handling for TE_STOP_BEFORE_EXECVE */
	void (*handle_exec) (struct tcb **current_tcp, void *data);
	/* Additional handling for TE_GROUP_STOP */
	void (*handle_group_stop) (unsigned int *restart_sig, void *data);
	/* Provide siginfo_t structure */
	void * (*get_siginfo) (void *data);
	/* Restart process after successful processing */
	bool (*restart_process)(struct tcb *tcp, unsigned int restart_sig,
				void *data);

	/* tracee memory/register/metadata manipulation */

	void (*clear_regs) (struct tcb *tcp);
	long (*get_regs) (struct tcb * const tcp);
	int (*get_scno) (struct tcb *tcp);
	int (*set_scno) (struct tcb *tcp, kernel_ulong_t scno);
	/* Set tracee's error code in accordance with tcb's data */
	int (*set_error) (struct tcb *tcp, unsigned long);
	/* Set tracee's return code in accordance with tcb's data */
	int (*set_success) (struct tcb *tcp, kernel_long_t);
	int (*get_syscall_result) (struct tcb *tcp);

	int (*umoven) (struct tcb *const tcp, kernel_ulong_t addr,
		       unsigned int len, void *const our_addr);
	int (*umovestr) (struct tcb *const tcp, kernel_ulong_t addr,
			 unsigned int len, char *laddr);
	int (*upeek) (struct tcb *tcp, unsigned long off, kernel_ulong_t *res);
	int (*upoke) (struct tcb *tcp, unsigned long off, kernel_ulong_t val);

	/*
	 * File I/O
	 *
	 * As of now, these functions are deemed to be executed in the context
	 * of the tracer on the target machine and not in the context of
	 * the specific tracee.
	 */

	/* Optional (can be implemented via open+readlink+close).
         * Used by: pathtrace_select_set */
	char * (*realpath) (struct tcb *tcp, const char *path,
			    char *resolved_path);
	/* Used by: read_int_from_file, realpath */
	int (*open) (struct tcb *tcp, const char *path, int flags, int mode);
	/* Used by: read_int_from_file */
	int (*pread) (struct tcb *tcp, int fd, void *buf, size_t count,
		      off_t offset);
	/* Used by: read_int_from_file, realpath */
	int (*close) (struct tcb *tcp, int fd);
	/* Used by: getfdpath, realpath */
	ssize_t (*readlink) (struct tcb *tcp, const char *path, char *buf,
			     size_t buf_size);
	/* Optional. Used by: getfdproto */
	ssize_t (*getxattr) (struct tcb *tcp, const char *path,
			     const char *name, void *buf, size_t buf_size);
	/* Optional. Used by: get_sockaddr_by_inode_uncached,
	 *                    genl_families_xlat */
	int (*socket) (struct tcb *tcp, int domain, int type, int protocol);
	/* Optional. Used by: send_query
	 * It's tracing backend responsibility to convert struct msghdr fields
	 * to tracee's format and back, it should be a drop-in replacement
	 * for users. Users, however, are responsible for proper generation
	 * of message data in target's format. */
	ssize_t (*sendmsg) (struct tcb *tcp, int fd, const struct msghdr *msg,
			    int flags);
	/* Optional. Used by: receive_response
	 * It's tracing backend responsibility to convert struct msghdr fields
	 * to tracee's format and back, it should be a drop-in replacement
	 * for users. Users, however, are responsible for proper interpretation
	 * of message data as provided in target's format. */
	ssize_t (*recvmsg) (struct tcb *tcp, int fd, struct msghdr *msg,
			    int flags);
};

extern const struct tracing_backend *cur_tracing_backend;

extern void set_tracing_backend(struct tracing_backend *backend);


static inline const char *
tracing_backend_name(void)
{
	return cur_tracing_backend->name;
}

static inline bool
tracing_backend_handle_arg(char arg, char *optarg)
{
	if (cur_tracing_backend->handle_arg)
		return cur_tracing_backend->handle_arg(arg, optarg);

	return false;
}

static inline bool
tracing_backend_init(int argc, char *argv[])
{
	if (cur_tracing_backend->init)
		return cur_tracing_backend->init(argc, argv);

	return true;
}

static inline void
tracing_backend_post_init(void)
{
	if (cur_tracing_backend->post_init)
		cur_tracing_backend->post_init();
}

static inline void
startup_child(char **argv)
{
	if (cur_tracing_backend->startup_child)
		cur_tracing_backend->startup_child(argv);
}

static inline void
attach_tcb(struct tcb *const tcp)
{
	if (cur_tracing_backend->attach_tcb)
		cur_tracing_backend->attach_tcb(tcp);
}

static inline void
detach(struct tcb *tcp)
{
	if (cur_tracing_backend->detach)
		cur_tracing_backend->detach(tcp);
}

static inline void
cleanup(void)
{
	if (cur_tracing_backend->cleanup)
		cur_tracing_backend->cleanup();
}

static inline const struct tcb_wait_data *
next_event(void)
{
	return cur_tracing_backend->next_event();
}

static inline void
handle_group_stop(unsigned int *restart_sig, void *data)
{
	if (cur_tracing_backend->handle_group_stop)
		cur_tracing_backend->handle_group_stop(restart_sig, data);
}

static inline void
handle_exec(struct tcb **current_tcp, void *data)
{
	if (cur_tracing_backend->handle_exec)
		cur_tracing_backend->handle_exec(current_tcp, data);
}

static inline void *
get_siginfo(void *data)
{
	if (cur_tracing_backend->get_siginfo)
		return cur_tracing_backend->get_siginfo(data);
	else
		return NULL;
}

static inline bool
restart_process(struct tcb *current_tcp, unsigned int restart_sig, void *data)
{
	return cur_tracing_backend->restart_process(current_tcp, restart_sig,
						    data);
}

static inline void
clear_regs(struct tcb *tcp)
{
	cur_tracing_backend->clear_regs(tcp);
}

static inline long
get_regs(struct tcb * const tcp)
{
	return cur_tracing_backend->get_regs(tcp);
}

static inline int
get_syscall(struct tcb *tcp)
{
	return cur_tracing_backend->get_scno(tcp);
}

static inline int
set_scno(struct tcb *tcp, kernel_ulong_t scno)
{
	return cur_tracing_backend->set_scno(tcp, scno);
}

static inline void
set_error(struct tcb *tcp, unsigned long new_error)
{
	cur_tracing_backend->set_error(tcp, new_error);
}

static inline int
set_success(struct tcb *tcp, kernel_long_t new_rval)
{
	return cur_tracing_backend->set_success(tcp, new_rval);
}

static inline int
get_syscall_result(struct tcb *tcp)
{
	return cur_tracing_backend->get_syscall_result(tcp);
}

static inline int
umoven(struct tcb *tcp, kernel_ulong_t addr, unsigned int len, void *laddr)
{
	return cur_tracing_backend->umoven(tcp, addr, len, laddr);
}

static inline int
umovestr(struct tcb *tcp, kernel_ulong_t addr, unsigned int len, char *laddr)
{
	return cur_tracing_backend->umovestr(tcp, addr, len, laddr);
}

static inline int
upeek(struct tcb *tcp, unsigned long off, kernel_ulong_t *res)
{
	return cur_tracing_backend->upeek(tcp, off, res);
}

static inline int
upoke(struct tcb *tcp, unsigned long off, kernel_ulong_t val)
{
	return cur_tracing_backend->upoke(tcp, off, val);
}

static inline char *
tracee_realpath(struct tcb *tcp, const char *path, char *resolved_path)
{
	if (cur_tracing_backend->realpath)
		return cur_tracing_backend->realpath(tcp, path, resolved_path);
	else
		return NULL;
}

static inline int
tracee_open(struct tcb *tcp, const char *path, int flags, int mode)
{
	return cur_tracing_backend->open(tcp, path, flags, mode);
}

static inline int
tracee_pread(struct tcb *tcp, int fd, void *buf, size_t count, off_t offset)
{
	return cur_tracing_backend->pread(tcp, fd, buf, count, offset);
}

static inline int
tracee_close(struct tcb *tcp, int fd)
{
	return cur_tracing_backend->close(tcp, fd);
}

static inline ssize_t
tracee_readlink(struct tcb *tcp, const char *path, char *buf, size_t buf_size)
{
	return cur_tracing_backend->readlink(tcp, path, buf, buf_size);
}

static inline ssize_t
tracee_getxattr(struct tcb *tcp, const char *path, const char *name, void *buf,
		size_t buf_size)
{
	if (cur_tracing_backend->getxattr)
		return cur_tracing_backend->getxattr(tcp, path, name, buf,
						     buf_size);
	else
		return ENOSYS;
}

static inline int
tracee_socket(struct tcb *tcp, int domain, int type, int protocol)
{
	if (cur_tracing_backend->socket)
		return cur_tracing_backend->socket(tcp, domain, type, protocol);
	else
		return ENOSYS;
}

static inline ssize_t
tracee_sendmsg(struct tcb *tcp, int fd, const struct msghdr *msg, int flags)
{
	if (cur_tracing_backend->sendmsg)
		return cur_tracing_backend->sendmsg(tcp, fd, msg, flags);
	else
		return ENOSYS;
}

static inline ssize_t
tracee_recvmsg(struct tcb *tcp, int fd, struct msghdr *msg, int flags)
{
	if (cur_tracing_backend->recvmsg)
		return cur_tracing_backend->recvmsg(tcp, fd, msg, flags);
	else
		return ENOSYS;
}

#else /* !ADDITIONAL_TRACING_BACKENDS */

# include "ptrace_backend.h"

# define tracing_backend_name()      "ptrace"
# define tracing_backend_handle_arg   false &&
# define tracing_backend_init        ptrace_init
# define tracing_backend_post_init() (void)0
# define startup_child               ptrace_startup_child
# define attach_tcb                  ptrace_attach_tcb
# define detach                      ptrace_detach
# define cleanup                     ptrace_cleanup
# define next_event                  ptrace_next_event
# define handle_group_stop           ptrace_handle_group_stop
# define handle_exec                 ptrace_handle_exec
# define get_siginfo                 ptrace_get_siginfo
# define restart_process             ptrace_restart_process
# define clear_regs                  ptrace_clear_regs
# define get_regs                    ptrace_get_regs
# define get_scno                    ptrace_get_scno
# define set_scno                    ptrace_set_scno
# define set_error                   ptrace_set_error
# define set_success                 ptrace_set_success
# define get_syscall_result          ptrace_get_syscall_result
# define umoven                      ptrace_umoven
# define umovestr                    ptrace_umovestr
# define upeek                       ptrace_upeek
# define upoke                       ptrace_upoke
# define tracee_open                 ptrace_open

# define tracee_realpath(_tcp, _path, _resolved_path) \
	realpath(_path, _resolved_path)
# define tracee_pread(_tcp, _fd, _buf, _count, _offset) \
	pread(_fd, _buf, _count, _offset)
# define tracee_close(_tcp, _fd) \
	close(_fd)
# define tracee_readlink(_tcp, _path, _buf, _buf_size) \
	readlink(_path, _buf, _buf_size)
# define tracee_getxattr(_tcp, _path, _name, _buf, _buf_size) \
	getxattr(_path, _name, _buf, _buf_size)
# define tracee_socket(_tcp, _domain, _type, _protocol) \
	socket(_domain, _type, _protocol)
# define tracee_sendmsg(_tcp, _fd, _msg, _flags) \
	sendmsg(_fd, _msg, _flags)
# define tracee_recvmsg(_tcp, _fd, _msg, _flags) \
	recvmsg(_fd, _msg, _flags)

#endif /* !ADDITIONAL_TRACING_PACKENDS */

#endif /* !STRACE_TRACING_BACKEND_H */
