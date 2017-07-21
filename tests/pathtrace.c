/*
 * Check strace's path/fd tracing ability.
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

#include "tests.h"

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sen.h"
#include "sysent.h"

#define TD 1
#define TF 2
#define TI 0
#define TN 4
#define TP 0
#define TS 0
#define TM 0
#define TST 0
#define TLST 0
#define TFST 0
#define TSTA 0
#define TSF 0
#define TFSF 0
#define TSFA 0
#define NF 0
#define MA 0
#define SI 0
#define SE 0
#define CST 0
#define SEN(arg) SEN_##arg, 0

static const struct_sysent syscallent[] = {
#include "syscallent.h"
};
typedef const char *pstr_t;
static const pstr_t ksyslist[] = {
#include "ksysent.h"
};

#define MAX_ARGS 6

enum arg_type {
	ARG_NONE,
	ARG_FD,
	ARG_PATH,

	ARG_TYPE_COUNT
};
#define _D ARG_FD
#define _P ARG_PATH

enum arg_fmt {
	AF_D = 0x10001,
	AF_LD,
	AF_KLD,
	AF_LLD,
	AF_U,
	AF_LU,
	AF_KLU,
	AF_LLU,
	AF_X,
	AF_LX,
	AF_KLX,
	AF_LLX,
	AF_S,

	AF_ANYTHING = 0,
	AF_IOC,
	AF_QCMD,

	AF_COUNT
};
#define _d AF_D
#define _ku AF_KLU
#define _x AF_X
#define _lx AF_LX
#define _kx AF_KLX
#define _s AF_S

static const char *af_strings[ARG_TYPE_COUNT][AF_COUNT] = {
	[ARG_NONE] = {
		[AF_ANYTHING] = "[^,]+",
		[AF_IOC] = "_IOC\\(_IOC_READ\\|_IOC_WRITE, 0xda, 0x7a, 0x1ead\\)",
		[AF_QCMD] = "QCMD\\(0xdeadda /\\* Q_\\?\\?\\? \\*/, 0x7a /\\* \\?\\?\\?QUOTA \\*/\\)",
	},
	[ARG_FD] = {
		[AF_ANYTHING] = "[^,]+",
		[AF_IOC] = "_IOC\\(0, 0, 0x2a, 0\\)",
		[AF_QCMD] = "QCMD\\(0 /\\* Q_\\?\\?\\? \\*/, 0x2a /\\* \\?\\?\\?QUOTA \\*/\\)"
	},
	[ARG_PATH] = {
		[AF_ANYTHING] = "[^,]+",
		[AF_IOC] = "_IOC\\([^,]+, [^,]+, [^,]+, [^,]+\\)",
		[AF_QCMD] = "QCMD\\(0(x[0-9a-f]+)? /\\* Q_[A-Z?]* \\*/, 0(x[0-9a-f]+)? /\\* [A-Z?]*QUOTA \\*/\\)"
	},
};

#define _(sc, ...) \
	[SEN_##sc] = { 1, __VA_ARGS__ }
static const enum arg_type path_args[][2 * MAX_ARGS + 1] = {
	_(ARCH_mmap,          0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(copy_file_range,   _D, _d,  0,  0, _D, _d),
	_(dup2,              _D, _d, _D, _d),
	_(dup3,              _D, _d, _D, _d),
	_(epoll_ctl,          0,  0,  0,  0, _D, _d),
	_(faccessat,         _D, _d, _P, _s),
	_(fanotify_mark,      0,  0,  0,  0,  0,  0, _D, _d, _P, _s),
	_(fchmodat,          _D, _d, _P, _s),
	_(fchownat,          _D, _d, _P, _s),
	_(fstatat64,         _D, _d, _P, _s),
	_(futimesat,         _D, _d, _P, _s),
	_(inotify_add_watch, _D, _d, _P, _s),
	_(kexec_file_load,   _D, _d, _D, _d),
	_(link,              _P, _s, _P, _s),
	_(linkat,            _D, _d, _P, _s, _D, _d, _P, _s),
	_(mkdirat,           _D, _d, _P, _s),
	_(mknodat,           _D, _d, _P, _s),
	_(mmap,               0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(mmap_4koff,         0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(mmap_pgoff,         0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(mount,             _P, _s, _P, _s),
	_(name_to_handle_at, _D, _d, _P, _s),
	_(newfstatat,        _D, _d, _P, _s),
	_(old_mmap,           0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(old_mmap_pgoff,     0,  0,  0,  0,  0,  0,  0,  0, _D, _d),
	_(openat,            _D, _d, _P, _s),
	_(pivotroot,         _P, _s, _P, _s),
	_(quotactl,           0,  2, _P, _s),
	_(readlinkat,        _D, _d, _P, _s),
	_(renameat,          _D, _d, _P, _s, _D, _d, _P, _s),
	_(renameat2,         _D, _d, _P, _s, _D, _d, _P, _s),
	_(sendfile,          _D, _d, _D, _d),
	_(sendfile64,        _D, _d, _D, _d),
	_(splice,            _D, _d,  0,  0, _D, _d),
	_(statx,             _D, _d, _P, _s),
	_(symlinkat,         _P, _s, _D, _d, _P, _s),
	_(tee,               _D, _d, _D, _d),
	_(unlinkat,          _D, _d, _P, _s),
	_(utimensat,         _D, _d, _P, _s),

	_(ioctl,             _D, _d,  0,  1,  0, _lx),

	/* These are handled by printargs */
	_(getpmsg,           _D, _kx,  0, _kx, 0, _kx, 0, _kx, 0, _kx),
	_(putpmsg,           _D, _kx,  0, _kx, 0, _kx, 0, _kx, 0, _kx),

	/* First argument is out, not in, and we inject-fail it, so _kx */
	_(getcwd,            _P, _kx, 0, _ku),

	_(bpf,                0),
	_(epoll_create,       0),
	_(epoll_create1,      0),
	_(eventfd2,           0),
	_(eventfd,            0),
	_(fanotify_init,      0),
	_(inotify_init1,      0),
	_(memfd_create,       0),
	_(perf_event_open,    0),
	_(pipe,               0),
	_(pipe2,              0),
	_(printargs,          0),
	_(socket,             0),
	_(socketpair,         0),
	_(timerfd_create,     0),
	_(timerfd_gettime,    0),
	_(timerfd_settime,    0),
	_(userfaultfd,        0),
};
#undef _

static bool blacklist[] = {
	[SEN_close] = true,
	[SEN_mmap] = true,
	[SEN_rt_sigreturn] = true,
	[SEN_pause] = true,
	[SEN_clone] = true,
	[SEN_fork] = true,
	[SEN_vfork] = true,
	[SEN_exit] = true,
	[SEN_ptrace] = true,
	[SEN_sigsuspend] = true,
	[SEN_sigreturn] = true,

	/* XXX */
	[SEN_poll] = true,
	[SEN_ppoll] = true,
	[SEN_select] = true,
	[SEN_oldselect] = true,
	[SEN_pselect6] = true,

	/* XXX XXX */
	[SEN_open] = true,
	[SEN_openat] = true,
	[SEN_mknod] = true,
	[SEN_mknodat] = true,
};

static const enum arg_type dummy_args[MAX_ARGS + 1] = { 0 };

static const char *path      = "path_trace_test.sample";
static const unsigned int fd = 42;

static unsigned int num_iter = 1;

static void
do_call(unsigned int sc)
{
	kernel_ulong_t opts[] = {
		[ARG_NONE] = (kernel_ulong_t) 0xbadc0deddeadda7aULL,
		[ARG_FD]   = fd,
		[ARG_PATH] = (uintptr_t) path,
	};

	kernel_ulong_t args[MAX_ARGS];
	enum arg_type arg_types[MAX_ARGS * 2 + 1];
	unsigned int i;
	unsigned int j;
	unsigned int val;
	bool do_print;

	if (blacklist[syscallent[sc].sen])
		return;

	memcpy(arg_types, ((unsigned) syscallent[sc].sen < ARRAY_SIZE(path_args)) ?
		 path_args[syscallent[sc].sen] : dummy_args, sizeof(arg_types));

	num_iter = 1;
	for (i = 0; i < syscallent[sc].nargs; i++)
		num_iter *= ARRAY_SIZE(opts);

	for (i = 0; i < num_iter; i++) {
		val = i;
		do_print = false;

		for (j = 0; j < MAX_ARGS; j++) {
			args[j] = opts[val % ARRAY_SIZE(opts)];

			if (arg_types[0] && arg_types[2 * j + 1] &&
			    ((val % ARRAY_SIZE(opts)) == arg_types[2 * j + 1]))
				do_print = true;

			val /= ARRAY_SIZE(opts);
		}

		if (!arg_types[0]) {
			if (syscallent[sc].sys_flags & TF) {
				if (args[0] == opts[ARG_PATH]) {
					do_print = true;
					arg_types[2] = AF_S;
				}
			} else if ((syscallent[sc].sys_flags & (TD | TN)) &&
			    (args[0] == opts[ARG_FD])) {
				do_print = true;
				arg_types[2] = AF_D;
			}
		}

		syscall(sc, args[0], args[1], args[2], args[3], args[4],
			args[5]);

		if (!do_print)
			continue;

		printf("%s\\(", syscallent[sc].sys_name);

		val = i;

		for (j = 0; j < syscallent[sc].nargs; j++) {
			if (j)
				printf(", ");

			switch ((enum arg_fmt) (arg_types[2 * j + 2])) {
			case AF_D:
				printf("%d", (int) args[j]);
				break;
			case AF_LD:
				printf("%ld", (long) args[j]);
				break;
			case AF_KLD:
			case AF_LLD:
				printf("%lld", (long long) args[j]);
				break;
			case AF_U:
				printf("%u", (unsigned int) args[j]);
				break;
			case AF_LU:
				printf("%lu", (unsigned long) args[j]);
				break;
			case AF_KLU:
			case AF_LLU:
				printf("%llu", (unsigned long long) args[j]);
				break;
			case AF_X:
				printf("%#x", (unsigned) args[j]);
				break;
			case AF_LX:
				printf("%#lx", (unsigned long) args[j]);
				break;
			case AF_KLX:
			case AF_LLX:
				printf("%#llx", (unsigned long long) args[j]);
				break;
			case AF_S:
				if (val % ARRAY_SIZE(opts) == ARG_PATH)
					printf("\"%s\"", path);
				else
					printf("%#llx", (unsigned long long) args[j]);
				break;
			default:
				printf("%s", af_strings[val % ARRAY_SIZE(opts)][arg_types[2 * j + 2]]);
				break;
			}

			val /= ARRAY_SIZE(opts);
		}

		printf("\\) = -1 ENOSYS \\(Function not implemented\\) "
		       "\\(INJECTED\\)\n");
	}
}

int
main(int argc, char **argv)
{
	unsigned int i;
	int tmp_fd;

	assert((tmp_fd = open(path, O_RDONLY | O_CREAT, 0600)) >= 0);
	printf("open\\(\"%s\", O_RDONLY\\|O_CREAT, 0600\\) = %d\n",
	       path, tmp_fd);
	assert(dup2(tmp_fd, fd) == (int) fd);
	printf("dup2\\(%d, %d\\) = %d\n", tmp_fd, fd, fd);
	assert(close(tmp_fd) == 0);
	printf("close\\(%d\\) = 0\n", tmp_fd);

	for (i = 0; i < ARRAY_SIZE(syscallent); ++i) {
	//for (i = __NR_dup2; i < __NR_dup2 + 1; ++i) {
		if (!syscallent[i].sys_name
#ifdef SYS_socket_nsubcalls
		    || (i >= SYS_socket_subcall &&
			i < SYS_socket_subcall + SYS_socket_nsubcalls)
#endif
#ifdef SYS_ipc_nsubcalls
		    || (i >= SYS_ipc_subcall &&
			i < SYS_ipc_subcall + SYS_ipc_nsubcalls)
#endif
#ifdef ARM_FIRST_SHUFFLED_SYSCALL
		    || (i >= ARM_FIRST_SHUFFLED_SYSCALL &&
			i <= ARM_FIRST_SHUFFLED_SYSCALL +
			    ARM_LAST_SPECIAL_SYSCALL + 1)
#endif
		   )
			continue;
		if (i >= ARRAY_SIZE(ksyslist) || !ksyslist[i])
			continue;
		if (strcmp(ksyslist[i], syscallent[i].sys_name))
			continue;

		do_call(i);
	}

	printf("\\+\\+\\+ exited with 0 \\+\\+\\+");

	return 0;
}
