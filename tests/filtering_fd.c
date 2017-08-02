/*
 * Check decoding of non-standard fd filters
 *
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

#include "tests.h"
#include <asm/unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __NR_dup2
void
test_dup2(void)
{
	int rc = dup2(5, -1);
	printf("dup2(5, -1) = %s\n", sprintrc(rc));
	rc = dup2(-1, 5);
	printf("dup2(-1, 5) = %s\n", sprintrc(rc));
}
#endif

#ifdef __NR_linkat
void
test_linkat(void)
{
	int rc = linkat(5, "old", -1, "new", 0);
	printf("linkat(5, \"old\", -1, \"new\", 0) = %s\n", sprintrc(rc));
	rc = linkat(-1, "old", 5, "new", 0);
	printf("linkat(-1, \"old\", 5, \"new\", 0) = %s\n", sprintrc(rc));
}
#endif

#ifdef __NR_symlinkat
void
test_symlinkat(void)
{
	int rc = symlinkat("new", 5, "old");
	printf("symlinkat(\"new\", 5, \"old\") = %s\n", sprintrc(rc));
}
#endif

#ifdef __NR_epoll_ctl
# include <sys/epoll.h>
void
test_epoll(void)
{
	int rc = epoll_ctl(-1, EPOLL_CTL_ADD, 5, NULL);
	printf("epoll_ctl(-1, EPOLL_CTL_ADD, 5, NULL) = %s\n", sprintrc(rc));
}
#endif

#if defined HAVE_SYS_FANOTIFY_H && defined HAVE_FANOTIFY_MARK && \
	defined __NR_fanotify_mark
# include <sys/fanotify.h>
void
test_fanotify_mark(void)
{
	int rc = fanotify_mark(-1, 0, 0, 5, ".");
	printf("fanotify_mark(-1, 0, 0, 5, \".\") = %s\n", sprintrc(rc));
}
#endif

#if defined __NR_select || defined __NR__newselect
# include <sys/select.h>
void
test_select(void)
{
	fd_set readset;
	FD_ZERO(&readset);
	FD_SET(5, &readset);
	int rc;
# ifndef __NR__newselect
	rc = syscall(__NR_select, 6, &readset, NULL, NULL, NULL);
	printf("select(6, [5], NULL, NULL, NULL) = %s\n", sprintrc(rc));
# else
	rc = syscall(__NR__newselect, 6, &readset, NULL, NULL, NULL);
	printf("_newselect(6, [5], NULL, NULL, NULL) = %s\n", sprintrc(rc));
# endif
}
#endif

#ifdef __NR_poll
# include <poll.h>
void
test_poll(void)
{
	struct pollfd pfds = {.fd = 5, .events = POLLIN};
	poll(&pfds, 1, 1);
	printf("poll([{fd=5, events=POLLIN}], 1, 1) = 1 "
	       "([{fd=5, revents=POLLNVAL}])\n");
}
#endif

int
main(int argc, char **argv)
{
	const char *const name = argc > 1 ? argv[1] : "mmap";
#ifdef __NR_dup2
	test_dup2();
#endif

#ifdef __NR_linkat
	test_linkat();
#endif

	mmap(NULL, 0, PROT_NONE, MAP_FILE, 5, 0);
	printf("%s(NULL, 0, PROT_NONE, MAP_FILE, 5, 0) = -1 EBADF (%m)\n",
	       name);

#ifdef __NR_symlinkat
	test_symlinkat();
#endif

#ifdef __NR_epoll_ctl
	test_epoll();
#endif

#if defined HAVE_SYS_FANOTIFY_H && defined HAVE_FANOTIFY_MARK && \
	defined __NR_fanotify_mark
	test_fanotify_mark();
#endif

#if defined __NR_select || defined __NR__newselect
	test_select();
#endif

#ifdef __NR_poll
	test_poll();
#endif

	puts("+++ exited with 0 +++");
	return 0;
}
