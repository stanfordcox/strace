/*
 * The asinfo main source. The asinfo tool is purposed to operate
 * with system calls and provide information about it.
 *
 * Copyright (c) 2017 Edgar A. Kaziakhmedov <edgar.kaziakhmedov@virtuozzo.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arch_interface.h"
#include "dispatchers.h"
#include "error_prints.h"
#include "macros.h"
#include "request_msgs.h"
#include "syscall_interface.h"
#include "xmalloc.h"

#ifndef HAVE_PROGRAM_INVOCATION_NAME
char *program_invocation_name;
#endif

static void
usage(void)
{
	printf("\
usage: asinfo (--set-arch arch | --get-arch | --list-arch)\n\
              [--set-abi abi | --get-abi | --list-abi]\n\
   or: asinfo [(--set-arch arch | --get-arch) [--set-abi abi | --get-abi]]\n\
              (--get-sysc num | name) | (--get-nargs num | name)\n\
\n\
Architecture:\n\
  --set-arch arch  use architecture ARCH for further operations\n\
  --get-arch       use architecture returned by uname for further operations\n\
  --list-arch      print out all architectures supported by strace\n\
                   (combined use list-arch and any ABI option is permitted)\n\
\n\
ABI:\n\
  --set-abi abi    use application binary interface ABI for further operations\n\
  --get-arch       use ABI mode used at compile time for further operations\n\
  --list-arch      print out all ABIs for specified architecture\n\
\n\
System call:\n\
  --get-sysc num   print name of system call with the NUM number\n\
  --get-sysc name  print number of all system calls with NAME substring\n\
  --get-nargs num  get number of arguments of system call with the NUM number\n\
  --get-nargs name get number of arguments of system calls with NAME substring\n\
\n\
Miscellaneous:\n\
  -h               print help message\n");
	exit(0);
}

void
die(void)
{
	exit(1);
}

static int
is_more1bit(unsigned int num)
{
	return !(num & (num - 1));
}

static unsigned
strpar2req(char *option)
{
	/* Convertion table to store string with options */
	const char *options[] = {
		[SD_REQ_GET_SYSC_BIT]	= "--get-sysc",
		[SD_REQ_GET_NARGS_BIT]  = "--get-nargs",
		[SD_REQ_GET_LIST_BIT]	= "--list-sysc",
		[AD_REQ_SET_ARCH_BIT]	= "--set-arch",
		[AD_REQ_GET_ARCH_BIT]	= "--get-arch",
		[AD_REQ_LIST_ARCH_BIT]	= "--list-arch",
		[ABD_REQ_SET_ABI_BIT]	= "--set-abi",
		[ABD_REQ_GET_ABI_BIT]	= "--get-abi",
		[ABD_REQ_LIST_ABI_BIT]	= "--list-abi",
		[SERV_REQ_HELP_BIT]	= "-h",
	};
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (options[i] && strcmp(option, options[i]) == 0)
			return i;
	}
	return SERV_REQ_ERROR_BIT;
}

static unsigned
command_dispatcher(int argc, char *argv[], char *args[])
{
	int i;
	unsigned final_req = 0;
	unsigned temp_req = 0;
	unsigned non_req_arg = AD_REQ_GET_ARCH | AD_REQ_LIST_ARCH	|
			       ABD_REQ_GET_ABI | ABD_REQ_LIST_ABI	|
			       SD_REQ_GET_LIST;

	if (!program_invocation_name || !*program_invocation_name) {
		static char name[] = "asinfo";
		program_invocation_name =
			(argv[0] && *argv[0]) ? argv[0] : name;
	}

	/* Try to find help option firstly */
	for (i = 1; i < argc; i++) {
		if (strpar2req(argv[i]) == SERV_REQ_HELP_BIT)
			usage();
	}
	/* For now, is is necessary to convert string parameter to number of
	   request and make basic check */
	for (i = 1; i < argc; i++) {
		if ((temp_req = strpar2req(argv[i])) == SERV_REQ_ERROR_BIT)
			error_msg_and_help("unrecognized option '%s'",
					   argv[i]);
		if (final_req & 1 << temp_req)
			error_msg_and_help("parameter '%s' has been used "
					   "more than once", argv[i]);
		if (!((1 << temp_req) & non_req_arg) &&
		     (i + 1 >= argc || strlen(argv[i + 1]) == 0 ||
		      strpar2req(argv[i + 1]) != SERV_REQ_ERROR_BIT))
			error_msg_and_help("parameter '%s' requires "
					   "argument", argv[i]);
		final_req |= 1 << temp_req;
		if (!((1 << temp_req) & non_req_arg)) {
			args[temp_req] = argv[i + 1];
			i++;
		}
	}
	/* Secondly, final_req should be logically checked */
	/* More than one option from one request group couldn't be set */
	if ((is_more1bit(final_req & SD_REQ_MASK) == 0) ||
	    (is_more1bit(final_req & AD_REQ_MASK) == 0) ||
	    (is_more1bit(final_req & ABD_REQ_MASK) == 0) ||
	    (is_more1bit(final_req & FD_REQ_MASK) == 0))
		error_msg_and_help("exclusive parameters");
	/* Check on mutually exclusive options chain */
	/* If at least one syscall option has been typed, therefore
	   arch_options couldn't be list-arch and
	   abi_option couldn't be list-abi */
	if ((final_req & SD_REQ_MASK) &&
	    (((final_req & AD_REQ_MASK) && (final_req & AD_REQ_LIST_ARCH)) ||
	     ((final_req & ABD_REQ_MASK) && (final_req & ABD_REQ_LIST_ABI))))
		error_msg_and_help("wrong parameters");

	/* list-arch couldn't be used with any abi options */
	if ((final_req & AD_REQ_LIST_ARCH) &&
	    (final_req & ABD_REQ_MASK))
		error_msg_and_help("--list-arch cannot be used with any "
				   "ABI parameters");

	/* ABI requests could be used just in a combination with arch
	   requests */
	if ((final_req & ABD_REQ_MASK) &&
	    !(final_req & AD_REQ_MASK))
		error_msg_and_help("ABI parameters could be used only with "
				   "architecture parameter");
	return final_req;
}

static char *
seek_sc_arg(char **input_args)
{
	int i;

	for (i = SD_REQ_GET_SYSC_BIT; i < SYSCALL_REQ_BIT_LAST; i++)
		if (input_args[i] != NULL)
			return input_args[i];
	return NULL;
}

int
main(int argc, char *argv[])
{
	ARCH_LIST_DEFINE(arch_list);
	SYSCALL_LIST_DEFINE(sc_list);
	/* This array is purposed to store arguments for options in the
	   most convenient way */
	char **input_args = xcalloc(sizeof(*input_args), REQ_LAST_BIT);
	unsigned reqs;
	int ret = 0;

	/* command_dispatcher turn */
	reqs = command_dispatcher(argc, argv, input_args);
	if (reqs == 0)
		error_msg_and_help("must have OPTIONS");

	/* arch_dispatcher turn */
	arch_list = arch_dispatcher(reqs, input_args[AD_REQ_SET_ARCH_BIT]);
	if (arch_list == NULL)
		perror_msg_and_die("unrecognized architecture '%s'",
				   input_args[AD_REQ_SET_ARCH_BIT]);
	/* abi_dispatcher turn */
	ret = abi_dispatcher(arch_list, reqs, input_args[ABD_REQ_SET_ABI_BIT]);
	if (ret != 0)
		perror_msg_and_die("unrecognized ABI mode '%s' for a given "
				   "architecture",
				   input_args[ABD_REQ_SET_ABI_BIT]);
	if (ret != 0 && !input_args[ABD_REQ_SET_ABI_BIT])
		perror_msg_and_die("current architecture isn't supported");
	/* syscall_dispatcher turn */
	sc_list = syscall_dispatcher(arch_list, reqs, seek_sc_arg(input_args));
	if (ss_error(sc_list))
		perror_msg_and_die("%s", ss_get_serror(sc_list));
	/* If we want to get info about only architectures thus we print out
	   architectures, otherwise system calls */
	if (!(reqs & SD_REQ_MASK))
		al_dump(arch_list);
	else
		ss_dump(sc_list);
	return 0;
}
