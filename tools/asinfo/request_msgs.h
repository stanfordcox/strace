/*
 * The request_msgs are messages used by dispatchers in asinfo tool to
 * operate with static data base.
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

#ifndef STRACE_ASINFO_REQ_MSGS
#define STRACE_ASINFO_REQ_MSGS

/* Request types for syscall_dispatcher,
 * arch_dispatcher, and filter_dispatcher,
 * which, in turn, could be combined
 */
enum syscall_req_bit {
	SD_REQ_GET_SYSC_BIT,
	SD_REQ_GET_NARGS_BIT,
	SD_REQ_GET_LIST_BIT,

	SYSCALL_REQ_BIT_LAST
};

enum arch_req_bit {
	AD_REQ_SET_ARCH_BIT = SYSCALL_REQ_BIT_LAST,
	AD_REQ_GET_ARCH_BIT,
	AD_REQ_LIST_ARCH_BIT,

	ARCH_REQ_BIT_LAST
};

enum abi_req_bit {
	ABD_REQ_SET_ABI_BIT = ARCH_REQ_BIT_LAST,
	ABD_REQ_GET_ABI_BIT,
	ABD_REQ_LIST_ABI_BIT,

	ABD_REQ_BIT_LAST
};

enum fd_req_bit {
	FD_REQ_SET_BASE_FILTER_BIT = ABD_REQ_BIT_LAST,

	FD_REQ_BIT_LAST
};

enum serv_req_bit {
	SERV_REQ_HELP_BIT = FD_REQ_BIT_LAST,
	SERV_REQ_ERROR_BIT,

	SERV_REQ_BIT_LAST
};

#define ENUM_FLAG(name) name = 1 << name##_BIT
enum req_type {
	ENUM_FLAG(SD_REQ_GET_SYSC),
	ENUM_FLAG(SD_REQ_GET_NARGS),
	ENUM_FLAG(SD_REQ_GET_LIST),
	ENUM_FLAG(AD_REQ_SET_ARCH),
	ENUM_FLAG(AD_REQ_GET_ARCH),
	ENUM_FLAG(AD_REQ_LIST_ARCH),
	ENUM_FLAG(ABD_REQ_SET_ABI),
	ENUM_FLAG(ABD_REQ_GET_ABI),
	ENUM_FLAG(ABD_REQ_LIST_ABI),
	ENUM_FLAG(FD_REQ_SET_BASE_FILTER),
	ENUM_FLAG(SERV_REQ_HELP),
	ENUM_FLAG(SERV_REQ_ERROR)
};
#undef ENUM_FLAG

#define BITMASK(hi, lo) ((1 << (hi)) - (1 << (lo)))
#define REQ_LAST_BIT SERV_REQ_BIT_LAST
#define SD_REQ_MASK BITMASK(SYSCALL_REQ_BIT_LAST, 0)
#define AD_REQ_MASK BITMASK(ARCH_REQ_BIT_LAST, SYSCALL_REQ_BIT_LAST)
#define ABD_REQ_MASK BITMASK(ABD_REQ_BIT_LAST, ARCH_REQ_BIT_LAST)
#define FD_REQ_MASK BITMASK(FD_REQ_BIT_LAST, ABD_REQ_BIT_LAST)
#define SERV_REQ_MASK BITMASK(SERV_REQ_BIT_LAST, FD_REQ_BIT_LAST)

#endif /* !STRACE_ASINFO_REQ_MSGS */
