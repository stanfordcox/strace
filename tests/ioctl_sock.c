/*
 * This file is part of ioctl_sock strace test.
 *
 * Copyright (c) 2016 JingPiao Chen <chenjingpiao@gmail.com>
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
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <net/if.h>

#define TEST_STRUCT_IFREQ_ARG_READ(cmd, addr) \
	ioctl(-1, cmd, addr); \
	printf("ioctl(-1, %s, {ifr_name=\"%.*s\"}) = -1 EBADF (%m)\n", \
	       #cmd, (int) sizeof(addr->ifr_name), \
	       addr->ifr_name)

#define TEST_STRUCT_IFREQ_ARG_WRITE(cmd, addr) \
	init_ifreq(cmd, addr); \
	ioctl(-1, cmd, addr); \
	printf("ioctl(-1, %s, {ifr_name=\"%.*s\", ", #cmd, \
	       (int) sizeof(addr->ifr_name), addr->ifr_name); \
	print_ifreq(cmd, ifr); \
	printf("}) = -1 EBADF (%m)\n")

static const unsigned int magic = 0xdeadbeef;

static void
init_magic(void *addr, const unsigned int size)
{
	unsigned int *p = addr;
	const unsigned int *end = addr + size - sizeof(int);

	for (; p <= end; ++p)
		*(unsigned int *) p = magic;
}

static void
init_sockaddr(void *addr)
{
	struct sockaddr_in *sin;
	sin = (struct sockaddr_in *) addr;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr("0.0.0.0");
}

static void
print_sockaddr(void *addr, const char *str)
{
	struct sockaddr_in *sin = (struct sockaddr_in *) addr;

	printf("%s={sa_family=AF_INET, sin_port=htons(%u), "
	       "sin_addr=inet_addr(\"0.0.0.0\")}",
	       str, sin->sin_port);
}

static void
init_ifreq(const unsigned int code, struct ifreq *ifr)
{
	switch (code) {
	case SIOCSIFADDR:
		init_sockaddr((void *) &ifr->ifr_addr);
		break;

	case SIOCSIFDSTADDR:
		init_sockaddr((void *) &ifr->ifr_dstaddr);
		break;

	case SIOCSIFBRDADDR:
		init_sockaddr((void *) &ifr->ifr_broadaddr);
		break;

	case SIOCSIFNETMASK:
		init_sockaddr((void *) &ifr->ifr_netmask);
		break;

	case SIOCSIFFLAGS:
		ifr->ifr_flags = IFF_UP;
		break;

	case SIOCSIFMETRIC:
		ifr->ifr_metric = magic;
		break;

	case SIOCSIFMTU:
		ifr->ifr_mtu = magic;
		break;

	case SIOCSIFSLAVE:
		memset(ifr->ifr_slave, 'B', sizeof(ifr->ifr_slave));
		break;

	case SIOCSIFHWADDR:
		init_magic(&ifr->ifr_hwaddr.sa_data,
			sizeof(ifr->ifr_hwaddr.sa_data));
		break;

	case SIOCSIFTXQLEN:
		ifr->ifr_qlen = magic;
		break;

	case SIOCSIFMAP:
		init_magic(&ifr->ifr_map, sizeof(ifr->ifr_map));
		break;
	}
}

static void
print_ifreq(const unsigned int code, const struct ifreq *ifr)
{
	switch (code) {
	case SIOCSIFADDR:
		print_sockaddr((void *) &ifr->ifr_addr, "ifr_addr");
		break;

	case SIOCSIFDSTADDR:
		print_sockaddr((void *) &ifr->ifr_dstaddr, "ifr_dstaddr");
		break;

	case SIOCSIFBRDADDR:
		print_sockaddr((void *) &ifr->ifr_broadaddr, "ifr_broadaddr");
		break;

	case SIOCSIFNETMASK:
		print_sockaddr((void *) &ifr->ifr_netmask, "ifr_netmask");
		break;

	case SIOCSIFFLAGS:
		printf("ifr_flags=IFF_UP");
		break;

	case SIOCSIFMETRIC:
		printf("ifr_metric=%d", ifr->ifr_metric);
		break;

	case SIOCSIFMTU:
		printf("ifr_mtu=%d", ifr->ifr_mtu);
		break;

	case SIOCSIFSLAVE:
		printf("ifr_slave=\"%.*s\"", (int) sizeof(ifr->ifr_slave),
		       ifr->ifr_slave);
		break;

	case SIOCSIFHWADDR: {
		const unsigned char *bytes =
			(unsigned char *) &ifr->ifr_hwaddr.sa_data;
		printf("ifr_hwaddr=%02x:%02x:%02x:%02x:%02x:%02x",
		       bytes[0], bytes[1], bytes[2],
		       bytes[3], bytes[4], bytes[5]);
		break;
	}

	case SIOCSIFTXQLEN:
		printf("ifr_qlen=%d", ifr->ifr_qlen);
		break;

	case SIOCSIFMAP:
		printf("ifr_map={mem_start=%#lx, "
		       "mem_end=%#lx, base_addr=%#x, "
		       "irq=%u, dma=%u, port=%u}",
		       ifr->ifr_map.mem_start,
		       ifr->ifr_map.mem_end,
		       (unsigned) ifr->ifr_map.base_addr,
		       (unsigned) ifr->ifr_map.irq,
		       (unsigned) ifr->ifr_map.dma,
		       (unsigned) ifr->ifr_map.port);
		break;
	}
}

int
main(void)
{
	char brname[] = "eth0";
	struct ifconf *const ifc = tail_alloc(sizeof(*ifc));
	struct ifreq *const ifr = tail_alloc(sizeof(*ifr));;
	init_magic(ifr, sizeof(*ifr));
	init_magic(ifc, sizeof(*ifc));
	memset(ifr->ifr_name, 'A', sizeof(ifr->ifr_name));

	ioctl(-1, SIOCGIFCONF, ifc);
	printf("ioctl(-1, SIOCGIFCONF, {%d}) = -1 EBADF (%m)\n", ifc->ifc_len);

#ifdef SIOCBRADDBR
	ioctl(-1, SIOCBRADDBR, brname);
	printf("ioctl(-1, SIOCBRADDBR, \"eth0\") = -1 EBADF (%m)\n");

	ioctl(-1, SIOCBRDELBR, brname);
	printf("ioctl(-1, SIOCBRDELBR, \"eth0\") = -1 EBADF (%m)\n");
#endif

#ifdef FIOSETOWN
	ioctl(-1, FIOSETOWN, &magic);
	printf("ioctl(-1, FIOSETOWN, [%d]) = -1 EBADF (%m)\n", magic);
#endif
#ifdef SIOCSPGRP
	ioctl(-1, SIOCSPGRP, &magic);
	printf("ioctl(-1, SIOCSPGRP, [%d]) = -1 EBADF (%m)\n", magic);
#endif
#ifdef FIOGETOWN
	ioctl(-1, FIOGETOWN, &magic);
	printf("ioctl(-1, FIOGETOWN, %#llx) = -1 EBADF (%m)\n",
	       (long long) &magic);
#endif
#ifdef SIOCGPGRP
	ioctl(-1, SIOCGPGRP, &magic);
	printf("ioctl(-1, SIOCGPGRP, %#llx) = -1 EBADF (%m)\n",
	       (long long) &magic);
#endif
#ifdef SIOCATMARK
	ioctl(-1, SIOCATMARK, &magic);
	printf("ioctl(-1, SIOCATMARK, %#llx) = -1 EBADF (%m)\n",
	       (long long) &magic);
#endif
#ifdef SIOCBRADDIF
	ioctl(-1, SIOCBRADDIF, 0);
	printf("ioctl(-1, SIOCBRADDIF) = -1 EBADF (%m)\n");
#endif
#ifdef SIOCBRDELIF
	ioctl(-1, SIOCBRDELIF, 0);
	printf("ioctl(-1, SIOCBRDELIF) = -1 EBADF (%m)\n");
#endif

	memset(ifr->ifr_newname, 'B', sizeof(ifr->ifr_newname));
	ioctl(-1, SIOCSIFNAME, ifr);
	printf("ioctl(-1, SIOCSIFNAME, {ifr_name=\"%.*s\", ifr_newname=\"%.*s\"})"
	       " = -1 EBADF (%m)\n", (int) sizeof(ifr->ifr_name), ifr->ifr_name,
	       (int) sizeof(ifr->ifr_newname), ifr->ifr_newname);

	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFDSTADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFBRDADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFNETMASK, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFFLAGS, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFMETRIC, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFMTU, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFSLAVE, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFHWADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFTXQLEN, ifr);
	TEST_STRUCT_IFREQ_ARG_WRITE(SIOCSIFMAP, ifr);

	ioctl(-1, SIOCGIFNAME, ifr);
	printf("ioctl(-1, SIOCGIFNAME, {ifr_index=%d}) = -1 EBADF (%m)\n",
	       ifr->ifr_ifindex);

	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFINDEX, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFDSTADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFBRDADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFNETMASK, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFFLAGS, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFMETRIC, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFMTU, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFSLAVE, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFHWADDR, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFTXQLEN, ifr);
	TEST_STRUCT_IFREQ_ARG_READ(SIOCGIFMAP, ifr);

	puts("+++ exited with 0 +++");
	return 0;
}
