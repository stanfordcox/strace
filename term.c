/*
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2017 The strace developers.
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

#include "defs.h"
/*
 * The C library's definition of struct termios might differ from
 * the kernel one, and we need to use the kernel layout.
 */
#include <linux/termios.h>

#include "xlat/tcxonc_options.h"
#include "xlat/tcflsh_options.h"
#include "xlat/baud_options.h"
#include "xlat/modem_flags.h"

#include "xlat/term_cflags.h"
#include "xlat/term_cflags_csize.h"
#include "xlat/term_iflags.h"
#include "xlat/term_lflags.h"
#include "xlat/term_oflags.h"
#include "xlat/term_oflags_bsdly.h"
#include "xlat/term_oflags_crdly.h"
#include "xlat/term_oflags_ffdly.h"
#include "xlat/term_oflags_nldly.h"
#include "xlat/term_oflags_tabdly.h"
#include "xlat/term_oflags_vtdly.h"

#include "xlat/termio_cc.h"
#include "xlat/termios_cc.h"

static void
decode_oflag(uint64_t val)
{
	static const struct {
		const struct xlat *xl;
		uint64_t mask;
		const char *dfl;
	} xlats[] = {
		{ term_oflags_bsdly,  BSDLY,  "BS?"  },
		{ term_oflags_crdly,  CRDLY,  "CR?"  },
		{ term_oflags_ffdly,  FFDLY,  "FF?"  },
		{ term_oflags_nldly,  NLDLY,  "NL?"  },
		{ term_oflags_tabdly, TABDLY, "TAB?" },
		{ term_oflags_vtdly,  VTDLY,  "VT?"  },
	};

	unsigned i;

	for (i = 0; i < ARRAY_SIZE(xlats); i++) {
		printxval64(xlats[i].xl, val & xlats[i].mask, xlats[i].dfl);
		tprints("|");

		val &= ~xlats[i].mask;
	}

	printflags64(term_oflags, val, NULL);
}

static void
decode_cflag(uint64_t val)
{
	printxval64(baud_options, val & CBAUD, "B???");
	tprints("|");
	printxval64(baud_options, (val & CIBAUD) >> IBSHIFT, "B???");
	tprintf("<<IBSHIFT|");
	printxval64(term_cflags_csize, val & CSIZE, "CS?");
	tprints("|");

	val &= ~(CBAUD | CIBAUD | CSIZE);
	printxval64(term_cflags, val, NULL);
}

static void
decode_flags(uint64_t iflag, uint64_t oflag, uint64_t cflag, uint64_t lflag)
{
	tprints("c_iflag=");
	printflags64(term_iflags, iflag, NULL);
	tprints(", c_oflag=");
	decode_oflag(oflag);
	tprints(", c_cflag=");
	decode_cflag(cflag);
	tprints(", c_lflag=");
	printflags64(term_lflags, lflag, NULL);
}

static void
print_cc_char(bool *first, const unsigned char *data, const char *s,
	      unsigned idx)
{
	if (*first)
		*first = false;
	else
		tprints(", ");

	if (s)
		tprintf("[%s] = ", s);
	else
		tprintf("[%u] = ", idx);

	tprintf("%#hhx", data[idx]);
}

static void
decode_term_cc(const struct xlat *xl, const unsigned char *data, unsigned size)
{
	uint64_t not_printed = (1ULL << size) - 1;
	unsigned i = 0;
	bool first = true;

	tprints("{");

	for (; xl->str; xl++) {
		if (xl->val >= size)
			continue;

		print_cc_char(&first, data, xl->str, xl->val);
		not_printed &= ~(1 << xl->val);
	}

	while (not_printed) {
		if (not_printed & 1)
			print_cc_char(&first, data, NULL, i);

		not_printed >>= 1;
		i++;
	}

	tprints("}");
}

static void
decode_termios(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct termios tios;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &tios))
		return;

	tprints("{");
	decode_flags(tios.c_iflag, tios.c_oflag, tios.c_cflag, tios.c_lflag);
	tprints(", ");

	if (abbrev(tcp)) {
		tprints("...");
	} else {
		tprintf("c_line=%u, ", tios.c_line);
		if (!(tios.c_lflag & ICANON))
			tprintf("c_cc[VMIN]=%u, c_cc[VTIME]=%u, ",
				tios.c_cc[VMIN], tios.c_cc[VTIME]);
		tprints("c_cc=");
		decode_term_cc(termios_cc, tios.c_cc, NCCS);
	}
	tprints("}");
}

static void
decode_termio(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct termio tio;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &tio))
		return;

	tprints("{");
	decode_flags(tio.c_iflag, tio.c_oflag, tio.c_cflag, tio.c_lflag);
	tprints(", ");

	if (abbrev(tcp)) {
		tprints("...");
	} else {
		tprintf("c_line=%u, ", tio.c_line);

#ifdef _VMIN /* thanks, alpha */
		if (!(tio.c_lflag & ICANON))
			tprintf("c_cc[_VMIN]=%d, c_cc[_VTIME]=%d, ",
				tio.c_cc[_VMIN], tio.c_cc[_VTIME]);

		tprints("c_cc=");
		decode_term_cc(termio_cc, tio.c_cc, NCC);
#else /* !_VMIN */
		if (!(tio.c_lflag & ICANON))
			tprintf("c_cc[VMIN]=%d, c_cc[VTIME]=%d, ",
				tio.c_cc[VMIN], tio.c_cc[VTIME]);

		tprints("c_cc=");
		decode_term_cc(termios_cc, tio.c_cc, NCC);
#endif /* !_VMIN */
	}

	tprints("}");
}

static void
decode_winsize(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct winsize ws;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &ws))
		return;
	tprintf("{ws_row=%d, ws_col=%d, ws_xpixel=%d, ws_ypixel=%d}",
		ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
}

#ifdef TIOCGSIZE
static void
decode_ttysize(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct ttysize ts;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &ts))
		return;
	tprintf("{ts_lines=%d, ts_cols=%d}",
		ts.ts_lines, ts.ts_cols);
}
#endif

static void
decode_modem_flags(struct tcb *const tcp, const kernel_ulong_t addr)
{
	int i;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &i))
		return;
	tprints("[");
	printflags(modem_flags, i, "TIOCM_???");
	tprints("]");
}

int
term_ioctl(struct tcb *const tcp, const unsigned int code,
	   const kernel_ulong_t arg)
{
	switch (code) {
	/* struct termios */
	case TCGETS:
#ifdef TCGETS2
	case TCGETS2:
#endif
	case TIOCGLCKTRMIOS:
		if (entering(tcp))
			return 0;
	case TCSETS:
#ifdef TCSETS2
	case TCSETS2:
#endif
	case TCSETSW:
#ifdef TCSETSW2
	case TCSETSW2:
#endif
	case TCSETSF:
#ifdef TCSETSF2
	case TCSETSF2:
#endif
	case TIOCSLCKTRMIOS:
		decode_termios(tcp, arg);
		break;

	/* struct termio */
	case TCGETA:
		if (entering(tcp))
			return 0;
	case TCSETA:
	case TCSETAW:
	case TCSETAF:
		decode_termio(tcp, arg);
		break;

	/* struct winsize */
	case TIOCGWINSZ:
		if (entering(tcp))
			return 0;
	case TIOCSWINSZ:
		decode_winsize(tcp, arg);
		break;

	/* struct ttysize */
#ifdef TIOCGSIZE
	case TIOCGSIZE:
		if (entering(tcp))
			return 0;
	case TIOCSSIZE:
		decode_ttysize(tcp, arg);
		break;
#endif

	/* ioctls with a direct decodable arg */
	case TCXONC:
		tprints(", ");
		printxval64(tcxonc_options, arg, "TC???");
		break;
	case TCFLSH:
		tprints(", ");
		printxval64(tcflsh_options, arg, "TC???");
		break;
	case TCSBRK:
	case TCSBRKP:
	case TIOCSCTTY:
		tprintf(", %d", (int) arg);
		break;

	/* ioctls with an indirect parameter displayed as modem flags */
	case TIOCMGET:
		if (entering(tcp))
			return 0;
	case TIOCMBIS:
	case TIOCMBIC:
	case TIOCMSET:
		decode_modem_flags(tcp, arg);
		break;

	/* ioctls with an indirect parameter displayed in decimal */
	case TIOCGPGRP:
	case TIOCGSID:
	case TIOCGETD:
	case TIOCGSOFTCAR:
	case TIOCGPTN:
	case FIONREAD:
	case TIOCOUTQ:
#ifdef TIOCGEXCL
	case TIOCGEXCL:
#endif
#ifdef TIOCGDEV
	case TIOCGDEV:
#endif
		if (entering(tcp))
			return 0;
	case TIOCSPGRP:
	case TIOCSETD:
	case FIONBIO:
	case FIOASYNC:
	case TIOCPKT:
	case TIOCSSOFTCAR:
	case TIOCSPTLCK:
		tprints(", ");
		printnum_int(tcp, arg, "%d");
		break;

	/* ioctls with an indirect parameter displayed as a char */
	case TIOCSTI:
		tprints(", ");
		printstrn(tcp, arg, 1);
		break;

	/* ioctls with no parameters */

	case TIOCSBRK:
	case TIOCCBRK:
	case TIOCCONS:
	case TIOCNOTTY:
	case TIOCEXCL:
	case TIOCNXCL:
	case FIOCLEX:
	case FIONCLEX:
#ifdef TIOCVHANGUP
	case TIOCVHANGUP:
#endif
#ifdef TIOCSSERIAL
	case TIOCSSERIAL:
#endif
		break;

	/* ioctls which are unknown */

	default:
		return RVAL_DECODED;
	}

	return RVAL_IOCTL_DECODED;
}
