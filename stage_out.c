/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH

 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *	derived from this software without specific prior written permission.
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

/*
 *  Output staging is based on the "open_memstream()" function, see:
 *  http://man7.org/linux/man-pages/man3/open_memstream.3.html
 *  Requires glibc version 2.7 mininal
 *
 *  open_memstream returns a FILE stream that allows writing to a 
 *  dynamically growing buffer, that can be either copied to 
 *  tcp->outf (syscall successful) or dropped (syscall failed)
 */

#include "defs.h"
#if HAVE_OPEN_MEMSTREAM

FILE *
strace_openmemstream(struct tcb *tcp)
{
	FILE *fp	= NULL;  // to be returned 

	if(debug_flag) {
        ; /* error_msg("stage_openmemstream working on tcp %p", tcp); */
    }
	if (NULL != tcp) {
		tcp->memfptr  = NULL;
		fp = open_memstream(&(tcp->memfptr), &(tcp->memfloc));
		if (NULL == fp)
			perror_msg_and_die("error during open_memstream");
		else
			/* call to fflush required to update tcp->memfptr, see open_memstream man page */
			fflush(fp);
		tcp->memf	= fp;
		if(debug_flag) {
            ; /* error_msg("stage_openmemstream for tcp: %p (opened memf: %p, memfptr: %p, size: %zu)", tcp, tcp->memf, tcp->memfptr, tcp->memfloc); */
        }
	}

	return fp;
}

void
drop_staged_out(struct tcb *tcp)
{
	if (NULL != tcp->memf) {
		if(debug_flag) {
			; /* error_msg("drop_stage_out (before flcose): for tcp: %p (opened memf: %p, memfptr: %p, size: %zu)", tcp, tcp->memf, tcp->memfptr, tcp->memfloc); */
        }

		if (fclose(tcp->memf)) {
            perror_msg("flose on tcp->memf");
        }
		if (NULL != tcp->memfptr) {
			if(debug_flag) {
			    error_msg("syscall output dropped: %s ...", tcp->memfptr); 
            }

            free(tcp->memfptr);
            tcp->memfptr = NULL;
        }

		/* reopen tcp->memf for subsequent use */
		strace_openmemstream(tcp);
	}
}

void
publish_staged_out(struct tcb *tcp)
{
	if (NULL != tcp->memf) {
		if(debug_flag) {
			; /* error_msg("publish_staged_out (before fclose): for tcp: %p (opened memf: %p, memfptr: %p, size: %zu)", tcp, tcp->memf, tcp->memfptr, tcp->memfloc); */
        }

		if (fclose(tcp->memf)) {
            perror_msg("flose on tcp->memf");
        }
		if (NULL != tcp->memfptr) {
    		if (0 > fprintf(tcp->outf, "%s", tcp->memfptr)) {
                /* ToDo: print suitable error msg */
            }

			if (debug_flag) {
                ; /* error_msg("publish_staged_out (after free): for tcp: %p (opened memf: %p, memfptr: %p, size: %zu)", tcp, tcp->memf, tcp->memfptr, tcp->memfloc); */
            }

			free(tcp->memfptr);
			tcp->memfptr = NULL;
		}

		/* reopen tcp->memf for subsequent use */
		strace_openmemstream(tcp);
	}
}
#endif /* if HAVE_OPEN_MEMSTREAM */
