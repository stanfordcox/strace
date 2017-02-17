/* included in syscall.c:get_regs() */
{
        size_t size;
        char *regs = gdb_get_regs(pid, &size);
	struct tcb *tcp = pid2tcb(pid);
        if (regs) {
                if (size == 0 || regs[0] == 'E') {
                        get_regs_error = -1;
                        free(regs);
                        return;
                }

		if (size == 624) {
			get_regs_error = 0;
			x86_io.iov_len = sizeof(i386_regs);

			/* specified in 32bit-core.xml */
			i386_regs.eax = be32toh(gdb_decode_hex_n(&regs[0], 8));
			i386_regs.ecx = be32toh(gdb_decode_hex_n(&regs[8], 8));
			i386_regs.edx = be32toh(gdb_decode_hex_n(&regs[16], 8));
			i386_regs.ebx = be32toh(gdb_decode_hex_n(&regs[24], 8));
			i386_regs.esp = be32toh(gdb_decode_hex_n(&regs[32], 8));
			i386_regs.ebp = be32toh(gdb_decode_hex_n(&regs[40], 8));
			i386_regs.esi = be32toh(gdb_decode_hex_n(&regs[48], 8));
			i386_regs.edi = be32toh(gdb_decode_hex_n(&regs[56], 8));
			i386_regs.eip = be32toh(gdb_decode_hex_n(&regs[60], 8));
			i386_regs.eflags = be32toh(gdb_decode_hex_n(&regs[68], 8));
			i386_regs.xcs = be32toh(gdb_decode_hex_n(&regs[76], 8));
			i386_regs.xss = be32toh(gdb_decode_hex_n(&regs[84], 8));
			i386_regs.xds = be32toh(gdb_decode_hex_n(&regs[92], 8));
			i386_regs.xes = be32toh(gdb_decode_hex_n(&regs[100], 8));
			i386_regs.xfs = be32toh(gdb_decode_hex_n(&regs[108], 8));
			i386_regs.xgs = be32toh(gdb_decode_hex_n(&regs[116], 8));

			/* specified in 32bit-linux.xml */
			i386_regs.orig_eax = be64toh(gdb_decode_hex_n(&regs[616], 8));

			update_personality(tcp, 1);
			free(regs);
			return;
		}

		else if (size >= 1088) {
			get_regs_error = 0;
			x86_io.iov_len = sizeof(x86_64_regs);

			/* specified in 64bit-core.xml */
			x86_64_regs.rax = be64toh(gdb_decode_hex_n(&regs[0], 16));
			x86_64_regs.rbx = be64toh(gdb_decode_hex_n(&regs[16], 16));
			x86_64_regs.rcx = be64toh(gdb_decode_hex_n(&regs[32], 16));
			x86_64_regs.rdx = be64toh(gdb_decode_hex_n(&regs[48], 16));
			x86_64_regs.rsi = be64toh(gdb_decode_hex_n(&regs[64], 16));
			x86_64_regs.rdi = be64toh(gdb_decode_hex_n(&regs[80], 16));
			x86_64_regs.rbp = be64toh(gdb_decode_hex_n(&regs[96], 16));
			x86_64_regs.rsp = be64toh(gdb_decode_hex_n(&regs[112], 16));
			x86_64_regs.r8  = be64toh(gdb_decode_hex_n(&regs[128], 16));
			x86_64_regs.r9  = be64toh(gdb_decode_hex_n(&regs[144], 16));
			x86_64_regs.r10 = be64toh(gdb_decode_hex_n(&regs[160], 16));
			x86_64_regs.r11 = be64toh(gdb_decode_hex_n(&regs[176], 16));
			x86_64_regs.r12 = be64toh(gdb_decode_hex_n(&regs[192], 16));
			x86_64_regs.r13 = be64toh(gdb_decode_hex_n(&regs[208], 16));
			x86_64_regs.r14 = be64toh(gdb_decode_hex_n(&regs[224], 16));
			x86_64_regs.r15 = be64toh(gdb_decode_hex_n(&regs[240], 16));
			x86_64_regs.rip = be64toh(gdb_decode_hex_n(&regs[256], 16));
			x86_64_regs.eflags = be32toh(gdb_decode_hex_n(&regs[272], 8));
			x86_64_regs.cs = be32toh(gdb_decode_hex_n(&regs[280], 8));
			x86_64_regs.ss = be32toh(gdb_decode_hex_n(&regs[288], 8));
			x86_64_regs.ds = be32toh(gdb_decode_hex_n(&regs[296], 8));
			x86_64_regs.es = be32toh(gdb_decode_hex_n(&regs[304], 8));
			x86_64_regs.fs = be32toh(gdb_decode_hex_n(&regs[312], 8));
			x86_64_regs.gs = be32toh(gdb_decode_hex_n(&regs[320], 8));

			/* specified in 64bit-linux.xml */
			x86_64_regs.orig_rax = be64toh(gdb_decode_hex_n(&regs[1072], 16));

			update_personality(tcp, 0);
			free(regs);
			return;
		}

                else {
                        get_regs_error = -1;
                        free(regs);
                        return;
                }
	}
}
