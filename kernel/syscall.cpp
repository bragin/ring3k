/*
 * nt loader
 *
 * Copyright 2006-2008 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "ntcall.h"
#include "ntwin32.h"

DEFAULT_DEBUG_CHANNEL(syscall);

typedef struct _NtCallDesc
{
	const char *name;
	void *func;
	unsigned int numargs;
} NtCallDesc;

#define NUL(x) { #x, NULL, 0 }	/* not even declared */
#define DEC(x,n) { #x, NULL, n }  /* no stub implemented */
#define IMP(x,n) { #x, (void*)x, n }	 /* entry point implemented */

NtCallDesc Win2kCalls[] =
{
#define SYSCALL_WIN2K
#include "ntsyscall.h"
#undef SYSCALL_WIN2K
};

NtCallDesc WinXPCalls[] =
{
#define SYSCALL_WINXP
#include "ntsyscall.h"
#undef SYSCALL_WINXP
};

NtCallDesc Win2kUICalls[] =
{
#define SYSCALL_WIN2K
#include "uisyscall.h"
#undef SYSCALL_WIN2K
};

NtCallDesc WinXPUICalls[] =
{
#define SYSCALL_WINXP
#include "uisyscall.h"
#undef SYSCALL_WINXP
};

NtCallDesc *NtCalls;
ULONG NumberOfNtCalls;

NtCallDesc *NtUICalls;
ULONG NumberOfUICalls;

static ULONG UICallOffset = 0x1000;

void InitSyscalls(bool xp)
{
	if (xp)
	{
		NumberOfNtCalls = sizeof WinXPCalls/sizeof WinXPCalls[0];
		NtCalls = WinXPCalls;
		NumberOfUICalls = sizeof WinXPUICalls/sizeof WinXPUICalls[0];
		NtUICalls = WinXPUICalls;
	}
	else
	{
		NumberOfNtCalls = sizeof Win2kCalls/sizeof Win2kCalls[0];
		NtCalls = Win2kCalls;
		NumberOfUICalls = sizeof Win2kUICalls/sizeof Win2kUICalls[0];
		NtUICalls = Win2kUICalls;
	}
}

void TraceSyscallEnter(ULONG id, NtCallDesc *ntcall, ULONG *args, ULONG retaddr)
{
	/* print a relay style trace line */
	if (!OptionTrace)
		return;

	fprintf(stderr,"%04lx: %s(", id, ntcall->name);
	if (ntcall->numargs)
	{
		unsigned int i;
		fprintf(stderr,"%08lx", args[0]);
		for (i=1; i<ntcall->numargs; i++)
			fprintf(stderr,",%08lx", args[i]);
	}
	fprintf(stderr,") ret=%08lx\n", retaddr);
}

void TraceSyscallExit(ULONG id, NtCallDesc *ntcall, ULONG r, ULONG retaddr)
{
	if (!OptionTrace)
		return;

	fprintf(stderr, "%04lx: %s retval=%08lx ret=%08lx\n",
			id, ntcall->name, r, retaddr);
}

NTSTATUS DoNtSyscall(ULONG id, ULONG func, ULONG *uargs, ULONG retaddr)
{
	NTSTATUS r = STATUS_INVALID_SYSTEM_SERVICE;
	NtCallDesc *ntcall = 0;
	ULONG args[16];
	const int magic_val = 0xfedc1248;	// random unlikely value
	int magic = magic_val;
	BOOLEAN win32k_func = FALSE;

	/* check the call number is in range */
	if (func >= 0 && func < NumberOfNtCalls)
		ntcall = &NtCalls[func];
	else if (func >= UICallOffset && func < (UICallOffset + NumberOfUICalls))
	{
		win32k_func = TRUE;
		ntcall = &NtUICalls[func - UICallOffset];
	}
	else
	{
		ERR("invalid syscall %ld ret=%08lx\n", func, retaddr);
		return r;
	}

	BYTE inst[4];
	r = CopyFromUser( inst, (const void*)retaddr, sizeof inst );
	if (r == STATUS_SUCCESS && inst[0] == 0xc2)
	{
		// detect the number of args
		if (!ntcall->func && !ntcall->numargs && inst[2] == 0)
		{
			ntcall->numargs = inst[1]/4;
			fprintf(stderr, "%s: %d args\n", ntcall->name, inst[1]/4);
		}

		// many syscalls are a short asm function
		// find the caller of that function
		if (OptionTrace)
		{
			ULONG r2 = 0;
			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_CONTROL;
			Current->GetContext( ctx );
			r = CopyFromUser( &r2, (const void*) ctx.Esp, sizeof r2);
			if (r == STATUS_SUCCESS)
				retaddr = r2;
		}
	}

	if (sizeof args/sizeof args[0] < ntcall->numargs)
		Die("not enough room for %d args\n", ntcall->numargs);

	/* call it */
	r = CopyFromUser( args, uargs, ntcall->numargs*sizeof (args[0]) );
	if (r < STATUS_SUCCESS)
		goto end;

	TraceSyscallEnter(id, ntcall, args, retaddr );

	// initialize the windows subsystem if necessary
	if (win32k_func)
		Win32kThreadInit(Current);

	/* debug info for this call */
	if (!ntcall->func)
	{
		FIXME("syscall %s (%02lx) not implemented\n", ntcall->name, func);
		r = STATUS_NOT_IMPLEMENTED;
		goto end;
	}

	__asm__(
		"pushl %%edx\n\t"
		"subl %%ecx, %%esp\n\t"
		"movl %%esp, %%edi\n\t"
		"cld\n\t"
		"repe\n\t"
		"movsb\n\t"
		"call *%%eax\n\t"
		"popl %%edx\n\t"
		: "=a"(r), "=d"(magic)   // output
		: "a"(ntcall->func), "c"(ntcall->numargs*4), "d"(magic), "S"(args) // input
		: "%edi"	// clobber
	);

	assert( magic == magic_val );

end:
	TraceSyscallExit(id, ntcall, r, retaddr);

	return r;
}
