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


#include <unistd.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "thread.h"
#include "debug.h"

#include "types.h"
#include "extern.h"

#define RTL_NUMBER_OF(A) (sizeof(A)/sizeof((A)[0]))

/* PROTOTYPES ****************************************************************/

static BOOLEAN KdbpCmdBackTrace(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdContinue(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdDisassembleX(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdHelp(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpCmdRegs(ULONG Argc, PCHAR Argv[]);
static BOOLEAN KdbpQuit(ULONG Argc, PCHAR Argv[]);

/* GLOBALS *******************************************************************/

CONTEXT KdbpContext;

/* FUNCTIONS *****************************************************************/

char Printable( WCHAR x )
{
	if (x>=0x20 && x<0x7f)
		return x;
	return '.';
}

int SPrintWideString( char *output, int len, unsigned short *str )
{
	int n;
	for (n=0; n<len && str[n]; n++)
		*output++ = Printable( str[n] );
	*output++ = 0;
	return n;
}

int SPrintUnicodeString( char *output, int len, UNICODE_STRING *us )
{
	int n;

	if (!us || !us->Buffer)
		return snprintf(output, len, "(null us)");

	for (n=0; n<len && n<us->Length/2; n++)
		*output++ = Printable( us->Buffer[n] );
	*output++ = 0;

	return n;
}

void DebugPrintf(const char *file, const char *func, int line, const char *fmt, ...)
{
	char buffer[0x100], fstr[16], *p;
	int sz, n, i, is_longlong;
	va_list va;

	if (!OptionTrace)
		return;

	va_start( va, fmt );

	p = buffer;
	sz = sizeof buffer - 1;

	while (*fmt && sz>0)
	{
		if (fmt[0] != '%')
		{
			*p++ = *fmt++;
			sz--;
			continue;
		}

		if (fmt[0] == '%' && fmt[1] == '%')
		{
			*p++ = *fmt;
			fmt += 2;
			sz--;
			continue;
		}

		i = 0;
		fstr[i++] = *fmt++;

		if (*fmt == '-')
			fstr[i++] = *fmt++;

		while (*fmt >= '0' && *fmt <= '9')
			fstr[i++] = *fmt++;

		is_longlong = 0;
		if (*fmt == 'l')
			fstr[i++] = *fmt++;
		if (*fmt == 'l')
		{
			fstr[i++] = *fmt++;
			is_longlong = 1;
		}

		fstr[i++] = *fmt;
		fstr[i++] = 0;

		n = 0;
		switch (*fmt)
		{
		case 'p':
			if (fmt[1] == 'w' && fmt[2] == 's')
			{
				n = SPrintWideString( p, sz, va_arg(va, unsigned short * ) );
				fmt += 2;
			}
			else if (fmt[1] == 'u' && fmt[2] == 's')
			{
				n = SPrintUnicodeString( p, sz, va_arg(va, UNICODE_STRING* ) );
				fmt += 2;
			}
			else
				n = snprintf( p, sz, "%p", va_arg( va, void* ) );
			break;
		case 'x':
			if (is_longlong)
				n = snprintf( p, sz, fstr, va_arg( va, long long ) );
			else
				n = snprintf( p, sz, fstr, va_arg( va, int ) );
			break;
		case 'd':
		case 'u':
		case 'o':
			if (is_longlong)
				n = snprintf( p, sz, fstr, va_arg( va, long long ) );
			else
				n = snprintf( p, sz, fstr, va_arg( va, int ) );
			break;
		case 's':
			n = snprintf( p, sz, fstr, va_arg( va, char * ) );
			break;
		case 'S':
			n = SPrintWideString( p, sz, va_arg(va, unsigned short * ) );
			break;
		case 'c':
			n = snprintf( p, sz, fstr, va_arg( va, int ) );
			break;
		case 0:
			break;
		default:
			n = snprintf( p, sz, "(?%c=%x)", *fmt, va_arg( va, unsigned int ) );
			break;
		}
		if (n<0)
			break;
		fmt++;
		p += n;
		sz -= n;
	}
	*p = 0;
	va_end( va );

#ifdef PRINT_PID_AND_TID
	ULONG pid = 0;
	ULONG tid = 0;
	if (Current) {
		tid = Current->TraceId();
		if (Current->Process)
			pid = Current->Process->Id;
	}
	fprintf(stderr, "%s:(pid:%lx, tid:%lx) %s", func, pid, tid, buffer);
#else
	fprintf( stderr, "%s %s", func, buffer );
#endif
}

VOID
KdbpPrint(
	IN CONST CHAR *Format,
	IN ...  OPTIONAL)
{
	va_list ap;

	/* Get the string */
	va_start(ap, Format);
	vfprintf(stderr, Format, ap);
	va_end(ap);
}

void DumpMem(void *p, unsigned int len)
{
	unsigned char *x = (unsigned char*) p;
	unsigned int i;
	char line[0x11];

	fprintf(stderr,"address %p\n", p);
	for(i=0; i<len; i++)
	{
		if (i%0x10 == 0)
		{
			memset( line, ' ', sizeof line );
			line[0x10] = 0;
		}
		line[i%0x10] = Printable(x[i]);
		fprintf(stderr,"%02x ", x[i] );
		if ((i+1)%0x10 == 0 || (i+1) == len)
			fprintf(stderr, "%*s\n", ((15 - i)%16)*3 + 20, line);
	}
}

//extern pid_t child_pid;

void Die(const char *fmt, ...)
{
	//char maps[0x30];
	va_list va;

	va_start( va, fmt );
	vfprintf(stderr, fmt, va);
	va_end( va );
	//sprintf(maps, "cat /proc/%d/maps", child_pid);
	//system(maps);
	exit(1);
}

void DumpRegs(CONTEXT *ctx)
{
	fprintf(stderr, "DumpRegs\n");
}

BYTE* DumpUserMem( BYTE *address )
{
	BYTE mem[0x80];
	unsigned int len = sizeof mem;
	unsigned char *x = mem;
	unsigned int i;
	char line[0x11];

	NTSTATUS r = CopyFromUser( mem, address, len );
	if (r)
	{
		fprintf(stderr, "address %p: invalid\n", address);
		return address;
	}

	fprintf(stderr,"address %p\n", address);
	for (i=0; i<len; i++)
	{
		if (i%0x10 == 0)
		{
			memset( line, ' ', sizeof line );
			line[0x10] = 0;
		}
		line[i%0x10] = Printable(x[i]);
		fprintf(stderr,"%02x ", x[i] );
		if ((i+1)%0x10 == 0 || (i+1) == len)
			fprintf(stderr, "%*s\n", ((15 - i)%16)*3 + 20, line);
	}
	return address + sizeof mem;
}

void DebuggerBacktrace(PCONTEXT ctx)
{
	ULONG frame, stack, x[2], i;
	NTSTATUS r;

	frame = ctx->Ebp;
	stack = ctx->Esp;

	r = CopyFromUser( &x[0], (void*) stack, sizeof x );
	if (r == STATUS_SUCCESS)
	{
		fprintf(stderr, "sysret = %08lx\n", x[0]);
	}

	for (i=0; i<0x10; i++)
	{
		fprintf(stderr, "%2ld: %08lx %08lx  ", i, stack, frame);
		if (stack > frame)
		{
			fprintf(stderr, "<invalid frame>\n");
			break;
		}

		r = CopyFromUser( &x[0], (void*) frame, sizeof x );
		if (r < STATUS_SUCCESS)
		{
			fprintf(stderr, "<invalid address>\n");
			break;
		}

		fprintf(stderr, "ret = %08lx\n", x[1]);
		if (!x[1])
			break;

		// next frame
		stack = frame;
		frame = x[0];
	}
}

typedef struct _ud_info
{
	ud_t ud_obj;
	BYTE *src;
} ud_info;

int UDInputHook(struct ud* ud_obj)
{
	ud_info *info = (ud_info*) ud_obj;
	BYTE b = 0;
	NTSTATUS r = CopyFromUser( &b, info->src, 1 );
	if (r < STATUS_SUCCESS)
		return UD_EOI;
	info->src++;
	return b;
}

BYTE *Unassemble( BYTE *address, int count )
{
	ud_info info;
	int i = count;
	BYTE *insn_addr = address;

	ud_init(&info.ud_obj);
	ud_set_input_hook(&info.ud_obj, UDInputHook);
	ud_set_mode(&info.ud_obj, 32);
	ud_set_syntax(&info.ud_obj, UD_SYN_INTEL);
	ud_set_pc(&info.ud_obj, (ULONG_PTR) address);

	info.src = address;

	while (ud_disassemble(&info.ud_obj))
	{
		insn_addr = (BYTE*)(ULONG) ud_insn_off(&info.ud_obj);
		fprintf(stderr,"%p %20s %s\n", insn_addr,
				ud_insn_hex(&info.ud_obj), ud_insn_asm(&info.ud_obj));
		insn_addr += ud_insn_len(&info.ud_obj);
		if (!--i)
			break;
	}

	return insn_addr;
}

void Chomp( char *buf )
{
	int len = strlen(buf);

	if (len && buf[len - 1 ] == '\n')
		buf[ len - 1 ] = 0;
}

static BOOLEAN KdbpCmdBackTrace(ULONG Argc, PCHAR Argv[])
{
	CONTEXT *ctx = &KdbpContext;

	DebuggerBacktrace(ctx);

	return TRUE;
}

static BOOLEAN KdbpCmdContinue(ULONG Argc, PCHAR Argv[])
{
	/* Exit the main loop */
	return FALSE;
}

static BOOLEAN KdbpCmdRegs(ULONG Argc, PCHAR Argv[])
{
	CONTEXT *ctx = &KdbpContext;

	fprintf(stderr, "eax %08lx ebx %08lx ecx %08lx edx %08lx\n"
		"esi %08lx edi %08lx ebp %08lx efl %08lx\n"
		"cs:eip %04lx:%08lx ss:esp %04lx:%08lx\n"
		"ds %04lx es %04lx fs %04lx gs %04lx\n",
		ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx,
		ctx->Esi, ctx->Edi, ctx->Ebp, ctx->EFlags,
		ctx->SegCs, ctx->Eip, ctx->SegSs, ctx->Esp,
		ctx->SegDs, ctx->SegEs, ctx->SegFs, ctx->SegGs);

	return TRUE;
}

static BOOLEAN KdbpCmdDisassembleX(ULONG Argc, PCHAR Argv[])
{
	ULONG Count;
	ULONG ul;
	ULONG_PTR Address = KdbpContext.Eip;

	if (Argv[0][0] == 'x') /* display memory */
		Count = 16;
	else /* disassemble */
		Count = 10;

	if (Argc >= 2)
	{
		/* Check for [L count] part */
		ul = 0;
		if (strcmp(Argv[Argc - 2], "L") == 0)
		{
			ul = strtoul(Argv[Argc - 1], NULL, 0);
			if (ul > 0)
			{
				Count = ul;
				Argc -= 2;
			}
		}
		else if (Argv[Argc - 1][0] == 'L')
		{
			ul = strtoul(Argv[Argc - 1] + 1, NULL, 0);
			if (ul > 0)
			{
				Count = ul;
				Argc--;
			}
		}

		/* Put the remaining arguments back together */
		Argc--;
		for (ul = 1; ul < Argc; ul++)
		{
			Argv[ul][strlen(Argv[ul])] = ' ';
		}
		Argc++;
	}

	/* Evaluate the expression */
	if (Argc > 1)
	{
		Address = (ULONG_PTR)strtol(Argv[1], NULL, 0x10);
	}
	else if (Argv[0][0] == 'x')
	{
		KdbpPrint("x: Address argument required.\n");
		return TRUE;
	}

	if (Argv[0][0] == 'x')
	{
		/* Display dwords */
		ul = 0;

		DumpUserMem((BYTE*)Address);
	}
	else
	{
		/* Disassemble */
		Unassemble((BYTE*)Address, Count);
	}

	return TRUE;
}

static BOOLEAN KdbpQuit(ULONG Argc, PCHAR Argv[])
{
	exit(1);
	return TRUE;
}

static const struct
{
	CONST CHAR *Name;
	CONST CHAR *Syntax;
	CONST CHAR *Help;
	BOOLEAN(*Fn)(ULONG Argc, PCHAR Argv[]);
} KdbDebuggerCommands[] = {
	{ "bt", "bt [*frameaddr|thread id]", "Prints current backtrace or from given frame addr", KdbpCmdBackTrace },
	{ "cont", "cont", "Continue execution (leave debugger)", KdbpCmdContinue },
	{ "x", "x [address] [L count]", "Display count dwords, starting at addr.", KdbpCmdDisassembleX },
	{ "help", "help", "Display help screen.", KdbpCmdHelp },
	{ "regs", "regs", "Display general purpose registers.", KdbpCmdRegs },
	{ "disasm", "disasm [address] [L count]", "Disassemble count instructions at address.", KdbpCmdDisassembleX },
	{ "quit", "quit", "Quit ring3k,", KdbpQuit }
};

static BOOLEAN
KdbpCmdHelp(ULONG Argc, PCHAR Argv[])
{
	ULONG i;

	KdbpPrint("Kernel debugger commands:\n");
	for (i = 0; i < RTL_NUMBER_OF(KdbDebuggerCommands); i++)
	{
		if (!KdbDebuggerCommands[i].Syntax) /* Command group */
		{
			if (i > 0)
				KdbpPrint("\n");

			KdbpPrint("\x1b[7m* %s:\x1b[0m\n", KdbDebuggerCommands[i].Help);
			continue;
		}

		KdbpPrint("  %-20s - %s\n",
			KdbDebuggerCommands[i].Syntax,
			KdbDebuggerCommands[i].Help);
	}

	return TRUE;
}

static BOOLEAN
KdbpDoCommand(IN PCHAR Command)
{
	ULONG i;
	PCHAR p;
	ULONG Argc;
	// FIXME: for what do we need a 1024 characters command line and 256 tokens?
	static PCH Argv[256];
	static CHAR OrigCommand[1024];

	strncpy(OrigCommand, Command, sizeof(OrigCommand));

	Argc = 0;
	p = Command;

	for (;;)
	{
		while (*p == '\t' || *p == ' ')
			p++;

		if (*p == '\0')
			break;

		i = strcspn(p, "\t ");
		Argv[Argc++] = p;
		p += i;
		if (*p == '\0')
			break;

		*p = '\0';
		p++;
	}

	if (Argc < 1)
		return TRUE;

	for (i = 0; i < RTL_NUMBER_OF(KdbDebuggerCommands); i++)
	{
		if (!KdbDebuggerCommands[i].Name)
			continue;

		if (strcmp(KdbDebuggerCommands[i].Name, Argv[0]) == 0)
		{
			return KdbDebuggerCommands[i].Fn(Argc, Argv);
		}
	}

	/* Now invoke the registered callbacks */
	/*if (KdbpInvokeCliCallbacks(Command, Argc, Argv))
	{
		return TRUE;
	}*/

	KdbpPrint("Command '%s' is unknown.\n", OrigCommand);
	return TRUE;
}


void Debugger( void )
{
	KdbpContext.ContextFlags = context_all;
	Current->GetContext(KdbpContext);
	//BYTE *d_address = (BYTE*) ctx.Esp;
	//BYTE *u_address = (BYTE*) ctx.Eip;
	char buf[100];
	int errors = 0;
	static bool help_displayed;

	if (!help_displayed)
	{
		KdbpCmdHelp(0, NULL);
		help_displayed = true;
	}

	while (errors < 3)
	{
		fprintf( stderr, "-");
		if (!fgets(buf, sizeof buf, stdin))
		{
			errors++;
			continue;
		}

		Chomp( buf );

		if (!KdbpDoCommand(buf)) return;
	}
}
