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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>
#include <execinfo.h>
#include <getopt.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "objdir.h"
#include "ntcall.h"
#include "section.h"
#include "timer.h"
#include "unicode.h"
#include "fiber.h"
#include "file.h"
#include "event.h"
#include "symlink.h"
#include "alloc_bitmap.h"
#include "registry_interface.h"
#include "registry_xml.h"
#include "registry_redis.h"

DEFAULT_DEBUG_CHANNEL(main);

PROCESS_LIST Processes;
THREAD *Current;
OBJECT *NtDLLSection;
int option_debug = 0;
ULONG KiIntSystemCall = 0;
bool forced_quit;
int RegistryIndex = -1;
IREGISTRY* Registry = NULL;

struct registry_ident {
	const char* name;
	IREGISTRY* (*create)();
};

struct registry_ident registry_list[] = {
	{"xml", REGISTRY_XML::Create},
	{"redis", REGISTRY_REDIS::Create},
	{NULL, NULL},
};


class DEFAULT_SLEEPER : public SLEEPER
{
public:
	virtual bool CheckEvents( bool wait );
	virtual ~DEFAULT_SLEEPER() {}
};

int SLEEPER::GetIntTimeout( LARGE_INTEGER& timeout )
{
	timeout.QuadPart = (timeout.QuadPart+9999)/10000;
	int t = INT_MAX;
	if (timeout.QuadPart < t)
		t = timeout.QuadPart;
	return t;
}

bool DEFAULT_SLEEPER::CheckEvents( bool wait )
{
	LARGE_INTEGER timeout;

	// check for expired timers
	bool timers_left = TIMEOUT::CheckTimers(timeout);

	// Check for a deadlock and quit.
	//  This happens if we're the only active thread,
	//  there's no more timers, and we're asked to wait.
	if (!timers_left && wait && FIBER::LastFiber())
		return true;
	if (!wait)
		return false;

	int t = GetIntTimeout( timeout );
	int r = poll( 0, 0, t );
	if (r >= 0)
		return false;
	if (errno != EINTR)
		Die("poll failed %d\n", errno);
	return false;
}

DEFAULT_SLEEPER DefaultSleeper;
SLEEPER* Sleeper = &DefaultSleeper;

int Schedule(void)
{
	/* while there's still a thread running */
	while (Processes.Head())
	{
		// check if any thing interesting has happened
		Sleeper->CheckEvents( false );

		// other fibers are active... schedule run them
		if (!FIBER::LastFiber())
		{
			FIBER::Yield();
			continue;
		}

		// there's still processes but no active threads ... sleep
		if (Sleeper->CheckEvents( true ))
			break;
	}

	return 0;
}

NTSTATUS CreateInitialProcess( THREAD **t, UNICODE_STRING& us )
{
	BYTE *pstack;
	const unsigned int stack_size = 0x100 * PAGE_SIZE;
	PROCESS *p = NULL;
	CONTEXT ctx;
	INITIAL_TEB init_teb;
	CLIENT_ID id;
	OBJECT *section = NULL;
	CFILE *file = 0;
	int r;

	r = OpenFile( file, us );
	if (r < STATUS_SUCCESS)
		return r;

	/* load the executable and ntdll */
	r = CreateSection( &section, file, 0, SEC_IMAGE, PAGE_EXECUTE_READWRITE );
	Release( file );
	if (r < STATUS_SUCCESS)
		return r;

	/* create the initial process */
	r = CreateProcess( &p, section );
	Release( section );
	section = NULL;

	if (r < STATUS_SUCCESS)
		return r;

	PPEB ppeb = (PPEB) p->PebSection->GetKernelAddress();
	p->CreateExePPB( &ppeb->ProcessParameters, us );

	/* map the stack */
	pstack = NULL;
	r = p->Vm->AllocateVirtualMemory( &pstack, 0, stack_size, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	/* TEB initialization data.
       StackBase > StackLimit because stack grows downward  */
	memset( &init_teb, 0, sizeof init_teb );
	init_teb.AllocatedStackBase = pstack;
	init_teb.StackBase = (BYTE*)init_teb.AllocatedStackBase + stack_size;
	init_teb.StackLimit = (BYTE*)init_teb.AllocatedStackBase + PAGE_SIZE;

	/* initialize the first thread's context */
	p->Vm->InitContext( ctx );
	ctx.Eip = (DWORD) GetEntryPoint( p );
	ctx.Esp = (DWORD) pstack + stack_size - 8;

	TRACE("entry point = %08lx\n", ctx.Eip);

	/* when starting nt processes, make the PEB the first arg of NtProcessStartup */
	r = p->Vm->CopyToUser( (BYTE*) ctx.Esp + 4, &p->PebBaseAddress, sizeof p->PebBaseAddress );

	if (r == STATUS_SUCCESS)
		r = CreateThread( t, p, &id, &ctx, &init_teb, FALSE );

	Release( p );

	return r;
}

NTSTATUS InitNtDLL( void )
{
	WCHAR ntdll[] =
	{
		'\\','?','?','\\','c',':','\\','w','i','n','n','t','\\',
		's','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0
	};
	CUNICODE_STRING us;
	CFILE *file = 0;
	NTSTATUS r;

	us.Set( ntdll );

	r = OpenFile( file, us );
	if (r < STATUS_SUCCESS)
		Die("failed to open ntdll\n");

	r = CreateSection( &NtDLLSection, file, 0, SEC_IMAGE, PAGE_EXECUTE_READWRITE );
	if (r < STATUS_SUCCESS)
		Die("failed to create ntdll section\n");

	KiIntSystemCall = GetProcAddress( NtDLLSection, "KiIntSystemCall" );
	TRACE("KiIntSystemCall = %08lx\n", KiIntSystemCall);
	InitSyscalls(KiIntSystemCall != 0);

	Release( file );

	return r;
}

void FreeNtDLL( void )
{
	Release( NtDLLSection );
	NtDLLSection = NULL;
}

void DoCleanup( void )
{
	int num_threads = 0, num_processes = 0;
	char process_name[1024];

	for ( PROCESS_ITER pi(Processes); pi; pi.Next() )
	{
		PROCESS *p = pi;
		if (p->IsSignalled())
			continue;
		num_processes++;
		fprintf(stderr, "process %04lx ", p->Id);
		if (p->Exe)
		{
			//fprintf(stderr, "%ws\n",  (((PE_SECTION *)(p->Exe))->ImageFileName).Buffer);
			SPrintUnicodeString(process_name, 1024, &(((PE_SECTION *)(p->Exe))->ImageFileName));
			fprintf(stderr, "%s\n", process_name);
		}
		else
			fprintf(stderr, "noname\n");

		for ( SIBLING_ITER ti(p->Threads); ti; ti.Next() )
		{
			THREAD *t = ti;
			if (t->IsSignalled())
				continue;
			fprintf(stderr, "\tthread %04lx\n", t->TraceId());
			num_threads++;
		}
	}
	if (num_threads || num_processes)
		fprintf(stderr, "%d threads %d processes left\n", num_threads, num_processes);
}

static void BacktraceAndQuit()
{
	const int max_frames = 20;
	void *bt[max_frames];
	char **names;
	int n=0, size;
	ULONG pid = 0, tid = 0;

	if (Current)
	{
		tid = Current->GetID();
		pid = Current->Process->Id;
	}

	size = backtrace(bt, max_frames);
	names = backtrace_symbols(bt, size);

	fprintf(stderr, "%lx.%lx: caught kernel SEGV (%d frames):\n", pid, tid, size);
	for (n=0; n<size; n++)
	{
		fprintf(stderr, "%d: %s\n", n, names[n]);
	}
	exit(1);
}

static void SegvHandler(int)
{
	BacktraceAndQuit();
}

static void AbortHandler(int)
{
	BacktraceAndQuit();
}

bool InitSkas();
bool InitTt( const char *loader_path );

struct trace_option
{
	const char *name;
	int enabled;
};

trace_option trace_option_list[] =
{
	{ "syscall", false },
	{ "tebshm", false },
	{ "pebshm", false },
	{ "ntshm", false },
	{ "gdishm", false },
	{ "usershm", false },
	{ "csrdebug", false },
	{ "ldrsnaps", false },
	{ "core", false },
	{ 0, false },
};

int& OptionTrace = trace_option_list[0].enabled;

void PrintRegistryDrivers()
{
	int i=0;
	while (registry_list[i].name) {
		printf("%s ", registry_list[i].name);
		i++;
	}
}

void Usage( void )
{
	const char usage[] =
		"Usage: %s [options] [native.exe]\n"
		"Options:\n"
		"  -d,--debug    break into debugger on exceptions\n"
		"  -g,--graphics select screen driver\n"
		"  -h,--help     print this message\n"
		"  -r,--registry select registry driver\n"
		"  -q,--quiet    quiet, suppress debug messages\n"
		"  -t,--trace=<options>    enable tracing\n"
		"  -v,--version  print version\n\n"
		"  smss.exe is started by default\n\n";
	printf( usage, PACKAGE_NAME );

	// list the trace options
	printf("  trace options: ");
	for (int i=0; trace_option_list[i].name; i++)
		printf("%s ", trace_option_list[i].name );
	printf("\n");

	// list the graphics drivers
	printf("  graphics drivers: ");
	ListGraphicsDrivers();
	printf("\n");

	printf("  registry drivers: ");
	PrintRegistryDrivers();
	printf("\n");

	printf("\n");

	exit(0);
}


void Version( void )
{
	const char version[] = "%s\n"
						   "Copyright (C) 2008-2009 Mike McCormack\n"
						   "Licence LGPL\n"
						   "This is free software: you are free to change and redistribute it.\n"
						   "There is NO WARRANTY, to the extent permitted by law.\n\n";
	printf( version, PACKAGE_STRING );
	exit(0);
}

bool TraceIsEnabled( const char *name )
{
	for (int i=0; trace_option_list[i].name; i++)
		if (!strcmp(name, trace_option_list[i].name))
			return trace_option_list[i].enabled;

	return false;
}

void EnableTrace( const char *name )
{
	for (int i=0; trace_option_list[i].name; i++)
	{
		const char *optname = trace_option_list[i].name;
		if ( strcmp( optname, name ))
			continue;
		trace_option_list[i].enabled = true;
		return;
	}

	fprintf(stderr, "unknown trace: %s\n\n", name);
	Usage();
}

void ParseTraceOptions( const char *options )
{
	if (!options)
	{
		EnableTrace( "syscall" );
		return;
	}

	const char *x, *p = options;
	unsigned int len;
	char str[10];
	while (*p)
	{
		x = strchr( p, ',' );
		if (x)
			len = x - p;
		else
			len = strlen( p );

		len = std::min( len, sizeof str );
		memcpy( str, p, len );
		str[len] = 0;
		EnableTrace( str );
		p += len;
		if ( *p == ',')
			p++;
	}
}

bool SetRegistryDriver(const char* arg)
{
	int i = 0;
	while (registry_list[i].name) {
		if (strcmp(registry_list[i].name, arg) == 0)
		{
			if (registry_list[i].create) {
				printf("Creating '%s' registry driver\n", arg);
				Registry = registry_list[i].create();
				return true;
			}
		}
		i++;
	}
	return false;
}

void ParseOptions(int argc, char **argv)
{
	while (1)
	{
		int option_index;
		static struct option long_options[] =
		{
			{"debug", no_argument, NULL, 'd' },
			{"graphics", required_argument, NULL, 'g' },
			{"help", no_argument, NULL, 'h' },
			{"trace", optional_argument, NULL, 't' },
			{"version", no_argument, NULL, 'v' },
			{"registry", required_argument, NULL, 'r'},
			{NULL, 0, 0, 0 },
		};

		int ch = getopt_long(argc, argv, "g:r:dhqt::v?", long_options, &option_index );
		if (ch == -1)
			break;

		switch (ch)
		{
		case 'd':
			option_debug = 1;
			break;
		case 'g':
			if (!SetGraphicsDriver( optarg ))
			{
				fprintf(stderr, "unknown graphics driver %s\n", optarg);
				Usage();
			}
			break;
		case '?':
		case 'h':
			Usage();
			break;
		case 't':
			ParseTraceOptions( optarg );
			break;
		case 'r':
		{
			for (int i=0;registry_list[i].name;i++)
			{
				if (strcmp(registry_list[i].name, optarg) == 0)
				{
					RegistryIndex = i;
					break;
				}
			}
		} break;
		case 'v':
			Version();
		}
	}
}

int main(int argc, char **argv)
{
	CUNICODE_STRING us;
	THREAD *initial_thread = NULL;
	const char *exename;


	ParseOptions( argc, argv );

	if (optind == argc)
	{
		// default to starting smss.exe
		exename = "\\??\\c:\\winnt\\system32\\smss.exe";
	}
	else
	{
		exename = argv[optind];
	}

	// Read debug channels options
	DebugInit();

	// the skas3 patch is deprecated...
	if (0) InitSkas();

	// pass our path so thread tracing can find the client stub
	InitTt( argv[0] );
	if (!pCreateAddressSpace)
		Die("no way to manage address spaces found\n");

	if (!TraceIsEnabled("core"))
	{
		// enable backtraces
		signal(SIGSEGV, SegvHandler);
		signal(SIGABRT, AbortHandler);
	}

	if (RegistryIndex >= 0)
	{
		TRACE("created registry: %s\n",registry_list[RegistryIndex].name);
		Registry = registry_list[RegistryIndex].create();
	}
	else
	{
		TRACE("created registry: xml\n");
		Registry = REGISTRY_XML::Create();
	}

	// quick sanity test
	ALLOCATION_BITMAP::Test();

	// initialize boottime
	SYSTEM_TIME_OF_DAY_INFORMATION dummy;
	GetSystemTimeOfDay( dummy );

	FIBER::FibersInit();
	InitRoot();
	CreateDirectoryObject( (PWSTR) L"\\" );
	CreateDirectoryObject( (PWSTR) L"\\??" );
	CUNICODE_STRING link_name, link_target;
	link_name.Set( L"\\DosDevices" );
	link_target.Copy( L"\\??" );
	CreateSymlink( link_name, link_target );
	CreateDirectoryObject( (PWSTR) L"\\Device" );
	CreateDirectoryObject( (PWSTR) L"\\Device\\MailSlot" );
	CreateDirectoryObject( (PWSTR) L"\\Security" );
	//create_directory_object( (PWSTR) L"\\DosDevices" );
	CreateDirectoryObject( (PWSTR) L"\\BaseNamedObjects" );
	CreateSyncEvent( (PWSTR) L"\\Security\\LSA_AUTHENTICATION_INITIALIZED" );
	CreateSyncEvent( (PWSTR) L"\\SeLsaInitEvent" );
	InitRandom();
	InitPipeDevice();
	// XP
	CreateDirectoryObject( (PWSTR) L"\\KernelObjects" );
	CreateSyncEvent( (PWSTR) L"\\KernelObjects\\CritSecOutOfMemoryEvent" );
	InitDrives();
	InitNtDLL();
	CreateKThread();

	us.Copy( exename );

	int r = CreateInitialProcess( &initial_thread, us );
	if (r < STATUS_SUCCESS)
		Die("create_initial_process() failed (%08x)\n", r);

	// run the main loop
	Schedule();

	NtGdiFini();
	r = initial_thread->Process->ExitStatus;
	//fprintf(stderr, "process exited (%08x)\n", r);
	Release( initial_thread );

	ShutdownKThread();
	DoCleanup();

	FreeRoot();
	FIBER::FibersFinish();
	FreeNtDLL();

	return r;
}
