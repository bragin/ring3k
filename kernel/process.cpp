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
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "object.inl"
#include "ntcall.h"
#include "section.h"
#include "timer.h"
#include "file.h"
#include "unicode.h"
#include "win32mgr.h"

// constructs unicode strings suitable for the
// PROCESS_PARAMS_FLAG_NORMALIZED flag in the PPB
static void copy_ustring_to_block( RTL_USER_PROCESS_PARAMETERS* p,
								   UNICODE_STRING *ustr, LPWSTR buffer, LPCWSTR str, ULONG maxlen )
{
	UINT len = strlenW( str );
	assert( len < maxlen );
	strcpyW( buffer, str );
	ustr->Buffer = (WCHAR*)((BYTE*)buffer - (BYTE*) p);
	ustr->Length = len*2;
	ustr->MaximumLength = maxlen*2;
}

struct INITIAL_PPB
{
	RTL_USER_PROCESS_PARAMETERS ppb;
	WCHAR CurrentDirectoryBuffer[MAX_PATH];
	WCHAR DllPathBuffer[MAX_PATH];
	WCHAR ImagePathNameBuffer[MAX_PATH];
	WCHAR CommandLineBuffer[MAX_PATH];
};

NTSTATUS PROCESS::create_parameters(
	RTL_USER_PROCESS_PARAMETERS **pparams, LPCWSTR ImageFile, LPCWSTR DllPath,
	LPCWSTR CurrentDirectory, LPCWSTR CommandLine, LPCWSTR WindowTitle, LPCWSTR Desktop)
{
	static const WCHAR initial_env[] =
	{
		'=',':',':','=',':',':','\\','\0',
		'S','y','s','t','e','m','R','o','o','t','=','C',':','\\','W','I','N','N','T','\0',
		'S','y','s','t','e','m','D','r','i','v','e','=','C',':','\0', 0
	};
	INITIAL_PPB init_ppb;
	RTL_USER_PROCESS_PARAMETERS *ppb, *p = &init_ppb.ppb;;
	LPWSTR penv;
	NTSTATUS r;

	assert( PAGE_SIZE >= sizeof init_ppb );

	memset( &init_ppb, 0, sizeof init_ppb );

	p->AllocationSize = PAGE_SIZE;
	p->Size = PAGE_SIZE;
	p->Flags = 0;  //PROCESS_PARAMS_FLAG_NORMALIZED;

	// PROCESS_PARAMS_FLAG_NORMALIZED indicates that pointer offsets
	// are relative to null.  If it's missing, offsets are relative
	// to the base of the block.
	// See RtlNormalizeProcessParams and RtlDeNormalizeProcessParams

	copy_ustring_to_block( p, &p->ImagePathName,
						   init_ppb.ImagePathNameBuffer, ImageFile, MAX_PATH );
	copy_ustring_to_block( p, &p->DllPath,
						   init_ppb.DllPathBuffer, DllPath, MAX_PATH );
	copy_ustring_to_block( p, &p->CurrentDirectory.DosPath,
						   init_ppb.CurrentDirectoryBuffer, CurrentDirectory, MAX_PATH );
	copy_ustring_to_block( p, &p->CommandLine,
						   init_ppb.CommandLineBuffer, CommandLine, MAX_PATH );

	// process parameters block
	ppb = NULL;
	r = vm->allocate_virtual_memory( (BYTE**) &ppb, 0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		die("address_space_mmap failed\n");

	// allocate the initial environment
	penv = NULL;
	r = vm->allocate_virtual_memory( (BYTE**) &penv, 0, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		die("address_space_mmap failed\n");

	// write the initial environment
	vm->copy_to_user( penv, initial_env, sizeof initial_env );

	// write the address of the environment string into the PPB
	p->Environment = penv;

	vm->copy_to_user( ppb, p, sizeof init_ppb );

	// write the address of the process parameters into the PEB
	*pparams = ppb;

	return 0;
}

/*
 * map a file (the locale data) into a process's memory
 */
NTSTATUS map_locale_data( ADDRESS_SPACE *vm, const char *name, void **addr )
{
	OBJECT *section = 0;
	CFILE *file = 0;
	NTSTATUS r;
	BYTE *data = 0;
	unicode_string_t us;
	char path[0x100];

	strcpy( path, "\\??\\c:\\winnt\\system32\\" );
	strcat( path, name );
	us.copy( path );

	r = open_file( file, us );
	if (r < STATUS_SUCCESS)
		die("locale data %s missing from system directory (%08lx)\n", name, r);

	r = create_section( &section, file, 0, SEC_FILE, PAGE_EXECUTE_READWRITE );
	release( file );
	if (r < STATUS_SUCCESS)
		die("failed to create section for locale data\n");

	r = mapit( vm, section, data );
	if (r < STATUS_SUCCESS)
		die("failed to map locale data (%08lx)\n", r);

	*addr = (void*) data;
	trace("locale data %s at %p\n", name, data);

	return STATUS_SUCCESS;
}

section_t *shared_section;
KUSER_SHARED_DATA *shared_memory_address;

class kshm_tracer : public BLOCK_TRACER
{
public:
	virtual void on_access( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool enabled() const;
};

bool kshm_tracer::enabled() const
{
	// disable this, as it's noisy
	return false;
}

void kshm_tracer::on_access( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->get_base_address();
	const char *field = "";

	if (ofs >= 0x30 && ofs <= 0x130)
	{
		field = " (SystemRoot) ";
	}
	else if (ofs >= 0x274 && ofs <= (0x274+0x40))
	{
		field = " (ProcessorFeatures)";
	}
	else switch (ofs)
	{
#define kshmfield(ofs,x) case ofs: field = " (" #x ")"; break;
		kshmfield(0x0264,NtProductType);
		kshmfield(0x0268,ProductTypeIsValid);
		kshmfield(0x02d0,KdDebuggerEnabled);
#undef kshmfield
	}

	fprintf(stderr, "%04lx: accessed kshm[%04lx]%s from %08lx\n",
			current->trace_id(), ofs, field, eip);
}

kshm_tracer kshm_trace;

NTSTATUS get_shared_memory_block( PROCESS *p )
{
	BYTE *shm = NULL;
	NTSTATUS r;
	WCHAR ntdir[] = { 'C',':','\\','W','I','N','N','T',0 };

	if (!shared_section)
	{
		LARGE_INTEGER sz;
		sz.QuadPart = 0x10000;
		r = create_section( &shared_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;

		// set the nt directory
		shared_memory_address = (KUSER_SHARED_DATA*) shared_section->get_kernel_address();
		memcpy( shared_memory_address->WindowsDirectory, ntdir, sizeof ntdir );

		// mark the product type as valid
		shared_memory_address->ProductIsValid = TRUE;
		shared_memory_address->NtProductType = 1;
		shared_memory_address->NtMajorVersion = 5;
		shared_memory_address->NtMinorVersion = 0;
		shared_memory_address->ImageNumberLow = 0x14c;
		shared_memory_address->ImageNumberHigh = 0x14c;

		// Windows XP's ntdll needs the system call address in shared memory
		ULONG kisc = (ULONG) p->pntdll + KiIntSystemCall;
		if (KiIntSystemCall)
			shared_memory_address->SystemCall = kisc;
	}

	r = shared_section->mapit( p->vm, shm, 0, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
		return r;

	p->vm->set_tracer( shm, kshm_trace );

	assert( shm == (BYTE*) 0x7ffe0000 );

	return STATUS_SUCCESS;
}

THREAD *find_thread_by_client_id( CLIENT_ID *id )
{
	for ( process_iter_t i(processes); i; i.next() )
	{
		PROCESS *p = i;
		if (p->id == (ULONG)id->UniqueProcess)
		{
			for ( sibling_iter_t j(p->threads); j; j.next() )
			{
				THREAD *t = j;
				if (t->get_id() == (ULONG)id->UniqueThread)
					return t;
			}
		}
	}

	return 0;
}

PROCESS *find_process_by_id( HANDLE UniqueProcess )
{
	for ( process_iter_t i(processes); i; i.next() )
	{
		PROCESS *p = i;
		if (p->id == (ULONG)UniqueProcess)
			return p;
	}
	return 0;
}

BOOLEAN PROCESS::is_signalled( void )
{
	for ( sibling_iter_t i(threads); i; i.next() )
	{
		THREAD *t = i;
		if (!t->is_terminated())
			return FALSE;
	}

	return TRUE;
}

NTSTATUS process_from_handle( HANDLE handle, PROCESS **process )
{
	return object_from_handle( *process, handle, 0 );
}


ULONG allocate_id()
{
	static ULONG unique_counter;

	return (++unique_counter) << 2;
}

NTSTATUS process_alloc_user_handle(
	PROCESS *p,
	OBJECT *obj,
	ACCESS_MASK access,
	HANDLE *out,
	HANDLE *copy )
{
	HANDLE handle;
	NTSTATUS r;

	handle = p->handle_table.alloc_handle( obj, access );
	if (!handle)
	{
		trace("out of handles?\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	trace("handle = %08lx\n", (ULONG)handle );

	// write the handle into our process's VM
	r = copy_to_user( out, &handle, sizeof handle );
	if (r < STATUS_SUCCESS)
	{
		trace("write to %p failed\n", out);
		p->handle_table.free_handle( handle );
	}

	if (copy)
		*copy = handle;

	return r;
}

NTSTATUS PROCESS::create_exe_ppb( RTL_USER_PROCESS_PARAMETERS **pparams, UNICODE_STRING& name )
{
	WCHAR image[MAX_PATH], cmd[MAX_PATH];
	NTSTATUS r;
	ULONG len;

	len = name.Length/2;
	if (len>4 && !memcmp( (WCHAR*) L"\\??\\", name.Buffer, 8))
	{
		len -= 4;
		memcpy( image, name.Buffer+4, len*2 );
	}
	else
		len = 0;
	image[ len ] = 0;

	strcpyW( cmd, (WCHAR*) L"\"" );
	strcatW( cmd, image );
	strcatW( cmd, (WCHAR*) L"\"" );

	r = create_parameters( pparams, image, (WCHAR*) L"c:\\", (WCHAR*) L"c:\\", cmd, (WCHAR*) L"", (WCHAR*) L"WinSta0\\Default");

	return r;
}

PROCESS::PROCESS() :
	exception_port(0),
	priority(0),
	hard_error_mode(1),
	win32k_info(0),
	window_station(0)
{
	ExitStatus = STATUS_PENDING;
	id = allocate_id();
	memset( &handle_table, 0, sizeof handle_table );
	processes.append( this );
}

PROCESS::~PROCESS()
{
	if (win32k_info)
		delete win32k_info;
	processes.unlink( this );
	exception_port = 0;
}

void PROCESS::terminate( NTSTATUS status )
{
	notify_watchers();
	// now release the process...
	handle_table.free_all_handles();
	if (win32k_info)
		free_user32_handles( this );
	ExitStatus = status;
	delete vm;
	vm = NULL;
	release( exe );
	exe = NULL;
}

class peb_tracer : public BLOCK_TRACER
{
public:
	virtual void on_access( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool enabled() const;
};

bool peb_tracer::enabled() const
{
	// disable this, as it's noisy
	return false;
}

void peb_tracer::on_access( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->get_base_address();
	const char *field = "";

	switch (ofs)
	{
#define pebfield(ofs,x) case ofs: field = " (" #x ")"; break;
		pebfield(0x0c,LdrData);
		pebfield(0x18,ProcessHeap);
		pebfield(0x2c,KernelCallbackTable);
#undef pebfield
	}

	fprintf(stderr, "%04lx: accessed peb[%04lx]%s from %08lx\n",
			current->trace_id(), ofs, field, eip);
}

peb_tracer peb_trace;

NTSTATUS create_process( PROCESS **pprocess, OBJECT *section )
{
	PROCESS *p;
	NTSTATUS r;

	p = new PROCESS();
	if (!p)
		return STATUS_INSUFFICIENT_RESOURCES;

	/* create a new address space */
	// FIXME: determine address space limits from exe
	p->vm = create_address_space( (BYTE*) 0x80000000 );
	if (!p->vm)
		die("create_address_space failed\n");

	addref( section );
	p->exe = section;

	// FIXME: use section->mapit, get rid of mapit(section, ...)
	r = mapit( p->vm, p->exe, p->pexe );
	if (r < STATUS_SUCCESS)
		return r;

	r = mapit( p->vm, ntdll_section, p->pntdll );
	if (r < STATUS_SUCCESS)
		return r;

	/* map the NT shared memory block early, so it gets the right address */
	r = get_shared_memory_block( p );
	if (r < STATUS_SUCCESS)
		return r;

	LARGE_INTEGER sz;
	sz.QuadPart = PAGE_SIZE;
	r = create_section( &p->peb_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	/* reserve the GDI shared section */
	BYTE *gdi_shared = GDI_SHARED_HANDLE_TABLE_ADDRESS;
	ULONG size = GDI_SHARED_HANDLE_TABLE_SIZE;
	r = p->vm->allocate_virtual_memory( &gdi_shared, 0, size, MEM_RESERVE, PAGE_NOACCESS );
	if (r < STATUS_SUCCESS)
		return r;

	/* allocate the PEB */
	BYTE *peb_addr = 0;
	r = p->peb_section->mapit( p->vm, peb_addr, 0, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	p->PebBaseAddress = (void*) peb_addr;
	PPEB ppeb = (PPEB) p->peb_section->get_kernel_address();

	/* map the locale data (for LdrInitializeThunk) */
	map_locale_data( p->vm, "l_intl.nls", &ppeb->UnicodeCaseTableData );
	map_locale_data( p->vm, "c_850.nls", &ppeb->OemCodePageData );
	map_locale_data( p->vm, "c_1252.nls", &ppeb->AnsiCodePageData );

	ppeb->NumberOfProcessors = 1;
	ppeb->ImageBaseAddress = (HINSTANCE) p->pexe;

	// versions for Windows 2000
	ppeb->OSMajorVersion = 5;
	ppeb->OSMinorVersion = 0;
	ppeb->OSBuildNumber = 0x01000893;
	ppeb->OSPlatformId = 2;
	ppeb->NtGlobalFlag = 0;
	if (trace_is_enabled("csrdebug"))
		ppeb->NtGlobalFlag |= FLG_ENABLE_CSRDEBUG;
	if (trace_is_enabled("ldrsnaps"))
		ppeb->NtGlobalFlag |= FLG_SHOW_LDR_SNAPS;

	*pprocess = p;

	p->vm->set_tracer( peb_addr, peb_trace );

	return r;
}

NTSTATUS NTAPI NtCreateProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE InheritFromProcessHandle,
	BOOLEAN InheritHandles,
	HANDLE SectionHandle,
	HANDLE DebugPort,
	HANDLE ExceptionPort )
{
	PROCESS *p = NULL;
	section_t *section = 0;
	NTSTATUS r;

	trace("%p %08lx %p %p %u %p %p %p\n", ProcessHandle, DesiredAccess,
		  ObjectAttributes, InheritFromProcessHandle, InheritHandles,
		  SectionHandle, DebugPort, ExceptionPort );

	r = object_from_handle( section, SectionHandle, SECTION_MAP_EXECUTE );
	if (r < STATUS_SUCCESS)
		return STATUS_INVALID_HANDLE;

	r = create_process( &p, section );
	if (r == STATUS_SUCCESS)
	{
		r = alloc_user_handle( p, DesiredAccess, ProcessHandle );
		release( p );
	}

	return r;
}

NTSTATUS open_process( OBJECT **process, OBJECT_ATTRIBUTES *oa )
{
	OBJECT *obj = NULL;
	PROCESS *p;
	NTSTATUS r;

	r = get_named_object( &obj, oa );
	if (r < STATUS_SUCCESS)
		return r;

	p = dynamic_cast<PROCESS*>( obj );
	if (!p)
	{
		release( obj );
		return STATUS_OBJECT_TYPE_MISMATCH;
	}

	*process = p;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtOpenProcess(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId)
{
	OBJECT_ATTRIBUTES oa;
	unicode_string_t us;
	OBJECT *process = NULL;
	CLIENT_ID id;
	NTSTATUS r;

	trace("%p %08lx %p %p\n", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );

	r = copy_from_user( &oa, ObjectAttributes, sizeof oa );
	if (r < STATUS_SUCCESS)
		return r;

	if (oa.ObjectName)
	{
		r = us.copy_from_user( oa.ObjectName );
		if (r < STATUS_SUCCESS)
			return r;
		oa.ObjectName = &us;
	}

	id.UniqueProcess = 0;
	id.UniqueThread = 0;
	if (ClientId)
	{
		r = copy_from_user( &id, ClientId, sizeof id );
		if (r < STATUS_SUCCESS)
			return r;
	}

	//trace("client id %p %p\n", id.UniqueProcess, id.UniqueThread);

	if (oa.ObjectName == 0)
	{
		//trace("cid\n");
		if (id.UniqueThread)
		{
			THREAD *t = find_thread_by_client_id( &id );
			if (!t)
				return STATUS_INVALID_CID;
			process = t->process;
		}
		else if (id.UniqueProcess)
		{
			process = find_process_by_id( id.UniqueProcess );
			if (!process)
				return STATUS_INVALID_PARAMETER;
				//return STATUS_INVALID_CID;
		}
		else
			return STATUS_INVALID_PARAMETER;
		addref( process );
	}
	else
	{
		//trace("objectname\n");

		if (!oa.ObjectName)
			return STATUS_INVALID_PARAMETER;

		if (ClientId)
			return STATUS_INVALID_PARAMETER_MIX;

		if (oa.Length != sizeof oa)
			return STATUS_INVALID_PARAMETER;

		if (us.Length == 0)
			return STATUS_OBJECT_PATH_SYNTAX_BAD;

		r = open_process( &process, &oa );
	}

	if (r == STATUS_SUCCESS)
	{
		r = alloc_user_handle( process, DesiredAccess, ProcessHandle );
	}
	release( process );

	return r;
}

NTSTATUS NTAPI NtSetInformationProcess(
	HANDLE Process,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength )
{
	PROCESS *p = 0;
	union
	{
		HANDLE port_handle;
		KPRIORITY priority;
		PROCESS_SESSION_INFORMATION session;
		ULONG hard_error_mode;
		BOOLEAN foreground;
		PROCESS_PRIORITY_CLASS priority_class;
		BOOLEAN enable_alignment_fault_fixup;
		ULONG execute_flags;
	} info;
	ULONG sz = 0;

	trace("%p %u %p %lu\n", Process, ProcessInformationClass, ProcessInformation, ProcessInformationLength );

	switch (ProcessInformationClass)
	{
	case ProcessExceptionPort:
		sz = sizeof info.port_handle;
		break;
	case ProcessBasePriority:
		sz = sizeof info.priority;
		break;
	case ProcessSessionInformation:
		sz = sizeof info.session;
		break;
	case ProcessDefaultHardErrorMode:
		sz = sizeof info.hard_error_mode;
		break;
	case ProcessUserModeIOPL:
		sz = 0;
		break;
	case ProcessForegroundInformation:
		sz = sizeof info.foreground;
		break;
	case ProcessPriorityClass:
		sz = sizeof info.priority_class;
		break;
	case ProcessEnableAlignmentFaultFixup:
		sz = sizeof info.enable_alignment_fault_fixup;
		break;
	case ProcessExecuteFlags:
		sz = sizeof info.execute_flags;
		break;
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	NTSTATUS r = process_from_handle( Process, &p );
	if (r < STATUS_SUCCESS)
		return r;

	if (ProcessInformationLength != sz)
		return STATUS_INFO_LENGTH_MISMATCH;

	r = copy_from_user( &info, ProcessInformation, sz );
	if (r < STATUS_SUCCESS)
		return r;

	switch (ProcessInformationClass)
	{
		case ProcessExceptionPort:
		{
			OBJECT *port = 0;
			r = object_from_handle( port, info.port_handle, 0 );
			if (r < STATUS_SUCCESS)
				return r;
			return set_exception_port( p, port );
		}
		case ProcessBasePriority:
			p->priority = info.priority;
			break;

		case ProcessSessionInformation:
		{
			PPEB ppeb = (PPEB) p->peb_section->get_kernel_address();
			ppeb->SessionId = info.session.SessionId;
			break;
		}

		case ProcessForegroundInformation:
			trace("set ProcessForegroundInformation\n");
			break;

		case ProcessPriorityClass:
			trace("set ProcessPriorityClass\n");
			break;

		case ProcessDefaultHardErrorMode:
			p->hard_error_mode = info.hard_error_mode;
			trace("set ProcessDefaultHardErrorMode\n");
			break;

		case ProcessUserModeIOPL:
			trace("set ProcessUserModeIOPL\n");
			break;

		case ProcessEnableAlignmentFaultFixup:
			trace("ProcessEnableAlignmentFaultFixup = %d\n",
				  info.enable_alignment_fault_fixup);
			break;

		case ProcessExecuteFlags:
			trace("setting to %08lx (%s%s%s)\n", info.execute_flags,
				  (info.execute_flags & MEM_EXECUTE_OPTION_DISABLE) ? "disable " : "",
				  (info.execute_flags & MEM_EXECUTE_OPTION_ENABLE) ? "enable " : "",
				  (info.execute_flags & MEM_EXECUTE_OPTION_PERMANENT) ? "permanent" : "");
			p->execute_flags = info.execute_flags;
			break;

		default:
			trace("unimplemented class %d\n", ProcessInformationClass);
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryInformationProcess(
	HANDLE Process,
	PROCESS_INFORMATION_CLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength )
{
	union
	{
		PROCESS_BASIC_INFORMATION basic;
		PROCESS_DEVICEMAP_INFORMATION device_map;
		PROCESS_SESSION_INFORMATION session;
		ULONG hard_error_mode;
		ULONG execute_flags;
	} info;
	ULONG len, sz = 0;
	NTSTATUS r;
	PROCESS *p;

	trace("%p %u %p %lu %p\n", Process, ProcessInformationClass,
		  ProcessInformation, ProcessInformationLength, ReturnLength );

	switch (ProcessInformationClass)
	{
		case ProcessBasicInformation:
			sz = sizeof info.basic;
			break;

		case ProcessDeviceMap:
			sz = sizeof info.device_map;
			break;

		case ProcessSessionInformation:
			sz = sizeof info.session;
			break;

		case ProcessDefaultHardErrorMode:
			sz = sizeof info.hard_error_mode;
			break;

		case ProcessExecuteFlags:
			sz = sizeof info.execute_flags;
			break;

		case ProcessExceptionPort:
			return STATUS_INVALID_INFO_CLASS;

		default:
			trace("info class %d\n", ProcessInformationClass);
			return STATUS_INVALID_INFO_CLASS;
	}

	memset( &info, 0, sizeof info );

	r = process_from_handle( Process, &p );
	if (r < STATUS_SUCCESS)
		return r;

	switch (ProcessInformationClass)
	{
		case ProcessBasicInformation:
			info.basic.ExitStatus = p->ExitStatus;
			info.basic.PebBaseAddress = (PPEB)p->PebBaseAddress;
			info.basic.UniqueProcessId = p->id;
			break;

		case ProcessDeviceMap:
			info.device_map.Query.DriveMap = 0x00000004;
			info.device_map.Query.DriveType[2] = DRIVE_FIXED;
			break;

		case ProcessSessionInformation:
		{
			PPEB ppeb = (PPEB) p->peb_section->get_kernel_address();
			info.session.SessionId = ppeb->SessionId;
			break;
		}

		case ProcessDefaultHardErrorMode:
			info.hard_error_mode = p->hard_error_mode;
			break;

		case ProcessExecuteFlags:
			info.execute_flags = p->execute_flags;
			break;

		default:
			assert(0);
	}

	len = sz;
	if (sz > ProcessInformationLength)
		sz = ProcessInformationLength;

	r = copy_to_user( ProcessInformation, &info, sz );
	if (r == STATUS_SUCCESS && ReturnLength)
		r = copy_to_user( ReturnLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtTerminateProcess(
	HANDLE Process,
	NTSTATUS Status)
{
	PROCESS *p;
	NTSTATUS r;

	trace("%p %08lx\n", Process, Status);

	if (Process == 0)
	{
		trace("called with Process=0\n");
		return STATUS_SUCCESS;
	}

	r = process_from_handle( Process, &p );
	if (r < STATUS_SUCCESS)
		return r;

	sibling_iter_t i(p->threads);
	while ( i )
	{
		THREAD *t = i;
		i.next();
		t->terminate( Status );
	}

	return STATUS_SUCCESS;
}
