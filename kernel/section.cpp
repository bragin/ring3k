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

#include <stdarg.h>
#include <sys/mman.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "ntcall.h"
#include "section.h"
#include "unicode.h"
#include "file.h"

DEFAULT_DEBUG_CHANNEL(section);

#include "object.inl"

SECTION::~SECTION()
{
	munmap( Addr, Len );
	close(FD);
}

int SECTION::GetFD()
{
	return FD;
}

void SECTION::AddRef()
{
	::AddRef( this );
}

void SECTION::Release()
{
	::Release( this );
}

NTSTATUS SECTION::Mapit( ADDRESS_SPACE *vm, BYTE *&addr, ULONG ZeroBits, ULONG State, ULONG prot )
{
	TRACE("anonymous map\n");
	if ((prot&0xff) > (Protect&0xff))
		return STATUS_INVALID_PARAMETER;
	NTSTATUS r = vm->MapFD( &addr, ZeroBits, Len, State, prot, this );
	return r;
}

SECTION::SECTION( int _fd, BYTE *a, size_t l, ULONG attr, ULONG prot ) :
	FD( _fd )
{
	Len = l;
	Addr = a;
	Attributes = attr;
	Protect = prot;
}

NTSTATUS SECTION::Query( SECTION_BASIC_INFORMATION *basic )
{
	basic->BaseAddress = 0; // FIXME
	basic->Attributes = Attributes;
	basic->Size.QuadPart = Len;
	return STATUS_SUCCESS;
}

NTSTATUS SECTION::Query( SECTION_IMAGE_INFORMATION *image )
{
	return STATUS_INVALID_PARAMETER;
}

void* SECTION::GetKernelAddress()
{
	return Addr;
}

const char *SECTION::GetSymbol( ULONG address )
{
	return 0;
}

PE_SECTION::PE_SECTION( int fd, const CUNICODE_STRING &FileName, BYTE *a, size_t l, ULONG attr, ULONG prot ) :
	SECTION(fd, a, l, attr, prot), ImageFileName(FileName)
{
}

PE_SECTION::~PE_SECTION()
{
}

NTSTATUS PE_SECTION::Query( SECTION_IMAGE_INFORMATION *image )
{
	IMAGE_NT_HEADERS *nt = GetNtHeader();

	// FIXME: assumes fixed base address...?
	image->EntryPoint = (BYTE*) nt->OptionalHeader.ImageBase +
						nt->OptionalHeader.AddressOfEntryPoint;
	image->StackZeroBits = 0;
	image->StackReserved = nt->OptionalHeader.SizeOfStackReserve;
	image->StackCommit = nt->OptionalHeader.SizeOfStackCommit;
	image->ImageSubsystem = nt->OptionalHeader.Subsystem;
	image->SubsystemVersionLow = nt->OptionalHeader.MinorSubsystemVersion;
	image->SubsystemVersionHigh = nt->OptionalHeader.MajorSubsystemVersion;
	image->Unknown1 = 0;
	image->ImageCharacteristics = 0x80000000 | nt->FileHeader.Characteristics;
	image->ImageMachineType = 0x10000 | nt->FileHeader.Machine;
	//image->ImageMachineType = 0;
	//info.image.Unknown2[3];

	if (image->StackCommit < 0x4000) image->StackCommit = 0x4000;

	FIXME("Stack reserve size: 0x%lx, Stack commit size: 0x%lx\n", image->StackReserved, image->StackCommit);

	return STATUS_SUCCESS;
}

NTSTATUS CreateSection( OBJECT **obj, CFILE *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect )
{
	SECTION *sec;
	NTSTATUS r = CreateSection( &sec, file, psz, attribs, protect );
	if (r == STATUS_SUCCESS)
		*obj = sec;
	return r;
}

NTSTATUS CreateSection(SECTION **section, CFILE *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect)
{
	SECTION *s;
	BYTE *addr;
	int fd, ofs = 0;
	ULONG len;
	NTSTATUS Status = STATUS_SUCCESS;

	if (file)
	{
		// FIXME: probably better to have a CFILE passed in
		//CFILE *file = dynamic_cast<CFILE*>( obj );
		//if (!file)
			//return STATUS_OBJECT_TYPE_MISMATCH;

		fd = file->GetFD();
		if (fd<0)
			return STATUS_OBJECT_TYPE_MISMATCH;
		fd = dup(fd);

		if (psz)
			len = psz->QuadPart;
		else
		{
			FILE_STANDARD_INFORMATION FileInfo;
			Status = file->QueryInformation(FileInfo);
			if (Status < 0)
			{
				ERR("Error 0x%08x querying file length\n", Status);
				return Status;
			}
			len = FileInfo.EndOfFile.QuadPart;
		}
	}
	else
	{
		if (!psz)
			return STATUS_INVALID_PARAMETER;
		len = psz->QuadPart;
		fd = CreateMappingFD( len );
		ofs = 0;
	}

	len += 0xfff;
	len &= ~0xfff;

	int write_mask = PAGE_READWRITE | PAGE_WRITECOPY /* |
					 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY */;
	int mmap_prot = PROT_READ;
	if (protect & write_mask)
		mmap_prot |= PROT_WRITE;
	addr = (BYTE*) mmap( NULL, len, mmap_prot, MAP_SHARED, fd, ofs );
	if (addr == (BYTE*) -1)
	{
		ERR("map failed!\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (attribs & SEC_IMAGE)
		s = new PE_SECTION( fd, file->GetFileName(), addr, len, attribs, protect );
	else
		s = new SECTION( fd, addr, len, attribs, protect );

	if (!s)
		return STATUS_NO_MEMORY;

	*section = s;

	return Status;
}

IMAGE_NT_HEADERS *PE_SECTION::GetNtHeader()
{
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*) Addr;
	IMAGE_NT_HEADERS *nt;

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	nt = (IMAGE_NT_HEADERS*) ((BYTE*) Addr + dos->e_lfanew);
	if (Len < (dos->e_lfanew + sizeof (*nt)))
		return NULL;

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (nt->FileHeader.SizeOfOptionalHeader != sizeof nt->OptionalHeader)
		return NULL;

	return nt;
}

NTSTATUS Mapit( ADDRESS_SPACE *vm, OBJECT *obj, BYTE *&addr )
{
	SECTION *sec = dynamic_cast<SECTION*>( obj );
	if (!sec)
		return STATUS_OBJECT_TYPE_MISMATCH;
	return sec->Mapit( vm, addr, 0, MEM_COMMIT, PAGE_READONLY );
}

// stub code for inserting into user address space
extern BYTE *RelayCode;
extern ULONG RelayCodeSize;
__asm__ (
	"\n"
".data\n"
".globl " ASM_NAME_PREFIX "RelayCode\n"
ASM_NAME_PREFIX "RelayCode:\n"
".align 4\n"
	"\tpushl %eax\n"			// save registers
	"\tpushl %ecx\n"
	"\tmovl 8(%esp), %ecx\n"	// get the return address
	"\tmovl (%ecx), %ecx\n"
	"\tmovl %ecx, 8(%esp)\n"
	"\tmovl $0x101, %eax\n"
	"\tint $0x2d\n"				// debug call
	"\tpopl %ecx\n"
	"\tpopl %eax\n"
	"\tret\n"
ASM_NAME_PREFIX "relay_code_end:\n"
".align 4\n"
ASM_NAME_PREFIX "RelayCodeSize:\n"
	"\t.long " ASM_NAME_PREFIX "relay_code_end - " ASM_NAME_PREFIX "RelayCode\n"
);

struct __attribute__ ((packed)) relay_stub
{
	BYTE x1; //  0xe8 call target
	ULONG common;
	ULONG target;
};

bool PE_SECTION::AddRelayStub( ADDRESS_SPACE *vm, BYTE *stub_addr, ULONG func, ULONG *user_addr, ULONG thunk_ofs )
{
	IMAGE_NT_HEADERS *nt = GetNtHeader();

	if (!func)
		return true;

	// replace the value in the stub with
	// the address of the function to forward to
	relay_stub stub;
	assert( sizeof stub == 9 );
	stub.x1 = 0xe8; // jump relative
	stub.common = thunk_ofs - 5;
	stub.target = nt->OptionalHeader.ImageBase + func;

	// copy the stub
	//PBYTE stub_addr = p + RelayCodeSize + sizeof stub*i;
	NTSTATUS r = vm->CopyToUser( stub_addr, &stub, sizeof stub );
	if (r < STATUS_SUCCESS)
	{
		ERR("stub copy failed %08lx\n", r);
		return false;
	}

	// write the offset of the stub back to the import table
	ULONG ofs = stub_addr - (PBYTE) nt->OptionalHeader.ImageBase;
	r = vm->CopyToUser( user_addr, &ofs, sizeof ofs );
	if (r < STATUS_SUCCESS)
	{
		ERR("failed to set address %08lx\n", r);
		return false;
	}

	//trace("[%02ld] old = %08lx new = %p\n", i, stub.target, stub_addr);
	return true;
}

// parse the exports table and generate relay code
void PE_SECTION::AddRelay(ADDRESS_SPACE *vm)
{
	IMAGE_DATA_DIRECTORY *export_data_dir;
	IMAGE_EXPORT_DIRECTORY *exp;
	IMAGE_NT_HEADERS *nt;
	ULONG *funcs;
	ULONG i;

	nt = GetNtHeader();

	export_data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	exp = (IMAGE_EXPORT_DIRECTORY*) VirtualAddrToOffset( export_data_dir->VirtualAddress );
	if (!exp)
	{
		ERR("no exports\n");
		return;
	}

	BYTE *p = 0;
	ULONG sz = (exp->NumberOfNames * sizeof (relay_stub) + 0xfff) & ~0xfff;
	TRACE("relay stubs at %p, %08lx\n", p, sz);
	NTSTATUS r = vm->AllocateVirtualMemory( &p, 0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (r < STATUS_SUCCESS)
	{
		Die("anonymous map failed %08lx\n", r);
		return;
	}

	funcs = (DWORD*) VirtualAddrToOffset( exp->AddressOfFunctions );
	if (!funcs)
	{
		Die("VirtualAddrToOffset failed\n");
		return;
	}

	r = vm->CopyToUser( p, RelayCode, RelayCodeSize );
	if (r < STATUS_SUCCESS)
	{
		ERR("relay copy failed %08lx\n", r);
		return;
	}

	//trace("%ld exported functions\n", exp->NumberOfFunctions);
	for (i = 0; i<exp->NumberOfFunctions; i++)
	{
		ULONG *user_addr = (ULONG*) (nt->OptionalHeader.ImageBase + exp->AddressOfFunctions);
		ULONG thunk_ofs = 0 - (RelayCodeSize + sizeof (relay_stub)*i );
		PBYTE stub_addr = p + RelayCodeSize + sizeof (relay_stub)*i;

		if (!AddRelayStub( vm, stub_addr, funcs[i], user_addr + i, thunk_ofs ))
			break;
	}
}

// maybe create a temp File to remap?
NTSTATUS PE_SECTION::Mapit( ADDRESS_SPACE *vm, BYTE *&base, ULONG ZeroBits, ULONG State, ULONG Protect )
{
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;
	IMAGE_SECTION_HEADER *sections;
	int r, sz, i;
	BYTE *p;
	MBLOCK *mb;

	dos = (IMAGE_DOS_HEADER*) Addr;

	nt = GetNtHeader();
	if (!nt)
		return STATUS_UNSUCCESSFUL;

	p = (BYTE*) nt->OptionalHeader.ImageBase;
	TRACE("image at %p\n", p);
	r = vm->AllocateVirtualMemory( &p, ZeroBits, 0x1000, MEM_COMMIT, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
	{
		ERR("map failed\n");
		goto fail;
	}

	// use of MBLOCK here is a bit of a hack
	// should convert this function to create a flat file to map
	mb = vm->FindBlock( p );
	mb->SetSection( this );

	r = vm->CopyToUser( p, Addr, 0x1000 );
	if (r < STATUS_SUCCESS)
		ERR("copy_to_user failed\n");

	sections = (IMAGE_SECTION_HEADER*) (Addr + dos->e_lfanew + sizeof (*nt));

	TRACE("read %d sections, load at %08lx\n",
			  nt->FileHeader.NumberOfSections,
			  nt->OptionalHeader.ImageBase);

	for ( i=0; i<nt->FileHeader.NumberOfSections; i++ )
	{
		TRACE("%-8s %08lx %08lx %08lx %08lx\n",
				  sections[i].Name,
				  sections[i].VirtualAddress,
				  sections[i].PointerToRawData,
				  sections[i].SizeOfRawData,
				  sections[i].Misc.VirtualSize);
		if (sections[i].VirtualAddress == 0)
			Die("virtual address was zero!\n");

		sz = (sections[i].Misc.VirtualSize + 0xfff )& ~0xfff;
		if (!sz)
			continue;

		p = (BYTE*) (nt->OptionalHeader.ImageBase + sections[i].VirtualAddress);
		// FIXME - map sections with correct permissions
		r = vm->AllocateVirtualMemory( &p, 0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (r < STATUS_SUCCESS)
			Die("anonymous map failed %08x\n", r);
		mb = vm->FindBlock( p );
		mb->SetSection( this );

		if (sections[i].SizeOfRawData)
		{
			r = vm->CopyToUser( p, Addr + sections[i].PointerToRawData, sections[i].SizeOfRawData);
			if (r < STATUS_SUCCESS)
				ERR("copy_to_user failed\n");
		}
	}

	//if (option_trace)
		//AddRelay(vm);

	base = (BYTE*) nt->OptionalHeader.ImageBase;
fail:

	return r;
}

void *PE_SECTION::VirtualAddrToOffset( DWORD virtual_ofs )
{
	IMAGE_NT_HEADERS *nt = GetNtHeader();
	IMAGE_SECTION_HEADER *section = (IMAGE_SECTION_HEADER*) &nt[1];
	int i;

	for (i=0; i<nt->FileHeader.NumberOfSections; i++)
	{
		if (section[i].VirtualAddress <= virtual_ofs &&
			(section[i].VirtualAddress + section[i].SizeOfRawData) > virtual_ofs )
		{
			return Addr + (virtual_ofs - section[i].VirtualAddress + section[i].PointerToRawData);
		}
	}
	return NULL;
}

// just to find LdrInitializeThunk
DWORD GetProcAddress( OBJECT *obj, const char *name )
{
	PE_SECTION *sec = dynamic_cast<PE_SECTION*>( obj );
	if (!sec)
		return 0;
	return sec->GetProcAddress( name );
}

IMAGE_EXPORT_DIRECTORY* PE_SECTION::GetExportsTable()
{
	IMAGE_NT_HEADERS* nt = GetNtHeader();
	IMAGE_DATA_DIRECTORY *export_data_dir;

	export_data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	return (IMAGE_EXPORT_DIRECTORY*) VirtualAddrToOffset( export_data_dir->VirtualAddress );
}

DWORD PE_SECTION::GetProcAddress( const char *name )
{
	TRACE("%s\n", name);

	IMAGE_EXPORT_DIRECTORY *exp = GetExportsTable();
	if (!exp)
		return 0;

	DWORD *p = (DWORD*) VirtualAddrToOffset( exp->AddressOfNames );
	if (!p)
		return 0;

	ULONG left = 0, n = 0, right = exp->NumberOfNames - 1;
	int r = -1;
	while ( left <= right )
	{
		n = (left+right)/2;
		char *x = (char*) VirtualAddrToOffset( p[n] );
		//trace("compare %s,%s\n", name, x);
		r = strcmp(name, x);
		if (r == 0)
			break;
		if (r < 0)
			right = n - 1;
		else
			left = n + 1;
	}

	// return the address if we get a match
	if (r != 0)
		return 0;

	assert( n < exp->NumberOfNames );

	return GetProcAddress( n );
}

DWORD PE_SECTION::GetProcAddress( ULONG ordinal )
{
	IMAGE_EXPORT_DIRECTORY *exp = GetExportsTable();

	if (ordinal >= exp->NumberOfFunctions)
		return 0;
	WORD *ords = (WORD*) VirtualAddrToOffset( exp->AddressOfNameOrdinals );
	if (!ords)
		return 0;
	DWORD *funcs = (DWORD*) VirtualAddrToOffset( exp->AddressOfFunctions );
	if (!funcs)
		return 0;
	//trace("returning %ld -> %04x -> %08lx\n", ordinal, ords[ordinal], funcs[ords[ordinal]]);
	return funcs[ords[ordinal]];
}

const char *PE_SECTION::NameOfOrdinal( ULONG ordinal )
{
	IMAGE_EXPORT_DIRECTORY* exp = GetExportsTable();

	DWORD *names = (DWORD*) VirtualAddrToOffset( exp->AddressOfNames );
	if (!names)
		return 0;
	WORD *ords = (WORD*) VirtualAddrToOffset( exp->AddressOfNameOrdinals );
	if (!ords)
		return 0;

	// there's no NumberOfNameOrdinals.  ordinal better be valid...
	for (int i=0; i<0xffff; i++)
		if (ords[i] == ordinal)
			return (char*) VirtualAddrToOffset( names[i] );
	return 0;
}

const char *PE_SECTION::GetSymbol( ULONG address )
{
	IMAGE_EXPORT_DIRECTORY* exp = GetExportsTable();

	// this translation probably should be done in address_space_impl_t::get_symbol
	IMAGE_NT_HEADERS *nt = GetNtHeader();
	address -= nt->OptionalHeader.ImageBase;

	ULONG *funcs = (ULONG*) VirtualAddrToOffset( exp->AddressOfFunctions );
	if (!funcs)
		return 0;

	for (ULONG i=0; i<exp->NumberOfFunctions; i++)
		if (funcs[i] == address)
			return NameOfOrdinal( i );

	return 0;
}

const char *GetSectionSymbol( OBJECT *object, ULONG address )
{
	TRACE("%p %08lx\n", object, address);
	if (!object)
		return 0;
	SECTION *section = dynamic_cast<SECTION*>( object );
	TRACE("%p %08lx\n", section, address);
	return section->GetSymbol( address );
}

void *GetEntryPoint( PROCESS *p )
{
	IMAGE_DOS_HEADER *dos = NULL;
	IMAGE_NT_HEADERS *nt;
	ULONG ofs = 0;
	ULONG entry = 0;
	NTSTATUS r;

	PPEB ppeb = (PPEB) p->PebSection->GetKernelAddress();
	dos = (IMAGE_DOS_HEADER*) ppeb->ImageBaseAddress;

	r = p->Vm->CopyFromUser( &ofs, &dos->e_lfanew, sizeof dos->e_lfanew );
	if (r < STATUS_SUCCESS)
		return NULL;

	nt = (IMAGE_NT_HEADERS*) ((BYTE*) dos + ofs);

	r = p->Vm->CopyFromUser( &entry, &nt->OptionalHeader.AddressOfEntryPoint,
							   sizeof nt->OptionalHeader.AddressOfEntryPoint );
	if (r < STATUS_SUCCESS)
		return NULL;

	return ((BYTE*)dos) + entry;
}

class SECTION_FACTORY : public OBJECT_FACTORY
{
private:
	OBJECT *File;
	PLARGE_INTEGER SectionSize;
	ULONG Attributes;
	ULONG Protect;
public:
	SECTION_FACTORY( OBJECT *_file, PLARGE_INTEGER _SectionSize, ULONG _Attributes, ULONG _Protect );
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

SECTION_FACTORY::SECTION_FACTORY(
	OBJECT *_file,
	PLARGE_INTEGER _SectionSize,
	ULONG _Attributes,
	ULONG _Protect ) :
	File(_file),
	SectionSize( _SectionSize),
	Attributes( _Attributes),
	Protect( _Protect )
{
}

NTSTATUS SECTION_FACTORY::AllocObject(OBJECT** obj)
{
	NTSTATUS r = CreateSection(obj, dynamic_cast<CFILE*>(File), SectionSize, Attributes, Protect);
	if (r < STATUS_SUCCESS)
		return r;
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

#define VALID_SECTION_FLAGS (\
	SEC_BASED | SEC_NO_CHANGE | SEC_FILE | SEC_IMAGE |\
	SEC_VLM | SEC_RESERVE | SEC_COMMIT | SEC_NOCACHE)

NTSTATUS NTAPI NtCreateSection(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER SectionSize,
	ULONG Protect,
	ULONG Attributes,
	HANDLE FileHandle )
{
	NTSTATUS r;
	OBJECT *file = NULL;
	LARGE_INTEGER sz;

	TRACE("%p %08lx %p %p %08lx %08lx %p\n", SectionHandle, DesiredAccess,
		  ObjectAttributes, SectionSize, Protect, Attributes, FileHandle );

	// check there's no bad flags
	if (Attributes & ~VALID_SECTION_FLAGS)
		return STATUS_INVALID_PARAMETER_6;

	switch (Attributes & (SEC_IMAGE|SEC_COMMIT|SEC_RESERVE))
	{
	case SEC_IMAGE:
	case SEC_RESERVE:
	case SEC_COMMIT:
		break;
	default:
		return STATUS_INVALID_PARAMETER_6;
	}

	r = VerifyForWrite( SectionHandle, sizeof *SectionHandle );
	if (r < STATUS_SUCCESS)
		return r;

	// PE sections cannot be written to
	if (Attributes & SEC_IMAGE)
	{
		switch (Protect)
		{
		case PAGE_READONLY:
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
			break;
		default:
			return STATUS_INVALID_PAGE_PROTECTION;
		}

		if (!FileHandle)
			return STATUS_INVALID_FILE_FOR_SECTION;

		r = ObjectFromHandle( file, FileHandle, 0 );
		if (r < STATUS_SUCCESS)
			return r;

		SectionSize = 0;
	}
	else
	{
		switch (Protect)
		{
		case PAGE_READONLY:
		case PAGE_READWRITE:
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
		case PAGE_WRITECOPY:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			break;
		default:
			return STATUS_INVALID_PAGE_PROTECTION;
		}

		if (FileHandle)
		{
			r = ObjectFromHandle( file, FileHandle, 0 );
			if (r < STATUS_SUCCESS)
				return r;
		}
	}

	if (SectionSize)
	{
		r = CopyFromUser( &sz, SectionSize, sizeof sz );
		if (r < STATUS_SUCCESS)
			return r;
		if (sz.QuadPart == 0)
			return STATUS_INVALID_PARAMETER_4;
		SectionSize = &sz;
	}

	SECTION_FACTORY factory( file, SectionSize, Attributes, Protect );
	return factory.Create( SectionHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenSection(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	return NtOpenObject<SECTION>( SectionHandle, DesiredAccess, ObjectAttributes );
}

// pg 108
NTSTATUS NTAPI NtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	ULONG CommitSize,
	PLARGE_INTEGER SectionOffset,
	PULONG ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG AllocationType,
	ULONG Protect )
{
	PROCESS *p = NULL;
	BYTE *addr = NULL;
	NTSTATUS r;

	TRACE("%p %p %p %lu %08lx %p %p %u %08lx %08lx\n",
		  SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
		  SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect );

	r = ProcessFromHandle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	SECTION *section = 0;
	r = ObjectFromHandle( section, SectionHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &addr, BaseAddress, sizeof addr );
	if (r < STATUS_SUCCESS)
		return r;

	if (addr)
		TRACE("requested specific address %p\n", addr);

	r = VerifyForWrite( ViewSize, sizeof *ViewSize );
	if (r < STATUS_SUCCESS)
		return r;

	r = section->Mapit( p->Vm, addr, ZeroBits,
						MEM_COMMIT | (AllocationType&MEM_TOP_DOWN), Protect );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyToUser( BaseAddress, &addr, sizeof addr );

	TRACE("mapped at %p\n", addr);

	return r;
}

NTSTATUS NTAPI NtUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID BaseAddress )
{
	PROCESS *p = NULL;
	NTSTATUS r;

	TRACE("%p %p\n", ProcessHandle, BaseAddress);

	r = ProcessFromHandle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	r = p->Vm->UnmapView( BaseAddress );

	return r;
}

NTSTATUS NTAPI NtQuerySection(
	HANDLE SectionHandle,
	SECTION_INFORMATION_CLASS SectionInformationClass,
	PVOID SectionInformation,
	ULONG SectionInformationLength,
	PULONG ResultLength )
{
	union
	{
		SECTION_BASIC_INFORMATION basic;
		SECTION_IMAGE_INFORMATION image;
	} info;
	NTSTATUS r;
	ULONG len;

	TRACE("%p %u %p %lu %p\n", SectionHandle, SectionInformationClass,
		  SectionInformation, SectionInformationLength, ResultLength );

	SECTION *section = 0;
	r = ObjectFromHandle( section, SectionHandle, SECTION_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	memset( &info, 0, sizeof info );

	switch (SectionInformationClass)
	{
	case SectionBasicInformation:
		len = sizeof info.basic;
		r = section->Query( &info.basic );
		break;

	case SectionImageInformation:
		len = sizeof info.image;
		r = section->Query( &info.image );
		break;

	default:
		FIXME("\n");
		r = STATUS_INVALID_PARAMETER;
	}

	if (r < STATUS_SUCCESS)
		return r;

	if (len > SectionInformationLength)
		return STATUS_BUFFER_TOO_SMALL;

	r = CopyToUser( SectionInformation, &info, len );
	if (r == STATUS_SUCCESS && ResultLength)
		r = CopyToUser( ResultLength, &len, sizeof len );

	return r;
}
