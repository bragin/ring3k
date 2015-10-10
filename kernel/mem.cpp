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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "mem.h"
#include "ntcall.h"
#include "list.h"
#include "platform.h"

#define MAX_CORE_MEMORY 0x10000000

static inline BOOLEAN MemAllocationTypeIsValid(ULONG state)
{
	state &= ~MEM_TOP_DOWN;
	return (state == MEM_RESERVE || state == MEM_COMMIT);
}

static inline BOOLEAN MemProtectionIsValid(ULONG protect)
{
	switch (protect)
	{
	case PAGE_EXECUTE:
		break;
	case PAGE_EXECUTE_READ:
		break;
	case PAGE_EXECUTE_READWRITE:
		break;
	case PAGE_EXECUTE_WRITECOPY:
		break;
	case PAGE_NOACCESS:
		break;
	case PAGE_READONLY:
		break;
	case PAGE_READWRITE:
		break;
	case PAGE_WRITECOPY:
		break;
	default:
		return 0;
	}
	return 1;
}

void ADDRESS_SPACE_IMPL::Verify()
{
	ULONG total = 0, count = 0;
	BOOLEAN free_blocks = 0, bad_xlate = 0;

	for ( MBLOCK_ITER i(blocks); i; i.Next() )
	{
		MBLOCK *mb = i;

		if ( mb->IsFree() )
			free_blocks++;
		// check xlate entries
		for ( ULONG i=0; i<mb->GetRegionSize(); i+=0x1000 )
			if ( XlateEntry(mb->GetBaseAddress() + i ) != mb )
				bad_xlate++;
		total += mb->GetRegionSize();
		count++;
	}

	ULONG sz = (size_t) highest_address;
	if (free_blocks || bad_xlate)
	{
		trace("invalid VM... %d free blocks %d bad xlate entries\n",
			  free_blocks, bad_xlate);
		for ( MBLOCK_ITER i(blocks); i; i.Next() )
		{
			MBLOCK *mb = i;
			mb->Dump();
		}
		trace("total %08lx in %ld allocations, %08lx\n", total, count, sz);
	}

	assert( free_blocks == 0 );
	assert( bad_xlate == 0 );
	assert( total < sz );
}

ADDRESS_SPACE_IMPL::ADDRESS_SPACE_IMPL() :
	lowest_address(0),
	highest_address(0)
{
}

ADDRESS_SPACE::~ADDRESS_SPACE()
{
}

ADDRESS_SPACE_IMPL::~ADDRESS_SPACE_IMPL()
{
}

void ADDRESS_SPACE_IMPL::Destroy()
{
	Verify();

	// free all the non-free allocations
	while (blocks.Head())
		FreeShared( blocks.Head() );

	::munmap( xlate, num_pages * sizeof (MBLOCK*) );
}

MBLOCK* ADDRESS_SPACE_IMPL::AllocGuardBlock(BYTE *address, ULONG size)
{
	MBLOCK *mb = AllocGuardPages( address, size );
	if (!mb)
		return NULL;
	mb->Reserve( this );
	UpdatePageTranslation( mb );
	InsertBlock( mb );
	return mb;
}

struct ADDRESS_SPACE_IMPL *(*pCreateAddressSpace)();

ADDRESS_SPACE *CreateAddressSpace( BYTE *high )
{
	ADDRESS_SPACE_IMPL *vm;

	vm = pCreateAddressSpace();
	if (!vm)
		return NULL;

	if (!vm->Init(high))
	{
		delete vm;
		return 0;
	}
	return vm;
}

bool ADDRESS_SPACE_IMPL::Init(BYTE *high)
{
	const size_t guard_size = 0x10000;

	highest_address = high;
	assert( high > (lowest_address + guard_size) );

	num_pages = ((unsigned long)high)>>12;
	xlate = (MBLOCK**) ::MmapAnon( 0, num_pages * sizeof (MBLOCK*), PROT_READ | PROT_WRITE );
	if (xlate == (MBLOCK**) -1)
		Die("failed to allocate page translation table\n");

	// make sure there's 0x10000 bytes of reserved memory at 0x00000000
	if (!AllocGuardBlock( NULL, guard_size ))
		return false;
	if (!AllocGuardBlock( highest_address - guard_size, guard_size ))
		return false;

	Verify();

	return true;
}

void ADDRESS_SPACE_IMPL::Dump()
{
	for ( MBLOCK_ITER i(blocks); i; i.Next() )
	{
		MBLOCK *mb = i;
		mb->Dump();
	}
}

NTSTATUS ADDRESS_SPACE_IMPL::FindFreeArea( int zero_bits, size_t length, int top_down, BYTE *&base )
{
	ULONG free_size;

	//trace("%08x\n", length);
	length = (length + 0xfff) & ~0xfff;

	free_size = 0;
	if (!top_down)
	{
		base = lowest_address;
		while (free_size < length)
		{
			if ((base+free_size) >= highest_address)
				return STATUS_NO_MEMORY;

			if (XlateEntry( base+free_size ))
			{
				MBLOCK *mb = XlateEntry( base+free_size );
				base = mb->GetBaseAddress() + mb->GetRegionSize();
				free_size = 0;
			}
			else if (((ULONG)base)&0xffff)
				base += 0x1000;
			else
				free_size += 0x1000;
		}
	}
	else
	{
		base = (BYTE*)(((ULONG)highest_address - length)&~0xffff);
		while (free_size < length)
		{
			if ((base+free_size) <= lowest_address)
				return STATUS_NO_MEMORY;
			if (XlateEntry( base+free_size ))
			{
				MBLOCK *mb = XlateEntry( base+free_size );
				base = mb->GetBaseAddress() - length;
				free_size = 0;
			}
			else if (((ULONG)base)&0xffff)
				base -= 0x1000;
			else
				free_size += 0x1000;
		}
	}
	return STATUS_SUCCESS;
}

MBLOCK *ADDRESS_SPACE_IMPL::GetMBLOCK( BYTE *address )
{
	// check requested block is within limits
	if (address >= highest_address)
		return NULL;

	// try using the address translation table
	return XlateEntry( address );
}

// bitmask returned by check_area
#define AREA_VALID 1
#define AREA_FREE 2
#define AREA_CONTIGUOUS 4

ULONG ADDRESS_SPACE_IMPL::CheckArea( BYTE *address, size_t length )
{
	ULONG flags = 0;

	// check requested block is within limits
	if (address >= highest_address)
		return flags;
	if (address+length > highest_address)
		return flags;
	if (!length)
		return flags;

	flags |= AREA_VALID;

	MBLOCK *mb = XlateEntry(address);

	if (!mb)
		flags |= AREA_FREE;

	flags |= AREA_CONTIGUOUS;
	for (ULONG i=0; i<length && (flags & AREA_CONTIGUOUS); i+=0x1000)
		if (mb != XlateEntry(address + i))
			flags &= ~(AREA_CONTIGUOUS | AREA_FREE);

	return flags;
}

void ADDRESS_SPACE_IMPL::InsertBlock( MBLOCK *mb )
{
	blocks.Append( mb );
}

void ADDRESS_SPACE_IMPL::RemoveBlock( MBLOCK *mb )
{
	assert( mb->IsFree() );
	blocks.Unlink( mb );
}

// splits one block into three parts (before, middle, after)
// returns the middle part
MBLOCK *ADDRESS_SPACE_IMPL::SplitArea( MBLOCK *mb, BYTE *address, size_t length )
{
	MBLOCK *ret;

	assert( length >= 0x1000);
	assert( !(length&0xfff) );
	assert( !(((int)address)&0xfff) );

	assert( mb->GetBaseAddress() <= address );
	assert( (mb->GetBaseAddress() + mb->GetRegionSize()) >= address );

	if (mb->GetBaseAddress() != address)
	{
		ret = mb->Split( address - mb->GetBaseAddress() );
		UpdatePageTranslation( ret );
		InsertBlock( ret );
	}
	else
		ret = mb;

	if (ret->GetRegionSize() != length)
	{
		MBLOCK *extra = ret->Split( length );
		UpdatePageTranslation( extra );
		InsertBlock( extra );
	}

	return ret;
}

void ADDRESS_SPACE_IMPL::UpdatePageTranslation( MBLOCK *mb )
{
	ULONG i;

	for ( i = 0; i<mb->GetRegionSize(); i += 0x1000 )
	{
		if (!mb->IsFree())
			XlateEntry( mb->GetBaseAddress() + i ) = mb;
		else
			XlateEntry( mb->GetBaseAddress() + i ) = NULL;
	}
}

NTSTATUS ADDRESS_SPACE_IMPL::GetMemRegion( BYTE *start, size_t length, int state )
{
	Verify();

	ULONG flags = CheckArea( start, length );

	if (!(flags & AREA_VALID))
	{
		trace("area not found\n");
		return STATUS_NO_MEMORY;
	}

	if ((state & MEM_RESERVE) && !(flags & AREA_FREE))
	{
		trace("memory not free\n");
		return STATUS_CONFLICTING_ADDRESSES;
	}

	/* check the size again */
	if (!(flags & AREA_CONTIGUOUS))
		return STATUS_CONFLICTING_ADDRESSES;

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::AllocateVirtualMemory( BYTE **start, int zero_bits, size_t length, int state, int prot )
{
	NTSTATUS r;

	r = CheckParams( *start, zero_bits, length, state, prot );
	if (r < STATUS_SUCCESS)
		return r;

	if (!*start)
	{
		r = FindFreeArea( zero_bits, length, state&MEM_TOP_DOWN, *start );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = GetMemRegion( *start, length, state );
	if (r < STATUS_SUCCESS)
		return r;

	MBLOCK *mb = XlateEntry( *start );
	if (!mb)
	{
		mb = AllocCorePages( *start, length );
		InsertBlock( mb );
		//xlate_entry( start ) = mb;
	}
	else
	{
		mb = SplitArea( mb, *start, length );
	}

	assert( mb->IsLinked() );

	assert( *start == mb->GetBaseAddress());
	assert( length == mb->GetRegionSize());

	return SetBlockState( mb, state, prot );
}

NTSTATUS ADDRESS_SPACE_IMPL::MapFD( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing )
{
	NTSTATUS r;

	r = CheckParams( *start, zero_bits, length, state, prot );
	if (r < STATUS_SUCCESS)
		return r;

	if (!*start)
	{
		r = FindFreeArea( zero_bits, length, state&MEM_TOP_DOWN, *start );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = GetMemRegion( *start, length, state );
	if (r < STATUS_SUCCESS)
		return r;

	MBLOCK *mb = XlateEntry( *start );
	if (mb)
		return STATUS_CONFLICTING_ADDRESSES;

	mb = AllocFDPages( *start, length, backing );
	InsertBlock( mb );
	assert( mb->IsLinked() );

	assert( *start == mb->GetBaseAddress());
	assert( length == mb->GetRegionSize());

	return SetBlockState( mb, state, prot );
}


NTSTATUS ADDRESS_SPACE_IMPL::CheckParams( BYTE *start, int zero_bits, size_t length, int state, int prot )
{
	//trace("%p %08x %08x\n", *start, length, prot);

	if (length == 0)
		return STATUS_MEMORY_NOT_ALLOCATED;

	assert( !(length & 0xfff) );

	// sanity checking
	if (length > (size_t)highest_address)
		return STATUS_INVALID_PARAMETER_2;

	if (start > highest_address)
		return STATUS_INVALID_PARAMETER_2;

	if (!MemAllocationTypeIsValid(state))
		return STATUS_INVALID_PARAMETER_5;

	if (!MemProtectionIsValid(prot))
		return STATUS_INVALID_PAGE_PROTECTION;

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::SetBlockState( MBLOCK *mb, int state, int prot )
{
	if (mb->IsFree())
	{
		mb->Reserve( this );
		UpdatePageTranslation( mb );
	}

	if (state & MEM_COMMIT)
	{
		mb->SetProt( prot );
		mb->Commit( this );
	}

	assert( !mb->IsFree() );
	Verify();
	//mb->dump();

	return STATUS_SUCCESS;
}

void ADDRESS_SPACE_IMPL::FreeShared( MBLOCK *mb )
{
	//mb->dump();
	if (mb->IsCommitted())
		mb->Uncommit( this );

	mb->Unreserve( this );
	UpdatePageTranslation( mb );
	RemoveBlock( mb );
	delete mb;
}

NTSTATUS ADDRESS_SPACE_IMPL::FreeVirtualMemory( void *start, size_t length, ULONG state )
{
	BYTE *addr;
	MBLOCK *mb;

	//trace("%p %08x %08lx\n", start, length, state);

	assert( !(length & 0xfff) );
	assert( !(((int)start)&0xfff) );

	if (!start)
		return STATUS_INVALID_PARAMETER;

	if (length > (size_t)highest_address)
		return STATUS_INVALID_PARAMETER_2;

	if (!length)
		return STATUS_INVALID_PARAMETER_2;

	addr = (BYTE*)start;
	if (addr > highest_address)
		return STATUS_INVALID_PARAMETER_2;

	Verify();

	mb = GetMBLOCK( addr );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_NO_MEMORY;
	}

	if (mb->GetRegionSize()<length)
		return STATUS_UNABLE_TO_FREE_VM;

	mb = SplitArea( mb, addr, length );
	if (!mb)
	{
		trace("failed to split area!\n");
		return STATUS_NO_MEMORY;
	}

	FreeShared( mb );

	Verify();

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::UnmapView( void *start )
{
	BYTE *addr = (BYTE*)start;

	MBLOCK *mb = GetMBLOCK( addr );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_NO_MEMORY;
	}

	// FIXME: should area be split?
	FreeShared( mb );

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::Query( BYTE *start, MEMORY_BASIC_INFORMATION *info )
{
	MBLOCK *mb;

	mb = GetMBLOCK( start );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_INVALID_PARAMETER;
	}

	return mb->Query( start, info );
}

NTSTATUS ADDRESS_SPACE_IMPL::GetKernelAddress( BYTE **address, size_t *len )
{
	MBLOCK *mb;
	ULONG ofs;

	//trace("%p %p %u\n", vm, *address, *len);

	if (*address >= highest_address)
		return STATUS_ACCESS_VIOLATION;

	if (*len > (size_t) highest_address)
		return STATUS_ACCESS_VIOLATION;

	if ((*address + *len) > highest_address)
		return STATUS_ACCESS_VIOLATION;

	mb = XlateEntry( *address );
	if (!mb)
		return STATUS_ACCESS_VIOLATION;

	//trace("%p\n", mb);

	assert (mb->GetBaseAddress() <= (*address));
	assert ((mb->GetBaseAddress() + mb->GetRegionSize()) > (*address));

	if (!mb->IsCommitted())
		return STATUS_ACCESS_VIOLATION;

	assert(mb->GetKernelAddress() != NULL);

	ofs = (*address - mb->GetBaseAddress());
	*address = mb->GetKernelAddress() + ofs;

	if ((ofs + *len) > mb->GetRegionSize())
		*len = mb->GetRegionSize() - ofs;

	//trace("copying %04x bytes to %p (size %04lx)\n", *len, *address, mb->get_region_size());
	assert( *len <= mb->GetRegionSize() );

	return STATUS_SUCCESS;
}

const char *ADDRESS_SPACE_IMPL::GetSymbol( BYTE *address )
{
	trace("%p\n", address );
	MBLOCK *mb = GetMBLOCK( address );
	if (!mb)
		return 0;

	// sections aren't continuous.
	//  when pe_section_t::mapit is fixed, fix here too
	//return get_section_symbol( mb->get_section(), address - mb->get_base_address() );

	return GetSectionSymbol( mb->GetSection(), (ULONG) address );
}

NTSTATUS ADDRESS_SPACE_IMPL::CopyFromUser( void *dest, const void *src, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	while (len)
	{
		n = len;
		x = (BYTE*) src;
		r = GetKernelAddress( &x, &n );
		if (r < STATUS_SUCCESS)
			break;
		memcpy( dest, x, n );
		assert( len >= n );
		len -= n;
		src = (BYTE*)src + n;
		dest = (BYTE*)dest + n;
	}

	return r;
}

NTSTATUS ADDRESS_SPACE_IMPL::CopyToUser( void *dest, const void *src, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	//trace("%p %p %04x\n", dest, src, len);

	while (len)
	{
		n = len;
		x = (BYTE*)dest;
		r = GetKernelAddress( &x, &n );
		if (r < STATUS_SUCCESS)
			break;
		//trace("%p %p %u\n", x, src, n);
		memcpy( x, src, n );
		assert( len >= n );
		len -= n;
		src = (BYTE*)src + n;
		dest = (BYTE*)dest + n;
	}

	if (len)
		trace("status %08lx copying to %p\n", r, dest );

	return r;
}

NTSTATUS ADDRESS_SPACE_IMPL::VerifyForWrite( void *dest, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	while (len)
	{
		n = len;
		x = (BYTE*) dest;
		r = GetKernelAddress( &x, &n );
		if (r < STATUS_SUCCESS)
			break;
		len -= n;
		dest = (BYTE*)dest + n;
	}

	return r;
}

MBLOCK* ADDRESS_SPACE_IMPL::FindBlock( BYTE *addr )
{
	return GetMBLOCK( addr );
}

bool ADDRESS_SPACE_IMPL::TracedAccess( void* addr, ULONG Eip )
{
	BYTE* address = (BYTE*) addr;
	MBLOCK* mb = GetMBLOCK( address );
	if (!mb)
		return false;
	return mb->TracedAccess( address, Eip );
}

bool ADDRESS_SPACE_IMPL::SetTraced( void* addr, bool traced )
{
	BYTE* address = (BYTE*) addr;
	MBLOCK* mb = GetMBLOCK( address );
	if (!mb)
		return false;
	return mb->SetTraced( this, traced );
}

bool ADDRESS_SPACE_IMPL::SetTracer( BYTE *addr, BLOCK_TRACER& tracer )
{
	// trace it
	MBLOCK* mb = GetMBLOCK( addr );
	if (!mb)
		return false;
	return mb->SetTracer( this, &tracer );
}

static inline ULONG mem_round_size(ULONG size)
{
	return (size + 0xfff)&~0xfff;
}

static inline BYTE *mem_round_addr(BYTE *addr)
{
	return (BYTE*) (((int)addr)&~0xfff);
}

NTSTATUS NTAPI NtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	OUT PVOID *BaseAddress,
	ULONG ZeroBits,
	OUT PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect)
{
	BYTE *addr = NULL;
	ULONG size = 0;
	NTSTATUS r;
	PROCESS *process;

	//trace("%p %p %lu %p %08lx %08lx\n", ProcessHandle, BaseAddress,
	//		ZeroBits, AllocationSize, AllocationType, Protect);

	/* check for a valid allocation type */
	if (!MemAllocationTypeIsValid(AllocationType))
		return STATUS_INVALID_PARAMETER_5;

	if (!MemProtectionIsValid(Protect))
		return STATUS_INVALID_PAGE_PROTECTION;

	r = CopyFromUser( &size, AllocationSize, sizeof (ULONG) );
	if (r)
		return r;

	r = CopyFromUser( &addr, BaseAddress, sizeof (PVOID) );
	if (r)
		return r;

	if (ZeroBits == 1 || ZeroBits > 20)
		return STATUS_INVALID_PARAMETER_3;

	r = ProcessFromHandle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	/* round address and size */
	if (size > mem_round_size( size ))
		return STATUS_INVALID_PARAMETER_4;
	size = mem_round_size( size );

	if (addr < mem_round_addr( addr ))
		return STATUS_INVALID_PARAMETER_2;
	addr = mem_round_addr( addr );

	r = process->vm->AllocateVirtualMemory( &addr, ZeroBits, size, AllocationType, Protect );

	trace("returns  %p %08lx  %08lx\n", addr, size, r);

	if (r < STATUS_SUCCESS)
		return r;

	r = CopyToUser( AllocationSize, &size, sizeof (ULONG) );
	if (r)
		return r;

	r = CopyToUser( BaseAddress, &addr, sizeof (BYTE*) );

	return r;
}

NTSTATUS NTAPI NtQueryVirtualMemory(
	HANDLE ProcessHandle,
	LPCVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	SIZE_T* ReturnLength )
{
	MEMORY_BASIC_INFORMATION info;
	SIZE_T len;
	NTSTATUS r;

	trace("%p %p %d %p %lu %p\n", ProcessHandle,
		  BaseAddress, MemoryInformationClass, MemoryInformation,
		  MemoryInformationLength, ReturnLength);

	if (MemoryInformationClass != MemoryBasicInformation)
		return STATUS_INVALID_PARAMETER;

	if (ReturnLength)
	{
		r = CopyFromUser( &len, ReturnLength, sizeof len );
		if (r)
			return r;
	}
	else
		len = sizeof info;

	PROCESS *p = 0;
	r = ProcessFromHandle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	r = p->vm->Query( (BYTE*) BaseAddress, &info );
	if (r)
		return r;

	if (len >= sizeof info )
		len = sizeof info;
	else
		r = STATUS_INFO_LENGTH_MISMATCH;

	r = CopyToUser( MemoryInformation, &info, len );
	if (r == STATUS_SUCCESS && ReturnLength)
		r = CopyToUser( ReturnLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection )
{
	PROCESS *process;
	PVOID addr = NULL;
	ULONG size = 0;
	NTSTATUS r;

	trace("%p %p %p %lu %p\n", ProcessHandle, BaseAddress,
		  NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

	r = ProcessFromHandle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &addr, BaseAddress, sizeof addr );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &size, NumberOfBytesToProtect, sizeof size );
	if (r < STATUS_SUCCESS)
		return r;

	trace("%p %08lx\n", addr, size );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten )
{
	size_t len, written = 0;
	BYTE *src, *dest;
	NTSTATUS r = STATUS_SUCCESS;
	PROCESS *p;

	trace("%p %p %p %08lx %p\n", ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );

	r = ProcessFromHandle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	while (NumberOfBytesToWrite)
	{
		len = NumberOfBytesToWrite;

		src = (BYTE*)Buffer;
		dest = (BYTE*)BaseAddress;

		r = Current->process->vm->GetKernelAddress( &src, &len );
		if (r < STATUS_SUCCESS)
			break;

		r = p->vm->GetKernelAddress( &dest, &len );
		if (r < STATUS_SUCCESS)
			break;

		trace("%p <- %p %u\n", dest, src, (unsigned int) len);

		memcpy( dest, src, len );

		Buffer = (BYTE*)Buffer + len;
		BaseAddress = (BYTE*) BaseAddress + len;
		NumberOfBytesToWrite -= len;
		written += len;
	}

	trace("wrote %d bytes\n", (unsigned int) written);

	if (NumberOfBytesWritten)
		r = CopyToUser( NumberOfBytesWritten, &written, sizeof written );

	return r;
}

NTSTATUS NTAPI NtFreeVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG RegionSize,
	ULONG FreeType )
{
	PROCESS *process;
	BYTE *addr = NULL;
	ULONG size = 0;
	NTSTATUS r;

	trace("%p %p %p %lu\n", ProcessHandle, BaseAddress, RegionSize, FreeType);

	switch (FreeType)
	{
	case MEM_DECOMMIT:
	case MEM_FREE:
	case MEM_RELEASE:
		break;
	default:
		return STATUS_INVALID_PARAMETER_4;
	}

	r = ProcessFromHandle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &size, RegionSize, sizeof (ULONG) );
	if (r)
		return r;

	r = CopyFromUser( &addr, BaseAddress, sizeof (PVOID) );
	if (r)
		return r;

	/* round address and size */
	if (size > mem_round_size( size ))
		return STATUS_INVALID_PARAMETER_3;
	size = mem_round_size( size );

	if (addr > mem_round_addr( addr ))
		return STATUS_INVALID_PARAMETER_2;
	addr = mem_round_addr( addr );

	r = process->vm->FreeVirtualMemory( addr, size, FreeType );

	r = CopyFromUser( &size, RegionSize, sizeof (ULONG) );
	if (r)
		return r;

	r = CopyFromUser( &addr, BaseAddress, sizeof (PVOID) );

	trace("returning %08lx\n", r);

	return r;
}

NTSTATUS NTAPI NtAreMappedFilesTheSame(PVOID Address1, PVOID Address2)
{
	trace("%p %p\n", Address1, Address2);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtAllocateUserPhysicalPages(
	HANDLE ProcessHandle,
	PULONG NumberOfPages,
	PULONG PageFrameNumbers)
{
	trace("%p %p %p\n", ProcessHandle, NumberOfPages, PageFrameNumbers);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtFlushVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG FlushSize,
	PIO_STATUS_BLOCK IoStatusBlock)
{
	trace("%p %p %p %p\n", ProcessHandle,
		  BaseAddress, FlushSize, IoStatusBlock);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtLockVirtualMemory(
	HANDLE ProcessHandle,
	PVOID *BaseAddres,
	PULONG Length,
	ULONG LockType)
{
	trace("does nothing\n");
	return STATUS_SUCCESS;
}
