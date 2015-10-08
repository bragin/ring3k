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

static inline BOOLEAN mem_allocation_type_is_valid(ULONG state)
{
	state &= ~MEM_TOP_DOWN;
	return (state == MEM_RESERVE || state == MEM_COMMIT);
}

static inline BOOLEAN mem_protection_is_valid(ULONG protect)
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

void ADDRESS_SPACE_IMPL::verify()
{
	ULONG total = 0, count = 0;
	BOOLEAN free_blocks = 0, bad_xlate = 0;

	for ( MBLOCK_iter_t i(blocks); i; i.next() )
	{
		MBLOCK *mb = i;

		if ( mb->IsFree() )
			free_blocks++;
		// check xlate entries
		for ( ULONG i=0; i<mb->GetRegionSize(); i+=0x1000 )
			if ( xlate_entry(mb->GetBaseAddress() + i ) != mb )
				bad_xlate++;
		total += mb->GetRegionSize();
		count++;
	}

	ULONG sz = (size_t) highest_address;
	if (free_blocks || bad_xlate)
	{
		trace("invalid VM... %d free blocks %d bad xlate entries\n",
			  free_blocks, bad_xlate);
		for ( MBLOCK_iter_t i(blocks); i; i.next() )
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

void ADDRESS_SPACE_IMPL::destroy()
{
	verify();

	// free all the non-free allocations
	while (blocks.head())
		free_shared( blocks.head() );

	::munmap( xlate, num_pages * sizeof (MBLOCK*) );
}

MBLOCK* ADDRESS_SPACE_IMPL::alloc_guard_block(BYTE *address, ULONG size)
{
	MBLOCK *mb = AllocGuardPages( address, size );
	if (!mb)
		return NULL;
	mb->Reserve( this );
	update_page_translation( mb );
	insert_block( mb );
	return mb;
}

struct ADDRESS_SPACE_IMPL *(*pcreate_address_space)();

ADDRESS_SPACE *create_address_space( BYTE *high )
{
	ADDRESS_SPACE_IMPL *vm;

	vm = pcreate_address_space();
	if (!vm)
		return NULL;

	if (!vm->init(high))
	{
		delete vm;
		return 0;
	}
	return vm;
}

bool ADDRESS_SPACE_IMPL::init(BYTE *high)
{
	const size_t guard_size = 0x10000;

	highest_address = high;
	assert( high > (lowest_address + guard_size) );

	num_pages = ((unsigned long)high)>>12;
	xlate = (MBLOCK**) ::mmap_anon( 0, num_pages * sizeof (MBLOCK*), PROT_READ | PROT_WRITE );
	if (xlate == (MBLOCK**) -1)
		Die("failed to allocate page translation table\n");

	// make sure there's 0x10000 bytes of reserved memory at 0x00000000
	if (!alloc_guard_block( NULL, guard_size ))
		return false;
	if (!alloc_guard_block( highest_address - guard_size, guard_size ))
		return false;

	verify();

	return true;
}

void ADDRESS_SPACE_IMPL::dump()
{
	for ( MBLOCK_iter_t i(blocks); i; i.next() )
	{
		MBLOCK *mb = i;
		mb->Dump();
	}
}

NTSTATUS ADDRESS_SPACE_IMPL::find_free_area( int zero_bits, size_t length, int top_down, BYTE *&base )
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

			if (xlate_entry( base+free_size ))
			{
				MBLOCK *mb = xlate_entry( base+free_size );
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
			if (xlate_entry( base+free_size ))
			{
				MBLOCK *mb = xlate_entry( base+free_size );
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

MBLOCK *ADDRESS_SPACE_IMPL::get_MBLOCK( BYTE *address )
{
	// check requested block is within limits
	if (address >= highest_address)
		return NULL;

	// try using the address translation table
	return xlate_entry( address );
}

// bitmask returned by check_area
#define AREA_VALID 1
#define AREA_FREE 2
#define AREA_CONTIGUOUS 4

ULONG ADDRESS_SPACE_IMPL::check_area( BYTE *address, size_t length )
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

	MBLOCK *mb = xlate_entry(address);

	if (!mb)
		flags |= AREA_FREE;

	flags |= AREA_CONTIGUOUS;
	for (ULONG i=0; i<length && (flags & AREA_CONTIGUOUS); i+=0x1000)
		if (mb != xlate_entry(address + i))
			flags &= ~(AREA_CONTIGUOUS | AREA_FREE);

	return flags;
}

void ADDRESS_SPACE_IMPL::insert_block( MBLOCK *mb )
{
	blocks.append( mb );
}

void ADDRESS_SPACE_IMPL::remove_block( MBLOCK *mb )
{
	assert( mb->IsFree() );
	blocks.unlink( mb );
}

// splits one block into three parts (before, middle, after)
// returns the middle part
MBLOCK *ADDRESS_SPACE_IMPL::split_area( MBLOCK *mb, BYTE *address, size_t length )
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
		update_page_translation( ret );
		insert_block( ret );
	}
	else
		ret = mb;

	if (ret->GetRegionSize() != length)
	{
		MBLOCK *extra = ret->Split( length );
		update_page_translation( extra );
		insert_block( extra );
	}

	return ret;
}

void ADDRESS_SPACE_IMPL::update_page_translation( MBLOCK *mb )
{
	ULONG i;

	for ( i = 0; i<mb->GetRegionSize(); i += 0x1000 )
	{
		if (!mb->IsFree())
			xlate_entry( mb->GetBaseAddress() + i ) = mb;
		else
			xlate_entry( mb->GetBaseAddress() + i ) = NULL;
	}
}

NTSTATUS ADDRESS_SPACE_IMPL::get_mem_region( BYTE *start, size_t length, int state )
{
	verify();

	ULONG flags = check_area( start, length );

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

NTSTATUS ADDRESS_SPACE_IMPL::allocate_virtual_memory( BYTE **start, int zero_bits, size_t length, int state, int prot )
{
	NTSTATUS r;

	r = check_params( *start, zero_bits, length, state, prot );
	if (r < STATUS_SUCCESS)
		return r;

	if (!*start)
	{
		r = find_free_area( zero_bits, length, state&MEM_TOP_DOWN, *start );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = get_mem_region( *start, length, state );
	if (r < STATUS_SUCCESS)
		return r;

	MBLOCK *mb = xlate_entry( *start );
	if (!mb)
	{
		mb = AllocCorePages( *start, length );
		insert_block( mb );
		//xlate_entry( start ) = mb;
	}
	else
	{
		mb = split_area( mb, *start, length );
	}

	assert( mb->IsLinked() );

	assert( *start == mb->GetBaseAddress());
	assert( length == mb->GetRegionSize());

	return set_block_state( mb, state, prot );
}

NTSTATUS ADDRESS_SPACE_IMPL::map_fd( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing )
{
	NTSTATUS r;

	r = check_params( *start, zero_bits, length, state, prot );
	if (r < STATUS_SUCCESS)
		return r;

	if (!*start)
	{
		r = find_free_area( zero_bits, length, state&MEM_TOP_DOWN, *start );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = get_mem_region( *start, length, state );
	if (r < STATUS_SUCCESS)
		return r;

	MBLOCK *mb = xlate_entry( *start );
	if (mb)
		return STATUS_CONFLICTING_ADDRESSES;

	mb = AllocFDPages( *start, length, backing );
	insert_block( mb );
	assert( mb->IsLinked() );

	assert( *start == mb->GetBaseAddress());
	assert( length == mb->GetRegionSize());

	return set_block_state( mb, state, prot );
}


NTSTATUS ADDRESS_SPACE_IMPL::check_params( BYTE *start, int zero_bits, size_t length, int state, int prot )
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

	if (!mem_allocation_type_is_valid(state))
		return STATUS_INVALID_PARAMETER_5;

	if (!mem_protection_is_valid(prot))
		return STATUS_INVALID_PAGE_PROTECTION;

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::set_block_state( MBLOCK *mb, int state, int prot )
{
	if (mb->IsFree())
	{
		mb->Reserve( this );
		update_page_translation( mb );
	}

	if (state & MEM_COMMIT)
	{
		mb->SetProt( prot );
		mb->Commit( this );
	}

	assert( !mb->IsFree() );
	verify();
	//mb->dump();

	return STATUS_SUCCESS;
}

void ADDRESS_SPACE_IMPL::free_shared( MBLOCK *mb )
{
	//mb->dump();
	if (mb->IsCommitted())
		mb->Uncommit( this );

	mb->Unreserve( this );
	update_page_translation( mb );
	remove_block( mb );
	delete mb;
}

NTSTATUS ADDRESS_SPACE_IMPL::free_virtual_memory( void *start, size_t length, ULONG state )
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

	verify();

	mb = get_MBLOCK( addr );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_NO_MEMORY;
	}

	if (mb->GetRegionSize()<length)
		return STATUS_UNABLE_TO_FREE_VM;

	mb = split_area( mb, addr, length );
	if (!mb)
	{
		trace("failed to split area!\n");
		return STATUS_NO_MEMORY;
	}

	free_shared( mb );

	verify();

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::unmap_view( void *start )
{
	BYTE *addr = (BYTE*)start;

	MBLOCK *mb = get_MBLOCK( addr );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_NO_MEMORY;
	}

	// FIXME: should area be split?
	free_shared( mb );

	return STATUS_SUCCESS;
}

NTSTATUS ADDRESS_SPACE_IMPL::query( BYTE *start, MEMORY_BASIC_INFORMATION *info )
{
	MBLOCK *mb;

	mb = get_MBLOCK( start );
	if (!mb)
	{
		trace("no areas found!\n");
		return STATUS_INVALID_PARAMETER;
	}

	return mb->Query( start, info );
}

NTSTATUS ADDRESS_SPACE_IMPL::get_kernel_address( BYTE **address, size_t *len )
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

	mb = xlate_entry( *address );
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

const char *ADDRESS_SPACE_IMPL::get_symbol( BYTE *address )
{
	trace("%p\n", address );
	MBLOCK *mb = get_MBLOCK( address );
	if (!mb)
		return 0;

	// sections aren't continuous.
	//  when pe_section_t::mapit is fixed, fix here too
	//return get_section_symbol( mb->get_section(), address - mb->get_base_address() );

	return get_section_symbol( mb->GetSection(), (ULONG) address );
}

NTSTATUS ADDRESS_SPACE_IMPL::copy_from_user( void *dest, const void *src, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	while (len)
	{
		n = len;
		x = (BYTE*) src;
		r = get_kernel_address( &x, &n );
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

NTSTATUS ADDRESS_SPACE_IMPL::copy_to_user( void *dest, const void *src, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	//trace("%p %p %04x\n", dest, src, len);

	while (len)
	{
		n = len;
		x = (BYTE*)dest;
		r = get_kernel_address( &x, &n );
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

NTSTATUS ADDRESS_SPACE_IMPL::verify_for_write( void *dest, size_t len )
{
	NTSTATUS r = STATUS_SUCCESS;
	size_t n;
	BYTE *x;

	while (len)
	{
		n = len;
		x = (BYTE*) dest;
		r = get_kernel_address( &x, &n );
		if (r < STATUS_SUCCESS)
			break;
		len -= n;
		dest = (BYTE*)dest + n;
	}

	return r;
}

MBLOCK* ADDRESS_SPACE_IMPL::find_block( BYTE *addr )
{
	return get_MBLOCK( addr );
}

bool ADDRESS_SPACE_IMPL::traced_access( void* addr, ULONG Eip )
{
	BYTE* address = (BYTE*) addr;
	MBLOCK* mb = get_MBLOCK( address );
	if (!mb)
		return false;
	return mb->TracedAccess( address, Eip );
}

bool ADDRESS_SPACE_IMPL::set_traced( void* addr, bool traced )
{
	BYTE* address = (BYTE*) addr;
	MBLOCK* mb = get_MBLOCK( address );
	if (!mb)
		return false;
	return mb->SetTraced( this, traced );
}

bool ADDRESS_SPACE_IMPL::set_tracer( BYTE *addr, BLOCK_TRACER& tracer )
{
	// trace it
	MBLOCK* mb = get_MBLOCK( addr );
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
	if (!mem_allocation_type_is_valid(AllocationType))
		return STATUS_INVALID_PARAMETER_5;

	if (!mem_protection_is_valid(Protect))
		return STATUS_INVALID_PAGE_PROTECTION;

	r = copy_from_user( &size, AllocationSize, sizeof (ULONG) );
	if (r)
		return r;

	r = copy_from_user( &addr, BaseAddress, sizeof (PVOID) );
	if (r)
		return r;

	if (ZeroBits == 1 || ZeroBits > 20)
		return STATUS_INVALID_PARAMETER_3;

	r = process_from_handle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	/* round address and size */
	if (size > mem_round_size( size ))
		return STATUS_INVALID_PARAMETER_4;
	size = mem_round_size( size );

	if (addr < mem_round_addr( addr ))
		return STATUS_INVALID_PARAMETER_2;
	addr = mem_round_addr( addr );

	r = process->vm->allocate_virtual_memory( &addr, ZeroBits, size, AllocationType, Protect );

	trace("returns  %p %08lx  %08lx\n", addr, size, r);

	if (r < STATUS_SUCCESS)
		return r;

	r = copy_to_user( AllocationSize, &size, sizeof (ULONG) );
	if (r)
		return r;

	r = copy_to_user( BaseAddress, &addr, sizeof (BYTE*) );

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
		r = copy_from_user( &len, ReturnLength, sizeof len );
		if (r)
			return r;
	}
	else
		len = sizeof info;

	PROCESS *p = 0;
	r = process_from_handle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	r = p->vm->query( (BYTE*) BaseAddress, &info );
	if (r)
		return r;

	if (len >= sizeof info )
		len = sizeof info;
	else
		r = STATUS_INFO_LENGTH_MISMATCH;

	r = copy_to_user( MemoryInformation, &info, len );
	if (r == STATUS_SUCCESS && ReturnLength)
		r = copy_to_user( ReturnLength, &len, sizeof len );

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

	r = process_from_handle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	r = copy_from_user( &addr, BaseAddress, sizeof addr );
	if (r < STATUS_SUCCESS)
		return r;

	r = copy_from_user( &size, NumberOfBytesToProtect, sizeof size );
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

	r = process_from_handle( ProcessHandle, &p );
	if (r < STATUS_SUCCESS)
		return r;

	while (NumberOfBytesToWrite)
	{
		len = NumberOfBytesToWrite;

		src = (BYTE*)Buffer;
		dest = (BYTE*)BaseAddress;

		r = current->process->vm->get_kernel_address( &src, &len );
		if (r < STATUS_SUCCESS)
			break;

		r = p->vm->get_kernel_address( &dest, &len );
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
		r = copy_to_user( NumberOfBytesWritten, &written, sizeof written );

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

	r = process_from_handle( ProcessHandle, &process );
	if (r < STATUS_SUCCESS)
		return r;

	r = copy_from_user( &size, RegionSize, sizeof (ULONG) );
	if (r)
		return r;

	r = copy_from_user( &addr, BaseAddress, sizeof (PVOID) );
	if (r)
		return r;

	/* round address and size */
	if (size > mem_round_size( size ))
		return STATUS_INVALID_PARAMETER_3;
	size = mem_round_size( size );

	if (addr > mem_round_addr( addr ))
		return STATUS_INVALID_PARAMETER_2;
	addr = mem_round_addr( addr );

	r = process->vm->free_virtual_memory( addr, size, FreeType );

	r = copy_from_user( &size, RegionSize, sizeof (ULONG) );
	if (r)
		return r;

	r = copy_from_user( &addr, BaseAddress, sizeof (PVOID) );

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
