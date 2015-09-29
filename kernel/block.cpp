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

class COREPAGES : public MBLOCK
{
public:
	COREPAGES( BYTE* address, size_t sz, BACKING_STORE* _backing );
	//COREPAGES( BYTE* address, size_t sz );
	virtual int local_map( int prot );
	virtual int remote_map( address_space *vm, ULONG prot );
	virtual MBLOCK *do_split( BYTE *address, size_t size );
	virtual ~COREPAGES();
private:
	BACKING_STORE* backing;
	int core_ofs;
};

COREPAGES::COREPAGES( BYTE* address, size_t sz, BACKING_STORE* _backing ) :
	MBLOCK( address, sz ),
	backing( _backing ),
	core_ofs(0)
{
	backing->addref();
}

int COREPAGES::local_map( int prot )
{
	int fd = backing->get_fd();
	kernel_address = (BYTE*) mmap( NULL, RegionSize, prot, MAP_SHARED, fd, core_ofs );
	if (kernel_address == (BYTE*) -1)
		return -1;
	return 0;
}

int COREPAGES::remote_map( address_space *vm, ULONG prot )
{
	int fd = backing->get_fd();
	int mmap_flags = mmap_flag_from_page_prot( prot );
	return vm->mmap( BaseAddress, RegionSize, mmap_flags, MAP_SHARED | MAP_FIXED, fd, core_ofs );
}

MBLOCK *COREPAGES::do_split( BYTE *address, size_t size )
{
	backing->addref();
	COREPAGES *rest = new COREPAGES( address, size, backing );
	rest->core_ofs = core_ofs + RegionSize - size;
	return rest;
}

COREPAGES::~COREPAGES()
{
	backing->release();
}

class GUARDPAGES : public MBLOCK
{
protected:
	GUARDPAGES();
public:
	GUARDPAGES( BYTE* address, size_t sz );
	virtual int local_map( int prot );
	virtual int remote_map( address_space *vm, ULONG prot );
	virtual MBLOCK *do_split( BYTE *address, size_t size );
	virtual ~GUARDPAGES();
};

GUARDPAGES::GUARDPAGES( BYTE* address, size_t sz ) :
	MBLOCK( address, sz )
{
}

GUARDPAGES::~GUARDPAGES()
{
}

int GUARDPAGES::local_map( int prot )
{
	return -1;
}

int GUARDPAGES::remote_map( address_space *vm, ULONG prot )
{
	return 0;
}

MBLOCK* GUARDPAGES::do_split( BYTE *address, size_t size )
{
	return new GUARDPAGES( address, size );
}

MBLOCK* alloc_guard_pages(BYTE* address, ULONG size)
{
	return new GUARDPAGES(address, size);
}

int create_mapping_fd( int sz )
{
	static int core_num = 0;

	char name[0x40];
	sprintf(name, "/tmp/win2k-%d", ++core_num);
	int fd = open( name, O_CREAT | O_TRUNC | O_RDWR, 0600 );
	if (fd < 0)
		return -1;

	unlink( name );

	int r = ftruncate( fd, sz );
	if (r < 0)
	{
		close(fd);
		fd = -1;
	}
	return fd;
}

class ANONYMOUS_PAGES: public BACKING_STORE
{
	int fd;
	int refcount;
public:
	ANONYMOUS_PAGES( int _fd ): fd(_fd), refcount(1) {}
	virtual int get_fd()
	{
		return fd;
	}
	virtual void addref()
	{
		refcount++;
	}
	virtual void release()
	{
		if (!--refcount) delete this;
	}
};

MBLOCK* alloc_core_pages(BYTE* address, ULONG size)
{
	int fd = create_mapping_fd( size );
	if (fd < 0)
		return NULL;
	BACKING_STORE* backing = new ANONYMOUS_PAGES( fd );
	MBLOCK *ret = new COREPAGES( address, size, backing );
	backing->release();
	return ret;
}

MBLOCK* alloc_fd_pages(BYTE* address, ULONG size, BACKING_STORE *backing )
{
	return new COREPAGES( address, size, backing );
}

MBLOCK::MBLOCK( BYTE *address, size_t size ) :
	BaseAddress( address ),
	RegionSize( size ),
	State( MEM_FREE ),
	kernel_address( NULL ),
	tracer(0),
	section(0)
{
}

MBLOCK::~MBLOCK()
{
	if (section)
		release( section );
	assert( is_free() );
}

void MBLOCK::dump()
{
	trace("%p %08lx %08lx %08lx %08lx\n", BaseAddress, RegionSize, Protect, State, Type );
}

MBLOCK *MBLOCK::split( size_t target_length )
{
	MBLOCK *ret;

	trace("splitting block\n");

	assert( target_length >= 0x1000);
	assert( !(target_length&0xfff) );

	if (RegionSize == target_length)
		return NULL;

	assert( target_length >= 0 );
	assert( target_length < RegionSize );

	ret = do_split( BaseAddress + target_length, RegionSize - target_length );
	if (!ret)
	{
		trace("split failed!\n");
		return NULL;
	}

	RegionSize = target_length;

	ret->State = State;
	ret->Type = Type;
	ret->Protect = Protect;
	if (kernel_address)
		ret->kernel_address = kernel_address + RegionSize;

	assert( !(RegionSize&0xfff) );
	assert( !(ret->RegionSize&0xfff) );
	assert( BaseAddress < ret->BaseAddress );
	assert( (BaseAddress+RegionSize) == ret->BaseAddress );

	return ret;
}

int MBLOCK::local_unmap()
{
	if (kernel_address)
		::munmap( kernel_address, RegionSize );
	kernel_address = 0;
	return 0;
}

int MBLOCK::remote_unmap( address_space *vm )
{
	return vm->munmap( BaseAddress, RegionSize );
}

ULONG MBLOCK::mmap_flag_from_page_prot( ULONG prot )
{
	// calculate the right protections first
	switch (prot)
	{
	case PAGE_EXECUTE:
		return PROT_EXEC;
	case PAGE_EXECUTE_READ:
		return PROT_EXEC | PROT_READ;
	case PAGE_EXECUTE_READWRITE:
		return PROT_EXEC | PROT_READ | PROT_WRITE;
	case PAGE_EXECUTE_WRITECOPY:
		trace("FIXME, PAGE_EXECUTE_WRITECOPY not supported\n");
		return PROT_EXEC | PROT_READ | PROT_WRITE;
	case PAGE_NOACCESS:
		return 0;
	case PAGE_READONLY:
		return PROT_READ;
	case PAGE_READWRITE:
		return PROT_READ | PROT_WRITE;
	case PAGE_WRITECOPY:
		trace("FIXME, PAGE_WRITECOPY not supported\n");
		return PROT_READ | PROT_WRITE;
	}
	trace("shouldn't get here\n");
	return STATUS_INVALID_PAGE_PROTECTION;
}

void MBLOCK::set_prot( ULONG prot )
{
	Protect = prot;
}

void MBLOCK::commit( address_space *vm )
{
	if (State != MEM_COMMIT)
	{
		State = MEM_COMMIT;
		Type = MEM_PRIVATE;

		//trace("committing %p/%p %08lx\n", kernel_address, BaseAddress, RegionSize);
		if (0 > local_map( PROT_READ | PROT_WRITE ) &&
			0 > local_map( PROT_READ ))
			die("couldn't map user memory into kernel %d\n", errno);
	}

	remote_remap( vm, tracer != 0 );
}

void MBLOCK::remote_remap( address_space *vm, bool except )
{
	int r = remote_map( vm, except ? PAGE_NOACCESS : Protect );
	if (0 < r )
		die("remote_map failed\n");
}

bool MBLOCK::set_tracer( address_space *vm, BLOCK_TRACER *bt )
{
	if (!bt->enabled())
		return false;
	assert( (tracer == 0) ^ (bt == 0) );
	tracer = bt;
	remote_remap( vm, tracer != 0 );
	return true;
}

void MBLOCK::reserve( address_space *vm )
{
	assert( State != MEM_COMMIT );
	if (State == MEM_RESERVE)
		return;
	State = MEM_RESERVE;
	Protect = 0;
	Type = MEM_PRIVATE;
	// FIXME: maybe allocate memory here
}

void MBLOCK::uncommit( address_space *vm )
{
	if (State != MEM_COMMIT)
		return;
	remote_unmap( vm );
	local_unmap();
	State = MEM_RESERVE;
	kernel_address = NULL;
}

void MBLOCK::unreserve( address_space *vm )
{
	assert( State != MEM_COMMIT );
	if (State != MEM_RESERVE)
		return;

	/* mark it as unallocated */
	Protect = 0;
	State = MEM_FREE;
	Type = 0;

	// FIXME: free core here?
}

NTSTATUS MBLOCK::query( BYTE *start, MEMORY_BASIC_INFORMATION *info )
{
	info->BaseAddress = (void*)((UINT)start & 0xfffff000);
	info->AllocationBase = BaseAddress;
	info->AllocationProtect = Protect;
	info->RegionSize = RegionSize;
	info->State = State;
	if (State == MEM_RESERVE)
		info->Protect = 0;
	else
		info->Protect = Protect;
	info->Type = Type;

	return STATUS_SUCCESS;
}

bool MBLOCK::traced_access( BYTE *address, ULONG Eip )
{
	if (!tracer)
		return false;
	tracer->on_access( this, address, Eip );
	return true;
}

bool MBLOCK::set_traced( address_space *vm, bool traced )
{
	if (!tracer)
		return false;
	remote_remap( vm, traced );
	return true;
}

void MBLOCK::set_section( object_t *s )
{
	if (section)
		release( section );
	section = s;
	addref( section );
}

void BLOCK_TRACER::on_access( MBLOCK *mb, BYTE *address, ULONG Eip )
{
	fprintf(stderr, "%04lx: accessed %p from %08lx\n",
			current->trace_id(), address, Eip );
}

bool BLOCK_TRACER::enabled() const
{
	return option_trace;
}

BLOCK_TRACER::~BLOCK_TRACER()
{
}
