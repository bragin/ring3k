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

class COREPAGES : public MBLOCK
{
public:
	COREPAGES( BYTE* address, size_t sz, BACKING_STORE* _backing );
	//COREPAGES( BYTE* address, size_t sz );
	virtual int LocalMap( int prot );
	virtual int RemoteMap( ADDRESS_SPACE *vm, ULONG prot );
	virtual MBLOCK *DoSplit( BYTE *address, size_t size );
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
	backing->AddRef();
}

int COREPAGES::LocalMap( int prot )
{
	int fd = backing->GetFD();
	KernelAddress = (BYTE*) mmap( NULL, RegionSize, prot, MAP_SHARED, fd, core_ofs );
	if (KernelAddress == (BYTE*) -1)
		return -1;
	return 0;
}

int COREPAGES::RemoteMap( ADDRESS_SPACE *vm, ULONG prot )
{
	int fd = backing->GetFD();
	int mmap_flags = MmapFlagFromPageProt( prot );
	return vm->Mmap( BaseAddress, RegionSize, mmap_flags, MAP_SHARED | MAP_FIXED, fd, core_ofs );
}

MBLOCK *COREPAGES::DoSplit( BYTE *address, size_t size )
{
	backing->AddRef();
	COREPAGES *rest = new COREPAGES( address, size, backing );
	rest->core_ofs = core_ofs + RegionSize - size;
	return rest;
}

COREPAGES::~COREPAGES()
{
	backing->Release();
}

class GUARDPAGES : public MBLOCK
{
protected:
	GUARDPAGES();
public:
	GUARDPAGES( BYTE* address, size_t sz );
	virtual int LocalMap( int prot );
	virtual int RemoteMap( ADDRESS_SPACE *vm, ULONG prot );
	virtual MBLOCK *DoSplit( BYTE *address, size_t size );
	virtual ~GUARDPAGES();
};

GUARDPAGES::GUARDPAGES( BYTE* address, size_t sz ) :
	MBLOCK( address, sz )
{
}

GUARDPAGES::~GUARDPAGES()
{
}

int GUARDPAGES::LocalMap( int prot )
{
	return -1;
}

int GUARDPAGES::RemoteMap( ADDRESS_SPACE *vm, ULONG prot )
{
	return 0;
}

MBLOCK* GUARDPAGES::DoSplit( BYTE *address, size_t size )
{
	return new GUARDPAGES( address, size );
}

MBLOCK* AllocGuardPages(BYTE* address, ULONG size)
{
	return new GUARDPAGES(address, size);
}

int CreateMappingFD( int sz )
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
	virtual int GetFD()
	{
		return fd;
	}
	virtual void AddRef()
	{
		refcount++;
	}
	virtual void Release()
	{
		if (!--refcount) delete this;
	}
};

MBLOCK* AllocCorePages(BYTE* address, ULONG size)
{
	int fd = CreateMappingFD( size );
	if (fd < 0)
		return NULL;
	BACKING_STORE* backing = new ANONYMOUS_PAGES( fd );
	MBLOCK *ret = new COREPAGES( address, size, backing );
	backing->Release();
	return ret;
}

MBLOCK* AllocFDPages(BYTE* address, ULONG size, BACKING_STORE *backing )
{
	return new COREPAGES( address, size, backing );
}

MBLOCK::MBLOCK( BYTE *address, size_t size ) :
	BaseAddress( address ),
	RegionSize( size ),
	State( MEM_FREE ),
	KernelAddress( NULL ),
	Tracer(0),
	Section(0)
{
}

MBLOCK::~MBLOCK()
{
	if (Section)
		release( Section );
	assert( IsFree() );
}

void MBLOCK::Dump()
{
	trace("%p %08lx %08lx %08lx %08lx\n", BaseAddress, RegionSize, Protect, State, Type );
}

MBLOCK *MBLOCK::Split( size_t target_length )
{
	MBLOCK *ret;

	trace("splitting block\n");

	assert( target_length >= 0x1000);
	assert( !(target_length&0xfff) );

	if (RegionSize == target_length)
		return NULL;

	assert( target_length >= 0 );
	assert( target_length < RegionSize );

	ret = DoSplit( BaseAddress + target_length, RegionSize - target_length );
	if (!ret)
	{
		trace("Split failed!\n");
		return NULL;
	}

	RegionSize = target_length;

	ret->State = State;
	ret->Type = Type;
	ret->Protect = Protect;
	if (KernelAddress)
		ret->KernelAddress = KernelAddress + RegionSize;

	assert( !(RegionSize&0xfff) );
	assert( !(ret->RegionSize&0xfff) );
	assert( BaseAddress < ret->BaseAddress );
	assert( (BaseAddress+RegionSize) == ret->BaseAddress );

	return ret;
}

int MBLOCK::LocalUnmap()
{
	if (KernelAddress)
		::munmap( KernelAddress, RegionSize );
	KernelAddress = 0;
	return 0;
}

int MBLOCK::RemoteUnmap( ADDRESS_SPACE *vm )
{
	return vm->Munmap( BaseAddress, RegionSize );
}

ULONG MBLOCK::MmapFlagFromPageProt( ULONG prot )
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

void MBLOCK::SetProt( ULONG prot )
{
	Protect = prot;
}

void MBLOCK::Commit( ADDRESS_SPACE *vm )
{
	if (State != MEM_COMMIT)
	{
		State = MEM_COMMIT;
		Type = MEM_PRIVATE;

		//trace("committing %p/%p %08lx\n", kernel_address, BaseAddress, RegionSize);
		if (0 > LocalMap( PROT_READ | PROT_WRITE ) &&
			0 > LocalMap( PROT_READ ))
			Die("couldn't map user memory into kernel %d\n", errno);
	}

	RemoteRemap( vm, Tracer != 0 );
}

void MBLOCK::RemoteRemap( ADDRESS_SPACE *vm, bool except )
{
	int r = RemoteMap( vm, except ? PAGE_NOACCESS : Protect );
	if (0 < r )
		Die("RemoteMap failed\n");
}

bool MBLOCK::SetTracer( ADDRESS_SPACE *vm, BLOCK_TRACER *bt )
{
	if (!bt->Enabled())
		return false;
	assert( (Tracer == 0) ^ (bt == 0) );
	Tracer = bt;
	RemoteRemap( vm, Tracer != 0 );
	return true;
}

void MBLOCK::Reserve( ADDRESS_SPACE *vm )
{
	assert( State != MEM_COMMIT );
	if (State == MEM_RESERVE)
		return;
	State = MEM_RESERVE;
	Protect = 0;
	Type = MEM_PRIVATE;
	// FIXME: maybe allocate memory here
}

void MBLOCK::Uncommit( ADDRESS_SPACE *vm )
{
	if (State != MEM_COMMIT)
		return;
	RemoteUnmap( vm );
	LocalUnmap();
	State = MEM_RESERVE;
	KernelAddress = NULL;
}

void MBLOCK::Unreserve( ADDRESS_SPACE *vm )
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

NTSTATUS MBLOCK::Query( BYTE *start, MEMORY_BASIC_INFORMATION *info )
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

bool MBLOCK::TracedAccess( BYTE *address, ULONG Eip )
{
	if (!Tracer)
		return false;
	Tracer->OnAccess( this, address, Eip );
	return true;
}

bool MBLOCK::SetTraced( ADDRESS_SPACE *vm, bool traced )
{
	if (!Tracer)
		return false;
	RemoteRemap( vm, traced );
	return true;
}

void MBLOCK::SetSection( OBJECT *s )
{
	if (Section)
		release( Section );
	Section = s;
	addref( Section );
}

void BLOCK_TRACER::OnAccess( MBLOCK *mb, BYTE *address, ULONG Eip )
{
	fprintf(stderr, "%04lx: accessed %p from %08lx\n",
			Current->TraceId(), address, Eip );
}

bool BLOCK_TRACER::Enabled() const
{
	return OptionTrace;
}

BLOCK_TRACER::~BLOCK_TRACER()
{
}
