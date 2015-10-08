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

#ifndef __MEM_H__
#define __MEM_H__

#include <unistd.h>
#include "list.h"
#include "object.h"

class MBLOCK;

// pure virtual base class for things that can execution code (eg. threads)
class EXECUTION_CONTEXT
{
public:
	virtual void HandleFault() = 0;
	virtual void HandleBreakpoint() = 0;
	virtual ~EXECUTION_CONTEXT() {};
};

class BACKING_STORE
{
public:
	virtual int GetFD() = 0;
	virtual void AddRef() = 0;
	virtual void Release() = 0;
	virtual ~BACKING_STORE() {};
};

class BLOCK_TRACER
{
public:
	virtual void OnAccess( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool Enabled() const;
	virtual ~BLOCK_TRACER();
};

class ADDRESS_SPACE
{
public:
	virtual ~ADDRESS_SPACE();
	virtual NTSTATUS Query( BYTE *start, MEMORY_BASIC_INFORMATION *info ) = 0;
	virtual NTSTATUS GetKernelAddress( BYTE **address, size_t *len ) = 0;
	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t len ) = 0;
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t len ) = 0;
	virtual NTSTATUS VerifyForWrite( void *dest, size_t len ) = 0;
	virtual NTSTATUS AllocateVirtualMemory( BYTE **start, int zero_bits, size_t length, int state, int prot ) = 0;
	virtual NTSTATUS MapFD( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing ) = 0;
	virtual NTSTATUS FreeVirtualMemory( void *start, size_t length, ULONG state ) = 0;
	virtual NTSTATUS UnmapView( void *start ) = 0;
	virtual void Dump() = 0;
	virtual int Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset ) = 0;
	virtual int Munmap( BYTE *address, size_t length ) = 0;
	virtual MBLOCK* FindBlock( BYTE *addr ) = 0;
	virtual const char *GetSymbol( BYTE *address ) = 0;
	virtual void Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec ) = 0;
	virtual void InitContext( CONTEXT& ctx ) = 0;
	virtual int GetFaultInfo( void *& addr ) = 0;
	virtual bool TracedAccess( void* address, ULONG Eip ) = 0;
	virtual bool SetTraced( void* address, bool traced ) = 0;
	virtual bool SetTracer( BYTE* address, BLOCK_TRACER& tracer) = 0;
};

unsigned int AllocateCoreMemory(unsigned int size);
int FreeCoreMemory( unsigned int offset, unsigned int size );
struct ADDRESS_SPACE *CreateAddressSpace( BYTE *high );

typedef LIST_ANCHOR<MBLOCK,0> MBLOCK_LIST;
typedef LIST_ITER<MBLOCK,0> MBLOCK_ITER;
typedef LIST_ELEMENT<MBLOCK> MBLOCK_ELEMENT;

class MBLOCK
{
public:
	MBLOCK_ELEMENT Entry[1];

protected:
	// windows-ish stuff
	PBYTE  BaseAddress;
	DWORD  Protect;
	SIZE_T RegionSize;
	DWORD  State;
	DWORD  Type;

	// linux-ish stuff
	BYTE *KernelAddress;

	// access tracing
	BLOCK_TRACER *Tracer;
	OBJECT *Section;

public:
	MBLOCK( BYTE *address, size_t size );
	virtual ~MBLOCK();
	virtual int LocalMap( int prot ) = 0;
	virtual int RemoteMap( ADDRESS_SPACE *vm, ULONG prot ) = 0;

protected:
	virtual MBLOCK *DoSplit( BYTE *address, size_t size ) = 0;

public:
	MBLOCK *Split( size_t length );
	int LocalUnmap();
	int RemoteUnmap( ADDRESS_SPACE *vm );
	void Commit( ADDRESS_SPACE *vm );
	void Reserve( ADDRESS_SPACE *vm );
	void Uncommit( ADDRESS_SPACE *vm );
	void Unreserve( ADDRESS_SPACE *vm );
	int IsCommitted()
	{
		return State == MEM_COMMIT;
	}
	int IsReserved()
	{
		return State == MEM_RESERVE;
	}
	int IsFree()
	{
		return State == MEM_FREE;
	}
	NTSTATUS Query( BYTE *address, MEMORY_BASIC_INFORMATION *info );
	void Dump();
	int IsLinked()
	{
		return Entry[0].IsLinked();
	}
	BYTE *GetKernelAddress()
	{
		return KernelAddress;
	};
	BYTE *GetBaseAddress()
	{
		return BaseAddress;
	};
	ULONG GetRegionSize()
	{
		return RegionSize;
	};
	ULONG GetProt()
	{
		return Protect;
	};
	OBJECT* GetSection()
	{
		return Section;
	};
	static ULONG MmapFlagFromPageProt( ULONG prot );
	void RemoteRemap( ADDRESS_SPACE *vm, bool except );
	bool SetTracer( ADDRESS_SPACE *vm, BLOCK_TRACER *tracer);
	bool TracedAccess( BYTE *address, ULONG Eip );
	bool SetTraced( ADDRESS_SPACE *vm, bool traced );
	void SetSection( OBJECT *section );
	void SetProt( ULONG prot );
};

MBLOCK* AllocGuardPages(BYTE* address, ULONG size);
MBLOCK* AllocCorePages(BYTE* address, ULONG size);
MBLOCK* AllocFDPages(BYTE* address, ULONG size, BACKING_STORE* backing);

int CreateMappingFD( int sz );

class ADDRESS_SPACE_IMPL : public ADDRESS_SPACE
{
private:
	BYTE *const lowest_address;
	BYTE *highest_address;
	MBLOCK_LIST blocks;
	int num_pages;
	MBLOCK **xlate;

protected:
	MBLOCK *&XlateEntry( BYTE *address )
	{
		return xlate[ ((unsigned int)address)>>12 ];
	}
	ADDRESS_SPACE_IMPL();
	bool Init( BYTE *high );
	void Destroy();
	MBLOCK *GetMBLOCK( BYTE *address );
	NTSTATUS FindFreeArea( int zero_bits, size_t length, int top_down, BYTE *&address );
	NTSTATUS CheckParams( BYTE *start, int zero_bits, size_t length, int state, int prot );
	NTSTATUS SetBlockState( MBLOCK *mb, int state, int prot );
	MBLOCK *SplitArea( MBLOCK *mb, BYTE *address, size_t length );
	void FreeShared( MBLOCK *mb );
	NTSTATUS GetMemRegion( BYTE *start, size_t length, int state );
	void InsertBlock( MBLOCK *x );
	void RemoveBlock( MBLOCK *x );
	ULONG CheckArea( BYTE *address, size_t length );
	MBLOCK* AllocGuardBlock(BYTE *address, ULONG size);

public:
	// a constructor that can fail...
	friend ADDRESS_SPACE *CreateAddressSpace( BYTE *high );

	~ADDRESS_SPACE_IMPL();
	void Verify();
	NTSTATUS Query( BYTE *start, MEMORY_BASIC_INFORMATION *info );

public:
	virtual NTSTATUS GetKernelAddress( BYTE **address, size_t *len );
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t len );
	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t len );
	virtual NTSTATUS VerifyForWrite( void *dest, size_t len );
	virtual NTSTATUS AllocateVirtualMemory( BYTE **start, int zero_bits, size_t length, int state, int prot );
	virtual NTSTATUS MapFD( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing );
	virtual NTSTATUS FreeVirtualMemory( void *start, size_t length, ULONG state );
	virtual NTSTATUS UnmapView( void *start );
	virtual void Dump();
	virtual int Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset ) = 0;
	virtual int Munmap( BYTE *address, size_t length ) = 0;
	virtual void UpdatePageTranslation( MBLOCK *mb );
	virtual MBLOCK* FindBlock( BYTE *addr );
	virtual const char *GetSymbol( BYTE *address );
	virtual void Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec ) = 0;
	virtual void InitContext( CONTEXT& ctx ) = 0;
	virtual bool TracedAccess( void* address, ULONG Eip );
	virtual bool SetTraced( void* address, bool traced );
	virtual bool SetTracer( BYTE* address, BLOCK_TRACER& tracer);
};

extern struct ADDRESS_SPACE_IMPL *(*pCreateAddressSpace)();

#endif // __MEM_H__
