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
class execution_context_t
{
public:
	virtual void handle_fault() = 0;
	virtual void handle_breakpoint() = 0;
	virtual ~execution_context_t() {};
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
	virtual NTSTATUS query( BYTE *start, MEMORY_BASIC_INFORMATION *info ) = 0;
	virtual NTSTATUS get_kernel_address( BYTE **address, size_t *len ) = 0;
	virtual NTSTATUS copy_to_user( void *dest, const void *src, size_t len ) = 0;
	virtual NTSTATUS copy_from_user( void *dest, const void *src, size_t len ) = 0;
	virtual NTSTATUS verify_for_write( void *dest, size_t len ) = 0;
	virtual NTSTATUS allocate_virtual_memory( BYTE **start, int zero_bits, size_t length, int state, int prot ) = 0;
	virtual NTSTATUS map_fd( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing ) = 0;
	virtual NTSTATUS free_virtual_memory( void *start, size_t length, ULONG state ) = 0;
	virtual NTSTATUS unmap_view( void *start ) = 0;
	virtual void dump() = 0;
	virtual int mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset ) = 0;
	virtual int munmap( BYTE *address, size_t length ) = 0;
	virtual MBLOCK* find_block( BYTE *addr ) = 0;
	virtual const char *get_symbol( BYTE *address ) = 0;
	virtual void run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, execution_context_t *exec ) = 0;
	virtual void init_context( CONTEXT& ctx ) = 0;
	virtual int get_fault_info( void *& addr ) = 0;
	virtual bool traced_access( void* address, ULONG Eip ) = 0;
	virtual bool set_traced( void* address, bool traced ) = 0;
	virtual bool set_tracer( BYTE* address, BLOCK_TRACER& tracer) = 0;
};

unsigned int allocate_core_memory(unsigned int size);
int free_core_memory( unsigned int offset, unsigned int size );
struct ADDRESS_SPACE *create_address_space( BYTE *high );

typedef LIST_ANCHOR<MBLOCK,0> MBLOCK_list_t;
typedef LIST_ITER<MBLOCK,0> MBLOCK_iter_t;
typedef LIST_ELEMENT<MBLOCK> MBLOCK_element_t;

class MBLOCK
{
public:
	MBLOCK_element_t entry[1];

protected:
	// windows-ish stuff
	PBYTE  BaseAddress;
	DWORD  Protect;
	SIZE_T RegionSize;
	DWORD  State;
	DWORD  Type;

	// linux-ish stuff
	BYTE *kernel_address;

	// access tracing
	BLOCK_TRACER *tracer;
	OBJECT *section;

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
		return entry[0].is_linked();
	}
	BYTE *GetKernelAddress()
	{
		return kernel_address;
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
		return section;
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
	MBLOCK_list_t blocks;
	int num_pages;
	MBLOCK **xlate;

protected:
	MBLOCK *&xlate_entry( BYTE *address )
	{
		return xlate[ ((unsigned int)address)>>12 ];
	}
	ADDRESS_SPACE_IMPL();
	bool init( BYTE *high );
	void destroy();
	MBLOCK *get_MBLOCK( BYTE *address );
	NTSTATUS find_free_area( int zero_bits, size_t length, int top_down, BYTE *&address );
	NTSTATUS check_params( BYTE *start, int zero_bits, size_t length, int state, int prot );
	NTSTATUS set_block_state( MBLOCK *mb, int state, int prot );
	MBLOCK *split_area( MBLOCK *mb, BYTE *address, size_t length );
	void free_shared( MBLOCK *mb );
	NTSTATUS get_mem_region( BYTE *start, size_t length, int state );
	void insert_block( MBLOCK *x );
	void remove_block( MBLOCK *x );
	ULONG check_area( BYTE *address, size_t length );
	MBLOCK* alloc_guard_block(BYTE *address, ULONG size);

public:
	// a constructor that can fail...
	friend ADDRESS_SPACE *create_address_space( BYTE *high );

	~ADDRESS_SPACE_IMPL();
	void verify();
	NTSTATUS query( BYTE *start, MEMORY_BASIC_INFORMATION *info );

public:
	virtual NTSTATUS get_kernel_address( BYTE **address, size_t *len );
	virtual NTSTATUS copy_from_user( void *dest, const void *src, size_t len );
	virtual NTSTATUS copy_to_user( void *dest, const void *src, size_t len );
	virtual NTSTATUS verify_for_write( void *dest, size_t len );
	virtual NTSTATUS allocate_virtual_memory( BYTE **start, int zero_bits, size_t length, int state, int prot );
	virtual NTSTATUS map_fd( BYTE **start, int zero_bits, size_t length, int state, int prot, BACKING_STORE *backing );
	virtual NTSTATUS free_virtual_memory( void *start, size_t length, ULONG state );
	virtual NTSTATUS unmap_view( void *start );
	virtual void dump();
	virtual int mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset ) = 0;
	virtual int munmap( BYTE *address, size_t length ) = 0;
	virtual void update_page_translation( MBLOCK *mb );
	virtual MBLOCK* find_block( BYTE *addr );
	virtual const char *get_symbol( BYTE *address );
	virtual void run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, execution_context_t *exec ) = 0;
	virtual void init_context( CONTEXT& ctx ) = 0;
	virtual bool traced_access( void* address, ULONG Eip );
	virtual bool set_traced( void* address, bool traced );
	virtual bool set_tracer( BYTE* address, BLOCK_TRACER& tracer);
};

extern struct ADDRESS_SPACE_IMPL *(*pcreate_address_space)();

#endif // __MEM_H__
