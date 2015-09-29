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
	virtual int get_fd() = 0;
	virtual void addref() = 0;
	virtual void release() = 0;
	virtual ~BACKING_STORE() {};
};

class BLOCK_TRACER
{
public:
	virtual void on_access( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool enabled() const;
	virtual ~BLOCK_TRACER();
};

class address_space
{
public:
	virtual ~address_space();
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
struct address_space *create_address_space( BYTE *high );

typedef list_anchor<MBLOCK,0> MBLOCK_list_t;
typedef list_iter<MBLOCK,0> MBLOCK_iter_t;
typedef list_element<MBLOCK> MBLOCK_element_t;

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
	object_t *section;

public:
	MBLOCK( BYTE *address, size_t size );
	virtual ~MBLOCK();
	virtual int local_map( int prot ) = 0;
	virtual int remote_map( address_space *vm, ULONG prot ) = 0;

protected:
	virtual MBLOCK *do_split( BYTE *address, size_t size ) = 0;

public:
	MBLOCK *split( size_t length );
	int local_unmap();
	int remote_unmap( address_space *vm );
	void commit( address_space *vm );
	void reserve( address_space *vm );
	void uncommit( address_space *vm );
	void unreserve( address_space *vm );
	int is_committed()
	{
		return State == MEM_COMMIT;
	}
	int is_reserved()
	{
		return State == MEM_RESERVE;
	}
	int is_free()
	{
		return State == MEM_FREE;
	}
	NTSTATUS query( BYTE *address, MEMORY_BASIC_INFORMATION *info );
	void dump();
	int is_linked()
	{
		return entry[0].is_linked();
	}
	BYTE *get_kernel_address()
	{
		return kernel_address;
	};
	BYTE *get_base_address()
	{
		return BaseAddress;
	};
	ULONG get_region_size()
	{
		return RegionSize;
	};
	ULONG get_prot()
	{
		return Protect;
	};
	object_t* get_section()
	{
		return section;
	};
	static ULONG mmap_flag_from_page_prot( ULONG prot );
	void remote_remap( address_space *vm, bool except );
	bool set_tracer( address_space *vm, BLOCK_TRACER *tracer);
	bool traced_access( BYTE *address, ULONG Eip );
	bool set_traced( address_space *vm, bool traced );
	void set_section( object_t *section );
	void set_prot( ULONG prot );
};

MBLOCK* alloc_guard_pages(BYTE* address, ULONG size);
MBLOCK* alloc_core_pages(BYTE* address, ULONG size);
MBLOCK* alloc_fd_pages(BYTE* address, ULONG size, BACKING_STORE* backing);

int create_mapping_fd( int sz );

class address_space_impl : public address_space
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
	address_space_impl();
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
	friend address_space *create_address_space( BYTE *high );

	~address_space_impl();
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

extern struct address_space_impl *(*pcreate_address_space)();

#endif // __MEM_H__
