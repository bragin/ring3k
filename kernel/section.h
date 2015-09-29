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

#ifndef __SECTION_H__
#define __SECTION_H__

struct section_t : public OBJECT, public BACKING_STORE
{
	int fd;
	BYTE *addr;
	size_t len;
	ULONG Attributes;
	ULONG Protect;
public:
	section_t( int fd, BYTE *a, size_t l, ULONG attr, ULONG prot );
	virtual ~section_t();
	virtual NTSTATUS mapit( address_space *vm, BYTE *&addr, ULONG ZeroBits, ULONG State, ULONG Prot );
	virtual void* get_kernel_address();
	virtual NTSTATUS query( SECTION_BASIC_INFORMATION *basic );
	virtual NTSTATUS query( SECTION_IMAGE_INFORMATION *image );
	virtual const char *get_symbol( ULONG address );
	virtual int get_fd();
	virtual void addref();
	virtual void release();
};

NTSTATUS create_section( OBJECT **obj, OBJECT *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect );
NTSTATUS create_section( section_t **section, OBJECT *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect );
NTSTATUS mapit( address_space *vm, OBJECT *obj, BYTE *&addr );
void *virtual_addr_to_offset( IMAGE_NT_HEADERS *nt, void *base, DWORD virtual_ofs );
DWORD get_proc_address(OBJECT *obj, const char *name);
void *get_entry_point( process_t *p );
NTSTATUS section_from_handle( HANDLE, section_t*& section, ACCESS_MASK access );

#endif
