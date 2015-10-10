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

struct SECTION : public OBJECT, public BACKING_STORE
{
	int FD;
	BYTE *Addr;
	size_t Len;
	ULONG Attributes;
	ULONG Protect;
public:
	SECTION( int fd, BYTE *a, size_t l, ULONG attr, ULONG prot );
	virtual ~SECTION();
	virtual NTSTATUS Mapit( ADDRESS_SPACE *vm, BYTE *&addr, ULONG ZeroBits, ULONG State, ULONG Prot );
	virtual void* GetKernelAddress();
	virtual NTSTATUS Query( SECTION_BASIC_INFORMATION *basic );
	virtual NTSTATUS Query( SECTION_IMAGE_INFORMATION *image );
	virtual const char *GetSymbol( ULONG address );
	virtual int GetFD();
	virtual void AddRef();
	virtual void Release();
};

NTSTATUS CreateSection( OBJECT **obj, OBJECT *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect );
NTSTATUS CreateSection( SECTION **section, OBJECT *file, PLARGE_INTEGER psz, ULONG attribs, ULONG protect );
NTSTATUS Mapit( ADDRESS_SPACE *vm, OBJECT *obj, BYTE *&addr );
void *VirtualAddrToOffset( IMAGE_NT_HEADERS *nt, void *base, DWORD virtual_ofs );
DWORD GetProcAddress(OBJECT *obj, const char *name);
void *GetEntryPoint( PROCESS *p );
NTSTATUS SectionFromHandle( HANDLE, SECTION*& section, ACCESS_MASK access );

#endif
