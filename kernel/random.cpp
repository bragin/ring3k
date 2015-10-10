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


#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "file.h"
#include "debug.h"

class RANDOM_DEV : public IO_OBJECT
{
public:
	RANDOM_DEV();
	virtual NTSTATUS Read( PVOID Buffer, ULONG Length, ULONG *read );
	virtual NTSTATUS Write( PVOID Buffer, ULONG Length, ULONG *written );
};

RANDOM_DEV::RANDOM_DEV()
{
}

NTSTATUS RANDOM_DEV::Read( PVOID Buffer, ULONG Length, ULONG *read )
{
	trace("RANDOM_DEV::Read\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS RANDOM_DEV::Write( PVOID Buffer, ULONG Length, ULONG *written )
{
	trace("RANDOM_DEV::Write\n");
	return STATUS_NOT_IMPLEMENTED;
}

class RANDOM_DEV_FACTORY: public OBJECT_FACTORY
{
public:
	NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS RANDOM_DEV_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new RANDOM_DEV;
	return STATUS_SUCCESS;
}

void InitRandom()
{
	RANDOM_DEV_FACTORY factory;
	unicode_string_t rand;
	rand.copy("\\Device\\KsecDD");
	OBJECT *obj = 0;
	NTSTATUS r;
	r = factory.CreateKernel( obj, rand );
	if (r < STATUS_SUCCESS)
		Die("failed to create random device\n");
}
