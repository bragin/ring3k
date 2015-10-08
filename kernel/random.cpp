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

class random_dev_t : public IO_OBJECT
{
public:
	random_dev_t();
	virtual NTSTATUS read( PVOID Buffer, ULONG Length, ULONG *read );
	virtual NTSTATUS write( PVOID Buffer, ULONG Length, ULONG *written );
};

random_dev_t::random_dev_t()
{
}

NTSTATUS random_dev_t::read( PVOID Buffer, ULONG Length, ULONG *read )
{
	trace("random_dev_t\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS random_dev_t::write( PVOID Buffer, ULONG Length, ULONG *written )
{
	trace("random_dev_t\n");
	return STATUS_NOT_IMPLEMENTED;
}

class random_dev_factory_t: public OBJECT_FACTORY
{
public:
	NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS random_dev_factory_t::AllocObject(OBJECT** obj)
{
	*obj = new random_dev_t;
	return STATUS_SUCCESS;
}

void init_random()
{
	random_dev_factory_t factory;
	unicode_string_t rand;
	rand.copy("\\Device\\KsecDD");
	OBJECT *obj = 0;
	NTSTATUS r;
	r = factory.create_kernel( obj, rand );
	if (r < STATUS_SUCCESS)
		die("failed to create random device\n");
}
