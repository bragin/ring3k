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
#include <assert.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "object.inl"
#include "ntcall.h"
#include "symlink.h"

symlink_t::symlink_t( const UNICODE_STRING& us )
{
	target.copy( &us );
}

symlink_t::~symlink_t()
{
}

class symlink_opener : public OPEN_INFO
{
public:
	NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
};

NTSTATUS symlink_opener::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	if (!obj)
		return STATUS_OBJECT_PATH_NOT_FOUND;
	addref( obj );
	return STATUS_SUCCESS;
}

NTSTATUS symlink_t::Open( OBJECT *&out, OPEN_INFO& info )
{
	if (info.path.Length != 0)
	{
		// follow the link
		trace("following %pus\n", &target );
		symlink_opener target_info;
		target_info.Attributes = info.Attributes;
		target_info.path.set( target );
		//target_info.root = parent;

		OBJECT *target_object;
		NTSTATUS r;
		r = open_root( target_object, target_info );
		if (r < STATUS_SUCCESS)
			return r;

		return target_object->Open( out, info );
	}

	trace("opening symlinks oa.Attributes = %08lx\n", info.Attributes);
	if (info.Attributes & OBJ_OPENLINK)
	{
		trace("OBJ_OPENLINK specified\n");
		return STATUS_INVALID_PARAMETER;
	}

	info.path.set( target );
	return open_root( out, info );
}

class symlink_factory_t : public OBJECT_FACTORY
{
private:
	const UNICODE_STRING& target;
public:
	symlink_factory_t(const UNICODE_STRING& _target);
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

symlink_factory_t::symlink_factory_t(const UNICODE_STRING& _target) :
	target( _target )
{
}

NTSTATUS symlink_factory_t::AllocObject(OBJECT** obj)
{
	trace("allocating object\n");
	if (target.Length == 0)
		return STATUS_INVALID_PARAMETER;

	if (target.Length > target.MaximumLength)
		return STATUS_INVALID_PARAMETER;

	*obj = new symlink_t( target );
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateSymbolicLinkObject(
	PHANDLE SymbolicLinkHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PUNICODE_STRING TargetName )
{
	unicode_string_t target;
	NTSTATUS r;

	r = target.copy_from_user( TargetName );
	if (r < STATUS_SUCCESS)
		return r;

	symlink_factory_t factory( target );
	return factory.create( SymbolicLinkHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS create_symlink( UNICODE_STRING& name, UNICODE_STRING& target )
{
	OBJECT *obj = 0;
	symlink_factory_t factory( target );
	return factory.create_kernel( obj, name );
}

NTSTATUS NTAPI NtOpenSymbolicLinkObject(
	PHANDLE SymlinkHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	return nt_open_object<symlink_t>( SymlinkHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtQuerySymbolicLinkObject(
	HANDLE SymbolicLinkHandle,
	PUNICODE_STRING LinkName,
	PULONG DataWritten )
{
	UNICODE_STRING name;
	NTSTATUS r;

	r = CopyFromUser( &name, LinkName, sizeof name );
	if (r < STATUS_SUCCESS)
		return r;

	// make sure we can write back the length
	r = VerifyForWrite( &LinkName->Length, sizeof LinkName->Length );
	if (r < STATUS_SUCCESS)
		return r;

	if (DataWritten)
	{
		r = VerifyForWrite( DataWritten, sizeof DataWritten );
		if (r < STATUS_SUCCESS)
			return r;
	}

	symlink_t *symlink = 0;
	r = object_from_handle( symlink, SymbolicLinkHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	const unicode_string_t& target = symlink->get_target();

	if (name.MaximumLength < target.Length)
		return STATUS_BUFFER_TOO_SMALL;

	r = CopyToUser( name.Buffer, target.Buffer, target.Length );
	if (r < STATUS_SUCCESS)
		return r;

	CopyToUser( &LinkName->Length, &target.Length, sizeof target.Length );

	if (DataWritten)
	{
		// convert from USHORT to ULONG
		ULONG len = target.Length;
		CopyToUser( DataWritten, &len, sizeof len );
	}

	return r;
}
