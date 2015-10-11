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

SYMLINK::SYMLINK( const UNICODE_STRING& us )
{
	target.Copy( &us );
}

SYMLINK::~SYMLINK()
{
}

class SYMLINK_OPENER : public OPEN_INFO
{
public:
	NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
};

NTSTATUS SYMLINK_OPENER::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	if (!obj)
		return STATUS_OBJECT_PATH_NOT_FOUND;
	AddRef( obj );
	return STATUS_SUCCESS;
}

NTSTATUS SYMLINK::Open( OBJECT *&out, OPEN_INFO& info )
{
	if (info.Path.Length != 0)
	{
		// follow the link
		trace("following %pus\n", &target );
		SYMLINK_OPENER target_info;
		target_info.Attributes = info.Attributes;
		target_info.Path.Set( target );
		//target_info.root = parent;

		OBJECT *target_object;
		NTSTATUS r;
		r = OpenRoot( target_object, target_info );
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

	info.Path.Set( target );
	return OpenRoot( out, info );
}

class SYMLINK_FACTORY : public OBJECT_FACTORY
{
private:
	const UNICODE_STRING& target;
public:
	SYMLINK_FACTORY(const UNICODE_STRING& _target);
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

SYMLINK_FACTORY::SYMLINK_FACTORY(const UNICODE_STRING& _target) :
	target( _target )
{
}

NTSTATUS SYMLINK_FACTORY::AllocObject(OBJECT** obj)
{
	trace("allocating object\n");
	if (target.Length == 0)
		return STATUS_INVALID_PARAMETER;

	if (target.Length > target.MaximumLength)
		return STATUS_INVALID_PARAMETER;

	*obj = new SYMLINK( target );
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
	CUNICODE_STRING target;
	NTSTATUS r;

	r = target.CopyFromUser( TargetName );
	if (r < STATUS_SUCCESS)
		return r;

	SYMLINK_FACTORY factory( target );
	return factory.Create( SymbolicLinkHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS CreateSymlink( UNICODE_STRING& name, UNICODE_STRING& target )
{
	OBJECT *obj = 0;
	SYMLINK_FACTORY factory( target );
	return factory.CreateKernel( obj, name );
}

NTSTATUS NTAPI NtOpenSymbolicLinkObject(
	PHANDLE SymlinkHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	return NtOpenObject<SYMLINK>( SymlinkHandle, DesiredAccess, ObjectAttributes );
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

	SYMLINK *symlink = 0;
	r = ObjectFromHandle( symlink, SymbolicLinkHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	const CUNICODE_STRING& target = symlink->GetTarget();

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
