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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "objdir.h"
#include "ntcall.h"
#include "symlink.h"

DEFAULT_DEBUG_CHANNEL(objdir);

#include "object.inl"

static OBJECT_DIR_IMPL *Root = 0;

OBJECT_DIR::OBJECT_DIR()
{
}

OBJECT_DIR::~OBJECT_DIR()
{
}

void OBJECT_DIR::SetObjParent( OBJECT *child, OBJECT_DIR *dir )
{
	child->Parent = dir;
}

OBJECT_DIR_IMPL::OBJECT_DIR_IMPL()
{
}

OBJECT_DIR_IMPL::~OBJECT_DIR_IMPL()
{
	//trace("destroying directory %pus\n", &name );
	OBJECT_ITER i(object_list);
	while( i )
	{
		OBJECT *obj = i;
		i.Next();
		Unlink( obj );
	}
}

void OBJECT_DIR_IMPL::Unlink( OBJECT *obj )
{
	assert( obj );
	object_list.Unlink( obj );
	SetObjParent( obj, 0 );
}

void OBJECT_DIR_IMPL::Append( OBJECT *obj )
{
	assert( obj );
	object_list.Append( obj );
	SetObjParent( obj, this );
}

bool OBJECT_DIR_IMPL::AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return CheckAccess( required, handle,
						 DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
						 DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
						 DIRECTORY_ALL_ACCESS );
}

OBJECT *OBJECT_DIR_IMPL::Lookup( UNICODE_STRING& name, bool ignore_case )
{
	//trace("searching for %pus\n", &name );
	for( OBJECT_ITER i(object_list); i; i.Next() )
	{
		OBJECT *obj = i;
		CUNICODE_STRING& entry_name  = obj->GetName();
		//trace("checking %pus\n", &entry_name );
		if (!entry_name.Compare( &name, ignore_case ))
			continue;
		return obj;
	}
	return 0;
}

class OBJECT_DIR_FACTORY : public OBJECT_FACTORY
{
public:
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS OBJECT_DIR_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new OBJECT_DIR_IMPL;
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

OBJECT *CreateDirectoryObject( PCWSTR name )
{
	OBJECT_DIR_IMPL *obj = new OBJECT_DIR_IMPL;

	if (name && name[0] == '\\' && name[1] == 0)
	{
		if (!Root)
			Root = obj;
		else
			delete obj;
		return Root;
	}

	CUNICODE_STRING us;
	us.Copy(name);
	OBJECT_ATTRIBUTES oa;
	memset( &oa, 0, sizeof oa );
	oa.Length = sizeof oa;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &us;
	NTSTATUS r = NameObject( obj, &oa );
	if (r < STATUS_SUCCESS)
	{
		Release( obj );
		obj = 0;
	}
	return obj;
}

NTSTATUS OpenRoot( OBJECT*& obj, OPEN_INFO& info )
{
	// look each directory in the path and make sure it exists
	OBJECT_DIR *dir = 0;

	NTSTATUS r;

	// parse the root directory
	if (info.Root)
	{
		// relative path
		if (info.Path.Buffer[0] == '\\')
			return STATUS_OBJECT_PATH_SYNTAX_BAD;

		r = ObjectFromHandle( dir, info.Root, DIRECTORY_QUERY );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
	{
		// absolute path
		if (info.Path.Buffer[0] != '\\')
			return STATUS_OBJECT_PATH_SYNTAX_BAD;
		dir = Root;
		info.Path.Buffer++;
		info.Path.Length -= 2;
	}

	if (info.Path.Length == 0)
	{
		obj = dir;
		return info.OnOpen( 0, obj, info );
	}

	return dir->Open( obj, info );
}

NTSTATUS OBJECT_DIR_IMPL::Open( OBJECT*& obj, OPEN_INFO& info )
{
	ULONG n = 0;
	UNICODE_STRING& path = info.Path;

	TRACE("path = %pus\n", &path );

	while (n < path.Length/2 && path.Buffer[n] != '\\')
		n++;

	if (n == 0)
		return STATUS_OBJECT_NAME_INVALID;

	UNICODE_STRING segment;
	segment.Buffer = path.Buffer;
	segment.Length = n * 2;
	segment.MaximumLength = 0;

	obj = Lookup( segment, info.CaseInsensitive() );

	if (n == path.Length/2)
		return info.OnOpen( this, obj, info );

	if (!obj)
		return STATUS_OBJECT_PATH_NOT_FOUND;

	path.Buffer += (n + 1);
	path.Length -= (n + 1) * 2;
	path.MaximumLength -= (n + 1) * 2;

	return obj->Open( obj, info );
}

class FIND_OBJECT : public OPEN_INFO
{
public:
	virtual NTSTATUS OnOpen( OBJECT_DIR *dir, OBJECT*& obj, OPEN_INFO& info );
};

NTSTATUS FIND_OBJECT::OnOpen( OBJECT_DIR *dir, OBJECT*& obj, OPEN_INFO& info )
{
	TRACE("FIND_OBJECT::on_open %pus %s\n", &info.Path,
		  obj ? "exists" : "doesn't exist");
	if (!obj)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	// hack until NtOpenSymbolicLinkObject is fixed
	if (dynamic_cast<SYMLINK*>( obj ) != NULL &&
	   (info.Attributes & OBJ_OPENLINK))
	{
		return STATUS_INVALID_PARAMETER;
	}

	AddRef( obj );

	return STATUS_SUCCESS;
}

NTSTATUS FindObjectByName( OBJECT **out, const OBJECT_ATTRIBUTES *oa )
{
	// no name
	if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer)
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	// too short
	if (oa->ObjectName->Length < 2)
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	// odd length
	if (oa->ObjectName->Length & 1)
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	FIND_OBJECT oi;
	oi.Attributes = oa->Attributes;
	oi.Root = oa->RootDirectory;
	oi.Path.Set( *oa->ObjectName );

	return OpenRoot( *out, oi );
}

class NAME_OBJECT : public OPEN_INFO
{
	OBJECT *obj_to_name;
public:
	NAME_OBJECT( OBJECT *in );
	virtual NTSTATUS OnOpen( OBJECT_DIR *dir, OBJECT*& obj, OPEN_INFO& info );
};

NAME_OBJECT::NAME_OBJECT( OBJECT *in ) :
	obj_to_name( in )
{
}

NTSTATUS NAME_OBJECT::OnOpen( OBJECT_DIR *dir, OBJECT*& obj, OPEN_INFO& info )
{
	TRACE("NAME_OBJECT::on_open %pus\n", &info.Path);

	if (obj)
	{
		WARN("object already exists\n");
		return STATUS_OBJECT_NAME_COLLISION;
	}

	obj = obj_to_name;

	NTSTATUS r;
	r = obj->Name.Copy( &info.Path );
	if (r < STATUS_SUCCESS)
		return r;

	dir->Append( obj );

	return STATUS_SUCCESS;
}

NTSTATUS NameObject( OBJECT *obj, const OBJECT_ATTRIBUTES *oa )
{
	if (!oa)
		return STATUS_SUCCESS;

	obj->Attr = oa->Attributes;
	if (!oa->ObjectName)
		return STATUS_SUCCESS;
	if (!oa->ObjectName->Buffer)
		return STATUS_SUCCESS;
	if (!oa->ObjectName->Length)
		return STATUS_SUCCESS;

	TRACE("NAME_OBJECT %pus\n", oa->ObjectName);

	NAME_OBJECT oi( obj );
	oi.Attributes = oa->Attributes;
	oi.Root = oa->RootDirectory;
	oi.Path.Set( *oa->ObjectName );

	return OpenRoot( obj, oi );
}

NTSTATUS GetNamedObject( OBJECT **out, const OBJECT_ATTRIBUTES *oa )
{
	OBJECT *obj;
	NTSTATUS r;

	if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || !oa->ObjectName->Buffer[0])
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	r = FindObjectByName( &obj, oa );
	if (r < STATUS_SUCCESS)
		return r;

	*out = obj;
	return STATUS_SUCCESS;
}

void InitRoot()
{
	Root = new OBJECT_DIR_IMPL;
	assert( Root );
}

void FreeRoot()
{
	//delete root;
}

NTSTATUS NTAPI NtCreateDirectoryObject(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	TRACE("%p %08lx %p\n", DirectoryHandle, DesiredAccess, ObjectAttributes );

	OBJECT_DIR_FACTORY factory;
	return factory.Create( DirectoryHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenDirectoryObject(
	PHANDLE DirectoryObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	return NtOpenObject<OBJECT_DIR>( DirectoryObjectHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtQueryDirectoryObject(
	HANDLE DirectoryHandle,
	PVOID Buffer,
	ULONG BufferLength,
	BOOLEAN ReturnSingleEntry,
	BOOLEAN RestartScan,
	PULONG Offset,  // called Context in Native API reference
	PULONG ReturnLength)
{
	TRACE("%p %p %lu %u %u %p %p\n", DirectoryHandle, Buffer, BufferLength,
		  ReturnSingleEntry, RestartScan, Offset, ReturnLength);

	ULONG ofs = 0;
	NTSTATUS r = CopyFromUser( &ofs, Offset, sizeof ofs );
	if (r < STATUS_SUCCESS)
		return r;

	OBJECT_DIR* dir = 0;
	r = ObjectFromHandle( dir, DirectoryHandle, DIRECTORY_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	FIXME("fixme\n");

	return STATUS_NO_MORE_ENTRIES;
}
