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
#include "object.inl"
#include "ntcall.h"
#include "symlink.h"

static OBJECT_DIR_IMPL *root = 0;

object_dir_t::object_dir_t()
{
}

object_dir_t::~object_dir_t()
{
}

void object_dir_t::set_obj_parent( OBJECT *child, object_dir_t *dir )
{
	child->parent = dir;
}

OBJECT_DIR_IMPL::OBJECT_DIR_IMPL()
{
}

OBJECT_DIR_IMPL::~OBJECT_DIR_IMPL()
{
	//trace("destroying directory %pus\n", &name );
	object_iter_t i(object_list);
	while( i )
	{
		OBJECT *obj = i;
		i.next();
		unlink( obj );
	}
}

void OBJECT_DIR_IMPL::unlink( OBJECT *obj )
{
	assert( obj );
	object_list.unlink( obj );
	set_obj_parent( obj, 0 );
}

void OBJECT_DIR_IMPL::append( OBJECT *obj )
{
	assert( obj );
	object_list.append( obj );
	set_obj_parent( obj, this );
}

bool OBJECT_DIR_IMPL::access_allowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return check_access( required, handle,
						 DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
						 DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
						 DIRECTORY_ALL_ACCESS );
}

OBJECT *OBJECT_DIR_IMPL::lookup( UNICODE_STRING& name, bool ignore_case )
{
	//trace("searching for %pus\n", &name );
	for( object_iter_t i(object_list); i; i.next() )
	{
		OBJECT *obj = i;
		unicode_string_t& entry_name  = obj->get_name();
		//trace("checking %pus\n", &entry_name );
		if (!entry_name.compare( &name, ignore_case ))
			continue;
		return obj;
	}
	return 0;
}

class object_dir_factory : public OBJECT_FACTORY
{
public:
	virtual NTSTATUS alloc_object(OBJECT** obj);
};

NTSTATUS object_dir_factory::alloc_object(OBJECT** obj)
{
	*obj = new OBJECT_DIR_IMPL;
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

OBJECT *create_directory_object( PCWSTR name )
{
	OBJECT_DIR_IMPL *obj = new OBJECT_DIR_IMPL;

	if (name && name[0] == '\\' && name[1] == 0)
	{
		if (!root)
			root = obj;
		else
			delete obj;
		return root;
	}

	unicode_string_t us;
	us.copy(name);
	OBJECT_ATTRIBUTES oa;
	memset( &oa, 0, sizeof oa );
	oa.Length = sizeof oa;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.ObjectName = &us;
	NTSTATUS r = name_object( obj, &oa );
	if (r < STATUS_SUCCESS)
	{
		release( obj );
		obj = 0;
	}
	return obj;
}

NTSTATUS open_root( OBJECT*& obj, OPEN_INFO& info )
{
	// look each directory in the path and make sure it exists
	object_dir_t *dir = 0;

	NTSTATUS r;

	// parse the root directory
	if (info.root)
	{
		// relative path
		if (info.path.Buffer[0] == '\\')
			return STATUS_OBJECT_PATH_SYNTAX_BAD;

		r = object_from_handle( dir, info.root, DIRECTORY_QUERY );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
	{
		// absolute path
		if (info.path.Buffer[0] != '\\')
			return STATUS_OBJECT_PATH_SYNTAX_BAD;
		dir = root;
		info.path.Buffer++;
		info.path.Length -= 2;
	}

	if (info.path.Length == 0)
	{
		obj = dir;
		return info.on_open( 0, obj, info );
	}

	return dir->open( obj, info );
}

NTSTATUS OBJECT_DIR_IMPL::open( OBJECT*& obj, OPEN_INFO& info )
{
	ULONG n = 0;
	UNICODE_STRING& path = info.path;

	trace("path = %pus\n", &path );

	while (n < path.Length/2 && path.Buffer[n] != '\\')
		n++;

	if (n == 0)
		return STATUS_OBJECT_NAME_INVALID;

	UNICODE_STRING segment;
	segment.Buffer = path.Buffer;
	segment.Length = n * 2;
	segment.MaximumLength = 0;

	obj = lookup( segment, info.case_insensitive() );

	if (n == path.Length/2)
		return info.on_open( this, obj, info );

	if (!obj)
		return STATUS_OBJECT_PATH_NOT_FOUND;

	path.Buffer += (n + 1);
	path.Length -= (n + 1) * 2;
	path.MaximumLength -= (n + 1) * 2;

	return obj->open( obj, info );
}

class find_object_t : public OPEN_INFO
{
public:
	virtual NTSTATUS on_open( object_dir_t *dir, OBJECT*& obj, OPEN_INFO& info );
};

NTSTATUS find_object_t::on_open( object_dir_t *dir, OBJECT*& obj, OPEN_INFO& info )
{
	trace("find_object_t::on_open %pus %s\n", &info.path,
		  obj ? "exists" : "doesn't exist");
	if (!obj)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	// hack until NtOpenSymbolicLinkObject is fixed
	if (dynamic_cast<symlink_t*>( obj ) != NULL &&
	   (info.Attributes & OBJ_OPENLINK))
	{
		return STATUS_INVALID_PARAMETER;
	}

	addref( obj );

	return STATUS_SUCCESS;
}

NTSTATUS find_object_by_name( OBJECT **out, const OBJECT_ATTRIBUTES *oa )
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

	find_object_t oi;
	oi.Attributes = oa->Attributes;
	oi.root = oa->RootDirectory;
	oi.path.set( *oa->ObjectName );

	return open_root( *out, oi );
}

class name_object_t : public OPEN_INFO
{
	OBJECT *obj_to_name;
public:
	name_object_t( OBJECT *in );
	virtual NTSTATUS on_open( object_dir_t *dir, OBJECT*& obj, OPEN_INFO& info );
};

name_object_t::name_object_t( OBJECT *in ) :
	obj_to_name( in )
{
}

NTSTATUS name_object_t::on_open( object_dir_t *dir, OBJECT*& obj, OPEN_INFO& info )
{
	trace("name_object_t::on_open %pus\n", &info.path);

	if (obj)
	{
		trace("object already exists\n");
		return STATUS_OBJECT_NAME_COLLISION;
	}

	obj = obj_to_name;

	NTSTATUS r;
	r = obj->name.copy( &info.path );
	if (r < STATUS_SUCCESS)
		return r;

	dir->append( obj );

	return STATUS_SUCCESS;
}

NTSTATUS name_object( OBJECT *obj, const OBJECT_ATTRIBUTES *oa )
{
	if (!oa)
		return STATUS_SUCCESS;

	obj->attr = oa->Attributes;
	if (!oa->ObjectName)
		return STATUS_SUCCESS;
	if (!oa->ObjectName->Buffer)
		return STATUS_SUCCESS;
	if (!oa->ObjectName->Length)
		return STATUS_SUCCESS;

	trace("name_object_t %pus\n", oa->ObjectName);

	name_object_t oi( obj );
	oi.Attributes = oa->Attributes;
	oi.root = oa->RootDirectory;
	oi.path.set( *oa->ObjectName );

	return open_root( obj, oi );
}

NTSTATUS get_named_object( OBJECT **out, const OBJECT_ATTRIBUTES *oa )
{
	OBJECT *obj;
	NTSTATUS r;

	if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || !oa->ObjectName->Buffer[0])
		return STATUS_OBJECT_PATH_SYNTAX_BAD;

	r = find_object_by_name( &obj, oa );
	if (r < STATUS_SUCCESS)
		return r;

	*out = obj;
	return STATUS_SUCCESS;
}

void init_root()
{
	root = new OBJECT_DIR_IMPL;
	assert( root );
}

void free_root()
{
	//delete root;
}

NTSTATUS NTAPI NtCreateDirectoryObject(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	trace("%p %08lx %p\n", DirectoryHandle, DesiredAccess, ObjectAttributes );

	object_dir_factory factory;
	return factory.create( DirectoryHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenDirectoryObject(
	PHANDLE DirectoryObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	return nt_open_object<object_dir_t>( DirectoryObjectHandle, DesiredAccess, ObjectAttributes );
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
	trace("%p %p %lu %u %u %p %p\n", DirectoryHandle, Buffer, BufferLength,
		  ReturnSingleEntry, RestartScan, Offset, ReturnLength);

	ULONG ofs = 0;
	NTSTATUS r = copy_from_user( &ofs, Offset, sizeof ofs );
	if (r < STATUS_SUCCESS)
		return r;

	object_dir_t* dir = 0;
	r = object_from_handle( dir, DirectoryHandle, DIRECTORY_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	trace("fixme\n");

	return STATUS_NO_MORE_ENTRIES;
}
