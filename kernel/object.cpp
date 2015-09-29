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


#include <unistd.h>

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "objdir.h"
#include "object.inl"
#include "mem.h"
#include "ntcall.h"

open_info_t::open_info_t() :
	Attributes( 0 ),
	root( 0 )
{
}

open_info_t::~open_info_t()
{
}

void object_t::addref( object_t *obj )
{
	obj->refcount ++;
	//trace("%p has %ld refs\n", obj, obj->refcount);
}

void object_t::release( object_t *obj )
{
	//trace("%p has %ld refs left\n", obj, obj->refcount - 1);
	if (!--obj->refcount)
	{
		//trace("destroying %p\n", obj);
		delete obj;
	}
}

NTSTATUS object_t::open( object_t *&out, open_info_t& info )
{
	if (info.path.Length != 0)
	{
		trace("length not zero\n");
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	addref( this );
	out = this;
	return STATUS_SUCCESS;
}

HANDLE handle_table_t::index_to_handle( ULONG index )
{
	return (HANDLE)((index+1)*4);
}

ULONG handle_table_t::handle_to_index( HANDLE handle )
{
	return ((ULONG)handle)/4 - 1;
}

HANDLE handle_table_t::alloc_handle( object_t *obj, ACCESS_MASK access )
{
	ULONG i;

	for (i=0; i<max_handles; i++)
	{
		if (!info[i].object)
		{
			info[i].object = obj;
			info[i].access = access;
			addref( obj );
			return index_to_handle( i );
		}
	}
	return 0;
}

NTSTATUS handle_table_t::free_handle( HANDLE handle )
{
	object_t *obj;
	ULONG n;

	n = (ULONG) handle;
	if (!n)
		return STATUS_INVALID_HANDLE;
	if (n&3)
		return STATUS_INVALID_HANDLE;

	n = handle_to_index( handle );
	if (n >= max_handles)
		return STATUS_INVALID_HANDLE;

	obj = info[n].object;
	if (!obj)
		return STATUS_INVALID_HANDLE;

	release( obj );
	info[n].object = NULL;
	info[n].access = 0;

	return STATUS_SUCCESS;
}

NTSTATUS handle_table_t::object_from_handle( object_t*& obj, HANDLE handle, ACCESS_MASK access )
{
	if (handle == NtCurrentThread())
	{
		obj = current;
		return STATUS_SUCCESS;
	}
	if (handle == NtCurrentProcess())
	{
		obj = current->process;
		return STATUS_SUCCESS;
	}
	ULONG n = (ULONG) handle;
	if (!n)
		return STATUS_INVALID_HANDLE;
	if (n&3)
		return STATUS_INVALID_HANDLE;
	n = handle_to_index( handle );
	if (n >= max_handles)
		return STATUS_INVALID_HANDLE;
	if (!info[n].object)
		return STATUS_INVALID_HANDLE;
	if (!info[n].object->access_allowed( access, info[n].access ))
		return STATUS_ACCESS_DENIED;
	obj = info[n].object;
	return STATUS_SUCCESS;
}

handle_table_t::~handle_table_t()
{
	free_all_handles();
}

void handle_table_t::free_all_handles()
{
	object_t *obj;
	ULONG i;

	for ( i=0; i<max_handles; i++ )
	{
		obj = info[i].object;
		if (!obj)
			continue;

		release( obj );
		info[i].object = NULL;
	}
}

NTSTATUS object_factory::on_open( object_dir_t* dir, object_t*& obj, open_info_t& info )
{
	// object already exists?
	if (obj)
	{
		if (!(info.Attributes & OBJ_OPENIF))
			return STATUS_OBJECT_NAME_COLLISION;
		addref( obj );
		return STATUS_OBJECT_NAME_EXISTS;
	}

	NTSTATUS r;
	r = alloc_object( &obj );
	if (r < STATUS_SUCCESS)
		return r;

	r = obj->name.copy( &info.path );
	if (r < STATUS_SUCCESS)
		return r;

	dir->append( obj );

	return STATUS_SUCCESS;
}

NTSTATUS object_factory::create_kernel( object_t*& obj, UNICODE_STRING& us )
{
	path.set( us );
	return open_root( obj, *this );
}

NTSTATUS object_factory::create(
	PHANDLE Handle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	object_attributes_t oa;
	object_t *obj = 0;
	NTSTATUS r;

	r = verify_for_write( Handle, sizeof *Handle );
	if (r < STATUS_SUCCESS)
		return r;

	if (ObjectAttributes)
	{
		r = oa.copy_from_user( ObjectAttributes );
		if (r < STATUS_SUCCESS)
			return r;

		trace("name = %pus\n", oa.ObjectName);
	}

	if (oa.ObjectName && oa.ObjectName->Length)
	{
		path.set( *oa.ObjectName );
		root = oa.RootDirectory;
		Attributes = oa.Attributes;
		r = open_root( obj, *this );
	}
	else
	{
		r = alloc_object( &obj );
	}

	if (r < STATUS_SUCCESS)
		return r;

	// maybe this should be done in alloc_object ?
	NTSTATUS r2 = alloc_user_handle( obj, AccessMask, Handle );
	if (r2 == STATUS_SUCCESS && (oa.Attributes & OBJ_PERMANENT ))
		trace("permanent object\n");
	else
		release( obj );

	return r;
}

object_factory::~object_factory()
{
}

object_t::object_t() :
	refcount( 1 ),
	attr( 0 ),
	parent( 0 )
{
}

object_t::~object_t()
{
	if (parent)
		parent->unlink( this );
}

bool object_t::check_access( ACCESS_MASK required, ACCESS_MASK handle, ACCESS_MASK read, ACCESS_MASK write, ACCESS_MASK all )
{
	ACCESS_MASK effective = handle & 0xffffff; // all standard + specific rights
	if (handle & MAXIMUM_ALLOWED)
		effective |= all;
	if (handle & GENERIC_READ)
		effective |= read;
	if (handle & GENERIC_WRITE)
		effective |= write;
	if (handle & GENERIC_ALL)
		effective |= all;
	return (required & ~effective) == 0;
}

bool object_t::access_allowed( ACCESS_MASK access, ACCESS_MASK handle_access )
{
	trace("fixme: no access check\n");
	return true;
}

sync_object_t::sync_object_t()
{
}

sync_object_t::~sync_object_t()
{
	assert( watchers.empty() );
}

void sync_object_t::notify_watchers()
{
	watch_iter_t i(watchers);
	while (i)
	{
		watch_t *w = i;
		i.next();
		w->notify();
	}
}

void sync_object_t::add_watch( watch_t *watch )
{
	watchers.append( watch );
}

void sync_object_t::remove_watch( watch_t *watch )
{
	watchers.unlink( watch );
}

watch_t::~watch_t()
{
}

BOOLEAN sync_object_t::satisfy( void )
{
	return TRUE;
}

NTSTATUS NTAPI NtClose( HANDLE Handle )
{
	trace("%p\n", Handle );
	return current->process->handle_table.free_handle( Handle );
}

NTSTATUS NTAPI NtQueryObject(
	HANDLE Object,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength)
{
	trace("%p %d %p %lu %p\n", Object, ObjectInformationClass,
		  ObjectInformation, ObjectInformationLength, ReturnLength);

	union
	{
		OBJECT_HANDLE_ATTRIBUTE_INFORMATION handle_info;
	} info;
	ULONG sz = 0;

	switch (ObjectInformationClass)
	{
	case ObjectHandleInformation:
		sz = sizeof info.handle_info;
		break;
	case ObjectBasicInformation:
	case ObjectNameInformation:
	case ObjectTypeInformation:
	case ObjectAllTypesInformation:
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	if (ObjectInformationLength != sz)
		return STATUS_INFO_LENGTH_MISMATCH;

	NTSTATUS r;
	object_t *obj = 0;
	r = object_from_handle( obj, Object, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	switch (ObjectInformationClass)
	{
	case ObjectHandleInformation:
		info.handle_info.Inherit = 0;
		info.handle_info.ProtectFromClose = 0;
		break;
	default:
		assert(0);
	}

	r = copy_to_user( ObjectInformation, &info, sz );
	if (r == STATUS_SUCCESS && ReturnLength)
		r = copy_to_user( ReturnLength, &sz, sizeof sz );

	return r;
}

NTSTATUS NTAPI NtSetInformationObject(
	HANDLE Object,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength)
{
	trace("%p %d %p %lu\n", Object, ObjectInformationClass,
		  ObjectInformation, ObjectInformationLength);

	union
	{
		OBJECT_HANDLE_ATTRIBUTE_INFORMATION handle_info;
	} info;
	ULONG sz = 0;

	switch (ObjectInformationClass)
	{
	case ObjectHandleInformation:
		sz = sizeof info.handle_info;
		break;
	case ObjectBasicInformation:
	case ObjectNameInformation:
	case ObjectTypeInformation:
	case ObjectAllTypesInformation:
		trace("unimplemented class %d\n", ObjectInformationClass);
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	if (ObjectInformationLength != sz)
		return STATUS_INFO_LENGTH_MISMATCH;

	NTSTATUS r;
	object_t *obj = 0;
	r = object_from_handle( obj, Object, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = copy_from_user( &info, ObjectInformation, sz );
	if (r < STATUS_SUCCESS)
		return r;

	switch (ObjectInformationClass)
	{
	case ObjectHandleInformation:
		break;
	default:
		assert(0);
	}

	return r;
}

NTSTATUS NTAPI NtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options)
{
	trace("%p %p %p %p %08lx %08lx %08lx\n",
		  SourceProcessHandle, SourceHandle, TargetProcessHandle,
		  TargetHandle, DesiredAccess, Attributes, Options);

	NTSTATUS r;

	process_t *sp = 0;
	r = process_from_handle( SourceProcessHandle, &sp );
	if (r < STATUS_SUCCESS)
		return r;

	trace("source process %p\n", sp );

	object_t *obj = 0;
	r = sp->handle_table.object_from_handle( obj, SourceHandle, DesiredAccess );
	if (r < STATUS_SUCCESS)
		return r;

	// don't lose the object if it's closed
	addref( obj );

	// FIXME: handle other options
	if (Options & DUPLICATE_CLOSE_SOURCE)
	{
		sp->handle_table.free_handle( SourceHandle );
	}

	// put the object into the target process's handle table
	process_t *tp = 0;
	r = process_from_handle( TargetProcessHandle, &tp );
	trace("target process %p\n", tp );
	if (r == STATUS_SUCCESS)
	{
		HANDLE handle;
		r = process_alloc_user_handle( tp, obj, DesiredAccess, TargetHandle, &handle );
		trace("new handle is %p\n", handle );
	}

	release( obj );

	return r;
}

NTSTATUS NTAPI NtQuerySecurityObject(
	HANDLE ObjectHandle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG SecurityDescriptorLength,
	PULONG ReturnLength)
{
	NTSTATUS r;

	// always checked
	r = verify_for_write( ReturnLength, sizeof *ReturnLength );
	if (r < STATUS_SUCCESS)
		return r;

	object_t *obj = 0;
	r = object_from_handle( obj, ObjectHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	SECURITY_DESCRIPTOR_RELATIVE sdr;
	ULONG sz = sizeof sdr;

#define SINF(x) ((SecurityInformation & (x)) ? #x " " : "")
	trace("%08lx = %s%s%s%s\n", SecurityInformation,
		  SINF(OWNER_SECURITY_INFORMATION),
		  SINF(GROUP_SECURITY_INFORMATION),
		  SINF(SACL_SECURITY_INFORMATION),
		  SINF(DACL_SECURITY_INFORMATION));
#undef SINF

	if (SecurityDescriptorLength >= sz)
	{
		sdr.Revision = SECURITY_DESCRIPTOR_REVISION;
		sdr.Sbz1 = 0;
		sdr.Control = SE_SELF_RELATIVE;

		// initialize offsets
		sdr.Owner = 0;
		sdr.Group = 0;
		sdr.Sacl = 0; // System Access Control List
		sdr.Dacl = 0; // Discretionary Access Control List

		r = copy_to_user( SecurityDescriptor, &sdr, sizeof sdr );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		r = STATUS_BUFFER_TOO_SMALL;

	copy_to_user( ReturnLength, &sz, sizeof sz);

	return r;
}

NTSTATUS NTAPI NtPrivilegeObjectAuditAlarm(
	PUNICODE_STRING SubsystemName,
	PVOID HandleId,
	HANDLE TokenHandle,
	ACCESS_MASK DesiredAccess,
	PPRIVILEGE_SET Privileges,
	BOOLEAN AccessGranted)
{
	unicode_string_t us;
	NTSTATUS r;

	r = us.copy_from_user( SubsystemName );
	if (r < STATUS_SUCCESS)
		return r;
	trace("SubsystemName = %pus\n", &us);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI NtPrivilegedServiceAuditAlarm(
	PUNICODE_STRING SubsystemName,
	PUNICODE_STRING ServiceName,
	HANDLE TokenHandle,
	PPRIVILEGE_SET Privileges,
	BOOLEAN AccessGranted)
{
	trace("\n");
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS NTAPI NtCloseObjectAuditAlarm(
	PUNICODE_STRING SubsystemName,
	PVOID HandleId,
	BOOLEAN GenerateOnClose)
{
	unicode_string_t us;
	NTSTATUS r;

	r = us.copy_from_user( SubsystemName );
	if (r < STATUS_SUCCESS)
		return r;
	trace("SubsystemName = %pus\n", &us);

	return STATUS_SUCCESS;
}
