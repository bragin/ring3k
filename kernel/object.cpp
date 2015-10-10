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

OPEN_INFO::OPEN_INFO() :
	Attributes( 0 ),
	Root( 0 )
{
}

OPEN_INFO::~OPEN_INFO()
{
}

void OBJECT::AddRef( OBJECT *obj )
{
	obj->RefCount ++;
	//trace("%p has %ld refs\n", obj, obj->refcount);
}

void OBJECT::Release( OBJECT *obj )
{
	//trace("%p has %ld refs left\n", obj, obj->refcount - 1);
	if (!--obj->RefCount)
	{
		//trace("destroying %p\n", obj);
		delete obj;
	}
}

NTSTATUS OBJECT::Open( OBJECT *&out, OPEN_INFO& info )
{
	if (info.Path.Length != 0)
	{
		trace("length not zero\n");
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	AddRef( this );
	out = this;
	return STATUS_SUCCESS;
}

HANDLE HANDLE_TABLE::IndexToHandle( ULONG index )
{
	return (HANDLE)((index+1)*4);
}

ULONG HANDLE_TABLE::HandleToIndex( HANDLE handle )
{
	return ((ULONG)handle)/4 - 1;
}

HANDLE HANDLE_TABLE::AllocHandle( OBJECT *obj, ACCESS_MASK access )
{
	ULONG i;

	for (i=0; i<MaxHandles; i++)
	{
		if (!Info[i].Object)
		{
			Info[i].Object = obj;
			Info[i].Access = access;
			AddRef( obj );
			return IndexToHandle( i );
		}
	}
	return 0;
}

NTSTATUS HANDLE_TABLE::FreeHandle( HANDLE handle )
{
	OBJECT *obj;
	ULONG n;

	n = (ULONG) handle;
	if (!n)
		return STATUS_INVALID_HANDLE;
	if (n&3)
		return STATUS_INVALID_HANDLE;

	n = HandleToIndex( handle );
	if (n >= MaxHandles)
		return STATUS_INVALID_HANDLE;

	obj = Info[n].Object;
	if (!obj)
		return STATUS_INVALID_HANDLE;

	Release( obj );
	Info[n].Object = NULL;
	Info[n].Access = 0;

	return STATUS_SUCCESS;
}

NTSTATUS HANDLE_TABLE::ObjectFromHandle( OBJECT*& obj, HANDLE handle, ACCESS_MASK access )
{
	if (handle == NtCurrentThread())
	{
		obj = Current;
		return STATUS_SUCCESS;
	}
	if (handle == NtCurrentProcess())
	{
		obj = Current->Process;
		return STATUS_SUCCESS;
	}
	ULONG n = (ULONG) handle;
	if (!n)
		return STATUS_INVALID_HANDLE;
	if (n&3)
		return STATUS_INVALID_HANDLE;
	n = HandleToIndex( handle );
	if (n >= MaxHandles)
		return STATUS_INVALID_HANDLE;
	if (!Info[n].Object)
		return STATUS_INVALID_HANDLE;
	if (!Info[n].Object->AccessAllowed( access, Info[n].Access ))
		return STATUS_ACCESS_DENIED;
	obj = Info[n].Object;
	return STATUS_SUCCESS;
}

HANDLE_TABLE::~HANDLE_TABLE()
{
	FreeAllHandles();
}

void HANDLE_TABLE::FreeAllHandles()
{
	OBJECT *obj;
	ULONG i;

	for ( i=0; i<MaxHandles; i++ )
	{
		obj = Info[i].Object;
		if (!obj)
			continue;

		Release( obj );
		Info[i].Object = NULL;
	}
}

NTSTATUS OBJECT_FACTORY::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	// object already exists?
	if (obj)
	{
		if (!(info.Attributes & OBJ_OPENIF))
			return STATUS_OBJECT_NAME_COLLISION;
		AddRef( obj );
		return STATUS_OBJECT_NAME_EXISTS;
	}

	NTSTATUS r;
	r = AllocObject( &obj );
	if (r < STATUS_SUCCESS)
		return r;

	r = obj->Name.copy( &info.Path );
	if (r < STATUS_SUCCESS)
		return r;

	dir->Append( obj );

	return STATUS_SUCCESS;
}

NTSTATUS OBJECT_FACTORY::CreateKernel( OBJECT*& obj, UNICODE_STRING& us )
{
	Path.set( us );
	return OpenRoot( obj, *this );
}

NTSTATUS OBJECT_FACTORY::Create(
	PHANDLE Handle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	object_attributes_t oa;
	OBJECT *obj = 0;
	NTSTATUS r;

	r = VerifyForWrite( Handle, sizeof *Handle );
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
		Path.set( *oa.ObjectName );
		Root = oa.RootDirectory;
		Attributes = oa.Attributes;
		r = OpenRoot( obj, *this );
	}
	else
	{
		r = AllocObject( &obj );
	}

	if (r < STATUS_SUCCESS)
		return r;

	// maybe this should be done in AllocObject ?
	NTSTATUS r2 = AllocUserHandle( obj, AccessMask, Handle );
	if (r2 == STATUS_SUCCESS && (oa.Attributes & OBJ_PERMANENT ))
		trace("permanent object\n");
	else
		Release( obj );

	return r;
}

OBJECT_FACTORY::~OBJECT_FACTORY()
{
}

OBJECT::OBJECT() :
	RefCount( 1 ),
	Attr( 0 ),
	Parent( 0 )
{
}

OBJECT::~OBJECT()
{
	if (Parent)
		Parent->Unlink( this );
}

bool OBJECT::CheckAccess( ACCESS_MASK required, ACCESS_MASK handle, ACCESS_MASK read, ACCESS_MASK write, ACCESS_MASK all )
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

bool OBJECT::AccessAllowed( ACCESS_MASK access, ACCESS_MASK handle_access )
{
	trace("fixme: no access check\n");
	return true;
}

SYNC_OBJECT::SYNC_OBJECT()
{
}

SYNC_OBJECT::~SYNC_OBJECT()
{
	assert( Watchers.Empty() );
}

void SYNC_OBJECT::NotifyWatchers()
{
	WATCH_ITER i(Watchers);
	while (i)
	{
		WATCH *w = i;
		i.Next();
		w->Notify();
	}
}

void SYNC_OBJECT::AddWatch( WATCH *watch )
{
	Watchers.Append( watch );
}

void SYNC_OBJECT::RemoveWatch( WATCH *watch )
{
	Watchers.Unlink( watch );
}

WATCH::~WATCH()
{
}

BOOLEAN SYNC_OBJECT::Satisfy( void )
{
	return TRUE;
}

NTSTATUS NTAPI NtClose( HANDLE Handle )
{
	trace("%p\n", Handle );
	return Current->Process->HandleTable.FreeHandle( Handle );
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
	OBJECT *obj = 0;
	r = ObjectFromHandle( obj, Object, 0 );
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

	r = CopyToUser( ObjectInformation, &info, sz );
	if (r == STATUS_SUCCESS && ReturnLength)
		r = CopyToUser( ReturnLength, &sz, sizeof sz );

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
	OBJECT *obj = 0;
	r = ObjectFromHandle( obj, Object, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &info, ObjectInformation, sz );
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

	PROCESS *sp = 0;
	r = ProcessFromHandle( SourceProcessHandle, &sp );
	if (r < STATUS_SUCCESS)
		return r;

	trace("source process %p\n", sp );

	OBJECT *obj = 0;
	r = sp->HandleTable.ObjectFromHandle( obj, SourceHandle, DesiredAccess );
	if (r < STATUS_SUCCESS)
		return r;

	// don't lose the object if it's closed
	AddRef( obj );

	// FIXME: handle other options
	if (Options & DUPLICATE_CLOSE_SOURCE)
	{
		sp->HandleTable.FreeHandle( SourceHandle );
	}

	// put the object into the target process's handle table
	PROCESS *tp = 0;
	r = ProcessFromHandle( TargetProcessHandle, &tp );
	trace("target process %p\n", tp );
	if (r == STATUS_SUCCESS)
	{
		HANDLE handle;
		r = ProcessAllocUserHandle( tp, obj, DesiredAccess, TargetHandle, &handle );
		trace("new handle is %p\n", handle );
	}

	Release( obj );

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
	r = VerifyForWrite( ReturnLength, sizeof *ReturnLength );
	if (r < STATUS_SUCCESS)
		return r;

	OBJECT *obj = 0;
	r = ObjectFromHandle( obj, ObjectHandle, 0 );
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

		r = CopyToUser( SecurityDescriptor, &sdr, sizeof sdr );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		r = STATUS_BUFFER_TOO_SMALL;

	CopyToUser( ReturnLength, &sz, sizeof sz);

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
