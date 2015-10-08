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
#include "debug.h"

#include "object.h"
#include "thread.h"
#include "ntcall.h"
#include "object.inl"

class MUTANT : public SYNC_OBJECT
{
	THREAD *owner;
	ULONG count;
public:
	MUTANT(BOOLEAN InitialOwner);
	NTSTATUS TakeOwnership();
	NTSTATUS ReleaseOwnership(ULONG& prev);
	virtual BOOLEAN IsSignalled();
	virtual BOOLEAN Satisfy();
};

MUTANT *MutantFromObj( OBJECT *obj )
{
	return dynamic_cast<MUTANT*>( obj );
}

MUTANT::MUTANT(BOOLEAN InitialOwner) :
	owner(0),
	count(0)
{
	if (InitialOwner)
		TakeOwnership();
}

BOOLEAN MUTANT::IsSignalled()
{
	return current != NULL;
}

BOOLEAN MUTANT::Satisfy()
{
	TakeOwnership();
	return TRUE;
}

NTSTATUS MUTANT::TakeOwnership()
{
	if (owner && owner != current)
		return STATUS_MUTANT_NOT_OWNED;
	owner = current;
	count++;
	return STATUS_SUCCESS;
}

NTSTATUS MUTANT::ReleaseOwnership(ULONG& prev)
{
	if (owner != current)
		return STATUS_MUTANT_NOT_OWNED;
	prev = count;
	if (!--count)
		owner = 0;
	return STATUS_SUCCESS;
}

class MUTANT_FACTORY : public OBJECT_FACTORY
{
private:
	BOOLEAN InitialOwner;
public:
	MUTANT_FACTORY(BOOLEAN io) : InitialOwner(io) {};
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS MUTANT_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new MUTANT(InitialOwner);
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateMutant(
	PHANDLE MutantHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN InitialOwner)
{
	trace("%p %08lx %p %u\n", MutantHandle,
		  AccessMask, ObjectAttributes, InitialOwner);

	MUTANT_FACTORY factory( InitialOwner );
	return factory.create( MutantHandle, AccessMask, ObjectAttributes );
}

NTSTATUS NTAPI NtReleaseMutant(
	HANDLE MutantHandle,
	PULONG PreviousState)
{
	MUTANT *mutant = 0;
	ULONG prev = 0;
	NTSTATUS r;

	trace("%p %p\n", MutantHandle, PreviousState);

	r = object_from_handle( mutant, MutantHandle, MUTEX_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	if (PreviousState)
	{
		r = verify_for_write( PreviousState, sizeof PreviousState );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = mutant->ReleaseOwnership( prev );
	if (r == STATUS_SUCCESS && PreviousState)
		r = copy_to_user( PreviousState, &prev, sizeof prev );

	return r;
}

NTSTATUS NTAPI NtOpenMutant(
	PHANDLE MutantHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %08lx %p\n", MutantHandle, DesiredAccess, ObjectAttributes );
	return nt_open_object<MUTANT>( MutantHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtQueryMutant(
	HANDLE MutantHandle,
	MUTANT_INFORMATION_CLASS MutantInformationClass,
	PVOID MutantInformation,
	ULONG MutantInformationLength,
	PULONG ReturnLength)
{
	return STATUS_NOT_IMPLEMENTED;
}
