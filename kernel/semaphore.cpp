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
#include "ntcall.h"
#include "object.inl"

class semaphore_t : public SYNC_OBJECT
{
protected:
	ULONG count;
	ULONG max_count;
public:
	semaphore_t( ULONG Initial, ULONG Maximum );
	virtual ~semaphore_t();
	virtual BOOLEAN IsSignalled();
	virtual BOOLEAN Satisfy();
	NTSTATUS release( ULONG count, ULONG& prev );
};

semaphore_t::semaphore_t( ULONG Initial, ULONG Maximum ) :
	count(Initial),
	max_count(Maximum)
{
}

semaphore_t::~semaphore_t()
{
}

BOOLEAN semaphore_t::IsSignalled()
{
	return (count>0);
}

BOOLEAN semaphore_t::Satisfy()
{
	count--;
	return TRUE;
}

NTSTATUS semaphore_t::release( ULONG release_count, ULONG& prev )
{
	prev = count;
	if ((count + release_count) > max_count)
		return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
	// FIXME: will this wake release_count watchers exactly?
	if (!count)
		NotifyWatchers();
	count += release_count;
	return STATUS_SUCCESS;
}

semaphore_t* semaphore_from_obj( OBJECT* obj )
{
	return dynamic_cast<semaphore_t*>(obj);
}

class semaphore_factory : public OBJECT_FACTORY
{
private:
	ULONG InitialCount;
	ULONG MaximumCount;
public:
	semaphore_factory(ULONG init, ULONG max) : InitialCount(init), MaximumCount(max) {}
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS semaphore_factory::AllocObject(OBJECT** obj)
{
	*obj = new semaphore_t( InitialCount, MaximumCount );
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateSemaphore(
	PHANDLE SemaphoreHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG InitialCount,
	ULONG MaximumCount )
{
	trace("%p %08lx %p %lu %lu\n", SemaphoreHandle, DesiredAccess,
		  ObjectAttributes, InitialCount, MaximumCount);

	semaphore_factory factory(InitialCount, MaximumCount);
	return factory.Create( SemaphoreHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtReleaseSemaphore(
	HANDLE SemaphoreHandle,
	ULONG ReleaseCount,
	PULONG PreviousCount)
{
	NTSTATUS r;

	trace("%p %ld %p\n", SemaphoreHandle, ReleaseCount, PreviousCount);

	if (ReleaseCount<1)
		return STATUS_INVALID_PARAMETER;

	semaphore_t *semaphore = 0;
	r = ObjectFromHandle( semaphore, SemaphoreHandle, SEMAPHORE_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	ULONG prev;
	r = semaphore->release( ReleaseCount, prev );
	if (r == STATUS_SUCCESS && PreviousCount)
	{
		r = CopyToUser( PreviousCount, &prev, sizeof prev );
	}

	return r;
}

NTSTATUS NTAPI NtOpenSemaphore(
	PHANDLE SemaphoreHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %ld %p\n", SemaphoreHandle, DesiredAccess, ObjectAttributes);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQuerySemaphore(
	HANDLE SemaphoreHandle,
	SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	PVOID SemaphoreInformation,
	ULONG SemaphoreInformationLength,
	PULONG ReturnLength)
{
	trace("%p %d %p %lu %p\n", SemaphoreHandle, SemaphoreInformationClass,
		  SemaphoreInformation, SemaphoreInformationLength, ReturnLength);
	return STATUS_NOT_IMPLEMENTED;
}
