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

class SEMAPHORE : public SYNC_OBJECT
{
protected:
	ULONG Count;
	ULONG MaxCount;
public:
	SEMAPHORE( ULONG Initial, ULONG Maximum );
	virtual ~SEMAPHORE();
	virtual BOOLEAN IsSignalled();
	virtual BOOLEAN Satisfy();
	NTSTATUS release( ULONG count, ULONG& prev );
};

SEMAPHORE::SEMAPHORE( ULONG Initial, ULONG Maximum ) :
	Count(Initial),
	MaxCount(Maximum)
{
}

SEMAPHORE::~SEMAPHORE()
{
}

BOOLEAN SEMAPHORE::IsSignalled()
{
	return (Count>0);
}

BOOLEAN SEMAPHORE::Satisfy()
{
	Count--;
	return TRUE;
}

NTSTATUS SEMAPHORE::release( ULONG release_count, ULONG& prev )
{
	prev = Count;
	if ((Count + release_count) > MaxCount)
		return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
	// FIXME: will this wake release_count watchers exactly?
	if (!Count)
		NotifyWatchers();
	Count += release_count;
	return STATUS_SUCCESS;
}

SEMAPHORE* SemaphoreFromObj( OBJECT* obj )
{
	return dynamic_cast<SEMAPHORE*>(obj);
}

class SEMAPHORE_FACTORY : public OBJECT_FACTORY
{
private:
	ULONG InitialCount;
	ULONG MaximumCount;
public:
	SEMAPHORE_FACTORY(ULONG init, ULONG max) : InitialCount(init), MaximumCount(max) {}
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS SEMAPHORE_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new SEMAPHORE( InitialCount, MaximumCount );
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

	SEMAPHORE_FACTORY factory(InitialCount, MaximumCount);
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

	SEMAPHORE *semaphore = 0;
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
