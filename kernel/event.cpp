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
#include "unicode.h"
#include "object.inl"
#include "event.h"

class EVENT_IMPL : public EVENT
{
protected:
	BOOLEAN state;
public:
	EVENT_IMPL( BOOLEAN _state );
	virtual ~EVENT_IMPL();
	virtual BOOLEAN IsSignalled( void );
	virtual BOOLEAN Satisfy( void ) = 0;
	void Set( PULONG prev );
	void Reset( PULONG prev );
	void Pulse( PULONG prev );
	virtual void Query(EVENT_BASIC_INFORMATION &info) = 0;
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
};

class AUTO_EVENT : public EVENT_IMPL
{
public:
	AUTO_EVENT( BOOLEAN state );
	virtual BOOLEAN Satisfy( void );
	virtual void Query(EVENT_BASIC_INFORMATION &info);
};

class MANUAL_EVENT : public EVENT_IMPL
{
public:
	MANUAL_EVENT( BOOLEAN state );
	virtual BOOLEAN Satisfy( void );
	virtual void Query(EVENT_BASIC_INFORMATION &info);
};

EVENT_IMPL::EVENT_IMPL( BOOLEAN _state ) :
	state( _state )
{
}

bool EVENT_IMPL::AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return check_access( required, handle,
						 EVENT_QUERY_STATE,
						 EVENT_MODIFY_STATE,
						 EVENT_ALL_ACCESS );
}

AUTO_EVENT::AUTO_EVENT( BOOLEAN _state) :
	EVENT_IMPL( _state )
{
}

MANUAL_EVENT::MANUAL_EVENT( BOOLEAN _state) :
	EVENT_IMPL( _state )
{
}

BOOLEAN EVENT_IMPL::IsSignalled( void )
{
	return state;
}

BOOLEAN AUTO_EVENT::Satisfy( void )
{
	state = 0;
	return TRUE;
}

BOOLEAN MANUAL_EVENT::Satisfy( void )
{
	return TRUE;
}

void AUTO_EVENT::Query( EVENT_BASIC_INFORMATION &info )
{
	info.EventType = SynchronizationEvent;
	info.SignalState = state;
}

void MANUAL_EVENT::Query( EVENT_BASIC_INFORMATION &info )
{
	info.EventType = NotificationEvent;
	info.SignalState = state;
}

EVENT::~EVENT( )
{
}

EVENT_IMPL::~EVENT_IMPL( )
{
}

void EVENT_IMPL::Set( PULONG prev )
{
	*prev = state;
	state = 1;

	notify_watchers();
}

void EVENT_IMPL::Reset( PULONG prev )
{
	*prev = state;
	state = 0;
}

void EVENT_IMPL::Pulse( PULONG prev )
{
	Set(prev);
	ULONG dummy;
	Reset(&dummy);
}

class EVENT_FACTORY : public OBJECT_FACTORY
{
private:
	EVENT_TYPE Type;
	BOOLEAN InitialState;
public:
	EVENT_FACTORY(EVENT_TYPE t, BOOLEAN s) : Type(t), InitialState(s) {}
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS EVENT_FACTORY::AllocObject(OBJECT** obj)
{
	switch (Type)
	{
	case NotificationEvent:
		*obj = new MANUAL_EVENT( InitialState );
		break;
	case SynchronizationEvent:
		*obj = new AUTO_EVENT( InitialState );
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

EVENT* CreateSyncEvent( PWSTR name, BOOL InitialState )
{
	EVENT *event = new AUTO_EVENT( InitialState );
	if (event)
	{
		OBJECT_ATTRIBUTES oa;
		UNICODE_STRING us;
		us.Buffer = name;
		us.Length = strlenW( name ) * 2;
		us.MaximumLength = 0;

		memset( &oa, 0, sizeof oa );
		oa.Length = sizeof oa;
		oa.Attributes = OBJ_CASE_INSENSITIVE;
		oa.ObjectName = &us;

		NTSTATUS r = name_object( event, &oa );
		if (r < STATUS_SUCCESS)
		{
			trace("name_object failed\n");
			release( event );
			event = 0;
		}
	}
	return event;
}

NTSTATUS NTAPI NtCreateEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	EVENT_TYPE EventType,
	BOOLEAN InitialState )
{
	trace("%p %08lx %p %u %u\n", EventHandle, DesiredAccess,
		  ObjectAttributes, EventType, InitialState);

	EVENT_FACTORY factory( EventType, InitialState );
	return factory.create( EventHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %08lx %p\n", EventHandle, DesiredAccess, ObjectAttributes );
	return nt_open_object<EVENT>( EventHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS Nteventfunc( HANDLE Handle, PULONG PreviousState, void (EVENT::*fn)(PULONG) )
{
	NTSTATUS r;
	ULONG prev;

	if (PreviousState)
	{
		r = verify_for_write( PreviousState, sizeof PreviousState );
		if (r < STATUS_SUCCESS)
			return r;
	}

	EVENT *event = 0;
	r = object_from_handle( event, Handle, EVENT_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	(event->*fn)( &prev );

	if (PreviousState)
		copy_to_user( PreviousState, &prev, sizeof prev );

	return r;
}

NTSTATUS NTAPI NtSetEvent(
	HANDLE Handle,
	PULONG PreviousState )
{
	return Nteventfunc( Handle, PreviousState, &EVENT::Set );
}

NTSTATUS NTAPI NtResetEvent(
	HANDLE Handle,
	PULONG PreviousState )
{
	return Nteventfunc( Handle, PreviousState, &EVENT::Reset );
}

NTSTATUS NTAPI NtPulseEvent(
	HANDLE Handle,
	PULONG PreviousState )
{
	return Nteventfunc( Handle, PreviousState, &EVENT::Pulse );
}

NTSTATUS NTAPI NtClearEvent(
	HANDLE Handle)
{
	EVENT *event;
	NTSTATUS r;

	trace("%p\n", Handle);

	r = object_from_handle( event, Handle, EVENT_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	ULONG prev;
	event->Reset( &prev );
	return r;
}

NTSTATUS NTAPI NtQueryEvent(
	HANDLE Handle,
	EVENT_INFORMATION_CLASS EventInformationClass,
	PVOID EventInformation,
	ULONG EventInformationLength,
	PULONG ReturnLength)
{
	EVENT *event;
	NTSTATUS r;

	r = object_from_handle( event, Handle, EVENT_QUERY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	union
	{
		EVENT_BASIC_INFORMATION basic;
	} info;
	ULONG sz = 0;

	switch (EventInformationClass)
	{
	case EventBasicInformation:
		sz = sizeof info.basic;
		break;
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	if (sz != EventInformationLength)
		return STATUS_INFO_LENGTH_MISMATCH;

	event->Query( info.basic );

	r = copy_to_user( EventInformation, &info, sz );
	if (r < STATUS_SUCCESS)
		return r;

	if (ReturnLength)
		copy_to_user( ReturnLength, &sz, sizeof sz );

	return r;
}

class EVENT_PAIR : public OBJECT
{
	AUTO_EVENT low, high;
public:
	EVENT_PAIR();
	NTSTATUS SetLow();
	NTSTATUS SetHigh();
	NTSTATUS SetLowWaitHigh();
	NTSTATUS SetHighWaitLow();
	NTSTATUS WaitHigh();
	NTSTATUS WaitLow();
};

EVENT_PAIR::EVENT_PAIR() :
	low(FALSE), high(FALSE)
{
}

NTSTATUS EVENT_PAIR::SetLow()
{
	ULONG prev;
	low.Set( &prev );
	return STATUS_SUCCESS;
}

NTSTATUS EVENT_PAIR::SetHigh()
{
	ULONG prev;
	high.Set( &prev );
	return STATUS_SUCCESS;
}

NTSTATUS EVENT_PAIR::WaitHigh()
{
	/*wait_watch_t *ww = new wait_watch_t(&high, current, FALSE, NULL);
	if (!ww)
		return STATUS_NO_MEMORY;

	return ww->notify();*/
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS EVENT_PAIR::WaitLow()
{
	/*wait_watch_t *ww = new wait_watch_t(&low, current, FALSE, NULL);
	if (!ww)
		return STATUS_NO_MEMORY;

	return ww->notify();*/
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS EVENT_PAIR::SetLowWaitHigh()
{
	SetLow();
	return WaitHigh();
}

NTSTATUS EVENT_PAIR::SetHighWaitLow()
{
	SetHigh();
	return WaitLow();
}

NTSTATUS EventPairOperation( HANDLE handle, NTSTATUS (EVENT_PAIR::*op)() )
{
	EVENT_PAIR *eventpair = 0;
	NTSTATUS r;
	r = object_from_handle( eventpair, handle, GENERIC_WRITE );
	if (r < STATUS_SUCCESS)
		return r;

	return (eventpair->*op)();
}

class EVENT_PAIR_FACTORY : public OBJECT_FACTORY
{
public:
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS EVENT_PAIR_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new EVENT_PAIR();
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateEventPair(
	PHANDLE EventPairHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %08lx %p\n", EventPairHandle, DesiredAccess, ObjectAttributes);
	EVENT_PAIR_FACTORY factory;
	return factory.create( EventPairHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenEventPair(
	PHANDLE EventPairHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %08lx %p\n", EventPairHandle, DesiredAccess, ObjectAttributes );
	return nt_open_object<EVENT_PAIR>( EventPairHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtSetHighEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::SetHigh );
}

NTSTATUS NTAPI NtSetHighWaitLowEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::SetHighWaitLow );
}

NTSTATUS NTAPI NtSetLowEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::SetLow );
}

NTSTATUS NTAPI NtSetLowWaitHighEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::SetLowWaitHigh );
}

NTSTATUS NTAPI NtWaitHighEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::WaitHigh );
}

NTSTATUS NTAPI NtWaitLowEventPair(
	HANDLE EventPairHandle)
{
	trace("%p\n", EventPairHandle );
	return EventPairOperation( EventPairHandle, &EVENT_PAIR::WaitLow );
}

NTSTATUS NTAPI NtSetLowWaitHighThread(void)
{
	trace("\n");
	return STATUS_NO_EVENT_PAIR;
}

NTSTATUS NTAPI NtSetHighWaitLowThread(void)
{
	trace("\n");
	return STATUS_NO_EVENT_PAIR;
}

NTSTATUS NTAPI NtOpenKeyedEvent(
	PHANDLE EventHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	// hack: just open an event for the moment
	return nt_open_object<EVENT>( EventHandle, DesiredAccess, ObjectAttributes );
}
