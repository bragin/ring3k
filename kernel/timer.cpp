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
#include <sys/time.h>
#include <time.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "timer.h"
#include "ntcall.h"
#include "object.h"
#include "debug.h"
#include "object.inl"

TIMEOUT_LIST TIMEOUT::g_Timeouts;
static LARGE_INTEGER BootTime;
static ULONG TickCount;

bool TIMEOUT::HasExpired()
{
	return !Entry[0].IsLinked();
}

bool TIMEOUT::QueueIsValid()
{
	TIMEOUT_ITER i(g_Timeouts);
	TIMEOUT *prev = 0;

	i.Reset();
	while (i)
	{
		TIMEOUT* x = i;
		if (prev && prev->Expires.QuadPart > x->Expires.QuadPart)
			return false;
		i.Next();
		prev = x;
	}

	return true;
}

// returns false if there were no timers
bool TIMEOUT::CheckTimers(LARGE_INTEGER& ret)
{
	LARGE_INTEGER now = CurrentTime();
	TIMEOUT *t;

	if (!g_Timeouts.Head())
		return false;

	ret.QuadPart = 0LL;
	while (1)
	{
		t = g_Timeouts.Head();
		if (!t)
			return true;

		if (t->Expires.QuadPart > now.QuadPart)
			break;

		t->DoTimeout();
	}

	// calculate the timeout
	ret.QuadPart = t->Expires.QuadPart - now.QuadPart;

	return true;
}

// FIXME: consider unifying this with logic in check_timers
//        to avoid conflicting return values
void TIMEOUT::TimeRemaining( LARGE_INTEGER& remaining )
{
	LARGE_INTEGER now = CurrentTime();
	remaining.QuadPart = Expires.QuadPart - now.QuadPart;
}

TIMEOUT::TIMEOUT(PLARGE_INTEGER t)
{
	SetTimeout(t);
}

void TIMEOUT::SetTimeout(PLARGE_INTEGER t)
{
	if (!t)
	{
		Remove();
		Expires.QuadPart = 0LL;
		return;
	}

	LARGE_INTEGER now = CurrentTime();
	if (t->QuadPart <= 0LL)
		Expires.QuadPart = now.QuadPart - t->QuadPart;
	else
		Expires.QuadPart = t->QuadPart;

	// check there wasn't an overflow
	if (Expires.QuadPart < 0LL)
		Expires.QuadPart = 0x7fffffffffffffffLL;

	Add();
	assert(!g_Timeouts.Empty());
	assert( QueueIsValid() );
}

void TIMEOUT::Add()
{
	TIMEOUT_ITER i(g_Timeouts);
	TIMEOUT* x;

	while ( (x = i) )
	{
		if (x->Expires.QuadPart > Expires.QuadPart)
			break;
		i.Next();
	}

	// if there's a timer before this one, no need to set the interval timer
	if (x)
		g_Timeouts.InsertBefore(x, this);
	else
		g_Timeouts.Append(this);
}

void TIMEOUT::Remove()
{
	if (Entry[0].IsLinked())
		g_Timeouts.Unlink(this);
}

extern KUSER_SHARED_DATA *SharedMemoryAddress;

// numbers from Wine's dlls/ntdll/time.c
/* 1601 to 1970 is 369 years plus 89 leap days */
const ULONGLONG TicksPerSec = 10000000;
const ULONGLONG SecsPerDay = 86400;
const ULONGLONG Secs1601To1970 = (369 * 365 + 89) * SecsPerDay;
const ULONGLONG Ticks1601To1970 = Secs1601To1970 * TicksPerSec;

LARGE_INTEGER TIMEOUT::CurrentTime()
{
	struct timeval tv;

	// timeofday gives seconds and milliseconds since 01-01-1970 00:00:00
	// windows uses 01-01-1601 00:00:00
	gettimeofday(&tv, NULL);
	LARGE_INTEGER ret;
	ret.QuadPart = (tv.tv_sec * 1000000LL + tv.tv_usec) * 10LL;
	ret.QuadPart += Ticks1601To1970;

	// calculate the tick count
	TickCount = (ret.QuadPart - BootTime.QuadPart) / 10000LL;

	// update the time in shared memory
	// High1Time and High2Time need to be the same,
	// as userspace loops waiting for them to be equal
	// presumably to avoid a race when the LowPart overflows
	if (SharedMemoryAddress)
	{
		KSYSTEM_TIME& st = SharedMemoryAddress->SystemTime;
		st.LowPart = ret.LowPart;
		st.High1Time = ret.HighPart;
		st.High2Time = ret.HighPart;

		// http://uninformed.org/index.cgi?v=2&a=2&p=18
		// milliseconds since boot (T)
		// T = shr(TickCountLow * TickCountMultiplier, 24)
		SharedMemoryAddress->TickCountMultiplier = 0x100000;
		SharedMemoryAddress->TickCountLow = ((TickCount * 0x01000000LL)/SharedMemoryAddress->TickCountMultiplier);
	}


	return ret;
}

ULONG TIMEOUT::GetTickCount()
{
	CurrentTime();
	return TickCount;
}

void GetSystemTimeOfDay( SYSTEM_TIME_OF_DAY_INFORMATION& time_of_day )
{
	if (!BootTime.QuadPart)
		BootTime = TIMEOUT::CurrentTime();

	time_of_day.CurrentTime = TIMEOUT::CurrentTime();
	time_of_day.BootTime = BootTime;
	time_of_day.TimeZoneBias.QuadPart = 0LL;
	time_of_day.CurrentTimeZoneId = 0;
}

void TIMEOUT::DoTimeout()
{
	// remove first so we can be added again
	Remove();
	SignalTimeout();
}

TIMEOUT::~TIMEOUT()
{
	Remove();
}

class NTTIMER : public SYNC_OBJECT, public TIMEOUT
{
protected:
	BOOLEAN Expired;
	ULONG Interval;
	THREAD *Thread;
	PKNORMAL_ROUTINE ApcRoutine;
	PVOID ApcContext;
public:
	NTTIMER();
	~NTTIMER();
	NTSTATUS Set(LARGE_INTEGER& DueTime, PKNORMAL_ROUTINE apc, PVOID context, BOOLEAN Resume, ULONG Period, BOOLEAN& prev);
	virtual BOOLEAN IsSignalled( void );
	virtual BOOLEAN Satisfy( void );
	virtual void SignalTimeout();
	void Cancel( BOOLEAN& prev );
};

NTTIMER::NTTIMER() :
	Expired(FALSE),
	Interval(0),
	Thread(0),
	ApcRoutine(0),
	ApcContext(0)
{
}

NTTIMER::~NTTIMER()
{
	if (Thread)
		Release( Thread );
}

NTTIMER *NtTimerFromObj( OBJECT *obj )
{
	return dynamic_cast<NTTIMER*>( obj );
}

BOOLEAN NTTIMER::IsSignalled( void )
{
	return Expired;
}

BOOLEAN NTTIMER::Satisfy( void )
{
	// FIXME: user correct time values
	if (ApcRoutine)
		Thread->QueueApcThread( ApcRoutine, ApcContext, 0, 0 );

	// restart the timer
	if (Interval)
	{
		LARGE_INTEGER when;
		when.QuadPart = Interval * -10000LL;
		SetTimeout( &when );
	}
	return TRUE;
}

void NTTIMER::SignalTimeout()
{
	Expired = TRUE;
	NotifyWatchers();
}

NTSTATUS NTTIMER::Set(
	LARGE_INTEGER& DueTime,
	PKNORMAL_ROUTINE apc,
	PVOID context,
	BOOLEAN Resume,
	ULONG Period,
	BOOLEAN& prev)
{
	//trace("%ld %p %p %d %ld\n", (ULONG)DueTime.QuadPart, apc, context, Resume, Period );

	prev = Expired;
	Interval = Period;
	Thread = Current;
	AddRef( Thread );
	ApcRoutine = apc;
	ApcContext = context;

	if (DueTime.QuadPart == 0LL)
	{
		Expired = TRUE;
		return STATUS_SUCCESS;
	}

	Expired = FALSE;
	SetTimeout( &DueTime );

	return STATUS_SUCCESS;
}

void NTTIMER::Cancel( BOOLEAN& prev )
{
	prev = Expired;
	SetTimeout( 0 );
	Expired = FALSE;
}

// SYNC_TIMER is a specialized timer
class SYNC_TIMER : public NTTIMER
{
public:
	virtual BOOLEAN Satisfy( void );
};

BOOLEAN SYNC_TIMER::Satisfy()
{
	Expired = FALSE;
	return NTTIMER::Satisfy();
}

class TIMER_FACTORY : public OBJECT_FACTORY
{
private:
	TIMER_TYPE Type;
public:
	TIMER_FACTORY(TIMER_TYPE t) : Type(t) {}
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS TIMER_FACTORY::AllocObject(OBJECT** obj)
{
	switch (Type)
	{
	case SynchronizationTimer:
		*obj = new SYNC_TIMER();
		break;
	case NotificationTimer:
		//*obj = new notify_timer_t();
		*obj = new NTTIMER();
		break;
	default:
		return STATUS_INVALID_PARAMETER_4;
	}
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateTimer(
	PHANDLE TimerHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes,
	TIMER_TYPE Type)
{
	trace("%p %08lx %p %u\n", TimerHandle, AccessMask, ObjectAttributes, Type );

	TIMER_FACTORY factory( Type );
	return factory.Create( TimerHandle, AccessMask, ObjectAttributes );
}

NTSTATUS NtOpenTimer(
	PHANDLE TimerHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("\n");
	return NtOpenObject<NTTIMER>( TimerHandle, AccessMask, ObjectAttributes );
}

NTSTATUS NtCancelTimer(
	HANDLE TimerHandle,
	PBOOLEAN PreviousState)
{
	NTSTATUS r;

	NTTIMER* timer = 0;
	r = ObjectFromHandle( timer, TimerHandle, TIMER_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	if (PreviousState)
	{
		r = VerifyForWrite( PreviousState, sizeof *PreviousState );
		if (r < STATUS_SUCCESS)
			return r;
	}

	BOOLEAN prev = 0;
	timer->Cancel(prev);

	if (PreviousState)
		CopyToUser( PreviousState, &prev, sizeof prev );

	return STATUS_SUCCESS;
}

NTSTATUS NtSetTimer(
	HANDLE TimerHandle,
	PLARGE_INTEGER DueTime,
	PTIMER_APC_ROUTINE TimerApcRoutine,
	PVOID TimerContext,
	BOOLEAN Resume,
	LONG Period,
	PBOOLEAN PreviousState)
{
	LARGE_INTEGER due;

	NTSTATUS r = CopyFromUser( &due, DueTime, sizeof due );
	if (r < STATUS_SUCCESS)
		return r;

	trace("due = %llx\n", due.QuadPart);

	NTTIMER* timer = 0;
	r = ObjectFromHandle( timer, TimerHandle, TIMER_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	if (PreviousState)
	{
		r = VerifyForWrite( PreviousState, sizeof *PreviousState );
		if (r < STATUS_SUCCESS)
			return r;
	}

	BOOLEAN prev = FALSE;
	r = timer->Set( due, (PKNORMAL_ROUTINE)TimerApcRoutine, TimerContext, Resume, Period, prev );
	if (r == STATUS_SUCCESS && PreviousState )
		CopyToUser( PreviousState, &prev, sizeof prev );

	return r;
}

NTSTATUS NTAPI NtQueryTimer(
	HANDLE TimerHandle,
	TIMER_INFORMATION_CLASS TimerInformationClass,
	PVOID TimerInformation,
	ULONG TimerInformationLength,
	PULONG ResultLength)
{
	NTSTATUS r;

	NTTIMER* timer = 0;
	r = ObjectFromHandle( timer, TimerHandle, TIMER_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	union
	{
		TIMER_BASIC_INFORMATION basic;
	} info;
	ULONG sz = 0;

	switch (TimerInformationClass)
	{
	case TimerBasicInformation:
		sz = sizeof info.basic;
		break;
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	// this seems like the wrong order, but agrees with what tests show
	r = VerifyForWrite( TimerInformation, sz );
	if (r < STATUS_SUCCESS)
		return r;

	if (sz != TimerInformationLength)
		return STATUS_INFO_LENGTH_MISMATCH;

	switch (TimerInformationClass)
	{
	case TimerBasicInformation:
		info.basic.SignalState = timer->IsSignalled();
		timer->TimeRemaining( info.basic.TimeRemaining );
		break;
	default:
		assert(0);
	}

	r = CopyToUser( TimerInformation, &info, sz );
	if (r < STATUS_SUCCESS)
		return r;

	if (ResultLength)
		CopyToUser( ResultLength, &sz, sizeof sz );

	return r;
}

NTSTATUS NTAPI NtQuerySystemTime(PLARGE_INTEGER CurrentTime)
{
	LARGE_INTEGER now = TIMEOUT::CurrentTime();

	return CopyToUser( CurrentTime, &now, sizeof now );
}

NTSTATUS NTAPI NtQueryTimerResolution( PULONG CoarsestResolution, PULONG FinestResolution, PULONG ActualResolution)
{
	ULONG resolution = 100000LL; // 10ms
	NTSTATUS r;
	r = CopyToUser( CoarsestResolution, &resolution );
	if (r < STATUS_SUCCESS)
		return r;
	r = CopyToUser( FinestResolution, &resolution );
	if (r < STATUS_SUCCESS)
		return r;
	r = CopyToUser( ActualResolution, &resolution );
	if (r < STATUS_SUCCESS)
		return r;
	return STATUS_SUCCESS;
}
