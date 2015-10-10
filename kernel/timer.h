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

#ifndef __TIMER_H__
#define __TIMER_H__

#include "list.h"

class TIMEOUT;

typedef LIST_ELEMENT<TIMEOUT> TIMEOUT_ENTRY;
typedef LIST_ANCHOR<TIMEOUT,0> TIMEOUT_LIST;
typedef LIST_ITER<TIMEOUT,0> TIMEOUT_ITER;

class TIMEOUT
{
	friend class LIST_ANCHOR<TIMEOUT,0> ;
	friend class LIST_ITER<TIMEOUT,0> ;
	TIMEOUT_ENTRY Entry[1];
private:
	static TIMEOUT_LIST g_Timeouts;
	LARGE_INTEGER Expires;
protected:
	void Add();
	void Remove();
	//void Set();
public:
	explicit TIMEOUT(PLARGE_INTEGER t = 0);
	void Set(PLARGE_INTEGER t);
	virtual ~TIMEOUT();
	static LARGE_INTEGER CurrentTime();
	static ULONG GetTickCount();
	void DoTimeout();
	void SetTimeout(PLARGE_INTEGER t);
	virtual void SignalTimeout() = 0;
	//static bool Timersctive();
	static bool CheckTimers(LARGE_INTEGER& ret);
	bool HasExpired();
	void TimeRemaining( LARGE_INTEGER& remaining );
	static bool QueueIsValid();
};

void GetSystemTimeOfDay( SYSTEM_TIME_OF_DAY_INFORMATION& time_of_day );

#endif // __TIMER_H__
