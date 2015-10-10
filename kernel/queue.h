/*
 * nt loader
 *
 * Copyright 2009 Mike McCormack
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

#ifndef __RING3K_QUEUE__
#define __RING3K_QUEUE__

#include "ntwin32.h"

class CMSG;
class MSG_WAITER;
class THREAD_MESSAGE_QUEUE;

typedef LIST_ANCHOR<CMSG,0> MSG_LIST;
typedef LIST_ITER<CMSG,0> MSG_ITER;
typedef LIST_ELEMENT<CMSG> MSG_ELEMENT;

typedef LIST_ANCHOR<MSG_WAITER,0> MSG_WAITER_LIST;
typedef LIST_ITER<MSG_WAITER,0> MSG_WAITER_ITER;
typedef LIST_ELEMENT<MSG_WAITER> MSG_WAITER_ELEMENT;

class MSG_WAITER
{
	friend class THREAD_MESSAGE_QUEUE;
	friend class LIST_ANCHOR<MSG_WAITER,0>;
	MSG_WAITER_ELEMENT Entry[1];
	THREAD *T;
	MSG& Msg;
public:
	MSG_WAITER( MSG& m);
};

class CMSG
{
public:
	MSG_ELEMENT Entry[1];
	HWND HWnd;
	UINT Message;
	WPARAM WParam;
	LPARAM LParam;
	DWORD Time;
public:
	CMSG( HWND _hwnd, UINT Message, WPARAM Wparam, LPARAM Lparam );
};

class WIN_TIMER;

typedef LIST_ANCHOR<WIN_TIMER,0> WIN_TIMER_LIST;
typedef LIST_ITER<WIN_TIMER,0> WIN_TIMER_ITER;
typedef LIST_ELEMENT<WIN_TIMER> WIN_TIMER_ELEMENT;

class WIN_TIMER
{
public:
	WIN_TIMER_ELEMENT Entry[1];
	HWND HWnd;
	UINT Id;
	void *LParam;
	UINT Period;
	LARGE_INTEGER Expiry;
public:
	WIN_TIMER( HWND Window, UINT Identifier );
	void Reset();
	bool Expired() const;
};

// derived from Wine's struct thread_input
// see wine/server/queue.c (by Alexandre Julliard)
class THREAD_MESSAGE_QUEUE :
	public SYNC_OBJECT,
	public timeout_t
{
	bool	QuitMessage;    // is there a pending quit message?
	int	ExitCode;       // exit code of pending quit message
	MSG_LIST MsgList;
	MSG_WAITER_LIST WaiterList;
	WIN_TIMER_LIST TimerList;
public:
	THREAD_MESSAGE_QUEUE();
	~THREAD_MESSAGE_QUEUE();
	BOOL PostMessage( HWND Window, UINT Message, WPARAM Wparam, LPARAM Lparam );
	void PostQuitMessage( ULONG exit_code );
	bool GetQuitMessage( MSG &msg );
	bool GetPaintMessage( HWND Window, MSG& msg );
	virtual BOOLEAN IsSignalled( void );
	virtual void SignalTimeout();
	BOOLEAN GetMessage( MSG& Message, HWND Window, ULONG MinMessage, ULONG MaxMessage);
	BOOLEAN GetMessageNoWait( MSG& Message, HWND Window, ULONG MinMessage, ULONG MaxMessage);
	bool GetPostedMessage( HWND Window, MSG& Message );
	BOOLEAN SetTimer( HWND Window, UINT Identifier, UINT Elapse, PVOID TimerProc );
	BOOLEAN KillTimer( HWND Window, UINT Identifier );
	WIN_TIMER* FindTimer( HWND Window, UINT Identifier );
	void TimerAdd( WIN_TIMER* timer );
	bool GetTimerMessage( HWND Window, MSG& msg );
	bool GetMessageTimeout( HWND Window, LARGE_INTEGER& timeout );
};

HWND FindWindowToRepaint( HWND Window, THREAD *thread );

#endif // __RING3K_QUEUE__
