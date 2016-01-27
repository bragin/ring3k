/*
 * message queues
 *
 * Based on wine/server/queue.c
 * Copyright (C) 2000 Alexandre Julliard
 *
 * Modifications for ring3k
 * Copyright 2006-2009 Mike McCormack
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
#include <stdio.h>
#include <assert.h>
#include <new>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "object.h"
#include "ntwin32.h"
#include "mem.h"
#include "debug.h"
#include "list.h"
#include "timer.h"
#include "win.h"
#include "queue.h"
#include "spy.h"

DEFAULT_DEBUG_CHANNEL(queue);

#include "object.inl"

CMSG::CMSG( HWND _hwnd, UINT _message, WPARAM _wparam, LPARAM _lparam ) :
	HWnd( _hwnd ),
	Message( _message ),
	WParam( _wparam ),
	LParam( _lparam )
{
	Time = TIMEOUT::GetTickCount();
}

THREAD_MESSAGE_QUEUE::THREAD_MESSAGE_QUEUE() :
	QuitMessage( 0 ),
	ExitCode( 0 )
{
}

THREAD_MESSAGE_QUEUE::~THREAD_MESSAGE_QUEUE()
{
	CMSG *msg;

	while ((msg = MsgList.Head()))
	{
		MsgList.Unlink( msg );
		delete msg;
	}
}

bool THREAD_MESSAGE_QUEUE::GetQuitMessage( MSG& msg )
{
	bool ret = QuitMessage;
	if (QuitMessage)
	{
		msg.message = WM_QUIT;
		msg.wParam = ExitCode;
		QuitMessage = false;
	}
	return ret;
}

bool THREAD_MESSAGE_QUEUE::GetPaintMessage( HWND Window, MSG& msg )
{
	WINDOW *win = WINDOW::FindWindowToRepaint( Window, Current );
	if (!win)
		return FALSE;

	msg.message = WM_PAINT;
	msg.time = TIMEOUT::GetTickCount();
	msg.hwnd = win->handle;

	return TRUE;
}

BOOLEAN THREAD_MESSAGE_QUEUE::IsSignalled( void )
{
	return FALSE;
}

void THREAD_MESSAGE_QUEUE::PostQuitMessage( ULONG ret )
{
	QuitMessage = true;
	ExitCode = ret;
}

BOOL THREAD_MESSAGE_QUEUE::PostMessage(
	HWND Window, UINT Message, WPARAM Wparam, LPARAM Lparam )
{
	MSG_WAITER *waiter = WaiterList.Head();
	if (waiter)
	{
		MSG& msg = waiter->Msg;
		msg.hwnd = Window;
		msg.message = Message;
		msg.wParam = Wparam;
		msg.lParam = Lparam;
		msg.time = TIMEOUT::GetTickCount();
		msg.pt.x = 0;
		msg.pt.y = 0;

		// remove from the list first
		WaiterList.Unlink( waiter );
		SetTimeout( 0 );

		// start the thread (might reschedule here )
		waiter->T->Start();

		return TRUE;
	}

	// no waiter, so store the message
	CMSG* msg = new CMSG( Window, Message, Wparam, Lparam );
	if (!msg)
		return FALSE;
	MsgList.Append( msg );

	// FIXME: wake up a thread that is waiting
	return TRUE;
}

// return true if we copied a message
bool THREAD_MESSAGE_QUEUE::GetPostedMessage( HWND Window, MSG& Message )
{
	CMSG *m = MsgList.Head();
	if (!m)
		return false;

	MsgList.Unlink( m );
	Message.hwnd = m->HWnd;
	Message.message = m->Message;
	Message.wParam = m->WParam;
	Message.lParam = m->LParam;
	Message.time = m->Time;
	Message.pt.x = 0;
	Message.pt.y = 0;
	delete m;

	return true;
}

MSG_WAITER::MSG_WAITER( MSG& m):
	Msg( m )
{
	T = Current;
}

WIN_TIMER::WIN_TIMER( HWND Window, UINT Identifier ) :
	HWnd( Window ),
	Id( Identifier ),
	LParam(0),
	Period(0)
{
	Expiry.QuadPart = 0LL;
}

WIN_TIMER* THREAD_MESSAGE_QUEUE::FindTimer( HWND Window, UINT Identifier )
{
	for (WIN_TIMER_ITER i(TimerList); i; i.Next())
	{
		WIN_TIMER *t = i;
		if (t->Id != Identifier)
			continue;
		if (t->HWnd != Window )
			continue;
		return t;
	}
	return NULL;
}

void WIN_TIMER::Reset()
{
	Expiry = TIMEOUT::CurrentTime();
	Expiry.QuadPart += Period*10000LL;
}

bool WIN_TIMER::Expired() const
{
	LARGE_INTEGER now = TIMEOUT::CurrentTime();
	return (now.QuadPart >= Expiry.QuadPart);
}

void THREAD_MESSAGE_QUEUE::TimerAdd( WIN_TIMER* timer )
{
	WIN_TIMER *t = NULL;

	// maintain list in order of expiry time
	for (WIN_TIMER_ITER i(TimerList); i; i.Next())
	{
		t = i;
		if (t->Expiry.QuadPart >= timer->Expiry.QuadPart)
			break;
	}
	if (t)
		TimerList.InsertBefore( t, timer );
	else
		TimerList.Append( timer );
}

bool THREAD_MESSAGE_QUEUE::GetTimerMessage( HWND Window, MSG& msg )
{
	LARGE_INTEGER now = TIMEOUT::CurrentTime();
	WIN_TIMER *t = NULL;
	for (WIN_TIMER_ITER i(TimerList); i; i.Next())
	{
		t = i;
		// stop searching after we reach a timer that has not expired
		if (t->Expiry.QuadPart > now.QuadPart)
			return false;
		if (Window == NULL || t->HWnd == Window)
			break;
	}

	if (!t)
		return false;

	// remove from the front of the queue
	TimerList.Unlink( t );

	msg.hwnd = t->HWnd;
	msg.message = WM_TIMER;
	msg.wParam = t->Id;
	msg.lParam = (UINT) t->LParam;
	msg.time = TIMEOUT::GetTickCount();
	msg.pt.x = 0;
	msg.pt.y = 0;

	// reset and add back to the queue
	t->Reset();
	TimerAdd( t );

	return true;
}

BOOLEAN THREAD_MESSAGE_QUEUE::SetTimer( HWND Window, UINT Identifier, UINT Elapse, PVOID TimerProc )
{
	WIN_TIMER* timer = FindTimer( Window, Identifier );
	if (timer)
		TimerList.Unlink( timer );
	else
		timer = new WIN_TIMER( Window, Identifier );
	TRACE("adding timer %p hwnd %p id %d\n", timer, Window, Identifier );
	timer->Period = Elapse;
	timer->LParam = TimerProc;
	TimerAdd( timer );
	return TRUE;
}

BOOLEAN THREAD_MESSAGE_QUEUE::KillTimer( HWND Window, UINT Identifier )
{
	WIN_TIMER* timer = FindTimer( Window, Identifier );
	if (!timer)
		return FALSE;
	TRACE("deleting timer %p hwnd %p id %d\n", timer, Window, Identifier );
	TimerList.Unlink( timer );
	delete timer;
	return TRUE;
}

bool THREAD_MESSAGE_QUEUE::GetMessageTimeout( HWND Window, LARGE_INTEGER& timeout )
{
	for (WIN_TIMER_ITER i(TimerList); i; i.Next())
	{
		WIN_TIMER *t = i;
		if (Window != NULL && t->HWnd != Window)
			continue;
		timeout = t->Expiry;
		return true;
	}
	return false;
}

// return true if we succeeded in copying a message
BOOLEAN THREAD_MESSAGE_QUEUE::GetMessageNoWait(
	MSG& Message, HWND Window, ULONG MinMessage, ULONG MaxMessage)
{
	//trace("checking posted messages\n");
	if (GetPostedMessage( Window, Message ))
		return true;

	//trace("checking quit messages\n");
	if (GetQuitMessage( Message ))
		return true;

	//trace("checking paint messages\n");
	if (GetPaintMessage( Window, Message ))
		return true;

	//trace("checking timer messages\n");
	if (GetTimerMessage( Window, Message ))
		return true;

	return false;
}

void THREAD_MESSAGE_QUEUE::SignalTimeout()
{
	MSG_WAITER *waiter = WaiterList.Head();
	if (waiter)
	{
		WaiterList.Unlink( waiter );
		SetTimeout( 0 );

		// start the thread (might reschedule here )
		waiter->T->Start();
	}
}

BOOLEAN THREAD_MESSAGE_QUEUE::GetMessage(
	MSG& Message, HWND Window, ULONG MinMessage, ULONG MaxMessage)
{
	if (GetMessageNoWait( Message, Window, MinMessage, MaxMessage))
		return true;

	LARGE_INTEGER t;
	if (GetMessageTimeout( Window, t ))
	{
		//trace("setting timeout %lld\n", t.QuadPart);
		SetTimeout( &t );
	}

	// wait for a message
	// a thread sending a message will restart us
	MSG_WAITER wait( Message );
	WaiterList.Append( &wait );
	Current->Stop();

	return !Current->IsTerminated();
}

BOOLEAN NTAPI NtUserGetMessage(PMSG Message, HWND Window, ULONG MinMessage, ULONG MaxMessage)
{
	// create a thread message queue if necessary
	if (!Current->Queue)
	{
		WARN("Calling GetMessage for a thread without input queue, creating it!\n");
		Current->Queue = new THREAD_MESSAGE_QUEUE;
	}

	NTSTATUS r = VerifyForWrite( Message, sizeof *Message );
	if (r != STATUS_SUCCESS)
		return FALSE;

	MSG msg;
	memset( &msg, 0, sizeof msg );
	if (Current->Queue->GetMessage(msg, Window, MinMessage, MaxMessage))
		CopyToUser( Message, &msg, sizeof msg );

	if (OptionTrace)
	{
		fprintf(stderr, "%lx.%lx: %s\n", Current->Process->Id, Current->GetID(), __FUNCTION__);
		fprintf(stderr, " msg.hwnd    = %p\n", msg.hwnd);
		fprintf(stderr, " msg.message = %08x (%s)\n", msg.message, GetMessageName(msg.message));
		fprintf(stderr, " msg.wParam  = %08x\n", msg.wParam);
		fprintf(stderr, " msg.lParam  = %08lx\n", msg.lParam);
		fprintf(stderr, " msg.time    = %08lx\n", msg.time);
		fprintf(stderr, " msg.pt.x    = %08lx\n", msg.pt.x);
		fprintf(stderr, " msg.pt.y    = %08lx\n", msg.pt.y);
	}

	return msg.message != WM_QUIT;
}

BOOLEAN NTAPI NtUserPostMessage( HWND Window, UINT Message, WPARAM Wparam, LPARAM Lparam )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	THREAD*& thread = win->GetWinThread();
	assert(thread != NULL);

	return thread->Queue->PostMessage( Window, Message, Wparam, Lparam );
}

BOOLEAN NTAPI NtUserPeekMessage( PMSG Message, HWND Window, UINT MaxMessage, UINT MinMessage, UINT Remove)
{
	THREAD_MESSAGE_QUEUE* queue = Current->Queue;
	if (!queue)
		return FALSE;

	NTSTATUS r = VerifyForWrite( Message, sizeof *Message );
	if (r != STATUS_SUCCESS)
		return FALSE;

	MSG msg;
	memset( &msg, 0, sizeof msg );
	BOOL ret = queue->GetMessageNoWait( msg, Window, MinMessage, MaxMessage );
	if (ret)
		CopyToUser( Message, &msg, sizeof msg );

	return ret;
}

UINT NTAPI NtUserSetTimer( HWND Window, UINT Identifier, UINT Elapse, PVOID TimerProc )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	THREAD*& thread = win->GetWinThread();
	assert(thread != NULL);

	return thread->Queue->SetTimer( Window, Identifier, Elapse, TimerProc );
}

BOOLEAN NTAPI NtUserKillTimer( HWND Window, UINT Identifier )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	THREAD*& thread = win->GetWinThread();
	assert(thread != NULL);

	return thread->Queue->KillTimer( Window, Identifier );
}
