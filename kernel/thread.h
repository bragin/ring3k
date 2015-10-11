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

#ifndef __THREAD_H__
#define __THREAD_H__

#include "object.h"
#include "list.h"
#include "timer.h"
#include "fiber.h"
#include "token.h"
#include "mem.h"

#define PAGE_SIZE 0x1000

class THREAD;

typedef LIST_ANCHOR<THREAD,0> SIBLING_LIST;
typedef LIST_ITER<THREAD,0> SIBLING_ITER;
typedef LIST_ELEMENT<THREAD> THREAD_ELEMENT;

struct PORT;
struct PROCESS;

struct EXCEPTION_STACK_FRAME
{
	PEXCEPTION_RECORD PRec;
	PCONTEXT PCtx;
	CONTEXT Ctx;
	EXCEPTION_RECORD Rec;
};

const ULONG context_all =
	CONTEXT_FLOATING_POINT |
	CONTEXT_DEBUG_REGISTERS |
	CONTEXT_EXTENDED_REGISTERS |
	CONTEXT_FULL ;

struct KERNEL_DEBUG_STRING_OUTPUT
{
	USHORT Length;
	USHORT Pad;
	ULONG Address;
	ULONG Unknown1;
	ULONG Unknown2;
};

struct SECTION;
class MBLOCK;
class THREAD_MESSAGE_QUEUE;

class RUNLIST_ENTRY
{
	friend class LIST_ANCHOR<RUNLIST_ENTRY,0>;
	friend class LIST_ELEMENT<RUNLIST_ENTRY>;
	LIST_ELEMENT<RUNLIST_ENTRY> Entry[1];
	static LIST_ANCHOR<RUNLIST_ENTRY,0> RunningThreads;
	static ULONG NumRunningThreads;
public:
	static ULONG NumActiveThreads();
	void RunlistAdd();
	void RunlistRemove();
};

class THREAD :
	public SYNC_OBJECT,
	public FIBER,
	public RUNLIST_ENTRY
{
	friend class LIST_ANCHOR<THREAD,0>;
	friend class LIST_ELEMENT<THREAD>;
	friend class LIST_ITER<THREAD,0>;
	THREAD_ELEMENT Entry[1];

protected:
	ULONG Id;

public:
	PROCESS *Process;

	// LPC information
	ULONG MessageId;
	PORT *Port;

	THREAD_MESSAGE_QUEUE* Queue;

public:
	THREAD( PROCESS *p );
	virtual ~THREAD();
	virtual ULONG TraceId();
	ULONG GetID()
	{
		return Id;
	}
	virtual void GetClientID( CLIENT_ID *id );
	virtual void Wait();
	virtual void Stop();

public:
	virtual void GetContext( CONTEXT& c ) = 0;
	virtual bool Win32kInitComplete() = 0;
	virtual NTSTATUS DoUserCallback( ULONG index, ULONG& length, PVOID& buffer) = 0;
	virtual NTSTATUS Terminate( NTSTATUS Status ) = 0;
	virtual bool IsTerminated() = 0;
	virtual void RegisterTerminatePort( OBJECT *port ) = 0;
	virtual NTSTATUS QueueApcThread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3) = 0;
	virtual TOKEN* GetToken() = 0;
	virtual NTSTATUS Resume( PULONG count ) = 0;
	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t count ) = 0;
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t count ) = 0;
	virtual NTSTATUS VerifyForWrite( void *dest, size_t count ) = 0;
	virtual void* Push( ULONG count ) = 0;
	virtual void Pop( ULONG count ) = 0;
	virtual PTEB GetTEB() = 0;
};

NTSTATUS CreateThread( THREAD **pthread, PROCESS *p, PCLIENT_ID id, CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended );
int RunThread(FIBER *arg);

extern THREAD *Current;

void SendTerminateMessage( THREAD *thread, OBJECT *port, LARGE_INTEGER& create_time );
bool SendException( THREAD *thread, EXCEPTION_RECORD &rec );

#endif // __THREAD_H__
