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

typedef LIST_ANCHOR<THREAD,0> sibling_list_t;
typedef LIST_ITER<THREAD,0> sibling_iter_t;
typedef LIST_ELEMENT<THREAD> thread_element_t;

struct PORT;
struct PROCESS;

struct exception_stack_frame
{
	PEXCEPTION_RECORD prec;
	PCONTEXT pctx;
	CONTEXT ctx;
	EXCEPTION_RECORD rec;
};

const ULONG context_all =
	CONTEXT_FLOATING_POINT |
	CONTEXT_DEBUG_REGISTERS |
	CONTEXT_EXTENDED_REGISTERS |
	CONTEXT_FULL ;

struct kernel_debug_string_output
{
	USHORT length;
	USHORT pad;
	ULONG address;
	ULONG unknown1;
	ULONG unknown2;
};

struct section_t;
class MBLOCK;
class thread_message_queue_tt;

class runlist_entry_t
{
	friend class LIST_ANCHOR<runlist_entry_t,0>;
	friend class LIST_ELEMENT<runlist_entry_t>;
	LIST_ELEMENT<runlist_entry_t> Entry[1];
	static LIST_ANCHOR<runlist_entry_t,0> running_threads;
	static ULONG num_running_threads;
public:
	static ULONG num_active_threads();
	void runlist_add();
	void runlist_remove();
};

class THREAD :
	public SYNC_OBJECT,
	public FIBER,
	public runlist_entry_t
{
	friend class LIST_ANCHOR<THREAD,0>;
	friend class LIST_ELEMENT<THREAD>;
	friend class LIST_ITER<THREAD,0>;
	thread_element_t Entry[1];

protected:
	ULONG id;

public:
	PROCESS *process;

	// LPC information
	ULONG MessageId;
	PORT *port;

	thread_message_queue_tt* queue;

public:
	THREAD( PROCESS *p );
	virtual ~THREAD();
	virtual ULONG TraceId();
	ULONG GetID()
	{
		return id;
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
	virtual token_t* GetToken() = 0;
	virtual NTSTATUS Resume( PULONG count ) = 0;
	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t count ) = 0;
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t count ) = 0;
	virtual NTSTATUS VerifyForWrite( void *dest, size_t count ) = 0;
	virtual void* Push( ULONG count ) = 0;
	virtual void Pop( ULONG count ) = 0;
	virtual PTEB GetTEB() = 0;
};

NTSTATUS create_thread( THREAD **pthread, PROCESS *p, PCLIENT_ID id, CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended );
int run_thread(FIBER *arg);

extern THREAD *Current;

void SendTerminateMessage( THREAD *thread, OBJECT *port, LARGE_INTEGER& create_time );
bool SendException( THREAD *thread, EXCEPTION_RECORD &rec );

#endif // __THREAD_H__
