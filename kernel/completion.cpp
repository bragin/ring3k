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

#include "ntcall.h"
#include "object.h"
#include "thread.h"
#include "file.h"
#include "debug.h"
#include "object.inl"

// COMPLETION_PACKET holds the data for one I/O completion
class COMPLETION_PACKET;

typedef LIST_ANCHOR<COMPLETION_PACKET,0> COMPLETION_LIST;
typedef LIST_ELEMENT<COMPLETION_PACKET> COMPLETION_LIST_ELEMENT;

class COMPLETION_PACKET
{
public:
	COMPLETION_LIST_ELEMENT entry[1];
	ULONG key;
	ULONG value;
	NTSTATUS status;
	ULONG info;
	COMPLETION_PACKET(ULONG k, ULONG v, NTSTATUS s, ULONG i) :
		key(k),
		value(v),
		status(s),
		info(i)
	{
	}
};

// COMPLETION_WAITER is instantiated on the stack of a thread waiting on an I/O completion
class COMPLETION_WAITER;

typedef LIST_ANCHOR<COMPLETION_WAITER,0> COMPLETION_WAITER_LIST;
typedef LIST_ELEMENT<COMPLETION_WAITER> COMPLETION_WAITER_LIST_ELEMENT;

class COMPLETION_WAITER
{
protected:
	friend class LIST_ANCHOR<COMPLETION_WAITER,0>;
	friend class LIST_ELEMENT<COMPLETION_WAITER>;
	COMPLETION_WAITER_LIST_ELEMENT entry[1];
	THREAD *thread;
	COMPLETION_PACKET *packet;
public:
	COMPLETION_WAITER(THREAD *t) : thread(t), packet(0) {}
	~COMPLETION_WAITER();
	void Stop( COMPLETION_WAITER_LIST& waiter_list, PLARGE_INTEGER timeout = 0);
	void Start();
	COMPLETION_PACKET *GetPacket();
	void SetPacket( COMPLETION_PACKET* _packet );
	bool IsLinked()
	{
		return entry[0].is_linked();
	}
};

void COMPLETION_WAITER::Stop(
	COMPLETION_WAITER_LIST& waiter_list,
	PLARGE_INTEGER timeout)
{
	waiter_list.append(this);
	//thread->set_timeout( timeout );
	thread->wait();
	//thread->set_timeout( 0 );
}

void COMPLETION_WAITER::Start()
{
	thread->Start();
}

COMPLETION_WAITER::~COMPLETION_WAITER()
{
	assert(!IsLinked());
}

void COMPLETION_WAITER::SetPacket( COMPLETION_PACKET* _packet )
{
	assert( packet == NULL );
	packet = _packet;
}

COMPLETION_PACKET *COMPLETION_WAITER::GetPacket()
{
	return packet;
}

class COMPLETION_PORT_IMPL;

typedef LIST_ANCHOR<COMPLETION_PORT_IMPL,0> COMPLETION_PORT_LIST;
typedef LIST_ELEMENT<COMPLETION_PORT_IMPL> COMPLETION_PORT_LIST_ELEMENT;

// COMPLETION_PORT_IMPL is the implementation of the I/O completion port object
class COMPLETION_PORT_IMPL : public COMPLETION_PORT
{
	friend class LIST_ANCHOR<COMPLETION_PORT_IMPL,0>;
	friend class LIST_ELEMENT<COMPLETION_PORT_IMPL>;
	COMPLETION_PORT_LIST_ELEMENT entry[1];
	static COMPLETION_PORT_LIST waiting_thread_ports;
	friend void check_completions( void );
private:
	ULONG num_threads;
	COMPLETION_LIST queue;
	COMPLETION_WAITER_LIST waiter_list;
public:
	COMPLETION_PORT_IMPL( ULONG num );
	virtual ~COMPLETION_PORT_IMPL();
	virtual BOOLEAN IsSignalled( void );
	virtual BOOLEAN Satisfy( void );
	virtual void Set(ULONG key, ULONG value, NTSTATUS status, ULONG info);
	virtual NTSTATUS Remove(ULONG& key, ULONG& value, NTSTATUS& status, ULONG& info, PLARGE_INTEGER timeout);
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
	void CheckWaiters();
	void PortWaitIdle();
	bool IsLinked()
	{
		return entry[0].is_linked();
	}
	void StartWaiter( COMPLETION_WAITER *waiter );
};

COMPLETION_PORT_IMPL::COMPLETION_PORT_IMPL( ULONG num ) :
	num_threads(num)
{
}

BOOLEAN COMPLETION_PORT_IMPL::Satisfy()
{
	return FALSE;
}

BOOLEAN COMPLETION_PORT_IMPL::IsSignalled()
{
	return TRUE;
}

bool COMPLETION_PORT_IMPL::AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return check_access( required, handle,
						 IO_COMPLETION_QUERY_STATE,
						 IO_COMPLETION_MODIFY_STATE,
						 IO_COMPLETION_ALL_ACCESS );
}

COMPLETION_PORT_IMPL::~COMPLETION_PORT_IMPL()
{
	assert(!IsLinked());
}

COMPLETION_PORT::~COMPLETION_PORT()
{
}

COMPLETION_PORT_LIST COMPLETION_PORT_IMPL::waiting_thread_ports;

void check_completions( void )
{
	COMPLETION_PORT_IMPL *port = COMPLETION_PORT_IMPL::waiting_thread_ports.head();
	if (!port)
		return;
	port->CheckWaiters();
}

void COMPLETION_PORT_IMPL::CheckWaiters()
{
	// start the first waiter
	COMPLETION_WAITER *waiter = waiter_list.head();
	assert( waiter );

	StartWaiter( waiter );
}

void COMPLETION_PORT_IMPL::PortWaitIdle()
{
	if (IsLinked())
		return;
	waiting_thread_ports.append( this );
}

void COMPLETION_PORT_IMPL::Set(ULONG key, ULONG value, NTSTATUS status, ULONG info)
{
	COMPLETION_PACKET *packet;
	packet = new COMPLETION_PACKET( key, value, status, info );
	queue.append( packet );

	// queue a packet if there's no waiting thread
	COMPLETION_WAITER *waiter = waiter_list.head();
	if (!waiter)
		return;

	// give each thread an I/O completion packet
	// and add it to the list of idle threads
	if (runlist_entry_t::num_active_threads() >= num_threads )
	{
		PortWaitIdle();
		return;
	}

	// there should only be one packet in the queue here
	StartWaiter( waiter );
	assert( queue.empty() );
}

void COMPLETION_PORT_IMPL::StartWaiter( COMPLETION_WAITER *waiter )
{
	// remove a packet from the queue
	COMPLETION_PACKET *packet = queue.head();
	assert( packet );
	queue.unlink( packet );

	// pass the packet to the waiting thread
	waiter->SetPacket( packet );

	// unlink the waiter, and possibly unlink this port
	waiter_list.unlink( waiter );
	if (waiter_list.empty() && IsLinked())
		waiting_thread_ports.unlink( this );

	// restart the waiter last
	waiter->Start();
}

NTSTATUS COMPLETION_PORT_IMPL::Remove(ULONG& key, ULONG& value, NTSTATUS& status, ULONG& info, PLARGE_INTEGER timeout)
{

	// try remove the completion entry first
	COMPLETION_PACKET *packet = queue.head();
	if (!packet)
	{
		// queue thread here
		COMPLETION_WAITER waiter(current);
		waiter.Stop( waiter_list, timeout );
		packet = waiter.GetPacket();
	}
	// this thread must be active... don't block ourselves
	else if (runlist_entry_t::num_active_threads() > num_threads )
	{
		// there's a packet ready but the system, is busy
		// a completion port isn't a FIFO - leave the packt alone
		// wait for idle, then remove the packet
		PortWaitIdle();
		COMPLETION_WAITER waiter(current);
		waiter.Stop( waiter_list, timeout );
		//if (queue.empty() && is_linked())
			//waiting_thread_ports.unlink( this );
		packet = waiter.GetPacket();
	}
	else
	{
		// there's enough free threads to run, and there's a packet waiting
		// we're ready to go
		queue.unlink( packet );
	}
	if (!packet)
		return STATUS_TIMEOUT;

	key = packet->key;
	value = packet->value;
	status = packet->status;
	info = packet->info;

	delete packet;

	return STATUS_SUCCESS;
}

class COMPLETION_FACTORY : public OBJECT_FACTORY
{
	static const int num_cpus = 1;
private:
	ULONG num_threads;
public:
	COMPLETION_FACTORY(ULONG n) : num_threads(n) {}
	virtual NTSTATUS AllocObject(OBJECT** obj);
};

NTSTATUS COMPLETION_FACTORY::AllocObject(OBJECT** obj)
{
	if (num_threads == 0)
		num_threads = num_cpus;

	*obj = new COMPLETION_PORT_IMPL( num_threads );
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}


NTSTATUS NTAPI NtCreateIoCompletion(
	PHANDLE IoCompletionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG NumberOfConcurrentThreads)
{
	trace("%p %08lx %p %ld\n", IoCompletionHandle, DesiredAccess,
		  ObjectAttributes, NumberOfConcurrentThreads);
	COMPLETION_FACTORY factory( NumberOfConcurrentThreads );
	return factory.create( IoCompletionHandle, DesiredAccess, ObjectAttributes );
}

NTSTATUS NTAPI NtOpenIoCompletion(
	PHANDLE IoCompletionHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	trace("%p %08lx %p\n", IoCompletionHandle, AccessMask,
		  ObjectAttributes);
	return nt_open_object<COMPLETION_PORT>( IoCompletionHandle, AccessMask, ObjectAttributes );
}

// blocking
NTSTATUS NTAPI NtRemoveIoCompletion(
	HANDLE IoCompletionHandle,
	PULONG IoCompletionKey,
	PULONG IoCompletionValue,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER TimeOut)
{
	NTSTATUS r;

	trace("%p %p %p %p %p\n", IoCompletionHandle, IoCompletionKey,
		  IoCompletionValue, IoStatusBlock, TimeOut);

	COMPLETION_PORT_IMPL *port = 0;
	r = object_from_handle( port, IoCompletionHandle, IO_COMPLETION_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	if (IoCompletionKey)
	{
		r = verify_for_write( IoCompletionKey, sizeof *IoCompletionKey );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (IoCompletionValue)
	{
		r = verify_for_write( IoCompletionValue, sizeof *IoCompletionValue );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (IoStatusBlock)
	{
		r = verify_for_write( IoStatusBlock, sizeof *IoStatusBlock );
		if (r < STATUS_SUCCESS)
			return r;
	}

	LARGE_INTEGER t;
	t.QuadPart = 0LL;
	if (TimeOut)
	{
		r = copy_from_user( &t, TimeOut, sizeof t );
		if (r < STATUS_SUCCESS)
			return r;
		TimeOut = &t;
	}

	ULONG key = 0, val = 0;
	IO_STATUS_BLOCK iosb;
	iosb.Status = 0;
	iosb.Information = 0;
	port->Remove( key, val, iosb.Status, iosb.Information, TimeOut );

	if (IoCompletionKey)
		copy_to_user( IoCompletionKey, &key, sizeof key );

	if (IoCompletionValue)
		copy_to_user( IoCompletionValue, &val, sizeof val );

	if (IoStatusBlock)
		copy_to_user( IoStatusBlock, &iosb, sizeof iosb );

	return r;
}

// nonblocking
NTSTATUS NTAPI NtSetIoCompletion(
	HANDLE IoCompletionHandle,
	ULONG IoCompletionKey,
	ULONG IoCompletionValue,
	NTSTATUS Status,
	ULONG Information)
{
	NTSTATUS r;

	trace("%p %08lx %08lx %08lx %08lx\n", IoCompletionHandle, IoCompletionKey,
		  IoCompletionValue, Status, Information);

	COMPLETION_PORT_IMPL *port = 0;
	r = object_from_handle( port, IoCompletionHandle, IO_COMPLETION_MODIFY_STATE );
	if (r < STATUS_SUCCESS)
		return r;

	port->Set( IoCompletionKey, IoCompletionValue, Status, Information );

	return STATUS_SUCCESS;
}
