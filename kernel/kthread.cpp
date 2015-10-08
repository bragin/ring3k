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


#include <unistd.h>

#include <stdarg.h>
#include <assert.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "object.inl"
#include "ntcall.h"
#include "section.h"
#include "timer.h"
#include "file.h"

class THREAD_IMPL;

class KERNEL_THREAD :
	public THREAD
{
public:
	bool terminated;
public:
	KERNEL_THREAD( PROCESS *p );
	virtual ~KERNEL_THREAD();
	virtual void get_context( CONTEXT& c );
	virtual bool win32k_init_complete();
	virtual NTSTATUS do_user_callback( ULONG index, ULONG& length, PVOID& buffer);
	virtual NTSTATUS terminate( NTSTATUS Status );
	virtual bool is_terminated();
	virtual void register_terminate_port( OBJECT *port );
	//virtual void wait();
	virtual NTSTATUS queue_apc_thread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);
	virtual token_t* get_token();
	virtual NTSTATUS resume( PULONG count );
	virtual NTSTATUS copy_to_user( void *dest, const void *src, size_t count );
	virtual NTSTATUS copy_from_user( void *dest, const void *src, size_t count );
	virtual NTSTATUS verify_for_write( void *dest, size_t count );
	virtual int run() = 0;
	virtual BOOLEAN IsSignalled( void );
	virtual void* push( ULONG count );
	virtual void pop( ULONG count );
	virtual PTEB get_teb();
};

KERNEL_THREAD::KERNEL_THREAD( PROCESS *p ) :
	THREAD( p ),
	terminated( false )
{
}

KERNEL_THREAD::~KERNEL_THREAD()
{
}

BOOLEAN KERNEL_THREAD::IsSignalled()
{
	return terminated;
}

void KERNEL_THREAD::get_context( CONTEXT& c )
{
	assert(0);
}

bool KERNEL_THREAD::win32k_init_complete()
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::do_user_callback( ULONG index, ULONG& length, PVOID& buffer)
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::terminate( NTSTATUS Status )
{
	if (terminated)
		return 0;
	terminated = true;
	start();
	return 0;
}

bool KERNEL_THREAD::is_terminated()
{
	return terminated;
}

void KERNEL_THREAD::register_terminate_port( OBJECT *port )
{
	assert(0);
}

/*void KERNEL_THREAD::wait()
{
	assert(0);
}*/

NTSTATUS KERNEL_THREAD::queue_apc_thread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3)
{
	assert(0);
	return 0;
}

token_t* KERNEL_THREAD::get_token()
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::resume( PULONG count )
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::copy_to_user( void *dest, const void *src, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	memcpy( dest, src, count );
	return STATUS_SUCCESS;
}

NTSTATUS KERNEL_THREAD::copy_from_user( void *dest, const void *src, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	memcpy( dest, src, count );
	return STATUS_SUCCESS;
}

NTSTATUS KERNEL_THREAD::verify_for_write( void *dest, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	return STATUS_SUCCESS;
}

void* KERNEL_THREAD::push( ULONG count )
{
	assert(0);
	return 0;
}

void KERNEL_THREAD::pop( ULONG count )
{
	assert(0);
}

PTEB KERNEL_THREAD::get_teb()
{
	assert(0);
	return 0;
}

class SECURITY_REFERENCE_MONITOR : public KERNEL_THREAD
{
public:
	SECURITY_REFERENCE_MONITOR( PROCESS *p );
	virtual int run();
};

SECURITY_REFERENCE_MONITOR::SECURITY_REFERENCE_MONITOR( PROCESS *p ) :
	KERNEL_THREAD( p )
{
}

int SECURITY_REFERENCE_MONITOR::run()
{
	const int maxlen = 0x100;
	//trace("starting kthread %p p = %p\n", this, process);
	current = static_cast<THREAD*>( this );
	//trace("current->process = %p\n", current->process);
	object_attributes_t rm_oa( (PCWSTR) L"\\SeRmCommandPort" );
	HANDLE port = 0, client = 0;
	NTSTATUS r = NtCreatePort( &port, &rm_oa, 0x100, 0x100, 0 );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		die("NtCreatePort(SeRmCommandPort) failed r = %08lx\n", r);

	BYTE buf[maxlen];
	LPC_MESSAGE *req = (LPC_MESSAGE*) buf;
	r = NtListenPort( port, req );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		die("NtListenPort(SeRmCommandPort) failed r = %08lx\n", r);

	HANDLE conn_port = 0;
	r = NtAcceptConnectPort( &conn_port, 0, req, TRUE, NULL, NULL );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		die("NtAcceptConnectPort(SeRmCommandPort) failed r = %08lx\n", r);

	r = NtCompleteConnectPort( conn_port );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		die("NtCompleteConnectPort(SeRmCommandPort) failed r = %08lx\n", r);

	unicode_string_t lsa;
	lsa.copy( (PCWSTR) L"\\SeLsaCommandPort" );

	SECURITY_QUALITY_OF_SERVICE qos;
	qos.Length = sizeof(qos);
	qos.ImpersonationLevel = SecurityAnonymous;
	qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	qos.EffectiveOnly = TRUE;

	r = NtConnectPort( &client, &lsa, &qos, NULL, NULL, NULL, NULL, NULL );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		die("NtConnectPort(SeLsaCommandPort) failed r = %08lx\n", r);

	while (!terminated)
	{
		ULONG client_handle;

		r = NtReplyWaitReceivePort( port, &client_handle, 0, req );
		if (r == STATUS_THREAD_IS_TERMINATING)
			return 0;

		if (r < STATUS_SUCCESS)
			die("NtReplyWaitReceivePort(SeRmCommandPort) failed r = %08lx\n", r);

		trace("got message %ld\n", req->MessageId );

		// send something back...
		r = NtReplyPort( port, req );
		if (r == STATUS_THREAD_IS_TERMINATING)
			return 0;

		if (r < STATUS_SUCCESS)
			die("NtReplyPort(SeRmCommandPort) failed r = %08lx\n", r);
	}

	trace("done\n");
	return 0;
}

class PLUG_AND_PLAY : public KERNEL_THREAD
{
public:
	PLUG_AND_PLAY( PROCESS *p );
	virtual int run();
};

PLUG_AND_PLAY::PLUG_AND_PLAY( PROCESS *p ) :
	KERNEL_THREAD( p )
{
}

int PLUG_AND_PLAY::run()
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	HANDLE pipe = 0;
	NTSTATUS r;
	LARGE_INTEGER timeout;
	current = static_cast<THREAD*>( this );

	unicode_string_t pipename;
	pipename.copy( "\\Device\\NamedPipe\\ntsvcs" );

	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &pipename;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	timeout.QuadPart = -10000LL;
	r = NtCreateNamedPipeFile( &pipe, GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,
							   &oa, &iosb, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN_IF, 0, TRUE,
							   TRUE, FALSE, -1, 0, 0, &timeout );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		trace("failed to create ntsvcs %08lx\n", r);

	if (terminated)
		stop();

	r = NtFsControlFile( pipe, 0, 0, 0, &iosb, FSCTL_PIPE_LISTEN, 0, 0, 0, 0 );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		trace("failed to connect ntsvcs %08lx\n", r);

	stop();
	return 0;
}

static PROCESS *kernel_process;
static KERNEL_THREAD* srm;
static KERNEL_THREAD* plugnplay;

void create_kthread(void)
{
	// process is for the handle table
	kernel_process = new PROCESS;
	srm = new SECURITY_REFERENCE_MONITOR( kernel_process );
	plugnplay = new PLUG_AND_PLAY( kernel_process );
	//release( kernel_process );

	srm->start();
	plugnplay->start();
}

void shutdown_kthread(void)
{
	srm->terminate( 0 );
	plugnplay->terminate( 0 );

	// run the threads until they complete
	while (!FIBER::last_fiber())
		FIBER::yield();

	delete kernel_process;
}
