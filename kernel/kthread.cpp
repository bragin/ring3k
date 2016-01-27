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

DEFAULT_DEBUG_CHANNEL(kthread);

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
	bool Terminated;
public:
	KERNEL_THREAD( PROCESS *p );
	virtual ~KERNEL_THREAD();
	virtual void GetContext( CONTEXT& c );
	virtual bool Win32kInitComplete();
	virtual NTSTATUS DoUserCallback( ULONG index, ULONG& length, PVOID& buffer);
	virtual NTSTATUS Terminate( NTSTATUS Status );
	virtual bool IsTerminated();
	virtual void RegisterTerminatePort( OBJECT *port );
	//virtual void Wait();
	virtual NTSTATUS QueueApcThread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);
	virtual TOKEN* GetToken();
	virtual NTSTATUS Resume( PULONG count );
	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS VerifyForWrite( void *dest, size_t count );
	virtual int Run() = 0;
	virtual BOOLEAN IsSignalled( void );
	virtual void* Push( ULONG count );
	virtual void Pop( ULONG count );
	virtual PTEB GetTEB();
};

KERNEL_THREAD::KERNEL_THREAD( PROCESS *p ) :
	THREAD( p ),
	Terminated( false )
{
}

KERNEL_THREAD::~KERNEL_THREAD()
{
}

BOOLEAN KERNEL_THREAD::IsSignalled()
{
	return Terminated;
}

void KERNEL_THREAD::GetContext( CONTEXT& c )
{
	assert(0);
}

bool KERNEL_THREAD::Win32kInitComplete()
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::DoUserCallback( ULONG index, ULONG& length, PVOID& buffer)
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::Terminate( NTSTATUS Status )
{
	if (Terminated)
		return 0;
	Terminated = true;
	Start();
	return 0;
}

bool KERNEL_THREAD::IsTerminated()
{
	return Terminated;
}

void KERNEL_THREAD::RegisterTerminatePort( OBJECT *port )
{
	assert(0);
}

/*void KERNEL_THREAD::Wait()
{
	assert(0);
}*/

NTSTATUS KERNEL_THREAD::QueueApcThread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3)
{
	assert(0);
	return 0;
}

TOKEN* KERNEL_THREAD::GetToken()
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::Resume( PULONG count )
{
	assert(0);
	return 0;
}

NTSTATUS KERNEL_THREAD::CopyToUser( void *dest, const void *src, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	memcpy( dest, src, count );
	return STATUS_SUCCESS;
}

NTSTATUS KERNEL_THREAD::CopyFromUser( void *dest, const void *src, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	memcpy( dest, src, count );
	return STATUS_SUCCESS;
}

NTSTATUS KERNEL_THREAD::VerifyForWrite( void *dest, size_t count )
{
	if (!dest)
		return STATUS_ACCESS_VIOLATION;
	return STATUS_SUCCESS;
}

void* KERNEL_THREAD::Push( ULONG count )
{
	assert(0);
	return 0;
}

void KERNEL_THREAD::Pop( ULONG count )
{
	assert(0);
}

PTEB KERNEL_THREAD::GetTEB()
{
	assert(0);
	return 0;
}

class SECURITY_REFERENCE_MONITOR : public KERNEL_THREAD
{
public:
	SECURITY_REFERENCE_MONITOR( PROCESS *p );
	virtual int Run();
};

SECURITY_REFERENCE_MONITOR::SECURITY_REFERENCE_MONITOR( PROCESS *p ) :
	KERNEL_THREAD( p )
{
}

int SECURITY_REFERENCE_MONITOR::Run()
{
	const int maxlen = 0x100;
	//trace("starting kthread %p p = %p\n", this, process);
	Current = static_cast<THREAD*>( this );
	//trace("current->process = %p\n", current->process);
	COBJECT_ATTRIBUTES rm_oa( (PCWSTR) L"\\SeRmCommandPort" );
	HANDLE port = 0, client = 0;
	NTSTATUS r = NtCreatePort( &port, &rm_oa, 0x100, 0x100, 0 );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		Die("NtCreatePort(SeRmCommandPort) failed r = %08lx\n", r);

	BYTE buf[maxlen];
	LPC_MESSAGE *req = (LPC_MESSAGE*) buf;
	r = NtListenPort( port, req );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		Die("NtListenPort(SeRmCommandPort) failed r = %08lx\n", r);

	HANDLE conn_port = 0;
	r = NtAcceptConnectPort( &conn_port, 0, req, TRUE, NULL, NULL );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		Die("NtAcceptConnectPort(SeRmCommandPort) failed r = %08lx\n", r);

	r = NtCompleteConnectPort( conn_port );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		Die("NtCompleteConnectPort(SeRmCommandPort) failed r = %08lx\n", r);

	CUNICODE_STRING lsa;
	lsa.Copy( (PCWSTR) L"\\SeLsaCommandPort" );

	SECURITY_QUALITY_OF_SERVICE qos;
	qos.Length = sizeof(qos);
	qos.ImpersonationLevel = SecurityAnonymous;
	qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	qos.EffectiveOnly = TRUE;

	r = NtConnectPort( &client, &lsa, &qos, NULL, NULL, NULL, NULL, NULL );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		Die("NtConnectPort(SeLsaCommandPort) failed r = %08lx\n", r);

	while (!Terminated)
	{
		ULONG client_handle;

		r = NtReplyWaitReceivePort( port, &client_handle, 0, req );
		if (r == STATUS_THREAD_IS_TERMINATING)
			return 0;

		if (r < STATUS_SUCCESS)
			Die("NtReplyWaitReceivePort(SeRmCommandPort) failed r = %08lx\n", r);

		TRACE("got message %ld\n", req->MessageId );

		// send something back...
		r = NtReplyPort( port, req );
		if (r == STATUS_THREAD_IS_TERMINATING)
			return 0;

		if (r < STATUS_SUCCESS)
			Die("NtReplyPort(SeRmCommandPort) failed r = %08lx\n", r);
	}

	TRACE("done\n");
	return 0;
}

class PLUG_AND_PLAY : public KERNEL_THREAD
{
public:
	PLUG_AND_PLAY( PROCESS *p );
	virtual int Run();
};

PLUG_AND_PLAY::PLUG_AND_PLAY( PROCESS *p ) :
	KERNEL_THREAD( p )
{
}

int PLUG_AND_PLAY::Run()
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	HANDLE pipe = 0;
	NTSTATUS r;
	LARGE_INTEGER timeout;
	Current = static_cast<THREAD*>( this );

	CUNICODE_STRING pipename;
	pipename.Copy( "\\Device\\NamedPipe\\ntsvcs" );

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
		TRACE("failed to create ntsvcs %08lx\n", r);

	if (Terminated)
		Stop();

	r = NtFsControlFile( pipe, 0, 0, 0, &iosb, FSCTL_PIPE_LISTEN, 0, 0, 0, 0 );
	if (r == STATUS_THREAD_IS_TERMINATING)
		return 0;
	if (r < STATUS_SUCCESS)
		TRACE("failed to connect ntsvcs %08lx\n", r);

	Stop();
	return 0;
}

static PROCESS *KernelProcess;
static KERNEL_THREAD* SRM;
static KERNEL_THREAD* PlugnPlay;

void CreateKThread(void)
{
	// process is for the handle table
	KernelProcess = new PROCESS;
	SRM = new SECURITY_REFERENCE_MONITOR( KernelProcess );
	PlugnPlay = new PLUG_AND_PLAY( KernelProcess );
	//release( kernel_process );

	SRM->Start();
	PlugnPlay->Start();
}

void ShutdownKThread(void)
{
	SRM->Terminate( 0 );
	PlugnPlay->Terminate( 0 );

	// run the threads until they complete
	while (!FIBER::LastFiber())
		FIBER::Yield();

	delete KernelProcess;
}
