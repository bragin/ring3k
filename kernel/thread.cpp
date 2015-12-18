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

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "object.inl"
#include "ntcall.h"
#include "section.h"
#include "timer.h"
#include "file.h"
#include "queue.h"

class THREAD_IMPL;

class THREAD_OBJ_WAIT;
typedef LIST_ANCHOR<THREAD_OBJ_WAIT, 0> THREAD_OBJ_WAIT_LIST;
typedef LIST_ELEMENT<THREAD_OBJ_WAIT> THREAD_OBJ_WAIT_ELEMENT;
typedef LIST_ITER<THREAD_OBJ_WAIT, 0> THREAD_OBJ_WAIT_ITER;

struct THREAD_OBJ_WAIT : public WATCH
{
	THREAD_OBJ_WAIT_ELEMENT Entry[1];
	SYNC_OBJECT *Obj;
	THREAD_IMPL *Thread;
public:
	THREAD_OBJ_WAIT( THREAD_IMPL* t, SYNC_OBJECT* o);
	virtual void Notify();
	virtual ~THREAD_OBJ_WAIT();
	BOOLEAN IsSignalled()
	{
		return Obj->IsSignalled();
	}
	BOOLEAN Satisfy()
	{
		return Obj->Satisfy();
	}
};

class CALLBACK_FRAME
{
	CONTEXT Ctx;
	CALLBACK_FRAME *Prev;
	// values from NtCallbackReturn
	NTSTATUS Status;
	ULONG Length;
	PVOID Buffer;
	BOOLEAN Complete;
public:
	CALLBACK_FRAME(THREAD_IMPL *t);
	void DoReturn(NTSTATUS s, ULONG l, PVOID b);
	void GetReturn(NTSTATUS& s, ULONG& l, PVOID& b);
	BOOLEAN IsComplete()
	{
		return Complete;
	}
	void Pop( THREAD_IMPL *t );
};

struct THREAD_APC;
typedef LIST_ANCHOR<THREAD_APC,0> THREAD_APC_LIST;
typedef LIST_ELEMENT<THREAD_APC> THREAD_APC_ELEMENT;

struct THREAD_APC
{
	THREAD_APC(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3) :
		Proc(ApcRoutine)
	{
		Arg[0] = Arg1;
		Arg[1] = Arg2;
		Arg[2] = Arg3;
	}
	THREAD_APC_ELEMENT Entry[1];
	PKNORMAL_ROUTINE Proc;
	PVOID Arg[3];
};

class THREAD_IMPL :
	public THREAD,
	public EXECUTION_CONTEXT,
	public TIMEOUT
{
	THREAD_STATE ThreadState;
	ULONG SuspendCount;

	//SYSTEM_THREAD_INFORMATION members
	NTSTATUS ExitStatus;
	SECTION *TebSection;
	PVOID TebBaseAddress;	// user
	PTEB Teb;		// kernel

	// list of APCs
	THREAD_APC_LIST ApcList;
	BOOLEAN Alerted;

	// blocking objects
	THREAD_OBJ_WAIT_LIST WaitList;
	BOOLEAN Alertable;
	WAIT_TYPE WaitType;
	BOOLEAN InWait;

	KERNEL_USER_TIMES Times;

	CONTEXT Ctx;
	BOOLEAN ContextChanged;

	OBJECT *TerminatePort;
	TOKEN *Token;

	// win32 callback stack
	CALLBACK_FRAME *CallbackFrame;
	PVOID Win32StartAddress;
	bool Win32kInitDone;

	// memory access tracing
	bool TraceStepAccess;
	void *TraceAccessedAddress;

public:
	THREAD_IMPL( PROCESS *p );
	~THREAD_IMPL();
	NTSTATUS Create( CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended );
	virtual BOOLEAN IsSignalled( void );
	void SetState( THREAD_STATE state );
	bool IsTerminated()
	{
		return ThreadState == StateTerminated;
	}
	void QueryInformation( THREAD_BASIC_INFORMATION& info );
	void QueryInformation( KERNEL_USER_TIMES& info );
	NTSTATUS ZeroTlsCells( ULONG index );
	NTSTATUS KernelDebuggerOutputString( struct KERNEL_DEBUG_STRING_OUTPUT *hdr );
	NTSTATUS KernelDebuggerCall( ULONG func, void *arg1, void *arg2 );
	BOOLEAN SoftwareInterrupt( BYTE number );
	void HandleUserSegv( ULONG code );
	bool TracedAccess();
	void StartExceptionHandler(EXCEPTION_STACK_FRAME& frame);
	NTSTATUS RaiseException( EXCEPTION_STACK_FRAME& info, BOOLEAN SearchFrames );
	NTSTATUS DoUserCallback( ULONG index, ULONG& length, PVOID& buffer);
	NTSTATUS UserCallbackReturn(PVOID Result, ULONG ResultLength, NTSTATUS Status );
	NTSTATUS Terminate( NTSTATUS Status );
	NTSTATUS TestAlert();
	NTSTATUS QueueApcThread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);
	BOOLEAN DeliverApc( NTSTATUS status );
	NTSTATUS Resume( PULONG count );
	int SetInitialRegs( void *start, void *stack);
	void CopyRegisters( CONTEXT& dest, CONTEXT &src, ULONG flags );
	void SetContext( CONTEXT& c, bool override_return=true );
	void GetContext( CONTEXT& c );
	void SetToken( TOKEN *tok );
	TOKEN* GetToken();
	CALLBACK_FRAME* SetCallback( CALLBACK_FRAME *cb );
	PVOID& GetWin32StartAddress();
	void RegisterTerminatePort( OBJECT *port );
	bool Win32kInitComplete();

	virtual int Run();

	// wait related functions
	NTSTATUS WaitOnHandles( ULONG count, PHANDLE handles, WAIT_TYPE type, BOOLEAN alert, PLARGE_INTEGER timeout );
	NTSTATUS CheckWait();
	NTSTATUS WaitOn( SYNC_OBJECT *obj );
	NTSTATUS CheckWaitAll();
	NTSTATUS CheckWaitAny();
	void EndWait();
	virtual void SignalTimeout(); // timeout_t
	NTSTATUS DelayExecution( LARGE_INTEGER& timeout );
	void Start();
	void Wait();
	void Notify();
	NTSTATUS Alert();
	ULONG IsLastThread();

	virtual void HandleFault();
	virtual void HandleBreakpoint();

	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS VerifyForWrite( void *dest, size_t count );

	virtual void* Push( ULONG count );
	virtual void Pop( ULONG count );
	virtual PTEB GetTEB();
};

LIST_ANCHOR<RUNLIST_ENTRY,0> RUNLIST_ENTRY::RunningThreads;
ULONG RUNLIST_ENTRY::NumRunningThreads;

void RUNLIST_ENTRY::RunlistAdd()
{
	assert( (NumRunningThreads == 0) ^ !RunningThreads.Empty() );
	RunningThreads.Prepend( this );
	NumRunningThreads++;
}

void RUNLIST_ENTRY::RunlistRemove()
{
	RunningThreads.Unlink( this );
	NumRunningThreads--;
	assert( (NumRunningThreads == 0) ^ !RunningThreads.Empty() );
}

ULONG RUNLIST_ENTRY::NumActiveThreads()
{
	return NumRunningThreads;
}

int THREAD_IMPL::SetInitialRegs( void *start, void *stack)
{
	Process->Vm->InitContext( Ctx );

	Ctx.Eip = (DWORD) start;
	Ctx.Esp = (DWORD) stack;

	ContextChanged = TRUE;

	return 0;
}

BOOLEAN THREAD_IMPL::IsSignalled( void )
{
	return (ThreadState == StateTerminated);
}

void THREAD_IMPL::SetState( THREAD_STATE state )
{
	ULONG prev_state = ThreadState;

	if (prev_state == StateTerminated)
		return;

	ThreadState = state;
	switch (state)
	{
	case StateWait:
		RunlistRemove();
		break;
	case StateRunning:
		RunlistAdd();
		break;
	case StateTerminated:
		NotifyWatchers();
		if (prev_state == StateRunning)
			RunlistRemove();
		break;
	default:
		Die("switch to unknown Thread state\n");
	}

	// ready to complete some I/O?
	if (NumActiveThreads() == 0)
		CheckCompletions();
}


NTSTATUS THREAD_IMPL::KernelDebuggerOutputString( struct KERNEL_DEBUG_STRING_OUTPUT *hdr )
{
	struct KERNEL_DEBUG_STRING_OUTPUT header;
	char *string;
	NTSTATUS r;

	r = CopyFromUser( &header, hdr, sizeof header );
	if (r < STATUS_SUCCESS)
	{
		trace("debug string output header invalid\n");
		return r;
	}

	if ( header.Length > 0x1000 )
	{
		trace("too long %d\n", header.Length );
		return STATUS_SUCCESS;
	}

	string = new char[ header.Length + 1 ];
	r = CopyFromUser( string, hdr+1, header.Length );
	if (r >= STATUS_SUCCESS)
	{
		if (string[header.Length - 1] == '\n')
			header.Length--;

		string[header.Length] = 0;
		fprintf(stderr, "%04lx: debug: %s\n", TraceId(), string);
	}
	else
		fprintf(stderr, "%04lx: debug - bad address\n", TraceId());

	delete[] string;
	return r;
}

ULONG THREAD::TraceId()
{
	if (!Process)
		return Id;
	return Id | (Process->Id<<8);
}

NTSTATUS THREAD_IMPL::KernelDebuggerCall( ULONG func, void *arg1, void *arg2 )
{
	NTSTATUS r;

	switch (func)
	{
		case 1:
			r = KernelDebuggerOutputString( (struct KERNEL_DEBUG_STRING_OUTPUT *)arg1 );
			break;
		case 0x101:
		{
			const char *sym = Process->Vm->GetSymbol( (BYTE*) arg1 );
			if (sym)
				fprintf(stderr, "%04lx: %s called\n", TraceId(), sym);
			else
				fprintf(stderr, "%04lx: %p called\n", TraceId(), arg1);
		}
		r = 0;
		break;
		default:
			DumpRegs( &Ctx );
			trace("unhandled function %ld\n", func );
			r = STATUS_NOT_IMPLEMENTED;
	}
	if (r < STATUS_SUCCESS)
		return r;

	// skip breakpoints after debugger calls
	BYTE inst[1];
	if (r == CopyFromUser( inst, (void*) Ctx.Eip, 1 ) &&
		inst[0] == 0xcc)
	{
		Ctx.Eip++;
	}
	return r;
}

BOOLEAN THREAD_IMPL::SoftwareInterrupt( BYTE number )
{
	if (number > 0x2e || number < 0x2b)
	{
		trace("Unhandled software interrupt %02x\n", number);
		return FALSE;
	}

	Ctx.Eip += 2;
	ContextChanged = FALSE;

	NTSTATUS r;
	switch (number)
	{
	case 0x2b:
		r = NtCallbackReturn( (void*) Ctx.Ecx, Ctx.Edx, Ctx.Eax );
		break;

	case 0x2c:
		r = NtSetLowWaitHighThread();
		break;

	case 0x2d:
		KernelDebuggerCall( Ctx.Eax, (void*) Ctx.Ecx, (void*) Ctx.Edx );
		r = Ctx.Eax;  // check if this returns a value
		break;

	case 0x2e:
		r = DoNtSyscall( TraceId(), Ctx.Eax, (ULONG*) Ctx.Edx, Ctx.Eip );
		break;

	default:
		assert(0);
	}

	if (!ContextChanged)
		Ctx.Eax = r;

	return TRUE;
}

bool THREAD_IMPL::TracedAccess()
{
	// only trace the first fault
	if (TraceStepAccess)
		return false;

	// get the fault address
	void* addr = 0;
	if (0 != Current->Process->Vm->GetFaultInfo( addr ))
		return false;

	// confirm the memory is traced
	if (!Current->Process->Vm->TracedAccess( addr, Ctx.Eip ))
		return false;

	TraceAccessedAddress = addr;
	TraceStepAccess = true;
	return true;
}

void THREAD_IMPL::HandleUserSegv( ULONG code )
{
	trace("%04lx: exception at %08lx\n", TraceId(), Ctx.Eip);
	if (OptionTrace)
	{
		DumpRegs( &Ctx );
		DebuggerBacktrace(&Ctx);
	}

	EXCEPTION_STACK_FRAME info;

	memset( &info, 0, sizeof info );
	memcpy( &info.Ctx, &Ctx, sizeof Ctx );

	// FIXME: might not be an access violation
	info.Rec.ExceptionCode = code;
	info.Rec.ExceptionFlags = EXCEPTION_CONTINUABLE;
	info.Rec.ExceptionRecord = 0;
	info.Rec.ExceptionAddress = (void*) Ctx.Eip;
	info.Rec.NumberParameters = 0;
	//ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];

	StartExceptionHandler( info );
}

void THREAD_IMPL::StartExceptionHandler(EXCEPTION_STACK_FRAME& info)
{
	if (0)
	{
		trace("ExceptionCode	%08lx\n", info.Rec.ExceptionCode);
		trace("ExceptionFlags   %08lx\n", info.Rec.ExceptionFlags);
		trace("ExceptionRecord  %p\n", info.Rec.ExceptionRecord);
		trace("ExceptionAddress %p\n", info.Rec.ExceptionAddress);
		trace("NumberParameters %ld\n", info.Rec.NumberParameters);
	}

	if (SendException( this, info.Rec ))
		return;

	info.Ctx.ContextFlags = context_all;

	info.Ctx.SegCs &= 0xffff;
	info.Ctx.SegEs &= 0xffff;
	info.Ctx.SegSs &= 0xffff;
	info.Ctx.SegDs &= 0xffff;
	info.Ctx.SegFs &= 0xffff;
	info.Ctx.SegGs &= 0xffff;

	// hack to stop looping
	if (info.Ctx.Eip & 0x80000000)
	{
		trace("Eip invalid %08lx\n", info.Ctx.Eip);
		Terminate(STATUS_ACCESS_VIOLATION);
		return;
	}

	// push the context, exception record and KiUserExceptionDispatcher args
	EXCEPTION_STACK_FRAME *stack = (EXCEPTION_STACK_FRAME*)((BYTE*) Ctx.Esp - sizeof info);
	info.PCtx = &stack->Ctx;
	info.PRec = &stack->Rec;
	Ctx.Esp = (LONG) stack;

	NTSTATUS r = CopyToUser( stack, &info, sizeof info );
	if (r < STATUS_SUCCESS)
	{
		trace("%04lx: invalid stack handling exception at %08lx\n", Id, Ctx.Eip);
		Terminate(r);
		return;
	}

	// get the address of the user side handler
	// FIXME: this should be stored in the PROCESS structure
	BYTE *pKiExceptionDispatcher = (BYTE*)Process->PNtDLL +
								   GetProcAddress( NtDLLSection, "KiUserExceptionDispatcher" );
	if (!pKiExceptionDispatcher)
		Die("failed to find KiExceptionDispatcher in ntdll\n");

	ContextChanged = 1;
	Ctx.Eip = (ULONG) pKiExceptionDispatcher;
}

CALLBACK_FRAME* THREAD_IMPL::SetCallback( CALLBACK_FRAME *cb )
{
	CALLBACK_FRAME *old = CallbackFrame;
	CallbackFrame = cb;
	return old;
}

CALLBACK_FRAME::CALLBACK_FRAME(THREAD_IMPL *t) :
	Status(STATUS_PENDING),
	Length(0),
	Buffer(0),
	Complete(FALSE)
{
	Ctx.ContextFlags = context_all;
	t->GetContext( Ctx );
	Prev = t->SetCallback( this );
}

void CALLBACK_FRAME::DoReturn( NTSTATUS s, ULONG l, PVOID b )
{
	assert(!Complete);
	Status = s;
	Length = l;
	Buffer = b;
	Complete = TRUE;
}

void CALLBACK_FRAME::Pop( THREAD_IMPL *t )
{
	assert( Complete );
	t->SetCallback( Prev );
	// clear context_changed so eax is set
	t->SetContext( Ctx, false );
}

void CALLBACK_FRAME::GetReturn(NTSTATUS& s, ULONG& l, PVOID& b)
{
	assert(Complete);
	s = Status;
	l = Length;
	b = Buffer;
}

void* THREAD_IMPL::Push( ULONG count )
{
	Ctx.Esp -= count;
	return (void*) Ctx.Esp;
}

void THREAD_IMPL::Pop( ULONG count )
{
	Ctx.Esp += count;
}

PTEB THREAD_IMPL::GetTEB()
{
	return Teb;
}

NTSTATUS THREAD_IMPL::DoUserCallback( ULONG index, ULONG &length, PVOID &buffer)
{
	struct
	{
		ULONG x[4];
	} frame;

	if (index == 0)
		Die("zero index in win32 callback\n");
	frame.x[0] = 0;
	frame.x[1] = index;
	frame.x[2] = Ctx.Esp;
	frame.x[3] = 0;

	//callback_stack.push( &Ctx, fn );

	ULONG new_esp = Ctx.Esp - sizeof frame;
	NTSTATUS r = CopyToUser( (void*) new_esp, &frame, sizeof frame );
	if (r < STATUS_SUCCESS)
	{
		trace("%04lx: invalid stack handling exception at %08lx\n", Id, Ctx.Eip);
		Terminate(r);
		return r;
	}

	// FIXME: limit recursion so we don't blow the stack

	// store the current user context
	CALLBACK_FRAME old_frame(this);

	// setup the new execution context
	BYTE *pKiUserCallbackDispatcher = (BYTE*)Process->PNtDLL +
									  GetProcAddress( NtDLLSection, "KiUserCallbackDispatcher" );

	ContextChanged = 1;
	Ctx.Eip = (ULONG) pKiUserCallbackDispatcher;
	Ctx.Esp = new_esp;

	// recurse, resume user execution here
	trace("continuing execution at %08lx\n", Ctx.Eip);
	Run();

	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;

	// fetch return values out of the frame
	old_frame.GetReturn(r, length, buffer);
	ContextChanged = 0;
	trace("callback returned %08lx\n", r);

	return r;
}

NTSTATUS THREAD_IMPL::UserCallbackReturn( PVOID Result, ULONG ResultLength, NTSTATUS Status )
{
	if (!CallbackFrame)
		return STATUS_UNSUCCESSFUL;
	if (Result && ResultLength == 12)
	{
		ULONG retvals[3];
		NTSTATUS r = CopyFromUser( retvals, Result, sizeof retvals );
		if (r >= STATUS_SUCCESS)
		{
			trace("Result = %08lx %08lx %08lx\n",
				  retvals[0], retvals[1], retvals[2]);
		}
	}
	CallbackFrame->DoReturn( Status, ResultLength, Result );
	return STATUS_SUCCESS;
}

NTSTATUS THREAD_IMPL::QueueApcThread(
	PKNORMAL_ROUTINE ApcRoutine,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3)
{
	THREAD_APC *apc;

	if (ThreadState == StateTerminated)
		return STATUS_ACCESS_DENIED;

	if (!ApcRoutine)
		return STATUS_SUCCESS;

	apc = new THREAD_APC(ApcRoutine, Arg1, Arg2, Arg3);
	if (!apc)
		return STATUS_NO_MEMORY;

	ApcList.Append( apc );
	if (InWait)
		Notify();

	return STATUS_SUCCESS;
}

BOOLEAN THREAD_IMPL::DeliverApc(NTSTATUS thread_return)
{
	// NOTE: can use this to Start a thread...
	THREAD_APC *apc = ApcList.Head();
	if (!apc)
		return FALSE;

	ApcList.Unlink( apc );

	// set the return code in Eax
	Ctx.Eax = thread_return;

	NTSTATUS r = STATUS_SUCCESS;
	ULONG new_esp = Ctx.Esp;

	// push current context ... for NtContinue
	new_esp -= sizeof Ctx;
	r = CopyToUser( (void*) new_esp, &Ctx, sizeof Ctx );
	if (r < STATUS_SUCCESS)
		goto end;

	// setup APC
	void *apc_stack[4];
	apc_stack[0] = (void*) apc->Proc;
	apc_stack[1] = apc->Arg[0];
	apc_stack[2] = apc->Arg[1];
	apc_stack[3] = apc->Arg[2];

	new_esp -= sizeof apc_stack;
	r = CopyToUser( (void*) new_esp, apc_stack, sizeof apc_stack );
	if (r < STATUS_SUCCESS)
		goto end;

	void *pKiUserApcDispatcher;
	pKiUserApcDispatcher = (BYTE*)Process->PNtDLL + GetProcAddress( NtDLLSection, "KiUserApcDispatcher" );
	if (!pKiUserApcDispatcher)
		Die("failed to find KiUserApcDispatcher in ntdll\n");

	Ctx.Esp = new_esp;
	Ctx.Eip = (ULONG) pKiUserApcDispatcher;
	ContextChanged = 1;

end:
	if (r < STATUS_SUCCESS)
		Terminate( r );
	delete apc;
	return TRUE;
}

void THREAD_IMPL::CopyRegisters( CONTEXT& dest, CONTEXT &src, ULONG flags )
{
#define SET(reg) dest.reg = src.reg
#define SETSEG(reg) dest.reg = src.reg&0xffff
	flags &= 0x1f; // remove CONTEXT_X86
	if (flags & CONTEXT_CONTROL)
	{
		SET( Ebp );
		SET( Eip );
		SETSEG( SegCs );
		SET( EFlags );
		SET( Esp );
		SETSEG( SegSs );
	}

	if (flags & CONTEXT_SEGMENTS)
	{
		SETSEG( SegDs );
		SETSEG( SegEs );
		SETSEG( SegFs );
		SET( SegGs );
	}

	if (flags & CONTEXT_INTEGER)
	{
		SET( Ebx );
		SET( Ecx );
		SET( Edx );
		SET( Esi );
		SET( Edi );
		SET( Eax );
	}

	if (flags & CONTEXT_FLOATING_POINT)
	{
		SET( FloatSave );
	}

	if (flags & CONTEXT_DEBUG_REGISTERS)
	{
		SET( Dr0 );
		SET( Dr1 );
		SET( Dr2 );
		SET( Dr3 );
		SET( Dr6 );
		SET( Dr7 );
	}
#undef SET
#undef SETSEG
}

void THREAD_IMPL::GetContext( CONTEXT& c )
{
	CopyRegisters( c, Ctx, c.ContextFlags );
}

// when override_return is true, Eax will not be set on syscall return
void THREAD_IMPL::SetContext( CONTEXT& c, bool override_return )
{
	CopyRegisters( Ctx, c, c.ContextFlags );
	ContextChanged = override_return;
	DumpRegs( &Ctx );
}

NTSTATUS THREAD_IMPL::CopyToUser( void *dest, const void *src, size_t count )
{
	assert( Process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return Process->Vm->CopyToUser( dest, src, count );
}

NTSTATUS THREAD_IMPL::CopyFromUser( void *dest, const void *src, size_t count )
{
	assert( Process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return Process->Vm->CopyFromUser( dest, src, count );
}

NTSTATUS THREAD_IMPL::VerifyForWrite( void *dest, size_t count )
{
	assert( Process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return Process->Vm->VerifyForWrite( dest, count );
}

NTSTATUS THREAD_IMPL::ZeroTlsCells( ULONG index )
{
	if (index >= (sizeof Teb->TlsSlots/sizeof Teb->TlsSlots[0]))
		return STATUS_INVALID_PARAMETER;
	Teb->TlsSlots[index] = 0;
	return STATUS_SUCCESS;
}

void THREAD_IMPL::RegisterTerminatePort( OBJECT *port )
{
	if (TerminatePort)
		Release(TerminatePort);
	AddRef( port );
	TerminatePort = port;
}

NTSTATUS THREAD_IMPL::Terminate( NTSTATUS status )
{
	if (ThreadState == StateTerminated)
		return STATUS_INVALID_PARAMETER;

	trace("%04lx: terminated\n", TraceId());

	ExitStatus = status;
	SetState( StateTerminated );

	// store the exit time
	Times.ExitTime = TIMEOUT::CurrentTime();

	// send the Thread terminate message if necessary
	if (TerminatePort)
	{
		SendTerminateMessage( this, TerminatePort, Times.CreateTime );
		TerminatePort = 0;
	}

	// if we just killed the last thread in the process, kill the process too
	if (Process->IsSignalled())
	{
		trace("last Thread in process exited %08lx\n", status);
		Process->Terminate( status );
	}

	if (this == Current)
		Stop();

	return STATUS_SUCCESS;
}

void THREAD::Stop()
{
	FIBER::Stop();
	Current = this;
}

int THREAD_IMPL::Run()
{
	int i = 0;
	while (1)
	{
		Current = this;

		if (ThreadState == StateTerminated)
			return 0;

		if (ThreadState != StateRunning)
		{
			trace("%04lx: Thread state wrong (%d)!\n", TraceId(), ThreadState);
			assert (0);
		}

		// run for 10ms
		LARGE_INTEGER timeout;
		timeout.QuadPart = 10L; // 10ms

		Process->Vm->Run( TebBaseAddress, &Ctx, false, timeout, this );

		if (TraceStepAccess)
		{
			// enable access to the memory, then single step over the access
			Process->Vm->SetTraced( TraceAccessedAddress, false );
			Process->Vm->Run( TebBaseAddress, &Ctx, true, timeout, this );
			Process->Vm->SetTraced( TraceAccessedAddress, true );
			TraceStepAccess = false;
		}

		if (CallbackFrame && CallbackFrame->IsComplete())
		{
			CallbackFrame->Pop( this );
			return 0;
		}

		// keep running the same thread for a while
		if (ThreadState == StateRunning && i<=10)
		{
			i++;
			continue;
		}

		i = 0;
		FIBER::Yield();
	}
	return 0;
}

void THREAD_IMPL::HandleFault()
{
	unsigned char inst[8];
	NTSTATUS r;

	memset( inst, 0, sizeof inst );
	assert( Current == this );
	r = CopyFromUser( inst, (void*) Ctx.Eip, 2 );
	if (r < STATUS_SUCCESS ||
			inst[0] != 0xcd ||
			!SoftwareInterrupt( inst[1] ))
	{
		if (inst[0] == 0xcc)
			trace("breakpoint (cc)!\n");
		if (TracedAccess())
			return;
		if (option_debug)
			Debugger();
		HandleUserSegv( STATUS_ACCESS_VIOLATION );
	}
}

void THREAD_IMPL::HandleBreakpoint()
{
	if (option_debug)
	{
		Debugger();
		return;
	}

	HandleUserSegv( STATUS_BREAKPOINT );
}

THREAD::THREAD(PROCESS *p) :
	FIBER( fiber_default_stack_size ),
	Process( p ),
	MessageId(0),
	Port(0),
	Queue(0)
{
	Id = AllocateId();
	AddRef( Process );
	Process->Threads.Append( this );
}

THREAD::~THREAD()
{
	if (Queue)
		delete Queue;
	Process->Threads.Unlink( this );
	Release( Process );
}

THREAD_IMPL::THREAD_IMPL( PROCESS *p ) :
	THREAD( p ),
	ThreadState(StateInitialized),
	SuspendCount(1),
	ExitStatus(STATUS_PENDING),
	TebSection(0),
	TebBaseAddress(0),
	Teb(0),
	Alerted(0),
	Alertable(0),
	WaitType(WaitAny),
	InWait(0),
	ContextChanged(0),
	TerminatePort(0),
	Token(0),
	CallbackFrame(0),
	Win32kInitDone(false),
	TraceStepAccess(false),
	TraceAccessedAddress(0)
{

	Times.CreateTime = TIMEOUT::CurrentTime();
	Times.ExitTime.QuadPart = 0;
	Times.UserTime.QuadPart = 0;
	Times.KernelTime.QuadPart = 0;
}

bool THREAD_IMPL::Win32kInitComplete()
{
	if (Win32kInitDone)
		return true;
	Win32kInitDone = true;
	return false;
}

void THREAD::GetClientID( CLIENT_ID *client_id )
{
	client_id->UniqueProcess = (HANDLE) (Process->Id);
	client_id->UniqueThread = (HANDLE) Id;
}

void THREAD_IMPL::QueryInformation( THREAD_BASIC_INFORMATION& info )
{
	info.ExitStatus = ExitStatus;
	info.TebBaseAddress = TebBaseAddress;
	GetClientID( &info.ClientId );
	// FIXME: AffinityMask, Priority, BasePriority
}

void THREAD_IMPL::QueryInformation( KERNEL_USER_TIMES& info )
{
	info = Times;
}

THREAD_IMPL::~THREAD_IMPL()
{
	// delete outstanding APCs
	while (ApcList.Empty())
	{
		THREAD_APC *apc = ApcList.Head();
		ApcList.Unlink( apc );
		delete apc;
	}
}

NTSTATUS THREAD_IMPL::Resume( PULONG count )
{
	if (count)
		*count = SuspendCount;
	if (!SuspendCount)
		return STATUS_SUCCESS;
	if (!--SuspendCount)
	{
		SetState( StateRunning );
		Start();
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtResumeThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount )
{
	THREAD *thread;
	ULONG count = 0;
	NTSTATUS r;

	trace("%p %p\n", ThreadHandle, PreviousSuspendCount );

	r = ObjectFromHandle( thread, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = thread->Resume( &count );

	if (r == STATUS_SUCCESS && PreviousSuspendCount)
		r = CopyToUser( PreviousSuspendCount, &count, sizeof count );

	return r;
}

NTSTATUS NTAPI NtSuspendThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount)
{
	trace("%p %p\n", ThreadHandle, PreviousSuspendCount );
	return STATUS_NOT_IMPLEMENTED;
}

THREAD_OBJ_WAIT::THREAD_OBJ_WAIT( THREAD_IMPL* t, SYNC_OBJECT* o):
	Obj(o),
	Thread(t)
{
	AddRef(Obj);
	Obj->AddWatch( this );
}

void THREAD_OBJ_WAIT::Notify()
{
	//trace("waking %p\n", Thread);
	Thread->Notify();
}

void THREAD_IMPL::Start()
{
	// check we weren't terminated
	if (ThreadState != StateTerminated)
		FIBER::Start();
}

void THREAD::Wait()
{
	Stop();
}

void THREAD_IMPL::Wait()
{
	SetState( StateWait );
	THREAD::Wait();
	SetState( StateRunning );
}

NTSTATUS THREAD_IMPL::CheckWait()
{
	NTSTATUS r;

	// check for satisfied waits first, then APCs
	r = (WaitType == WaitAll) ? CheckWaitAll() : CheckWaitAny();
	if (r == STATUS_PENDING && Alertable && DeliverApc(STATUS_USER_APC))
		return STATUS_USER_APC;
	return r;
}

THREAD_OBJ_WAIT::~THREAD_OBJ_WAIT()
{
	Obj->RemoveWatch( this );
	Release(Obj);
}

NTSTATUS THREAD_IMPL::WaitOn( SYNC_OBJECT *obj )
{
	THREAD_OBJ_WAIT *wait = new THREAD_OBJ_WAIT( this, obj );
	if (!wait)
		return STATUS_NO_MEMORY;

	// Append to list so value in CheckWaitAny() is right.
	WaitList.Append( wait );
	return STATUS_SUCCESS;
}

void THREAD_IMPL::EndWait()
{
	THREAD_OBJ_WAIT_ITER i(WaitList);

	while (i)
	{
		THREAD_OBJ_WAIT *wait = i;
		i.Next();
		WaitList.Unlink( wait );
		delete wait;
	}
}

NTSTATUS THREAD_IMPL::CheckWaitAll()
{
	THREAD_OBJ_WAIT_ITER i(WaitList);

	while (i)
	{
		THREAD_OBJ_WAIT *wait = i;

		if (!wait->Obj->IsSignalled())
			return STATUS_PENDING;
		i.Next();
	}

	i.Reset();
	while (i)
	{
		THREAD_OBJ_WAIT *wait = i;
		wait->Obj->Satisfy();
		i.Next();
	}
	return STATUS_SUCCESS;
}

NTSTATUS THREAD_IMPL::CheckWaitAny()
{
	THREAD_OBJ_WAIT_ITER i(WaitList);
	ULONG ret = 0; // return handle index to Thread

	while (i)
	{
		THREAD_OBJ_WAIT *wait = i;

		i.Next();
		if (wait->IsSignalled())
		{
			wait->Satisfy();
			return ret;
		}
		ret++;
	}
	return STATUS_PENDING;
}

void THREAD_IMPL::Notify()
{
	if (!InWait)
		return;
	InWait = FALSE;
	Start();
}

void THREAD_IMPL::SignalTimeout()
{
	Notify();
}

NTSTATUS THREAD_IMPL::WaitOnHandles(
	ULONG count,
	PHANDLE handles,
	WAIT_TYPE type,
	BOOLEAN alert,
	PLARGE_INTEGER timeout)
{
	NTSTATUS r = STATUS_SUCCESS;

	Alertable = alert;
	WaitType = type;

	// iterate the array and wait on each handle
	for (ULONG i=0; i<count; i++)
	{
		trace("handle[%ld] = %08lx\n", i, (ULONG) handles[i]);
		OBJECT *any = 0;
		r = ObjectFromHandle( any, handles[i], SYNCHRONIZE );
		if (r < STATUS_SUCCESS)
		{
			EndWait();
			return r;
		}

		SYNC_OBJECT *obj = dynamic_cast<SYNC_OBJECT*>( any );
		if (!obj)
		{
			EndWait();
			return STATUS_INVALID_HANDLE;
		}

		r = WaitOn( obj );
		if (r < STATUS_SUCCESS)
		{
			EndWait();
			return r;
		}
	}

	// make sure we wait for a little bit every time
	LARGE_INTEGER t;
	if (timeout && timeout->QuadPart <= 0 && timeout->QuadPart> -100000LL)
	{
		t.QuadPart = -100000LL;
		timeout = &t;
	}

	SetTimeout( timeout );
	while (1)
	{
		r = CheckWait();
		if (r != STATUS_PENDING)
			break;

		if (Alerted)
		{
			Alerted = FALSE;
			r = STATUS_ALERTED;
			break;
		}

		if (timeout && HasExpired())
		{
			r = STATUS_TIMEOUT;
			break;
		}

		InWait = TRUE;
		Wait();
		assert( InWait == FALSE );
	}

	EndWait();
	SetTimeout( 0 );

	return r;
}

NTSTATUS THREAD_IMPL::Alert()
{
	Alerted = TRUE;
	if (InWait)
		Notify();
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtWaitForSingleObject(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout)
{
	NTSTATUS r;

	trace("%p %d %p\n", Handle, Alertable, Timeout);

	OBJECT *any = 0;
	r = ObjectFromHandle( any, Handle, SYNCHRONIZE );
	if (r < STATUS_SUCCESS)
		return r;

	SYNC_OBJECT *obj = dynamic_cast<SYNC_OBJECT*>( any );
	if (!obj)
		return STATUS_INVALID_HANDLE;

	LARGE_INTEGER time;
	if (Timeout)
	{
		r = CopyFromUser( &time, Timeout, sizeof *Timeout );
		if (r < STATUS_SUCCESS)
			return r;
		Timeout = &time;
	}

	THREAD_IMPL *t = dynamic_cast<THREAD_IMPL*>( Current );
	assert( t );
	return t->WaitOnHandles( 1, &Handle, WaitAny, Alertable, Timeout );
}

NTSTATUS NTAPI NtWaitForMultipleObjects(
	ULONG HandleCount,
	PHANDLE Handles,
	WAIT_TYPE WaitType,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout)
{
	NTSTATUS r;

	trace("%lu %p %u %u %p\n", HandleCount, Handles, WaitType, Alertable, Timeout);

	if (HandleCount < 1 || HandleCount > MAXIMUM_WAIT_OBJECTS)
		return STATUS_INVALID_PARAMETER_1;

	LARGE_INTEGER t;
	if (Timeout)
	{
		r = CopyFromUser( &t, Timeout, sizeof t );
		if (r < STATUS_SUCCESS)
			return r;
		Timeout = &t;
	}

	// copy the array of handles
	HANDLE hcopy[MAXIMUM_WAIT_OBJECTS];
	r = CopyFromUser( hcopy, Handles, HandleCount * sizeof (HANDLE) );
	if (r < STATUS_SUCCESS)
		return r;

	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->WaitOnHandles( HandleCount, hcopy, WaitType, Alertable, Timeout );
}

NTSTATUS NTAPI NtDelayExecution( BOOLEAN Alertable, PLARGE_INTEGER Interval )
{
	LARGE_INTEGER timeout;
	NTSTATUS r;

	r = CopyFromUser( &timeout, Interval, sizeof timeout );
	if (r < STATUS_SUCCESS)
		return r;

	trace("timeout = %llx\n", timeout.QuadPart);
	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	r = thread->WaitOnHandles( 0, 0, WaitAny, Alertable, &timeout );
	if (r == STATUS_TIMEOUT)
		r = STATUS_SUCCESS;
	return r;
}

class TEB_TRACER : public BLOCK_TRACER
{
public:
	virtual void OnAccess( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool Enabled() const;
};

bool TEB_TRACER::Enabled() const
{
	return TraceIsEnabled( "tebshm" );
}

void TEB_TRACER::OnAccess( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->GetBaseAddress();
	fprintf(stderr, "%04lx: accessed Teb[%04lx] from %08lx\n",
			Current->TraceId(), ofs, eip);
}

TEB_TRACER TEBTrace;

NTSTATUS CreateThread( THREAD **pthread, PROCESS *p, PCLIENT_ID id, CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended )
{
	THREAD_IMPL *t = new THREAD_IMPL( p );
	if (!t)
		return STATUS_INSUFFICIENT_RESOURCES;
	NTSTATUS r = t->Create( ctx, init_teb, suspended );
	if (r < STATUS_SUCCESS)
	{
		trace("releasing partially built Thread\n");
		Release( t );
		t = 0;
	}
	else
	{
		*pthread = t;
		// FIXME: does a Thread die when its last handle is closed?
		AddRef( t );

		t->GetClientID( id );
	}

	return r;
}

NTSTATUS THREAD_IMPL::Create( CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended )
{
	void *pLdrInitializeThunk;
	void *pKiUserApcDispatcher;
	PTEB pteb = NULL;
	BYTE *addr = 0;
	void *stack;
	NTSTATUS r;
	struct
	{
		void *pLdrInitializeThunk;
		void *unk1;
		void *pntdll;  /* set to pexe if running a win32 program */
		void *unk2;
		CONTEXT ctx;
		void *ret;	 /* return address (to KiUserApcDispatcher?) */
	} init_stack;

	/* allocate the TEB */
	LARGE_INTEGER sz;
	sz.QuadPart = PAGE_SIZE;
	r = CreateSection( &TebSection, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	r = TebSection->Mapit( Process->Vm, addr, 0, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	Teb = (PTEB) TebSection->GetKernelAddress();

	pteb = (PTEB) addr;
	Teb->Peb = (PPEB) Process->PebBaseAddress;
	Teb->Tib.Self = &pteb->Tib;
	Teb->StaticUnicodeString.Buffer = pteb->StaticUnicodeBuffer;
	Teb->StaticUnicodeString.MaximumLength = sizeof pteb->StaticUnicodeBuffer;
	Teb->StaticUnicodeString.Length = sizeof pteb->StaticUnicodeBuffer;

	// FIXME: need a good Thread test for these
	Teb->DeallocationStack = init_teb->StackReserved;
	Teb->Tib.StackBase = init_teb->StackCommit;
	Teb->Tib.StackLimit = init_teb->StackReserved;

	GetClientID( &Teb->ClientId );

	/* setup fs in the user address space */
	TebBaseAddress = pteb;

	/* find entry points */
	pLdrInitializeThunk = (BYTE*)Process->PNtDLL + GetProcAddress( NtDLLSection, "LdrInitializeThunk" );
	if (!pLdrInitializeThunk)
		Die("failed to find LdrInitializeThunk in ntdll\n");

	pKiUserApcDispatcher = (BYTE*)Process->PNtDLL + GetProcAddress( NtDLLSection, "KiUserApcDispatcher" );
	if (!pKiUserApcDispatcher)
		Die("failed to find KiUserApcDispatcher in ntdll\n");

	trace("LdrInitializeThunk = %p pKiUserApcDispatcher = %p\n",
		  pLdrInitializeThunk, pKiUserApcDispatcher );

	// FIXME: should set initial registers then queue an APC

	/* set up the stack */
	stack = (BYTE*) ctx->Esp - sizeof init_stack;

	/* setup the registers */
	int err = SetInitialRegs( pKiUserApcDispatcher, stack );
	if (0>err)
		trace("SetInitialRegs failed (%d)\n", err);

	memset( &init_stack, 0, sizeof init_stack );
	init_stack.pntdll = Process->PNtDLL;  /* set to pexe if running a win32 program */
	init_stack.pLdrInitializeThunk = pLdrInitializeThunk;

	/* copy the context onto the stack for NtContinue */
	memcpy( &init_stack.ctx, ctx, sizeof *ctx );
	init_stack.ret  = (void*) 0xf00baa;

	r = Process->Vm->CopyToUser( stack, &init_stack, sizeof init_stack );
	if (r < STATUS_SUCCESS)
		trace("failed to copy initial stack data\n");

	if (!suspended)
		Resume( NULL );

	Process->Vm->SetTracer( addr, TEBTrace );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreateThread(
	PHANDLE Thread,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE Process,
	PCLIENT_ID ClientId,
	PCONTEXT Context,
	PINITIAL_TEB InitialTeb,
	BOOLEAN CreateSuspended )
{
	INITIAL_TEB init_teb;
	CONTEXT ctx;
	NTSTATUS r;
	PROCESS *p;
	THREAD *t = NULL;
	CLIENT_ID id;

	trace("%p %08lx %p %p %p %p %p %d\n", Thread, DesiredAccess, ObjectAttributes,
		  Process, ClientId, Context, InitialTeb, CreateSuspended);

	r = CopyFromUser( &ctx, Context, sizeof ctx );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &init_teb, InitialTeb, sizeof init_teb );
	if (r < STATUS_SUCCESS)
		return r;

	r = ProcessFromHandle( Process, &p );
	if (r < STATUS_SUCCESS)
		return r;

	memset( &id, 0, sizeof id );
	r = CreateThread( &t, p, &id, &ctx, &init_teb, CreateSuspended );

	if (r == STATUS_SUCCESS)
	{
		r = AllocUserHandle( t, DesiredAccess, Thread );
		Release( t );
	}

	if (r == STATUS_SUCCESS)
		r = CopyToUser( ClientId, &id, sizeof id );

	return r;
}

NTSTATUS NTAPI NtContinue(
	PCONTEXT Context,
	BOOLEAN RaiseAlert)
{
	NTSTATUS r;

	trace("%p %d\n", Context, RaiseAlert);

	CONTEXT c;
	r = CopyFromUser( &c, Context, sizeof c );
	if (r < STATUS_SUCCESS)
		return r;

	c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	thread->SetContext( c );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtYieldExecution( void )
{
	THREAD *t = Current;
	for (int i=0; i<0x10; i++)
		FIBER::Yield();
	Current = t;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtTerminateThread(
	HANDLE ThreadHandle,
	NTSTATUS Status)
{
	THREAD *t;
	NTSTATUS r;

	trace("%p %08lx\n", ThreadHandle, Status);

	if (ThreadHandle == 0)
		t = Current;
	else
	{
		r = ObjectFromHandle( t, ThreadHandle, 0 );
		if (r < STATUS_SUCCESS)
			return r;
	}

	// If we killed ourselves we'll return the the scheduler but never run again.
	return t->Terminate( Status );
}

ULONG THREAD_IMPL::IsLastThread()
{
	for ( SIBLING_ITER i(Process->Threads); i; i.Next() )
	{
		THREAD *t = i;
		if (t != this && !t->IsTerminated())
			return 0;
	}
	return 1;
}

NTSTATUS NTAPI NtQueryInformationThread(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength)
{
	union
	{
		THREAD_BASIC_INFORMATION basic;
		KERNEL_USER_TIMES times;
		ULONG last_thread;
	} info;
	ULONG sz = 0;
	NTSTATUS r;
	THREAD_IMPL *t;

	trace("%p %d %p %lu %p\n", ThreadHandle,
		  ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

	switch( ThreadInformationClass )
	{
	case ThreadBasicInformation:
		sz = sizeof info.basic;
		break;
	case ThreadTimes:
		sz = sizeof info.times;
		break;
	case ThreadAmILastThread:
		sz = sizeof info.last_thread;
		break;
	default:
		trace("info class %d\n", ThreadInformationClass);
		return STATUS_INVALID_INFO_CLASS;
	}

	if (sz != ThreadInformationLength)
		return STATUS_INFO_LENGTH_MISMATCH;

	memset( &info, 0, sizeof info );

	r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	if (ReturnLength)
	{
		r = VerifyForWrite( ReturnLength, sizeof *ReturnLength );
		if (r < STATUS_SUCCESS)
			return r;
	}

	switch( ThreadInformationClass )
	{
	case ThreadBasicInformation:
		t->QueryInformation( info.basic );
		break;
	case ThreadTimes:
		t->QueryInformation( info.times );
		break;
	case ThreadAmILastThread:
		info.last_thread = t->IsLastThread();
		break;
	default:
		assert(0);
	}

	r = CopyToUser( ThreadInformation, &info, sz );

	if (r == STATUS_SUCCESS && ReturnLength)
		CopyToUser( ReturnLength, &sz, sizeof sz );

	return r;
}

NTSTATUS NTAPI NtAlertThread(
	HANDLE ThreadHandle)
{
	NTSTATUS r;
	THREAD_IMPL *t = 0;

	trace("%p\n", ThreadHandle);

	r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	return t->Alert();
}

NTSTATUS NTAPI NtAlertResumeThread(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount)
{
	trace("%p %p\n", ThreadHandle, PreviousSuspendCount);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtTestAlert(void)
{
	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->TestAlert();
}

NTSTATUS THREAD_IMPL::TestAlert()
{
	if (Alerted)
	{
		Alerted = FALSE;
		return STATUS_ALERTED;
	}

	DeliverApc(STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

void THREAD_IMPL::SetToken( TOKEN *tok )
{
	if (Token) Release( Token );
	if (tok) AddRef( tok );
	Token = tok;
}

TOKEN *THREAD_IMPL::GetToken()
{
	return Token;
}

PVOID& THREAD_IMPL::GetWin32StartAddress()
{
	return Win32StartAddress;
}

NTSTATUS NTAPI NtSetInformationThread(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength)
{
	trace("%p %u %p %lu\n", ThreadHandle, ThreadInformationClass,
		  ThreadInformation, ThreadInformationLength);

	THREAD_IMPL *t = 0;
	NTSTATUS r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	switch (ThreadInformationClass)
	{
		case ThreadPriority:
			return STATUS_SUCCESS;
		case ThreadBasePriority:
			return STATUS_SUCCESS;
		case ThreadImpersonationToken:
		{
			HANDLE TokenHandle = 0;
			if (ThreadInformationLength != sizeof TokenHandle)
				return STATUS_INFO_LENGTH_MISMATCH;
			NTSTATUS r = CopyFromUser( &TokenHandle, ThreadInformation, sizeof TokenHandle );
			if (r < STATUS_SUCCESS)
				return r;
			TOKEN *token = NULL;
			if (TokenHandle)
			{
				r = ObjectFromHandle(token, TokenHandle, 0);
				if (r < STATUS_SUCCESS)
				{
					trace("invalid token handle, status: 0x%08lx\n", r);
					return r;
				}
			}
			t->SetToken( token );
			return STATUS_SUCCESS;
		}
		case ThreadZeroTlsCell:
		{
			ULONG index = 0;
			NTSTATUS r = CopyFromUser( &index, ThreadInformation, sizeof index );
			if (r < STATUS_SUCCESS)
				return r;
			return t->ZeroTlsCells( index );
			return STATUS_SUCCESS; // FIXME: ?????????????????????????
		}
		case ThreadQuerySetWin32StartAddress:
		{
			PVOID& Win32StartAddress = t->GetWin32StartAddress();
			if (ThreadInformationLength != sizeof Win32StartAddress)
				return STATUS_INFO_LENGTH_MISMATCH;
			return CopyFromUser( &Win32StartAddress, ThreadInformation, sizeof Win32StartAddress );
		}
		default:
			break;
	}
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQueueApcThread(
	HANDLE ThreadHandle,
	PKNORMAL_ROUTINE ApcRoutine,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3)
{
	trace("%p %p %p %p %p\n", ThreadHandle, ApcRoutine, Arg1, Arg2, Arg3);

	THREAD *t = 0;
	NTSTATUS r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	return t->QueueApcThread(ApcRoutine, Arg1, Arg2, Arg3);
}

NTSTATUS output_debug_string( EXCEPTION_RECORD& exrec )
{
	NTSTATUS r;

	if (exrec.NumberParameters != 2)
	{
		trace("OutputDebugStringA with %ld args\n",
			  exrec.NumberParameters);
		return STATUS_INVALID_PARAMETER;
	}

	ULONG len = exrec.ExceptionInformation[0];
	LPCWSTR str = (LPCWSTR) exrec.ExceptionInformation[1];

	char buffer[0x100];
	len = min( sizeof buffer - 1, len );

	r = CopyFromUser( buffer, str, len );
	if (r != STATUS_SUCCESS)
	{
		trace("OutputDebugStringA %p %ld (unreadable)\n", str, len);
		return r;
	}
	buffer[len] = 0;

	if (OptionTrace)
		fprintf(stderr, "OutputDebugString: %s\n", buffer );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtRaiseException( PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context, BOOL SearchFrames )
{
	EXCEPTION_STACK_FRAME info;
	NTSTATUS r;

	r = CopyFromUser( &info.Rec, ExceptionRecord, sizeof info.Rec );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &info.Ctx, Context, sizeof info.Ctx );
	if (r < STATUS_SUCCESS)
		return r;

	// Get this when OutputDebugStringA is used
	if (info.Rec.ExceptionCode == DBG_PRINTEXCEPTION_C)
	{
		output_debug_string( info.Rec );
		THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
		assert( thread );
		thread->SetContext( info.Ctx );
		return STATUS_SUCCESS;
	}

	// FIXME: perhaps we should blow away everything pushed on after the current frame

	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->RaiseException( info, SearchFrames );
}

NTSTATUS THREAD_IMPL::RaiseException(
	EXCEPTION_STACK_FRAME& info,
	BOOLEAN SearchFrames )
{
	// Pop our args
	Ctx.Esp += 12;

	// NtRaiseException probably just pushes two pointers on the stack
	// rather than copying the full context and exception record...

	if (!SearchFrames)
		Terminate( info.Rec.ExceptionCode );
	else
		StartExceptionHandler( info );

	return STATUS_SUCCESS;  // not used
}

NTSTATUS NTAPI NtCallbackReturn(
	PVOID Result,
	ULONG ResultLength,
	NTSTATUS Status)
{
	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->UserCallbackReturn(Result, ResultLength, Status);
}

NTSTATUS OpenThread(THREAD **thread, OBJECT_ATTRIBUTES *oa)
{
	OBJECT *obj = NULL;
	THREAD *p;
	NTSTATUS r;

	r = GetNamedObject(&obj, oa);
	if (r < STATUS_SUCCESS)
		return r;

	p = dynamic_cast<THREAD*>(obj);
	if (!p)
	{
		Release(obj);
		return STATUS_OBJECT_TYPE_MISMATCH;
	}

	*thread = p;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtOpenThread(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId)
{
	OBJECT_ATTRIBUTES SafeObjectAttributes;
	CUNICODE_STRING SafeObjectName;
	CLIENT_ID SafeClientId;
	THREAD *Thread = NULL;
	NTSTATUS Status;
	
	trace("%p %08lx %p %p\n", ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
	
	Status = CopyFromUser(&SafeObjectAttributes, ObjectAttributes, sizeof SafeObjectAttributes);
	if (Status < STATUS_SUCCESS)
		return Status;

	if (SafeObjectAttributes.ObjectName)
	{
		Status = SafeObjectName.CopyFromUser(SafeObjectAttributes.ObjectName);
		if (Status < STATUS_SUCCESS)
			return Status;
		SafeObjectAttributes.ObjectName = &SafeObjectName;
	}

	SafeClientId.UniqueProcess = 0;
	SafeClientId.UniqueThread = 0;
	if (ClientId)
	{
		Status = CopyFromUser(&SafeClientId, ClientId, sizeof SafeClientId);
		if (Status < STATUS_SUCCESS)
			return Status;
	}

	trace("client id %p %p\n", SafeClientId.UniqueProcess, SafeClientId.UniqueThread);

	if (SafeObjectAttributes.ObjectName == 0)
	{
		trace("cid\n");
		if (SafeClientId.UniqueProcess)
		{
			Thread = FindThreadByClientId(&SafeClientId);
			if (!Thread)
				return STATUS_INVALID_CID;
		}
		else
		{
			Thread = FindThreadById(SafeClientId.UniqueThread);
			if (!Thread)
				return STATUS_INVALID_CID;
		}
	}
	else
	{
		trace("objectname\n");

		if (!SafeObjectAttributes.ObjectName)
			return STATUS_INVALID_PARAMETER;

		if (ClientId)
			return STATUS_INVALID_PARAMETER_MIX;

		if (SafeObjectAttributes.Length != sizeof SafeObjectAttributes)
			return STATUS_INVALID_PARAMETER;

		if (SafeObjectName.Length == 0)
			return STATUS_OBJECT_PATH_SYNTAX_BAD;

		Status = OpenThread(&Thread, &SafeObjectAttributes);
	}

	if (Status == STATUS_SUCCESS)
	{
		Status = AllocUserHandle(Thread, DesiredAccess, ThreadHandle);
	}

	trace("returning 0x%08lx\n", Status);
	
	return Status;
}

NTSTATUS NTAPI NtSetThreadExecutionState(
	EXECUTION_STATE ExecutionState,
	PEXECUTION_STATE PreviousExecutionState )
{
	trace("%ld %p\n", ExecutionState, PreviousExecutionState );
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtGetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT Context)
{
	trace("%p %p\n", ThreadHandle, Context );

	THREAD *t = 0;
	NTSTATUS r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	CONTEXT c;
	r = CopyFromUser( &c, Context, sizeof c );
	if (r < STATUS_SUCCESS)
		return r;

	t->GetContext( c );

	r = CopyToUser( Context, &c, sizeof c );
	return r;
}

NTSTATUS NTAPI NtSetContextThread(
	HANDLE ThreadHandle,
	PCONTEXT Context)
{
	trace("%p %p\n", ThreadHandle, Context );

	THREAD_IMPL *t = 0;
	NTSTATUS r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	CONTEXT c;
	r = CopyFromUser( &c, Context, sizeof c );
	if (r < STATUS_SUCCESS)
		return r;

	t->SetContext( c );
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryDefaultLocale(
	BOOLEAN ThreadOrSystem,
	PLCID Locale)
{
	trace("%x %p\n", ThreadOrSystem, Locale);

	LCID lcid = MAKELCID( MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), SORT_DEFAULT );

	return CopyToUser( Locale, &lcid, sizeof lcid );
}

NTSTATUS NTAPI NtQueryDefaultUILanguage(
	LANGID* Language)
{
	LANGID lang = MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT);
	return CopyToUser( Language, &lang, sizeof lang );
}

NTSTATUS NTAPI NtQueryInstallUILanguage(
	LANGID* Language)
{
	LANGID lang = MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT);
	return CopyToUser( Language, &lang, sizeof lang );
}

NTSTATUS NTAPI NtImpersonateThread(
	HANDLE ThreadHandle,
	HANDLE TargetThreadHandle,
	PSECURITY_QUALITY_OF_SERVICE SecurityQoS)
{
	trace("\n");

	THREAD *t = 0;
	NTSTATUS r = ObjectFromHandle( t, ThreadHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	THREAD *target = 0;
	r = ObjectFromHandle( target, TargetThreadHandle, THREAD_DIRECT_IMPERSONATION );
	if (r < STATUS_SUCCESS)
		return r;

	SECURITY_QUALITY_OF_SERVICE qos;
	r = CopyFromUser( &qos, SecurityQoS, sizeof qos );
	if (r < STATUS_SUCCESS)
		return r;

	return STATUS_SUCCESS;
}
