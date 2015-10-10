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

class thread_obj_wait_t;
typedef LIST_ANCHOR<thread_obj_wait_t, 0> thread_obj_wait_list_t;
typedef LIST_ELEMENT<thread_obj_wait_t> thread_obj_wait_element_t;
typedef LIST_ITER<thread_obj_wait_t, 0> thread_obj_wait_iter_t;

struct thread_obj_wait_t : public WATCH
{
	thread_obj_wait_element_t Entry[1];
	SYNC_OBJECT *obj;
	THREAD_IMPL *thread;
public:
	thread_obj_wait_t( THREAD_IMPL* t, SYNC_OBJECT* o);
	virtual void Notify();
	virtual ~thread_obj_wait_t();
	BOOLEAN IsSignalled()
	{
		return obj->IsSignalled();
	}
	BOOLEAN Satisfy()
	{
		return obj->Satisfy();
	}
};

class callback_frame_t
{
	CONTEXT ctx;
	callback_frame_t *prev;
	// values from NtCallbackReturn
	NTSTATUS status;
	ULONG length;
	PVOID buffer;
	BOOLEAN complete;
public:
	callback_frame_t(THREAD_IMPL *t);
	void do_return(NTSTATUS s, ULONG l, PVOID b);
	void get_return(NTSTATUS& s, ULONG& l, PVOID& b);
	BOOLEAN is_complete()
	{
		return complete;
	}
	void pop( THREAD_IMPL *t );
};

struct thread_apc_t;
typedef LIST_ANCHOR<thread_apc_t,0> thread_apc_list_t;
typedef LIST_ELEMENT<thread_apc_t> thread_apc_element_t;

struct thread_apc_t
{
	thread_apc_t(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3) :
		proc(ApcRoutine)
	{
		arg[0] = Arg1;
		arg[1] = Arg2;
		arg[2] = Arg3;
	}
	thread_apc_element_t Entry[1];
	PKNORMAL_ROUTINE proc;
	PVOID arg[3];
};

class THREAD_IMPL :
	public THREAD,
	public EXECUTION_CONTEXT,
	public timeout_t
{
	THREAD_STATE ThreadState;
	ULONG SuspendCount;

	//SYSTEM_THREAD_INFORMATION members
	NTSTATUS ExitStatus;
	section_t *teb_section;
	PVOID TebBaseAddress;	// user
	PTEB teb;		// kernel

	// list of APCs
	thread_apc_list_t apc_list;
	BOOLEAN alerted;

	// blocking objects
	thread_obj_wait_list_t wait_list;
	BOOLEAN Alertable;
	WAIT_TYPE WaitType;
	BOOLEAN in_wait;

	KERNEL_USER_TIMES times;

	CONTEXT ctx;
	BOOLEAN context_changed;

	OBJECT *terminate_port;
	token_t *token;

	// win32 callback stack
	callback_frame_t *callback_frame;
	PVOID Win32StartAddress;
	bool win32k_init_done;

	// memory access tracing
	bool trace_step_access;
	void *trace_accessed_address;

public:
	THREAD_IMPL( PROCESS *p );
	~THREAD_IMPL();
	NTSTATUS create( CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended );
	virtual BOOLEAN IsSignalled( void );
	void set_state( THREAD_STATE state );
	bool IsTerminated()
	{
		return ThreadState == StateTerminated;
	}
	void query_information( THREAD_BASIC_INFORMATION& info );
	void query_information( KERNEL_USER_TIMES& info );
	NTSTATUS zero_tls_cells( ULONG index );
	NTSTATUS kernel_debugger_output_string( struct kernel_debug_string_output *hdr );
	NTSTATUS kernel_debugger_call( ULONG func, void *arg1, void *arg2 );
	BOOLEAN software_interrupt( BYTE number );
	void handle_user_segv( ULONG code );
	bool traced_access();
	void start_exception_handler(exception_stack_frame& frame);
	NTSTATUS raise_exception( exception_stack_frame& info, BOOLEAN SearchFrames );
	NTSTATUS DoUserCallback( ULONG index, ULONG& length, PVOID& buffer);
	NTSTATUS user_callback_return(PVOID Result, ULONG ResultLength, NTSTATUS Status );
	NTSTATUS Terminate( NTSTATUS Status );
	NTSTATUS test_alert();
	NTSTATUS QueueApcThread(PKNORMAL_ROUTINE ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);
	BOOLEAN deliver_apc( NTSTATUS status );
	NTSTATUS Resume( PULONG count );
	int set_initial_regs( void *start, void *stack);
	void copy_registers( CONTEXT& dest, CONTEXT &src, ULONG flags );
	void set_context( CONTEXT& c, bool override_return=true );
	void GetContext( CONTEXT& c );
	void set_token( token_t *tok );
	token_t* GetToken();
	callback_frame_t* set_callback( callback_frame_t *cb );
	PVOID& win32_start_address();
	void RegisterTerminatePort( OBJECT *port );
	bool Win32kInitComplete();

	virtual int Run();

	// wait related functions
	NTSTATUS wait_on_handles( ULONG count, PHANDLE handles, WAIT_TYPE type, BOOLEAN alert, PLARGE_INTEGER timeout );
	NTSTATUS check_wait();
	NTSTATUS wait_on( SYNC_OBJECT *obj );
	NTSTATUS check_wait_all();
	NTSTATUS check_wait_any();
	void end_wait();
	virtual void SignalTimeout(); // timeout_t
	NTSTATUS delay_execution( LARGE_INTEGER& timeout );
	void start();
	void Wait();
	void notify();
	NTSTATUS alert();
	ULONG is_last_thread();

	virtual void HandleFault();
	virtual void HandleBreakpoint();

	virtual NTSTATUS CopyToUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS CopyFromUser( void *dest, const void *src, size_t count );
	virtual NTSTATUS VerifyForWrite( void *dest, size_t count );

	virtual void* Push( ULONG count );
	virtual void Pop( ULONG count );
	virtual PTEB GetTEB();
};

LIST_ANCHOR<runlist_entry_t,0> runlist_entry_t::running_threads;
ULONG runlist_entry_t::num_running_threads;

void runlist_entry_t::runlist_add()
{
	assert( (num_running_threads == 0) ^ !running_threads.Empty() );
	running_threads.Prepend( this );
	num_running_threads++;
}

void runlist_entry_t::runlist_remove()
{
	running_threads.Unlink( this );
	num_running_threads--;
	assert( (num_running_threads == 0) ^ !running_threads.Empty() );
}

ULONG runlist_entry_t::num_active_threads()
{
	return num_running_threads;
}

int THREAD_IMPL::set_initial_regs( void *start, void *stack)
{
	process->Vm->InitContext( ctx );

	ctx.Eip = (DWORD) start;
	ctx.Esp = (DWORD) stack;

	context_changed = TRUE;

	return 0;
}

BOOLEAN THREAD_IMPL::IsSignalled( void )
{
	return (ThreadState == StateTerminated);
}

void THREAD_IMPL::set_state( THREAD_STATE state )
{
	ULONG prev_state = ThreadState;

	if (prev_state == StateTerminated)
		return;

	ThreadState = state;
	switch (state)
	{
	case StateWait:
		runlist_remove();
		break;
	case StateRunning:
		runlist_add();
		break;
	case StateTerminated:
		NotifyWatchers();
		if (prev_state == StateRunning)
			runlist_remove();
		break;
	default:
		Die("switch to unknown thread state\n");
	}

	// ready to complete some I/O?
	if (num_active_threads() == 0)
		CheckCompletions();
}


NTSTATUS THREAD_IMPL::kernel_debugger_output_string( struct kernel_debug_string_output *hdr )
{
	struct kernel_debug_string_output header;
	char *string;
	NTSTATUS r;

	r = CopyFromUser( &header, hdr, sizeof header );
	if (r < STATUS_SUCCESS)
	{
		trace("debug string output header invalid\n");
		return r;
	}

	if ( header.length > 0x1000 )
	{
		trace("too long %d\n", header.length );
		return STATUS_SUCCESS;
	}

	string = new char[ header.length + 1 ];
	r = CopyFromUser( string, hdr+1, header.length );
	if (r >= STATUS_SUCCESS)
	{
		if (string[header.length - 1] == '\n')
			header.length--;

		string[header.length] = 0;
		fprintf(stderr, "%04lx: debug: %s\n", TraceId(), string);
	}
	else
		fprintf(stderr, "%04lx: debug - bad address\n", TraceId());

	delete[] string;
	return r;
}

ULONG THREAD::TraceId()
{
	if (!process)
		return id;
	return id | (process->Id<<8);
}

NTSTATUS THREAD_IMPL::kernel_debugger_call( ULONG func, void *arg1, void *arg2 )
{
	NTSTATUS r;

	switch (func)
	{
		case 1:
			r = kernel_debugger_output_string( (struct kernel_debug_string_output *)arg1 );
			break;
		case 0x101:
		{
			const char *sym = process->Vm->GetSymbol( (BYTE*) arg1 );
			if (sym)
				fprintf(stderr, "%04lx: %s called\n", TraceId(), sym);
			else
				fprintf(stderr, "%04lx: %p called\n", TraceId(), arg1);
		}
		r = 0;
		break;
		default:
			DumpRegs( &ctx );
			trace("unhandled function %ld\n", func );
			r = STATUS_NOT_IMPLEMENTED;
	}
	if (r < STATUS_SUCCESS)
		return r;

	// skip breakpoints after debugger calls
	BYTE inst[1];
	if (r == CopyFromUser( inst, (void*) ctx.Eip, 1 ) &&
		inst[0] == 0xcc)
	{
		ctx.Eip++;
	}
	return r;
}

BOOLEAN THREAD_IMPL::software_interrupt( BYTE number )
{
	if (number > 0x2e || number < 0x2b)
	{
		trace("Unhandled software interrupt %02x\n", number);
		return FALSE;
	}

	ctx.Eip += 2;
	context_changed = FALSE;

	NTSTATUS r;
	switch (number)
	{
	case 0x2b:
		r = NtCallbackReturn( (void*) ctx.Ecx, ctx.Edx, ctx.Eax );
		break;

	case 0x2c:
		r = NtSetLowWaitHighThread();
		break;

	case 0x2d:
		kernel_debugger_call( ctx.Eax, (void*) ctx.Ecx, (void*) ctx.Edx );
		r = ctx.Eax;  // check if this returns a value
		break;

	case 0x2e:
		r = DoNtSyscall( TraceId(), ctx.Eax, (ULONG*) ctx.Edx, ctx.Eip );
		break;

	default:
		assert(0);
	}

	if (!context_changed)
		ctx.Eax = r;

	return TRUE;
}

bool THREAD_IMPL::traced_access()
{
	// only trace the first fault
	if (trace_step_access)
		return false;

	// get the fault address
	void* addr = 0;
	if (0 != Current->process->Vm->GetFaultInfo( addr ))
		return false;

	// confirm the memory is traced
	if (!Current->process->Vm->TracedAccess( addr, ctx.Eip ))
		return false;

	trace_accessed_address = addr;
	trace_step_access = true;
	return true;
}

void THREAD_IMPL::handle_user_segv( ULONG code )
{
	trace("%04lx: exception at %08lx\n", TraceId(), ctx.Eip);
	if (OptionTrace)
	{
		DumpRegs( &ctx );
		DebuggerBacktrace(&ctx);
	}

	exception_stack_frame info;

	memset( &info, 0, sizeof info );
	memcpy( &info.ctx, &ctx, sizeof ctx );

	// FIXME: might not be an access violation
	info.rec.ExceptionCode = code;
	info.rec.ExceptionFlags = EXCEPTION_CONTINUABLE;
	info.rec.ExceptionRecord = 0;
	info.rec.ExceptionAddress = (void*) ctx.Eip;
	info.rec.NumberParameters = 0;
	//ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];

	start_exception_handler( info );
}

void THREAD_IMPL::start_exception_handler(exception_stack_frame& info)
{
	if (0)
	{
		trace("ExceptionCode	%08lx\n", info.rec.ExceptionCode);
		trace("ExceptionFlags   %08lx\n", info.rec.ExceptionFlags);
		trace("ExceptionRecord  %p\n", info.rec.ExceptionRecord);
		trace("ExceptionAddress %p\n", info.rec.ExceptionAddress);
		trace("NumberParameters %ld\n", info.rec.NumberParameters);
	}

	if (SendException( this, info.rec ))
		return;

	info.ctx.ContextFlags = context_all;

	info.ctx.SegCs &= 0xffff;
	info.ctx.SegEs &= 0xffff;
	info.ctx.SegSs &= 0xffff;
	info.ctx.SegDs &= 0xffff;
	info.ctx.SegFs &= 0xffff;
	info.ctx.SegGs &= 0xffff;

	// hack to stop looping
	if (info.ctx.Eip & 0x80000000)
	{
		trace("Eip invalid %08lx\n", info.ctx.Eip);
		Terminate(STATUS_ACCESS_VIOLATION);
		return;
	}

	// push the context, exception record and KiUserExceptionDispatcher args
	exception_stack_frame *stack = (exception_stack_frame*)((BYTE*) ctx.Esp - sizeof info);
	info.pctx = &stack->ctx;
	info.prec = &stack->rec;
	ctx.Esp = (LONG) stack;

	NTSTATUS r = CopyToUser( stack, &info, sizeof info );
	if (r < STATUS_SUCCESS)
	{
		trace("%04lx: invalid stack handling exception at %08lx\n", id, ctx.Eip);
		Terminate(r);
		return;
	}

	// get the address of the user side handler
	// FIXME: this should be stored in the PROCESS structure
	BYTE *pKiExceptionDispatcher = (BYTE*)process->PNtDLL +
								   get_proc_address( NtDLLSection, "KiUserExceptionDispatcher" );
	if (!pKiExceptionDispatcher)
		Die("failed to find KiExceptionDispatcher in ntdll\n");

	context_changed = 1;
	ctx.Eip = (ULONG) pKiExceptionDispatcher;
}

callback_frame_t* THREAD_IMPL::set_callback( callback_frame_t *cb )
{
	callback_frame_t *old = callback_frame;
	callback_frame = cb;
	return old;
}

callback_frame_t::callback_frame_t(THREAD_IMPL *t) :
	status(STATUS_PENDING),
	length(0),
	buffer(0),
	complete(FALSE)
{
	ctx.ContextFlags = context_all;
	t->GetContext( ctx );
	prev = t->set_callback( this );
}

void callback_frame_t::do_return( NTSTATUS s, ULONG l, PVOID b )
{
	assert(!complete);
	status = s;
	length = l;
	buffer = b;
	complete = TRUE;
}

void callback_frame_t::pop( THREAD_IMPL *t )
{
	assert( complete );
	t->set_callback( prev );
	// clear context_changed so eax is set
	t->set_context( ctx, false );
}

void callback_frame_t::get_return(NTSTATUS& s, ULONG& l, PVOID& b)
{
	assert(complete);
	s = status;
	l = length;
	b = buffer;
}

void* THREAD_IMPL::Push( ULONG count )
{
	ctx.Esp -= count;
	return (void*) ctx.Esp;
}

void THREAD_IMPL::Pop( ULONG count )
{
	ctx.Esp += count;
}

PTEB THREAD_IMPL::GetTEB()
{
	return teb;
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
	frame.x[2] = ctx.Esp;
	frame.x[3] = 0;

	//callback_stack.push( &ctx, fn );

	ULONG new_esp = ctx.Esp - sizeof frame;
	NTSTATUS r = CopyToUser( (void*) new_esp, &frame, sizeof frame );
	if (r < STATUS_SUCCESS)
	{
		trace("%04lx: invalid stack handling exception at %08lx\n", id, ctx.Eip);
		Terminate(r);
		return r;
	}

	// FIXME: limit recursion so we don't blow the stack

	// store the current user context
	callback_frame_t old_frame(this);

	// setup the new execution context
	BYTE *pKiUserCallbackDispatcher = (BYTE*)process->PNtDLL +
									  get_proc_address( NtDLLSection, "KiUserCallbackDispatcher" );

	context_changed = 1;
	ctx.Eip = (ULONG) pKiUserCallbackDispatcher;
	ctx.Esp = new_esp;

	// recurse, resume user execution here
	trace("continuing execution at %08lx\n", ctx.Eip);
	Run();

	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;

	// fetch return values out of the frame
	old_frame.get_return(r, length, buffer);
	context_changed = 0;
	trace("callback returned %08lx\n", r);

	return r;
}

NTSTATUS THREAD_IMPL::user_callback_return( PVOID Result, ULONG ResultLength, NTSTATUS Status )
{
	if (!callback_frame)
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
	callback_frame->do_return( Status, ResultLength, Result );
	return STATUS_SUCCESS;
}

NTSTATUS THREAD_IMPL::QueueApcThread(
	PKNORMAL_ROUTINE ApcRoutine,
	PVOID Arg1,
	PVOID Arg2,
	PVOID Arg3)
{
	thread_apc_t *apc;

	if (ThreadState == StateTerminated)
		return STATUS_ACCESS_DENIED;

	if (!ApcRoutine)
		return STATUS_SUCCESS;

	apc = new thread_apc_t(ApcRoutine, Arg1, Arg2, Arg3);
	if (!apc)
		return STATUS_NO_MEMORY;

	apc_list.Append( apc );
	if (in_wait)
		notify();

	return STATUS_SUCCESS;
}

BOOLEAN THREAD_IMPL::deliver_apc(NTSTATUS thread_return)
{
	// NOTE: can use this to start a thread...
	thread_apc_t *apc = apc_list.Head();
	if (!apc)
		return FALSE;

	apc_list.Unlink( apc );

	// set the return code in Eax
	ctx.Eax = thread_return;

	NTSTATUS r = STATUS_SUCCESS;
	ULONG new_esp = ctx.Esp;

	// push current context ... for NtContinue
	new_esp -= sizeof ctx;
	r = CopyToUser( (void*) new_esp, &ctx, sizeof ctx );
	if (r < STATUS_SUCCESS)
		goto end;

	// setup APC
	void *apc_stack[4];
	apc_stack[0] = (void*) apc->proc;
	apc_stack[1] = apc->arg[0];
	apc_stack[2] = apc->arg[1];
	apc_stack[3] = apc->arg[2];

	new_esp -= sizeof apc_stack;
	r = CopyToUser( (void*) new_esp, apc_stack, sizeof apc_stack );
	if (r < STATUS_SUCCESS)
		goto end;

	void *pKiUserApcDispatcher;
	pKiUserApcDispatcher = (BYTE*)process->PNtDLL + get_proc_address( NtDLLSection, "KiUserApcDispatcher" );
	if (!pKiUserApcDispatcher)
		Die("failed to find KiUserApcDispatcher in ntdll\n");

	ctx.Esp = new_esp;
	ctx.Eip = (ULONG) pKiUserApcDispatcher;
	context_changed = 1;

end:
	if (r < STATUS_SUCCESS)
		Terminate( r );
	delete apc;
	return TRUE;
}

void THREAD_IMPL::copy_registers( CONTEXT& dest, CONTEXT &src, ULONG flags )
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
	copy_registers( c, ctx, c.ContextFlags );
}

// when override_return is true, Eax will not be set on syscall return
void THREAD_IMPL::set_context( CONTEXT& c, bool override_return )
{
	copy_registers( ctx, c, c.ContextFlags );
	context_changed = override_return;
	DumpRegs( &ctx );
}

NTSTATUS THREAD_IMPL::CopyToUser( void *dest, const void *src, size_t count )
{
	assert( process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return process->Vm->CopyToUser( dest, src, count );
}

NTSTATUS THREAD_IMPL::CopyFromUser( void *dest, const void *src, size_t count )
{
	assert( process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return process->Vm->CopyFromUser( dest, src, count );
}

NTSTATUS THREAD_IMPL::VerifyForWrite( void *dest, size_t count )
{
	assert( process->IsValid() );
	if (IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	return process->Vm->VerifyForWrite( dest, count );
}

NTSTATUS THREAD_IMPL::zero_tls_cells( ULONG index )
{
	if (index >= (sizeof teb->TlsSlots/sizeof teb->TlsSlots[0]))
		return STATUS_INVALID_PARAMETER;
	teb->TlsSlots[index] = 0;
	return STATUS_SUCCESS;
}

void THREAD_IMPL::RegisterTerminatePort( OBJECT *port )
{
	if (terminate_port)
		Release(terminate_port);
	AddRef( port );
	terminate_port = port;
}

NTSTATUS THREAD_IMPL::Terminate( NTSTATUS status )
{
	if (ThreadState == StateTerminated)
		return STATUS_INVALID_PARAMETER;

	trace("%04lx: terminated\n", TraceId());

	ExitStatus = status;
	set_state( StateTerminated );

	// store the exit time
	times.ExitTime = timeout_t::current_time();

	// send the thread terminate message if necessary
	if (terminate_port)
	{
		SendTerminateMessage( this, terminate_port, times.CreateTime );
		terminate_port = 0;
	}

	// if we just killed the last thread in the process, kill the process too
	if (process->IsSignalled())
	{
		trace("last thread in process exited %08lx\n", status);
		process->Terminate( status );
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
			trace("%04lx: thread state wrong (%d)!\n", TraceId(), ThreadState);
			assert (0);
		}

		// run for 10ms
		LARGE_INTEGER timeout;
		timeout.QuadPart = 10L; // 10ms

		process->Vm->Run( TebBaseAddress, &ctx, false, timeout, this );

		if (trace_step_access)
		{
			// enable access to the memory, then single step over the access
			process->Vm->SetTraced( trace_accessed_address, false );
			process->Vm->Run( TebBaseAddress, &ctx, true, timeout, this );
			process->Vm->SetTraced( trace_accessed_address, true );
			trace_step_access = false;
		}

		if (callback_frame && callback_frame->is_complete())
		{
			callback_frame->pop( this );
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
	r = CopyFromUser( inst, (void*) ctx.Eip, 2 );
	if (r < STATUS_SUCCESS ||
			inst[0] != 0xcd ||
			!software_interrupt( inst[1] ))
	{
		if (inst[0] == 0xcc)
			trace("breakpoint (cc)!\n");
		if (traced_access())
			return;
		if (option_debug)
			Debugger();
		handle_user_segv( STATUS_ACCESS_VIOLATION );
	}
}

void THREAD_IMPL::HandleBreakpoint()
{
	if (option_debug)
	{
		Debugger();
		return;
	}

	handle_user_segv( STATUS_BREAKPOINT );
}

THREAD::THREAD(PROCESS *p) :
	FIBER( fiber_default_stack_size ),
	process( p ),
	MessageId(0),
	port(0),
	queue(0)
{
	id = AllocateId();
	AddRef( process );
	process->Threads.Append( this );
}

THREAD::~THREAD()
{
	if (queue)
		delete queue;
	process->Threads.Unlink( this );
	Release( process );
}

THREAD_IMPL::THREAD_IMPL( PROCESS *p ) :
	THREAD( p ),
	ThreadState(StateInitialized),
	SuspendCount(1),
	ExitStatus(STATUS_PENDING),
	teb_section(0),
	TebBaseAddress(0),
	teb(0),
	alerted(0),
	Alertable(0),
	WaitType(WaitAny),
	in_wait(0),
	context_changed(0),
	terminate_port(0),
	token(0),
	callback_frame(0),
	win32k_init_done(false),
	trace_step_access(false),
	trace_accessed_address(0)
{

	times.CreateTime = timeout_t::current_time();
	times.ExitTime.QuadPart = 0;
	times.UserTime.QuadPart = 0;
	times.KernelTime.QuadPart = 0;
}

bool THREAD_IMPL::Win32kInitComplete()
{
	if (win32k_init_done)
		return true;
	win32k_init_done = true;
	return false;
}

void THREAD::GetClientID( CLIENT_ID *client_id )
{
	client_id->UniqueProcess = (HANDLE) (process->Id);
	client_id->UniqueThread = (HANDLE) id;
}

void THREAD_IMPL::query_information( THREAD_BASIC_INFORMATION& info )
{
	info.ExitStatus = ExitStatus;
	info.TebBaseAddress = TebBaseAddress;
	GetClientID( &info.ClientId );
	// FIXME: AffinityMask, Priority, BasePriority
}

void THREAD_IMPL::query_information( KERNEL_USER_TIMES& info )
{
	info = times;
}

THREAD_IMPL::~THREAD_IMPL()
{
	// delete outstanding APCs
	while (apc_list.Empty())
	{
		thread_apc_t *apc = apc_list.Head();
		apc_list.Unlink( apc );
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
		set_state( StateRunning );
		start();
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

thread_obj_wait_t::thread_obj_wait_t( THREAD_IMPL* t, SYNC_OBJECT* o):
	obj(o),
	thread(t)
{
	AddRef(obj);
	obj->AddWatch( this );
}

void thread_obj_wait_t::Notify()
{
	//trace("waking %p\n", thread);
	thread->notify();
}

void THREAD_IMPL::start()
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
	set_state( StateWait );
	THREAD::Wait();
	set_state( StateRunning );
}

NTSTATUS THREAD_IMPL::check_wait()
{
	NTSTATUS r;

	// check for satisfied waits first, then APCs
	r = (WaitType == WaitAll) ? check_wait_all() : check_wait_any();
	if (r == STATUS_PENDING && Alertable && deliver_apc(STATUS_USER_APC))
		return STATUS_USER_APC;
	return r;
}

thread_obj_wait_t::~thread_obj_wait_t()
{
	obj->RemoveWatch( this );
	Release(obj);
}

NTSTATUS THREAD_IMPL::wait_on( SYNC_OBJECT *obj )
{
	thread_obj_wait_t *wait = new thread_obj_wait_t( this, obj );
	if (!wait)
		return STATUS_NO_MEMORY;

	// Append to list so value in check_wait_any() is right.
	wait_list.Append( wait );
	return STATUS_SUCCESS;
}

void THREAD_IMPL::end_wait()
{
	thread_obj_wait_iter_t i(wait_list);

	while (i)
	{
		thread_obj_wait_t *wait = i;
		i.Next();
		wait_list.Unlink( wait );
		delete wait;
	}
}

NTSTATUS THREAD_IMPL::check_wait_all()
{
	thread_obj_wait_iter_t i(wait_list);

	while (i)
	{
		thread_obj_wait_t *wait = i;

		if (!wait->obj->IsSignalled())
			return STATUS_PENDING;
		i.Next();
	}

	i.Reset();
	while (i)
	{
		thread_obj_wait_t *wait = i;
		wait->obj->Satisfy();
		i.Next();
	}
	return STATUS_SUCCESS;
}

NTSTATUS THREAD_IMPL::check_wait_any()
{
	thread_obj_wait_iter_t i(wait_list);
	ULONG ret = 0; // return handle index to thread

	while (i)
	{
		thread_obj_wait_t *wait = i;

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

void THREAD_IMPL::notify()
{
	if (!in_wait)
		return;
	in_wait = FALSE;
	start();
}

void THREAD_IMPL::SignalTimeout()
{
	notify();
}

NTSTATUS THREAD_IMPL::wait_on_handles(
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
			end_wait();
			return r;
		}

		SYNC_OBJECT *obj = dynamic_cast<SYNC_OBJECT*>( any );
		if (!obj)
		{
			end_wait();
			return STATUS_INVALID_HANDLE;
		}

		r = wait_on( obj );
		if (r < STATUS_SUCCESS)
		{
			end_wait();
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

	set_timeout( timeout );
	while (1)
	{
		r = check_wait();
		if (r != STATUS_PENDING)
			break;

		if (alerted)
		{
			alerted = FALSE;
			r = STATUS_ALERTED;
			break;
		}

		if (timeout && has_expired())
		{
			r = STATUS_TIMEOUT;
			break;
		}

		in_wait = TRUE;
		Wait();
		assert( in_wait == FALSE );
	}

	end_wait();
	set_timeout( 0 );

	return r;
}

NTSTATUS THREAD_IMPL::alert()
{
	alerted = TRUE;
	if (in_wait)
		notify();
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
	return t->wait_on_handles( 1, &Handle, WaitAny, Alertable, Timeout );
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
	return thread->wait_on_handles( HandleCount, hcopy, WaitType, Alertable, Timeout );
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
	r = thread->wait_on_handles( 0, 0, WaitAny, Alertable, &timeout );
	if (r == STATUS_TIMEOUT)
		r = STATUS_SUCCESS;
	return r;
}

class teb_tracer : public BLOCK_TRACER
{
public:
	virtual void OnAccess( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool Enabled() const;
};

bool teb_tracer::Enabled() const
{
	return TraceIsEnabled( "tebshm" );
}

void teb_tracer::OnAccess( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->GetBaseAddress();
	fprintf(stderr, "%04lx: accessed teb[%04lx] from %08lx\n",
			Current->TraceId(), ofs, eip);
}

teb_tracer teb_trace;

NTSTATUS create_thread( THREAD **pthread, PROCESS *p, PCLIENT_ID id, CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended )
{
	THREAD_IMPL *t = new THREAD_IMPL( p );
	if (!t)
		return STATUS_INSUFFICIENT_RESOURCES;
	NTSTATUS r = t->create( ctx, init_teb, suspended );
	if (r < STATUS_SUCCESS)
	{
		trace("releasing partially built thread\n");
		Release( t );
		t = 0;
	}
	else
	{
		*pthread = t;
		// FIXME: does a thread die when its last handle is closed?
		AddRef( t );

		t->GetClientID( id );
	}

	return r;
}

NTSTATUS THREAD_IMPL::create( CONTEXT *ctx, INITIAL_TEB *init_teb, BOOLEAN suspended )
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
	r = create_section( &teb_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	r = teb_section->mapit( process->Vm, addr, 0, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
		return r;

	teb = (PTEB) teb_section->get_kernel_address();

	pteb = (PTEB) addr;
	teb->Peb = (PPEB) process->PebBaseAddress;
	teb->Tib.Self = &pteb->Tib;
	teb->StaticUnicodeString.Buffer = pteb->StaticUnicodeBuffer;
	teb->StaticUnicodeString.MaximumLength = sizeof pteb->StaticUnicodeBuffer;
	teb->StaticUnicodeString.Length = sizeof pteb->StaticUnicodeBuffer;

	// FIXME: need a good thread test for these
	teb->DeallocationStack = init_teb->StackReserved;
	teb->Tib.StackBase = init_teb->StackCommit;
	teb->Tib.StackLimit = init_teb->StackReserved;

	GetClientID( &teb->ClientId );

	/* setup fs in the user address space */
	TebBaseAddress = pteb;

	/* find entry points */
	pLdrInitializeThunk = (BYTE*)process->PNtDLL + get_proc_address( NtDLLSection, "LdrInitializeThunk" );
	if (!pLdrInitializeThunk)
		Die("failed to find LdrInitializeThunk in ntdll\n");

	pKiUserApcDispatcher = (BYTE*)process->PNtDLL + get_proc_address( NtDLLSection, "KiUserApcDispatcher" );
	if (!pKiUserApcDispatcher)
		Die("failed to find KiUserApcDispatcher in ntdll\n");

	trace("LdrInitializeThunk = %p pKiUserApcDispatcher = %p\n",
		  pLdrInitializeThunk, pKiUserApcDispatcher );

	// FIXME: should set initial registers then queue an APC

	/* set up the stack */
	stack = (BYTE*) ctx->Esp - sizeof init_stack;

	/* setup the registers */
	int err = set_initial_regs( pKiUserApcDispatcher, stack );
	if (0>err)
		trace("set_initial_regs failed (%d)\n", err);

	memset( &init_stack, 0, sizeof init_stack );
	init_stack.pntdll = process->PNtDLL;  /* set to pexe if running a win32 program */
	init_stack.pLdrInitializeThunk = pLdrInitializeThunk;

	/* copy the context onto the stack for NtContinue */
	memcpy( &init_stack.ctx, ctx, sizeof *ctx );
	init_stack.ret  = (void*) 0xf00baa;

	r = process->Vm->CopyToUser( stack, &init_stack, sizeof init_stack );
	if (r < STATUS_SUCCESS)
		trace("failed to copy initial stack data\n");

	if (!suspended)
		Resume( NULL );

	process->Vm->SetTracer( addr, teb_trace );

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
	r = create_thread( &t, p, &id, &ctx, &init_teb, CreateSuspended );

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
	thread->set_context( c );

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

ULONG THREAD_IMPL::is_last_thread()
{
	for ( sibling_iter_t i(process->Threads); i; i.Next() )
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
		t->query_information( info.basic );
		break;
	case ThreadTimes:
		t->query_information( info.times );
		break;
	case ThreadAmILastThread:
		info.last_thread = t->is_last_thread();
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

	return t->alert();
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
	return thread->test_alert();
}

NTSTATUS THREAD_IMPL::test_alert()
{
	if (alerted)
	{
		alerted = FALSE;
		return STATUS_ALERTED;
	}

	deliver_apc(STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

void THREAD_IMPL::set_token( token_t *tok )
{
	if (token)
		Release( token );
	AddRef( tok );
	token = tok;
}

token_t *THREAD_IMPL::GetToken()
{
	return token;
}

PVOID& THREAD_IMPL::win32_start_address()
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
			token_t *token = 0;
			r = ObjectFromHandle(token, TokenHandle, 0);
			if (r < STATUS_SUCCESS)
				return r;
			t->set_token( token );
			return STATUS_SUCCESS;
		}
		case ThreadZeroTlsCell:
		{
			ULONG index = 0;
			NTSTATUS r = CopyFromUser( &index, ThreadInformation, sizeof index );
			if (r < STATUS_SUCCESS)
				return r;
			return t->zero_tls_cells( index );
			return STATUS_SUCCESS; // FIXME: ?????????????????????????
		}
		case ThreadQuerySetWin32StartAddress:
		{
			PVOID& Win32StartAddress = t->win32_start_address();
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
	exception_stack_frame info;
	NTSTATUS r;

	r = CopyFromUser( &info.rec, ExceptionRecord, sizeof info.rec );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &info.ctx, Context, sizeof info.ctx );
	if (r < STATUS_SUCCESS)
		return r;

	// Get this when OutputDebugStringA is used
	if (info.rec.ExceptionCode == DBG_PRINTEXCEPTION_C)
	{
		output_debug_string( info.rec );
		THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
		assert( thread );
		thread->set_context( info.ctx );
		return STATUS_SUCCESS;
	}

	// FIXME: perhaps we should blow away everything pushed on after the current frame

	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->raise_exception( info, SearchFrames );
}

NTSTATUS THREAD_IMPL::raise_exception(
	exception_stack_frame& info,
	BOOLEAN SearchFrames )
{
	// pop our args
	ctx.Esp += 12;

	// NtRaiseException probably just pushes two pointers on the stack
	// rather than copying the full context and exception record...

	if (!SearchFrames)
		Terminate( info.rec.ExceptionCode );
	else
		start_exception_handler( info );

	return STATUS_SUCCESS;  // not used
}

NTSTATUS NTAPI NtCallbackReturn(
	PVOID Result,
	ULONG ResultLength,
	NTSTATUS Status)
{
	THREAD_IMPL *thread = dynamic_cast<THREAD_IMPL*>( Current );
	assert( thread );
	return thread->user_callback_return(Result, ResultLength, Status);
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

	t->set_context( c );
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
