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


#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <assert.h>

#include <sys/wait.h>
#include <sched.h>

#include <sys/ptrace.h>
#ifdef HAVE_ASM_PTRACE_H
#include <asm/ptrace.h>
#endif

#include "windef.h"
#include "winnt.h"
#include "mem.h"
#include "thread.h"

#include "ptrace_if.h"
#include "debug.h"
#include "platform.h"
#include "ptrace_base.h"

DEFAULT_DEBUG_CHANNEL(ptrace);

#define CTX_HAS_CONTROL(flags) ((flags)&1)
#define CTX_HAS_INTEGER(flags) ((flags)&2)
#define CTX_HAS_SEGMENTS(flags) ((flags)&4)
#define CTX_HAS_FLOAT(flags) ((flags)&8)
#define CTX_HAS_DEBUG(flags) ((flags)&0x10)

#define CTX_HAS_INTEGER_CONTROL_OR_SEGMENTS(flags) ((flags)&7)

int PTRACE_ADRESS_SPACE_IMPL::SetContext( PCONTEXT ctx )
{
	long regs[FRAME_SIZE];

	memset( regs, 0, sizeof regs );

	regs[EBX] = ctx->Ebx;
	regs[ECX] = ctx->Ecx;
	regs[EDX] = ctx->Edx;
	regs[ESI] = ctx->Esi;
	regs[EDI] = ctx->Edi;
	regs[EAX] = ctx->Eax;

	regs[DS] = ctx->SegDs;
	regs[ES] = ctx->SegEs;
	regs[FS] = ctx->SegFs;
	regs[GS] = ctx->SegGs;
	regs[SS] = ctx->SegSs;

	regs[CS] = ctx->SegCs;
	regs[SS] = ctx->SegSs;
	regs[UESP] = ctx->Esp;
	regs[EIP] = ctx->Eip;
	regs[EBP] = ctx->Ebp;
	regs[EFL] = ctx->EFlags;

	// hack - ignore the data and code segments passed from userspace
	// ntdll uses values that disagree with what Linux supports
	regs[DS] = GetUserspaceDataSeg();
	regs[ES] = GetUserspaceDataSeg();
	regs[SS] = GetUserspaceDataSeg();
	regs[SS] = GetUserspaceDataSeg();
	regs[CS] = GetUserspaceCodeSeg();

	return PtraceSetRegs( GetChildPid(), regs );
}

int PTRACE_ADRESS_SPACE_IMPL::GetContext( PCONTEXT ctx )
{
	long regs[FRAME_SIZE];
	int r;

	memset( ctx, 0, sizeof *ctx );

	r = PtraceGetRegs( GetChildPid(), regs );
	if (r < 0)
		return r;

	ctx->ContextFlags = CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_CONTROL;

	// CONTEXT_INTEGER
	ctx->Ebx = regs[EBX];
	ctx->Ecx = regs[ECX];
	ctx->Edx = regs[EDX];
	ctx->Esi = regs[ESI];
	ctx->Edi = regs[EDI];
	ctx->Eax = regs[EAX];

	// CONTEXT_SEGMENTS
	ctx->SegDs = regs[DS];
	ctx->SegEs = regs[ES];
	ctx->SegFs = regs[FS];
	ctx->SegGs = regs[GS];

	// CONTEXT_CONTROL
	ctx->SegSs = regs[SS];
	ctx->Esp = regs[UESP];
	ctx->SegCs = regs[CS];
	ctx->Eip = regs[EIP];
	ctx->Ebp = regs[EBP];
	ctx->EFlags = regs[EFL];

#if 0
	if (CTX_HAS_FLOAT(flags))
	{
		struct user_i387_struct fpregs;

		r = ptrace_get_fpregs( GetChildPid(), &fpregs );
		if (r < 0)
			return r;

		ctx->ContextFlags |= CONTEXT_FLOATING_POINT;

		ctx->FloatSave.ControlWord = fpregs.cwd;
		ctx->FloatSave.StatusWord = fpregs.swd;
		ctx->FloatSave.TagWord = fpregs.twd;
		//FloatSave. = fpregs.fip;
		//FloatSave. = fpregs.fcs;
		//FloatSave. = fpregs.foo;
		//FloatSave. = fpregs.fos;
		//FloatSave. = fpregs.fip;
		assert( sizeof fpregs.st_space == sizeof ctx->FloatSave.RegisterArea );
		memcpy( ctx->FloatSave.RegisterArea, fpregs.st_space, sizeof fpregs.st_space );
		//ErrorOffset;
		//ErrorSelector;
		//DataOffset;
		//DataSelector;
		//Cr0NpxState;
		trace("not complete\n");
	}

	if (flags & ~CONTEXT86_FULL)
		Die( "invalid context flags\n");
#endif

	return 0;
}

void PTRACE_ADRESS_SPACE_IMPL::WaitForSignal( pid_t pid, int signal )
{
	while (1)
	{
		int r, status = 0;
		r = wait4( pid, &status, WUNTRACED, NULL );
		if (r < 0)
		{
			if (errno == EINTR)
				continue;
			Die("wait_for_signal: wait4() failed %d\n", errno);
		}
		if (r != pid)
			continue;
		if (WIFEXITED(status) )
			Die("Client died\n");

		if (WIFSTOPPED(status) && WEXITSTATUS(status) == signal)
			return;

		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGINT)
			exit( 1 );

		// if we get a SEGV here, the client has crashed
		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGSEGV)
		{
			CONTEXT ctx;
			GetContext( &ctx );
			DumpRegs( &ctx );
			Die( "client crashed in stub code :-(\n");
		}

		if (WIFSTOPPED(status) && WEXITSTATUS(status) == SIGALRM)
			WARN("stray SIGALRM\n");
		else
			WARN("stray signal %d\n", WEXITSTATUS(status));

		// start the child again so we can get the next signal
		r = ptrace( PTRACE_CONT, pid, 0, 0 );
		if (r < 0)
			Die("PTRACE_CONT failed %d\n", errno);
	}
}

int PTRACE_ADRESS_SPACE_IMPL::PtraceRun( PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout )
{
	int r, status = 0;

	// set itimer (SIGALRM)
	SigTarget = this;
	AlarmTimeout( timeout );

	/* set the current thread's context */
	r = SetContext( ctx );
	if (r<0)
		Die("set_thread_context failed\n");

	/* run it */
	r = ptrace( (__ptrace_request) (single_step ? PTRACE_SYSEMU_SINGLESTEP : PTRACE_SYSEMU), GetChildPid(), 0, 0 );
	if (r<0)
		Die("PTRACE_CONT failed (%d) (PTRACE_SYSEMU not supported?)\n", errno);

	/* wait until it needs our attention */
	while (1)
	{
		r = wait4( GetChildPid(), &status, WUNTRACED, NULL );
		if (r == -1 && errno == EINTR)
			continue;
		if (r < 0)
			Die("wait4 failed (%d)\n", errno);
		if (r != GetChildPid())
			continue;
		break;
	}

	r = GetContext( ctx );
	if (r < 0)
		Die("failed to get registers\n");

	// cancel itimer (SIGALRM)
	CancelTimer();
	SigTarget = 0;

	return status;
}

void PTRACE_ADRESS_SPACE_IMPL::AlarmTimeout(LARGE_INTEGER &timeout)
{
	/* set the timeout */
	struct itimerval val;
	val.it_value.tv_sec = timeout.QuadPart/1000LL;
	val.it_value.tv_usec = (timeout.QuadPart%1000LL)*1000LL;
	val.it_interval.tv_sec = 0;
	val.it_interval.tv_usec = 0;
	int r = setitimer(ITIMER_REAL, &val, NULL);
	if (r < 0)
		Die("couldn't set itimer\n");
}

void PTRACE_ADRESS_SPACE_IMPL::CancelTimer()
{
	int r = setitimer(ITIMER_REAL, NULL, NULL);
	if (r < 0)
		Die("couldn't cancel itimer\n");
}

PTRACE_ADRESS_SPACE_IMPL* PTRACE_ADRESS_SPACE_IMPL::SigTarget;

void PTRACE_ADRESS_SPACE_IMPL::SigitimerHandler(int signal)
{
	if (SigTarget)
		SigTarget->Handle( signal );
}

void PTRACE_ADRESS_SPACE_IMPL::Handle( int signal )
{
	//trace("signal %d\n", signal);
	pid_t pid = GetChildPid();
	assert( pid != -1);
#ifdef HAVE_SIGQUEUE
	sigval val;
	val.sival_int = 0;
	sigqueue(pid, SIGALRM, val);
#else
	kill(pid, SIGALRM);
#endif
}

void PTRACE_ADRESS_SPACE_IMPL::SetSignals()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = PTRACE_ADRESS_SPACE_IMPL::SigitimerHandler;
	sigemptyset(&sa.sa_mask);

	if (0 > sigaction(SIGALRM, &sa, NULL))
		Die("unable to set action for SIGALRM\n");

	// turn the signal on
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	if (0 > sigprocmask(SIG_UNBLOCK, &sigset, NULL))
		Die("unable to unblock SIGALRM\n");
}

void PTRACE_ADRESS_SPACE_IMPL::Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec )
{
	SetUserspaceFs(TebBaseAddress, ctx->SegFs);

	while (1)
	{
		int status = PtraceRun( ctx, single_step, timeout );
		if (WIFSIGNALED(status))
			break;

		if (WIFEXITED(status))
			break;

		if (!WIFSTOPPED(status))
			Die("unknown wait4 status\n");

		int sig = WEXITSTATUS(status);

		if (sig == SIGSEGV)
		{
			exec->HandleFault();
			break;
		}

		if (sig == SIGSTOP)
			break;

		if (sig == SIGCONT)
		{
			TRACE("got SIGCONT\n");
			continue;
		}

		if (sig == SIGTRAP)
		{
			// trapped after single stepping
			if (single_step)
				break;

			siginfo_t siginfo;
			memset(&siginfo, 0, sizeof siginfo);
			int r = PtraceGetSignalInfo( GetChildPid(), &siginfo );
			if (r < 0)
				Die("ptrace_get_signal_info failed\n");
			if (siginfo.si_code == 0x80)
			{
				// assumes int $3 (0xcc, not 0xcd 0x03)
				TRACE("breakpoint!\n");
				ctx->Eip--;
				exec->HandleBreakpoint();
			}
			else
			{
				// assumes int $0x80 (0xcd 0x80)
				ctx->Eip -= 2;
				TRACE("syscall!\n");
				exec->HandleFault();
			}
			continue;
		}

		if (sig == SIGALRM)
			break;

		if (sig == SIGWINCH)
			break;

		if (sig == SIGINT)
			exit( 1 );

		if (single_step)
			break;

		TRACE("stopped, signal %d\n", WEXITSTATUS(status));
		exec->HandleBreakpoint();
		break;
	}
}

int PTRACE_ADRESS_SPACE_IMPL::GetFaultInfo( void *& addr )
{
	siginfo_t info;
	memset( &info, 0, sizeof info );
	int r = PtraceGetSignalInfo( GetChildPid(), &info );
	addr = info.si_addr;
	return r;
}

unsigned short PTRACE_ADRESS_SPACE_IMPL::GetUserspaceCodeSeg()
{
	unsigned short cs;
	__asm__ __volatile__ ( "\n\tmovw %%cs, %0\n" : "=r"( cs ) : );
	return cs;
}

unsigned short PTRACE_ADRESS_SPACE_IMPL::GetUserspaceDataSeg()
{
	unsigned short cs;
	__asm__ __volatile__ ( "\n\tmovw %%ds, %0\n" : "=r"( cs ) : );
	return cs;
}

void PTRACE_ADRESS_SPACE_IMPL::InitContext( CONTEXT& ctx )
{
	memset( &ctx, 0, sizeof ctx );
	ctx.SegFs = GetUserspaceFs();
	ctx.SegDs = GetUserspaceDataSeg();
	ctx.SegEs = GetUserspaceDataSeg();
	ctx.SegSs = GetUserspaceDataSeg();
	ctx.SegCs = GetUserspaceCodeSeg();
	ctx.EFlags = 0x00000296;
}

int PTRACE_ADRESS_SPACE_IMPL::SetUserspaceFs(void *TebBaseAddress, ULONG fs)
{
	struct user_desc ldt;
	int r;

	memset( &ldt, 0, sizeof ldt );
	ldt.entry_number = (fs >> 3);
	ldt.base_addr = (unsigned long) TebBaseAddress;
	ldt.limit = 0xfff;
	ldt.seg_32bit = 1;

	r = PtraceSetThreadArea( GetChildPid(), &ldt );
	if (r<0)
		Die("set %%fs failed, fs = %ld errno = %d child = %d\n", fs, errno, GetChildPid());
	return r;
}
