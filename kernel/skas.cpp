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

class SKAS3_ADDRESS_SPACE_IMPL: public PTRACE_ADRESS_SPACE_IMPL
{
	static int NumAddressSpaces;
	int FD;
	static unsigned short UserFs;
public:
	static pid_t ChildPid;
	SKAS3_ADDRESS_SPACE_IMPL(int _fd);
	virtual pid_t GetChildPid();
	virtual ~SKAS3_ADDRESS_SPACE_IMPL();
	virtual int Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset );
	virtual int Munmap( BYTE *address, size_t length );
	virtual void Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec );
	static pid_t CreateTrace(void);
	static void InitFs(void);
	virtual unsigned short GetUserspaceFs();
};

pid_t SKAS3_ADDRESS_SPACE_IMPL::ChildPid = -1;
int SKAS3_ADDRESS_SPACE_IMPL::NumAddressSpaces;
unsigned short SKAS3_ADDRESS_SPACE_IMPL::UserFs;

// target for timer signals
pid_t SKAS3_ADDRESS_SPACE_IMPL::GetChildPid()
{
	return ChildPid;
}

int DoForkChild(void *arg)
{
	_exit(1);
}

/* from Wine */
struct modify_ldt_s
{
	unsigned int  entry_number;
	unsigned long base_addr;
	unsigned int  limit;
	unsigned int  seg_32bit : 1;
	unsigned int  contents : 2;
	unsigned int  read_exec_only : 1;
	unsigned int  limit_in_pages : 1;
	unsigned int  seg_not_present : 1;
	unsigned int  usable : 1;
	unsigned int  garbage : 25;
};

static inline int SetThreadArea( struct modify_ldt_s *ptr )
{
	int res;
	__asm__ __volatile__( "pushl %%ebx\n\t"
						  "movl %3,%%ebx\n\t"
						  "int $0x80\n\t"
						  "popl %%ebx"
						  : "=a" (res), "=m" (*ptr)
						  : "0" (243) /* SYS_set_thread_area */, "q" (ptr), "m" (*ptr) );
	if (res >= 0) return res;
	errno = -res;
	return -1;
}

// allocate fs in the current process
void SKAS3_ADDRESS_SPACE_IMPL::InitFs(void)
{
	unsigned short fs;
	__asm__ __volatile__ ( "\n\tmovw %%fs, %0\n" : "=r"( fs ) : );
	if (fs != 0)
	{
		UserFs = fs;
		return;
	}

	struct modify_ldt_s ldt;
	memset( &ldt, 0, sizeof ldt );
	ldt.entry_number = -1;
	int r = SetThreadArea( &ldt );
	if (r<0)
		Die("alloc %%fs failed, errno = %d\n", errno);
	UserFs = (ldt.entry_number << 3) | 3;
}

unsigned short SKAS3_ADDRESS_SPACE_IMPL::GetUserspaceFs()
{
	return UserFs;
}

pid_t SKAS3_ADDRESS_SPACE_IMPL::CreateTrace(void)
{
	pid_t pid;

	// init fs before forking
	InitFs();

	// clone this process
	const int stack_size = 0x1000;
	void *stack = MmapAnon( 0, stack_size, PROT_READ | PROT_WRITE );
	pid = clone( DoForkChild, (char*) stack + stack_size,
				 CLONE_FILES | CLONE_STOPPED | SIGCHLD, NULL );
	if (pid == -1)
	{
		trace("clone failed (%d)\n", errno);
		return pid;
	}
	if (pid == 0)
	{
		// using CLONE_STOPPED we should never get here
		Die("CLONE_STOPPED\n");
	}

	int r = ::ptrace( PTRACE_ATTACH, pid, 0, 0 );
	if (r < 0)
	{
		trace("ptrace_attach failed (%d)\n", errno);
		return -1;
	}

	return pid;
}

SKAS3_ADDRESS_SPACE_IMPL::SKAS3_ADDRESS_SPACE_IMPL(int _fd) :
	FD(_fd)
{
	NumAddressSpaces++;
}

void SKAS3_ADDRESS_SPACE_IMPL::Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec )
{
	/* load the process address space into the child process */
	int r = PtraceSetAddressSpace( ChildPid, FD );
	if (r < 0)
		Die("ptrace_set_address_space failed %d (%d)\n", r, errno);

	PTRACE_ADRESS_SPACE_IMPL::Run( TebBaseAddress, ctx, single_step, timeout, exec );
}

SKAS3_ADDRESS_SPACE_IMPL::~SKAS3_ADDRESS_SPACE_IMPL()
{
	Destroy();
	close( FD );
	assert(NumAddressSpaces>0);
	NumAddressSpaces--;
	if (NumAddressSpaces == 0)
	{
		ptrace( PTRACE_KILL, ChildPid, 0, 0 );
		kill( ChildPid, SIGTERM );
		ChildPid = -1;
	}
}

ADDRESS_SPACE_IMPL* CreateSkas3AddressSpace()
{
	if (SKAS3_ADDRESS_SPACE_IMPL::ChildPid == -1)
	{
		// Set up the signal handler and unmask it first.
		// The child's signal handler will be unmasked too.
		SKAS3_ADDRESS_SPACE_IMPL::ChildPid = SKAS3_ADDRESS_SPACE_IMPL::CreateTrace();
	}

	int fd = PtraceAllocAddressSpaceFD();
	if (fd < 0)
		return NULL;

	return new SKAS3_ADDRESS_SPACE_IMPL( fd );
}

int SKAS3_ADDRESS_SPACE_IMPL::Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset )
{
	return RemoteMMap( FD, address, length, prot, flags, file, offset );
}

int SKAS3_ADDRESS_SPACE_IMPL::Munmap( BYTE *address, size_t length )
{
	return RemoteMUnmap( FD, address, length );
}

bool InitSkas()
{
	int fd = PtraceAllocAddressSpaceFD();
	if (fd < 0)
	{
		trace("skas3 patch not present\n");
		return false;
	}
	close( fd );
	trace("using skas3\n");
	PTRACE_ADRESS_SPACE_IMPL::SetSignals();
	pCreateAddressSpace = &CreateSkas3AddressSpace;
	return true;
}

