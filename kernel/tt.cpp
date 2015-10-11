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
#include <stdio.h>
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

#include "client.h"
#include "ptrace_base.h"

const char StubName[] = "ring3k-client";
char StubPath[MAX_PATH];

class TT_ADDRESS_SPACE_IMPL: public PTRACE_ADRESS_SPACE_IMPL
{
	long StubRegs[FRAME_SIZE];
	pid_t ChildPid;
protected:
	int UsersideReq( int type );
public:
	TT_ADDRESS_SPACE_IMPL();
	virtual pid_t GetChildPid();
	virtual ~TT_ADDRESS_SPACE_IMPL();
	virtual int Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset );
	virtual int Munmap( BYTE *address, size_t length );
	virtual unsigned short GetUserspaceFs();
};

pid_t TT_ADDRESS_SPACE_IMPL::GetChildPid()
{
	return ChildPid;
}

TT_ADDRESS_SPACE_IMPL::TT_ADDRESS_SPACE_IMPL()
{
	int r;
	pid_t pid;

	pid = fork();
	if (pid == -1)
		Die("fork() failed %d\n", errno);

	if (pid == 0)
	{
		::ptrace( PTRACE_TRACEME, 0, 0, 0 );
		r = ::execl( StubPath, StubName, NULL );
		// the next line should not be reached
		Die("exec failed (%d) - %s missing?\n", r, StubPath);
	}

	// trace through exec after traceme
	WaitForSignal( pid, SIGTRAP );
	r = ::ptrace( PTRACE_CONT, pid, 0, 0 );
	if (r < 0)
		Die("PTRACE_CONT failed (%d)\n", errno);

	// client should hit a breakpoint
	WaitForSignal( pid, SIGTRAP );
	r = PtraceGetRegs( pid, StubRegs );
	if (r < 0)
		Die("constructor: ptrace_get_regs failed (%d)\n", errno);

	ChildPid = pid;
}

TT_ADDRESS_SPACE_IMPL::~TT_ADDRESS_SPACE_IMPL()
{
	assert( SigTarget == 0 );
	//trace(stderr,"~tt_address_space_impl()\n");
	Destroy();
	ptrace( PTRACE_KILL, ChildPid, 0, 0 );
	assert( ChildPid != -1 );
	kill( ChildPid, SIGTERM );
	ChildPid = -1;
}

ADDRESS_SPACE_IMPL* CreateTTAddressSpace()
{
	//trace("create_tt_address_space\n");
	// Set up the signal handler and unmask it first.
	// The child's signal handler will be unmasked too.
	return new TT_ADDRESS_SPACE_IMPL();
}

int TT_ADDRESS_SPACE_IMPL::UsersideReq( int type )
{
	struct tt_req *ureq = (struct tt_req *) StubRegs[EBX];
	int r;

	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->type, type );

	r = PtraceSetRegs( ChildPid, StubRegs );
	if (r < 0)
		Die("ptrace_set_regs failed\n");
	r = ::ptrace( PTRACE_CONT, ChildPid, 0, 0 );
	if (r < 0)
		Die("ptrace( PTRACE_CONT ) failed\n");

	WaitForSignal( ChildPid, SIGTRAP );
	r = PtraceGetRegs( ChildPid, StubRegs );
	if (r < 0)
		Die("ptrace_get_regs failed (%d)\n", errno);

	return StubRegs[EAX];
}

int TT_ADDRESS_SPACE_IMPL::Mmap( BYTE *address, size_t length, int prot, int flags, int file, off_t offset )
{
	//trace("tt_address_space_impl::mmap()\n");

	// send our pid to the stub
	struct tt_req *ureq = (struct tt_req *) StubRegs[EBX];
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.pid, getpid() );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.fd, file );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.addr, (int) address );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.len, length );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.ofs, offset );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.prot, prot );
	return UsersideReq( tt_req_map );
}

int TT_ADDRESS_SPACE_IMPL::Munmap( BYTE *address, size_t length )
{
	//trace("tt_address_space_impl::munmap()\n");
	struct tt_req *ureq = (struct tt_req *) StubRegs[EBX];
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.addr, (int) address );
	ptrace( PTRACE_POKEDATA, ChildPid, &ureq->u.map.len, length );
	return UsersideReq( tt_req_umap );
}

unsigned short TT_ADDRESS_SPACE_IMPL::GetUserspaceFs()
{
	return StubRegs[FS];
}

void GetStubPath( const char *kernel_path )
{
	// FIXME: handle loader in path too
	const char *p = strrchr( kernel_path, '/' );
	int len;
	if (p)
	{
		len = p - kernel_path + 1;
	}
	else
	{
		static const char current_dir[] = "./";
		p = current_dir;
		len = sizeof current_dir - 1;
	}

	memcpy( StubPath, kernel_path, len );
	StubPath[len] = 0;
	if ((len + sizeof StubName) > sizeof StubPath)
		Die("path too long\n");
	strcat( StubPath, StubName );
}

// quick check that /proc is mounted
void CheckProc()
{
	int fd = open("/proc/self/fd/0", O_RDONLY);
	if (fd < 0)
		Die("/proc not mounted\n");
	close( fd );
}

bool InitTt( const char *kernel_path )
{
	GetStubPath( kernel_path );
	CheckProc();
	trace("using thread tracing, kernel %s, client %s\n", kernel_path, StubPath );
	PTRACE_ADRESS_SPACE_IMPL::SetSignals();
	pCreateAddressSpace = &CreateTTAddressSpace;
	return true;
}
