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

//
// fiber implementation
//
// Fibers allow multiple execution contexts in thread.
// They are cooperative, and must be switched explicitly.
//
// Lots of gcc specific code here.
// Tested on Linux.  Windows has a native fiber implementation.
//

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include "fiber.h"
#include "platform.h"

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#else
#define VALGRIND_STACK_REGISTER(start,end)
#endif


#define NORET __attribute__((noreturn))

// current_fiber needs visibility from asm code
FIBER* current_fiber;
FIBER* sleeping_fiber; // single linked list through prev

extern "C" void switch_fiber(void);
__asm__ (
"\n"
".globl " ASM_NAME_PREFIX "switch_fiber\n"
ASM_NAME_PREFIX "switch_fiber:\n"
	// ret addr
	"\tpushl %eax\n"
	"\tpushl %ebx\n"
	"\tpushl %ecx\n"
	"\tpushl %edx\n"
	"\tpushl %esi\n"
	"\tpushl %edi\n"
	"\tpushl %ebp\n"
	"\tmovl " ASM_NAME_PREFIX "current_fiber, %eax\n"
	"\tmovl %esp, 4(%eax)\n"
	"\tmovl 8(%eax), %eax\n"
	"\tmovl %eax, " ASM_NAME_PREFIX "current_fiber\n"
	"\tmovl 4(%eax), %esp\n"
	"\tpopl %ebp\n"
	"\tpopl %edi\n"
	"\tpopl %esi\n"
	"\tpopl %edx\n"
	"\tpopl %ecx\n"
	"\tpopl %ebx\n"
	"\tpopl %eax\n"
	"\tret\n"
);

extern "C" void fiber_init(void *arg);
__asm__ (
"\n"
".globl " ASM_NAME_PREFIX "fiber_init\n"
ASM_NAME_PREFIX "fiber_init:\n"
	"\tsub $12, %esp\n"
	"\tpushl %ebx\n"
	"\tcall *%eax\n"
	"\tpopl %ebx\n"
	"\tpushl %eax\n"
	"\tpushl %ebx\n"
	"\tcall " ASM_NAME_PREFIX "fiber_exit\n"
);

void FIBER::Yield(void)
{
	if (!current_fiber->next)
		return;
	if (current_fiber->next == current_fiber)
		return;
	switch_fiber();
}

extern "C" void NORET fiber_exit(FIBER *t, int ret)
{
	t->Stop();
	assert(0);
}

void FIBER::RemoveFromRunlist()
{
	assert(current_fiber->next);
	assert(current_fiber->prev);
	assert(current_fiber->prev->next == current_fiber);
	assert(current_fiber->next->prev == current_fiber);
	current_fiber->next->prev = current_fiber->prev;
	current_fiber->prev->next = current_fiber->next;
	current_fiber->prev = 0;
}

void FIBER::Stop()
{
	RemoveFromRunlist();
	Yield();
}

void FIBER::Start()
{
	assert(prev == 0);
	next = current_fiber->next;
	prev = current_fiber;
	next->prev = this;
	prev->next = this;
}

int FIBER::Run()
{
	return 0;
}

int FIBER::RunFiber( FIBER* fiber )
{
	return fiber->Run();
}

FIBER::FIBER( unsigned sz ) :
	next(0),
	prev(0),
	stack_size( sz )
{
	assert(current_fiber);

	stack = ::MmapAnon(0, stack_size + guard_size*2, PROT_NONE);
	if (stack == (void*) -1)
	{
		fprintf(stderr,"failed to allocate stack\n");
		exit(1);
	}

	/* remap fixed */
	stack = ::MmapAnon( (unsigned char*)stack + guard_size, stack_size, PROT_READ|PROT_WRITE|PROT_EXEC, 1 );
	assert (stack != (void*) -1);

	char *stack_end = (char*) stack + stack_size;
	VALGRIND_STACK_REGISTER(stack, stack_end);

	fiber_stack_t *frame = (fiber_stack_t*) (stack_end - sizeof (fiber_stack_t));

	frame->ebp = 0;
	frame->esi = 0;
	frame->edi = 0;
	frame->edx = 0;
	frame->ecx = 0;
	frame->ebx = (long) this;
	frame->eax = (long) &FIBER::RunFiber;
	frame->eip = (long) &fiber_init;

	// link it in to the circular list
	stack_pointer = frame;
}

FIBER::FIBER() :
	stack_pointer(0),
	next(0),
	prev(0),
	stack(0),
	stack_size(0)
{
}

void FIBER::FibersInit(void)
{
	assert(!current_fiber);

	FIBER *t = new FIBER;

	t->next = t;
	t->prev = t;
	current_fiber = t;
}

void FIBER::FibersFinish(void)
{
	assert(current_fiber);
	assert(LastFiber());
	current_fiber->prev = 0;
	delete current_fiber;
	current_fiber = 0;
}

FIBER::~FIBER()
{
	assert(prev == 0);
	if (stack)
		munmap( (unsigned char*) stack - guard_size, stack_size);
}

bool FIBER::LastFiber()
{
	return (current_fiber->next == current_fiber);
}
