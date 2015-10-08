/*
 * fiber implementation
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

// Fibers implement an infrastructure for cooperative multitasking
//  by allow multiple execution contexts in a single thread.
// Being cooperative, they must be switched explicitly.
//
// Lots of gcc specific code here.
// Tested on Linux.  Windows has a native fiber implementation.

#ifndef __FIBER_H__
#define __FIBER_H__

class FIBER
{
	struct fiber_stack_t
	{
		long ebp;
		long esi;
		long edi;
		long edx;
		long ecx;
		long ebx;
		long eax;
		long eip;
	};

private:				// offset 0 = vtable pointer
	fiber_stack_t *stack_pointer;	// offset 4
	FIBER *next;			// offset 8
	FIBER *prev;
	void *stack;
	unsigned int stack_size;

private:
	void RemoveFromRunlist();
	void AddToRunlist();
	FIBER();
	static int RunFiber( FIBER* fiber );

public:
	static const unsigned int fiber_default_stack_size = 0x10000;
	static const unsigned int guard_size = 0x1000;

public:
	static void FibersInit();
	static void FibersFinish();
	FIBER( unsigned int size );
	virtual ~FIBER();
	static void Yield();
	static bool LastFiber();
	void Start();
	void Stop();
	virtual int Run();
};

#endif // __FIBER_H__
