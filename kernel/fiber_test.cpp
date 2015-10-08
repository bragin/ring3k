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

#include <stdio.h>
#include "fiber.h"

class FIBER_TEST: public FIBER
{
	int num;
public:
	FIBER_TEST(int n);
	virtual int Run();
};

FIBER_TEST::FIBER_TEST(int n) :
	FIBER( fiber_default_stack_size ),
	num(n)
{
}

int FIBER_TEST::Run()
{
	int i;

	for (i=0; i<10; i++)
	{
		printf("fiber%d i=%d\n", num, i);
		FIBER::Yield();
	}
	printf("fiber%d finished\n", num );
	return 0;
}

int main(int argc, char **argv)
{
	FIBER::FibersInit();
	FIBER* t1 = new FIBER_TEST(1);
	FIBER* t2 = new FIBER_TEST(2);
	printf("scheduling...\n");
	t1->Start();
	t2->Start();
	while (!FIBER::LastFiber())
		FIBER::Yield();
	delete t1;
	delete t2;
	FIBER::FibersFinish();
	printf("done\n");
	return 0;
}
