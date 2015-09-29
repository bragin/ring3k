/*
 * nt loader
 *
 * Copyright 2006-2009 Mike McCormack
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

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "ntwin32.h"
#include "mem.h"
#include "section.h"
#include "debug.h"
#include "win32mgr.h"

class WIN32K_NULL : public WIN32K_MANAGER
{
public:
	virtual BOOL init();
	virtual void fini();
	virtual DEVICE_CONTEXT* alloc_screen_dc_ptr();
	virtual int getcaps( int index );
};

BOOL WIN32K_NULL::init()
{
	return TRUE;
}

void WIN32K_NULL::fini()
{
}

int WIN32K_NULL::getcaps( int index )
{
	trace("%d\n", index);
	return 0;
}

DEVICE_CONTEXT* WIN32K_NULL::alloc_screen_dc_ptr()
{
	// FIXME: make graphics functions more generic
	assert( 0 );
	return 0;
	//return new DEVICE_CONTEXT;
}

WIN32K_NULL win32k_manager_null;

WIN32K_MANAGER* init_null_win32k_manager()
{
	return &win32k_manager_null;
}

