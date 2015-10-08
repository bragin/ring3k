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

#ifndef __EVENT_H__
#define __EVENT_H__

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "object.h"

class EVENT : public SYNC_OBJECT
{
public:
	virtual ~EVENT();
	virtual BOOLEAN IsSignalled( void ) = 0;
	virtual BOOLEAN Satisfy( void ) = 0;
	virtual void set( PULONG prev ) = 0;
	virtual void reset( PULONG prev ) = 0;
	virtual void pulse( PULONG prev ) = 0;
	virtual void query(EVENT_BASIC_INFORMATION &info) = 0;
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle ) = 0;
};

EVENT* create_sync_event( PWSTR name, BOOL InitialState = 0 );

#endif // __EVENT_H__
