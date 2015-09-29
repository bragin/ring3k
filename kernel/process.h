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

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "thread.h"

class win32k_info_t;

struct PROCESS : public sync_object_t
{
	sibling_list_t threads;
	ADDRESS_SPACE *vm;
	OBJECT *exe;
	BYTE *pntdll;
	BYTE *pexe;

	// PROCESS_BASIC_INFORMATION
	NTSTATUS ExitStatus;
	section_t *peb_section;
	void* PebBaseAddress;
	ULONG id;

	handle_table_t handle_table;

	process_element_t entry[1];

	// exception handling
	OBJECT *exception_port;

	KPRIORITY priority;
	ULONG hard_error_mode;

	win32k_info_t *win32k_info;

	ULONG execute_flags;

	HANDLE window_station;

public:
	NTSTATUS create_exe_ppb( RTL_USER_PROCESS_PARAMETERS **pparams, UNICODE_STRING& name );
	NTSTATUS create_parameters(
		RTL_USER_PROCESS_PARAMETERS **pparams, LPCWSTR ImageFile, LPCWSTR DllPath,
		LPCWSTR CurrentDirectory, LPCWSTR CommandLine, LPCWSTR WindowTitle, LPCWSTR Desktop);

public:
	PROCESS();
	~PROCESS();
	virtual BOOLEAN is_signalled( void );
	void terminate( NTSTATUS status );
	bool is_valid()
	{
		return id != 0;
	}
};

extern process_list_t processes;

NTSTATUS create_process( PROCESS **pprocess, OBJECT *section );
NTSTATUS set_exception_port( PROCESS *process, OBJECT *obj );

#endif // __PROCESS_H__
