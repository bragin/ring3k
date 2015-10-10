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

class WIN32K_INFO;

struct PROCESS : public SYNC_OBJECT
{
	sibling_list_t Threads;
	ADDRESS_SPACE *Vm;
	OBJECT *Exe;
	BYTE *PNtDLL;
	BYTE *PExe;

	// PROCESS_BASIC_INFORMATION
	NTSTATUS ExitStatus;
	section_t *PebSection;
	void* PebBaseAddress;
	ULONG Id;

	HANDLE_TABLE HandleTable;

	PROCESS_ELEMENT Entry[1];

	// exception handling
	OBJECT *ExceptionPort;

	KPRIORITY Priority;
	ULONG HardErrorMode;

	WIN32K_INFO *Win32kInfo;

	ULONG ExecuteFlags;

	HANDLE WindowStation;

public:
	NTSTATUS CreateExePPB( RTL_USER_PROCESS_PARAMETERS **pparams, UNICODE_STRING& name );
	NTSTATUS CreateParameters(
		RTL_USER_PROCESS_PARAMETERS **pparams, LPCWSTR ImageFile, LPCWSTR DllPath,
		LPCWSTR CurrentDirectory, LPCWSTR CommandLine, LPCWSTR WindowTitle, LPCWSTR Desktop);

public:
	PROCESS();
	~PROCESS();
	virtual BOOLEAN IsSignalled( void );
	void Terminate( NTSTATUS status );
	bool IsValid()
	{
		return Id != 0;
	}
};

extern PROCESS_LIST Processes;

NTSTATUS CreateProcess( PROCESS **pprocess, OBJECT *section );
NTSTATUS SetExceptionPort( PROCESS *process, OBJECT *obj );

#endif // __PROCESS_H__
