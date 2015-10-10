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

#ifndef __NTCALL_H__
#define __NTCALL_H__

// FIXME: the following should go in a different file

void InitSyscalls(bool xp);
NTSTATUS DoNtSyscall(ULONG id, ULONG func, ULONG *uargs, ULONG retaddr);
NTSTATUS CopyToUser( void *dest, const void *src, size_t len );
NTSTATUS CopyFromUser( void *dest, const void *src, size_t len );
NTSTATUS VerifyForWrite( void *dest, size_t len );

template <typename T>
NTSTATUS CopyToUser( T* dest, const T* src )
{
	return CopyToUser( dest, src, sizeof (T) );
}

template <typename T>
NTSTATUS CopyFromUser( T* dest, const T* src )
{
	return CopyFromUser( dest, src, sizeof (T) );
}

class ADDRESS_SPACE;
class THREAD;
class PROCESS;

#include "list.h"

typedef LIST_ANCHOR<PROCESS,0> PROCESS_LIST;
typedef LIST_ITER<PROCESS,0> PROCESS_ITER;
typedef LIST_ELEMENT<PROCESS> PROCESS_ELEMENT;

#include "thread.h"
#include "process.h"

extern THREAD *Current;
extern PROCESS_LIST Processes;
ULONG AllocateId();
extern OBJECT *NtDLLSection;

NTSTATUS CopyOAFromUser( OBJECT_ATTRIBUTES *koa, UNICODE_STRING *kus, const OBJECT_ATTRIBUTES *uoa );
void FreeOA( OBJECT_ATTRIBUTES *oa );
void FreeUS( UNICODE_STRING *us );

NTSTATUS ProcessFromHandle( HANDLE handle, PROCESS **process );
NTSTATUS ThreadFromHandle( HANDLE handle, THREAD **thread );
THREAD *FindThreadByClientId( CLIENT_ID *id );

NTSTATUS ProcessAllocUserHandle( PROCESS *process, OBJECT *obj, ACCESS_MASK access, HANDLE *out, HANDLE *copy );

static inline NTSTATUS AllocUserHandle( OBJECT *obj, ACCESS_MASK access, HANDLE *out )
{
	return ProcessAllocUserHandle( Current->Process, obj, access, out, 0 );
}

static inline NTSTATUS AllocUserHandle( OBJECT *obj, ACCESS_MASK access, HANDLE *out, HANDLE *copy )
{
	return ProcessAllocUserHandle( Current->Process, obj, access, out, copy );
}

// from reg.cpp
void InitRegistry( void );
void FreeRegistry( void );

// from main.cpp
extern int& OptionTrace;
bool TraceIsEnabled( const char *name );

extern ULONG KiIntSystemCall;

class SLEEPER
{
public:
	virtual ~SLEEPER() {};
	virtual bool CheckEvents( bool wait ) = 0;
protected:
	int GetIntTimeout( LARGE_INTEGER& timeout );
};

extern SLEEPER* Sleeper;

// from section.cpp
const char *GetSectionSymbol( OBJECT *section, ULONG address );

// from random.cpp
void InitRandom();

// from pipe.cpp
void InitPipeDevice();

// from ntgdi.cpp
void NtGdiFini();
void ListGraphicsDrivers();
bool SetGraphicsDriver( const char *driver );

#define GDI_SHARED_HANDLE_TABLE_ADDRESS ((BYTE*)0x00370000)
#define GDI_SHARED_HANDLE_TABLE_SIZE 0x60000

// from ntgdi.cpp
NTSTATUS Win32kProcessInit(PROCESS *p);
NTSTATUS Win32kThreadInit(THREAD *t);

// from kthread.cpp
void CreateKThread(void);
void ShutdownKThread(void);

#endif // __NTCALL_H__
