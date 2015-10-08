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

void init_syscalls(bool xp);
NTSTATUS do_nt_syscall(ULONG id, ULONG func, ULONG *uargs, ULONG retaddr);
NTSTATUS copy_to_user( void *dest, const void *src, size_t len );
NTSTATUS copy_from_user( void *dest, const void *src, size_t len );
NTSTATUS verify_for_write( void *dest, size_t len );

template <typename T>
NTSTATUS copy_to_user( T* dest, const T* src )
{
	return copy_to_user( dest, src, sizeof (T) );
}

template <typename T>
NTSTATUS copy_from_user( T* dest, const T* src )
{
	return copy_from_user( dest, src, sizeof (T) );
}

class ADDRESS_SPACE;
class THREAD;
class PROCESS;

#include "list.h"

typedef LIST_ANCHOR<PROCESS,0> process_list_t;
typedef LIST_ITER<PROCESS,0> process_iter_t;
typedef LIST_ELEMENT<PROCESS> process_element_t;

#include "thread.h"
#include "process.h"

extern THREAD *current;
extern process_list_t processes;
ULONG allocate_id();
extern OBJECT *ntdll_section;

NTSTATUS copy_oa_from_user( OBJECT_ATTRIBUTES *koa, UNICODE_STRING *kus, const OBJECT_ATTRIBUTES *uoa );
void free_oa( OBJECT_ATTRIBUTES *oa );
void free_us( UNICODE_STRING *us );

NTSTATUS process_from_handle( HANDLE handle, PROCESS **process );
NTSTATUS thread_from_handle( HANDLE handle, THREAD **thread );
THREAD *find_thread_by_client_id( CLIENT_ID *id );

NTSTATUS process_alloc_user_handle( PROCESS *process, OBJECT *obj, ACCESS_MASK access, HANDLE *out, HANDLE *copy );

static inline NTSTATUS alloc_user_handle( OBJECT *obj, ACCESS_MASK access, HANDLE *out )
{
	return process_alloc_user_handle( current->process, obj, access, out, 0 );
}

static inline NTSTATUS alloc_user_handle( OBJECT *obj, ACCESS_MASK access, HANDLE *out, HANDLE *copy )
{
	return process_alloc_user_handle( current->process, obj, access, out, copy );
}

// from reg.cpp
void init_registry( void );
void free_registry( void );

// from main.cpp
extern int& option_trace;
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
const char *get_section_symbol( OBJECT *section, ULONG address );

// from random.cpp
void init_random();

// from pipe.cpp
void init_pipe_device();

// from ntgdi.cpp
void ntgdi_fini();
void list_graphics_drivers();
bool set_graphics_driver( const char *driver );

#define GDI_SHARED_HANDLE_TABLE_ADDRESS ((BYTE*)0x00370000)
#define GDI_SHARED_HANDLE_TABLE_SIZE 0x60000

// from ntgdi.cpp
NTSTATUS win32k_process_init(PROCESS *p);
NTSTATUS win32k_thread_init(THREAD *t);

// from kthread.cpp
void CreateKThread(void);
void ShutdownKThread(void);

#endif // __NTCALL_H__
