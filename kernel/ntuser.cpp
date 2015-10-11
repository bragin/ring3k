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


#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <new>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "section.h"
#include "objdir.h"
#include "ntwin32.h"
#include "win32mgr.h"
#include "mem.h"
#include "debug.h"
#include "object.inl"
#include "alloc_bitmap.h"
#include "queue.h"
#include "message.h"
#include "win.h"

WNDCLS_LIST wndcls_list;
WINDOW *active_window;
WINDOW *desktop_window;

ULONG NTAPI NtUserGetThreadState( ULONG InfoClass )
{
	switch (InfoClass)
	{
	case 0: // GetFocus
	case 1: // GetActiveWindow
	case 2: // GetCapture
	case 5: // GetInputState
	case 6: // GetCursor
	case 8: // used in PeekMessageW
	case 9: // GetMessageExtraInfo
	case 0x0a: // used in InSendMessageEx
	case 0x0b: // GetMessageTime
	case 0x0c: // ?
		return 0;
	case 0x10: // ?
		return 0;
	case 0x11: // sets TEB->Win32ThreadInfo for the current thread
		return 1;
	default:
		trace("%ld\n", InfoClass );
	}
	return 0;
}

// see http://winterdom.com/dev/ui/wnd.html

#define USER_HANDLE_WINDOW 1

struct USER_HANDLE_ENTRY
{
	union
	{
		void *object;
		USHORT next_free;
	};
	void *owner;
	USHORT type;
	USHORT highpart;
};

struct USER_SHARED_MEM
{
	ULONG x1;
	ULONG x2;
	ULONG max_window_handle;
	ULONG x3[459];
	COLORREF ButtonHilight;
	COLORREF ButtonDkShadow;
};

static const ULONG user_shared_mem_size = 0x20000;
static const ULONG user_shared_mem_reserve = 0x10000;

// section for user handle table
static SECTION *user_handle_table_section = 0;

// kernel address for user handle table (shared)
static USER_HANDLE_ENTRY *user_handle_table;

// section for user shared memory
static SECTION *user_shared_section = 0;

// kernel address for memory shared with the user process
static USER_SHARED_MEM *user_shared;

// bitmap of free memory
ALLOCATION_BITMAP user_shared_bitmap;

MESSAGE_MAP_SHARED_MEMORY message_maps[NUMBER_OF_MESSAGE_MAPS];

static USHORT next_user_handle = 1;

#define MAX_USER_HANDLES 0x200

void check_max_window_handle( ULONG n )
{
	n++;
	if (user_shared->max_window_handle<n)
		user_shared->max_window_handle = n;
	trace("max_window_handle = %04lx\n", user_shared->max_window_handle);
}

void init_user_handle_table()
{
	USHORT i;
	next_user_handle = 1;
	for ( i=next_user_handle; i<(MAX_USER_HANDLES-1); i++ )
	{
		user_handle_table[i].object = (void*) (i+1);
		user_handle_table[i].owner = 0;
		user_handle_table[i].type = 0;
		user_handle_table[i].highpart = 1;
	}
}

ULONG alloc_user_handle( void* obj, ULONG type, PROCESS *owner )
{
	assert( type != 0 );
	ULONG ret = next_user_handle;
	ULONG next = user_handle_table[ret].next_free;
	assert( next != ret );
	assert( user_handle_table[ret].type == 0 );
	assert( user_handle_table[ret].owner == 0 );
	assert( next <= MAX_USER_HANDLES );
	user_handle_table[ret].object = obj;
	user_handle_table[ret].type = type;
	user_handle_table[ret].owner = (void*) owner;
	next_user_handle = next;
	check_max_window_handle( ret );
	return (user_handle_table[ret].highpart << 16) | ret;
}

void free_user_handle( HANDLE handle )
{
	UINT n = (UINT) handle;
	USHORT lowpart = n&0xffff;

	trace("freeing handle %08x\n", n);
	user_handle_table[lowpart].type = 0;
	user_handle_table[lowpart].owner = 0;
	user_handle_table[lowpart].object = 0;

	// update the free handle list
	user_handle_table[lowpart].next_free = next_user_handle;
	next_user_handle = lowpart;

	// FIXME: maybe decrease max_window_handle?
}

void delete_user_object( ULONG i )
{
	USER_HANDLE_ENTRY *entry = user_handle_table+i;
	trace("deleting user handle %ld\n", i);
	assert(entry->object != NULL);
	switch (entry->type)
	{
	case USER_HANDLE_WINDOW:
		delete (WINDOW*) entry->object;
		break;
	default:
		trace("object %ld (%p), type = %08x owner = %p\n",
			  i, entry->object, entry->type, entry->owner);
		assert(0);
	}
}

void free_user32_handles( PROCESS *p )
{
	ULONG i;
	assert( p != NULL );
	if (!user_handle_table)
		return;
	for (i=0; i<user_shared->max_window_handle; i++)
	{
		if (p == (PROCESS*) user_handle_table[i].owner)
			delete_user_object( i );
	}
}

void* user_obj_from_handle( HANDLE handle, ULONG type )
{
	UINT n = (UINT) handle;
	USHORT lowpart = n&0xffff;
	//USHORT highpart = (n>>16);

	if (lowpart == 0 || lowpart > user_shared->max_window_handle)
		return NULL;
	if (type != user_handle_table[lowpart].type)
		return NULL;
	//FIXME: check high part and type
	//if (user_handle_table[].highpart != highpart)
	return user_handle_table[lowpart].object;
}

WINDOW *WindowFromHandle( HANDLE handle )
{
	void *obj = user_obj_from_handle( handle, 1 );
	if (!obj)
		return NULL;
	return (WINDOW*) obj;
}

void *init_user_shared_memory()
{
	// read/write for the kernel and read only for processes
	if (!user_shared)
	{
		LARGE_INTEGER sz;
		NTSTATUS r;

		sz.QuadPart = sizeof (USER_HANDLE_ENTRY) * MAX_USER_HANDLES;
		r = CreateSection( &user_handle_table_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return 0;

		user_handle_table = (USER_HANDLE_ENTRY*) user_handle_table_section->GetKernelAddress();

		init_user_handle_table();

		sz.QuadPart = user_shared_mem_size;
		r = CreateSection( &user_shared_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return 0;

		user_shared = (USER_SHARED_MEM*) user_shared_section->GetKernelAddress();

		// setup the allocation bitmap for user objects (eg. windows)
		void *object_area = (void*) ((BYTE*) user_shared + user_shared_mem_reserve);
		user_shared_bitmap.SetArea( object_area,
									 user_shared_mem_size - user_shared_mem_reserve );

		// create the window stations directory too
		CreateDirectoryObject( (PWSTR) L"\\Windows\\WindowStations" );

		// see wine/dlls/user32/sysparams.c
		user_shared->ButtonHilight = RGB(255,255,255);
		user_shared->ButtonDkShadow = RGB(64,64,64);
	}

	trace("user_handle_table at %p\n", user_handle_table );
	trace("user_shared at %p\n", user_shared );

	return user_shared;
}

class NTUSERSHM_TRACER : public BLOCK_TRACER
{
public:
	virtual void OnAccess( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool Enabled() const;
};

bool NTUSERSHM_TRACER::Enabled() const
{
	return TraceIsEnabled( "usershm" );
}

bool message_map_on_access( BYTE *address, ULONG eip )
{
	for (ULONG i=0; i<NUMBER_OF_MESSAGE_MAPS; i++)
	{
		if (!message_maps[i].Bitmap)
			continue;
		if (address < message_maps[i].Bitmap)
			continue;
		ULONG ofs = address - message_maps[i].Bitmap;
		if (ofs > message_maps[i].MaxMessage/8)
			continue;
		fprintf(stderr, "%04lx: accessed message map[%ld][%04lx] from %08lx\n",
				Current->TraceId(), i, ofs, eip);
		return true;
	}
	return false;
}

bool window_on_access( BYTE *address, ULONG eip )
{
	for (ULONG i=0; i<user_shared->max_window_handle; i++)
	{
		switch (user_handle_table[i].type)
		{
			case USER_HANDLE_WINDOW:
			{
				// window shared memory structures are variable size
				// have the window check itself
				WINDOW* wnd = reinterpret_cast<WINDOW*>( user_handle_table[i].object);
				if (wnd->OnAccess( address, eip ))
					return true;
			}
		}
	}
	return false;
}

void NTUSERSHM_TRACER::OnAccess( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->GetBaseAddress();
	if (ofs < user_shared_mem_reserve)
	{
		const char *name = "";
		switch (ofs)
		{
		case 8:
			name = " (max_window_handle)";
			break;
		}
		fprintf(stderr, "%04lx: accessed ushm[%04lx]%s from %08lx\n",
				Current->TraceId(), ofs, name, eip);
		return;
	}

	if (message_map_on_access( address, eip ))
		return;

	if (window_on_access( address, eip ))
		return;

	fprintf(stderr, "%04lx: accessed ushm[%04lx] from %08lx\n",
			Current->TraceId(), ofs, eip);
}

static NTUSERSHM_TRACER ntusershm_trace;

class NTUSERHANDLE_TRACER : public BLOCK_TRACER
{
public:
	virtual void OnAccess( MBLOCK *mb, BYTE *address, ULONG eip );
	virtual bool Enabled() const;
};

bool NTUSERHANDLE_TRACER::Enabled() const
{
	return TraceIsEnabled( "usershm" );
}

void NTUSERHANDLE_TRACER::OnAccess( MBLOCK *mb, BYTE *address, ULONG eip )
{
	ULONG ofs = address - mb->GetBaseAddress();
	const int sz = sizeof (USER_HANDLE_ENTRY);
	ULONG number = ofs/sz;
	const char *field = "unknown";
	switch (ofs % sz)
	{
#define f(n, x) case n: field = #x; break;
		f( 0, owner )
		f( 4, object )
		f( 8, type )
		f( 10, highpart )
#undef f
	default:
		field = "unknown";
	}

	fprintf(stderr, "%04lx: accessed user handle[%04lx]+%s (%ld) from %08lx\n",
			Current->TraceId(), number, field, ofs%sz, eip);
}
static NTUSERHANDLE_TRACER ntuserhandle_trace;

BYTE* alloc_message_bitmap( PROCESS* proc, MESSAGE_MAP_SHARED_MEMORY& map, ULONG last_message )
{
	ULONG sz = (last_message+7)/8;
	BYTE *msg_map = user_shared_bitmap.Alloc( sz );
	memset( msg_map, 0, sz );
	ULONG ofs = (BYTE*)msg_map - (BYTE*)user_shared;
	map.Bitmap = (BYTE*) (proc->Win32kInfo->user_shared_mem + ofs);
	map.MaxMessage = last_message;
	trace("bitmap = %p last = %ld\n", map.Bitmap, map.MaxMessage);
	return msg_map;
}

NTUSERINFO *alloc_user_info()
{
	NTUSERINFO *info = (NTUSERINFO*) user_shared_bitmap.Alloc( sizeof (NTUSERINFO) );
	info->DesktopWindow = desktop_window;
	ULONG ofs = (BYTE*)info - (BYTE*)user_shared;
	return (NTUSERINFO*) (Current->Process->Win32kInfo->user_shared_mem + ofs);
}

void create_desktop_window()
{
	if (desktop_window)
		return;

	desktop_window = new WINDOW;
	if (!desktop_window)
		return;

	memset( desktop_window, 0, sizeof (WINDOW) );
	desktop_window->rcWnd.left = 0;
	desktop_window->rcWnd.top = 0;
	desktop_window->rcWnd.right = 640;
	desktop_window->rcWnd.bottom = 480;
	desktop_window->rcClient = desktop_window->rcWnd;

	desktop_window->handle = (HWND) alloc_user_handle( desktop_window, USER_HANDLE_WINDOW, Current->Process );
}

// should be called from NtGdiInit to map the user32 shared memory
NTSTATUS map_user_shared_memory( PROCESS *proc )
{
	NTSTATUS r;

	assert( proc->Win32kInfo );
	BYTE*& user_shared_mem = proc->Win32kInfo->user_shared_mem;
	BYTE*& user_handles = proc->Win32kInfo->user_handles;

	// map the user shared memory block into the process's memory
	if (!init_user_shared_memory())
		return STATUS_UNSUCCESSFUL;

	// already mapped into this process?
	if (user_shared_mem)
		return STATUS_SUCCESS;

	r = user_shared_section->Mapit( proc->Vm, user_shared_mem, 0,
									MEM_COMMIT, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	if (OptionTrace)
	{
		proc->Vm->SetTracer( user_shared_mem, ntusershm_trace );
		proc->Vm->SetTracer( user_handles, ntuserhandle_trace );
	}

	// map the shared handle table
	r = user_handle_table_section->Mapit( proc->Vm, user_handles, 0,
										  MEM_COMMIT, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	trace("user shared at %p\n", user_shared_mem);

	return STATUS_SUCCESS;
}

BOOLEAN do_gdi_init()
{
	NTSTATUS r;
	r = map_user_shared_memory( Current->Process );
	if (r < STATUS_SUCCESS)
		return FALSE;

	// check set the offset
	BYTE*& user_shared_mem = Current->Process->Win32kInfo->user_shared_mem;
	Current->GetTEB()->KernelUserPointerOffset = (BYTE*) user_shared - user_shared_mem;

	// create the desktop window for alloc_user_info
	create_desktop_window();
	Current->GetTEB()->NtUserInfo = alloc_user_info();

	return TRUE;
}

NTSTATUS NTAPI NtUserProcessConnect(HANDLE Process, PVOID Buffer, ULONG BufferSize)
{
	union
	{
		USER_PROCESS_CONNECT_INFO win2k;
		USER_PROCESS_CONNECT_INFO_XP winxp;
	} info;
	const ULONG version = 0x50000;
	NTSTATUS r;

	PROCESS *proc = 0;
	r = ObjectFromHandle( proc, Process, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	if (BufferSize != sizeof info.winxp && BufferSize != sizeof info.win2k)
	{
		trace("buffer size wrong %ld (not WinXP or Win2K?)\n", BufferSize);
		return STATUS_UNSUCCESSFUL;
	}

	r = CopyFromUser( &info, Buffer, BufferSize );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	if (info.winxp.Version != version)
	{
		trace("version wrong %08lx %08lx\n", info.winxp.Version, version);
		return STATUS_UNSUCCESSFUL;
	}


	// check if we're already connected
	r = Win32kProcessInit( proc );
	if (r < STATUS_SUCCESS)
		return r;

	r = map_user_shared_memory( proc );
	if (r < STATUS_SUCCESS)
		return r;

	info.win2k.Ptr[0] = (void*)proc->Win32kInfo->user_shared_mem;
	info.win2k.Ptr[1] = (void*)proc->Win32kInfo->user_handles;
	info.win2k.Ptr[2] = (void*)0xbee30000;
	info.win2k.Ptr[3] = (void*)0xbee40000;

	for (ULONG i=0; i<NUMBER_OF_MESSAGE_MAPS; i++ )
	{
		info.win2k.MessageMap[i].MaxMessage = 0;
		info.win2k.MessageMap[i].Bitmap = (BYTE*)i;
	}

	alloc_message_bitmap( proc, info.win2k.MessageMap[0x1b], 0x400 );
	message_maps[0x1b] = info.win2k.MessageMap[0x1b];
	alloc_message_bitmap( proc, info.win2k.MessageMap[0x1c], 0x400 );
	message_maps[0x1c] = info.win2k.MessageMap[0x1c];

	r = CopyToUser( Buffer, &info, BufferSize );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

PVOID g_Funcs[9];
PVOID g_FuncsW[20];
PVOID g_FuncsA[20];

// Funcs array has 9 function pointers
// FuncsW array has 20 function pointers
// FuncsA array has 20 function pointers
// Base is the Base address of the DLL containing the functions
BOOLEAN NTAPI NtUserInitializeClientPfnArrays(
	PVOID Funcs,
	PVOID FuncsW,
	PVOID FuncsA,
	PVOID Base)
{
	NTSTATUS r;

	r = CopyFromUser( &g_Funcs, Funcs, sizeof g_Funcs );
	if (r < 0)
		return r;
	r = CopyFromUser( &g_FuncsW, FuncsW, sizeof g_FuncsW );
	if (r < 0)
		return r;
	r = CopyFromUser( &g_FuncsA, FuncsA, sizeof g_FuncsA );
	if (r < 0)
		return r;
	return 0;
}

BOOLEAN NTAPI NtUserInitialize(ULONG u_arg1, ULONG u_arg2, ULONG u_arg3)
{
	return TRUE;
}

ULONG NTAPI NtUserCallNoParam(ULONG Index)
{
	switch (Index)
	{
	case 0:
		return 0; // CreateMenu
	case 1:
		return 0; // CreatePopupMenu
	case 2:
		return 0; // DestroyCaret
	case 3:
		return 0; // ?
	case 4:
		return 0; // GetInputDesktop
	case 5:
		return 0; // GetMessagePos
	case 6:
		return 0; // ?
	case 7:
		return 0xfeed0007;
	case 8:
		return 0; // ReleaseCapture
	case 0x0a:
		return 0; // EndDialog?
	case 0x12:
		return 0; // ClientThreadSetup?
	case 0x15:
		return 0; // MsgWaitForMultipleObjects
	default:
		return FALSE;
	}
}

BOOLEAN NtReleaseDC( HANDLE hdc )
{
	trace("%p\n", hdc );
	return Win32kManager->ReleaseDC( hdc );
}

BOOLEAN NtPostQuitMessage( ULONG ret )
{
	trace("%08lx\n", ret );
	if (Current->Queue)
		Current->Queue->PostQuitMessage( ret );
	return TRUE;
}

PVOID NtGetWindowPointer( HWND window )
{
	trace("%p\n", window );
	WINDOW *win = WindowFromHandle( window );
	if (!win)
		return 0;
	return win->GetWininfo();
}

ULONG NTAPI NtUserCallOneParam(ULONG Param, ULONG Index)
{
	switch (Index)
	{
	case 0x16: // BeginDeferWindowPos
		return TRUE;
	case 0x17: // WindowFromDC
		return TRUE;
	case 0x18: // AllowSetForegroundWindow
		return TRUE;
	case 0x19: // used by CreateIconIndirect
		return TRUE;
	case 0x1a: // used by DdeUnitialize
		return TRUE;
	case 0x1b: // used by MsgWaitForMultipleObjectsEx
		return TRUE;
	case 0x1c: // EnumClipboardFormats
		return TRUE;
	case 0x1d: // used by MsgWaitForMultipleObjectsEx
		return TRUE;
	case 0x1e: // GetKeyboardLayout
		return TRUE;
	case 0x1f: // GetKeyboardType
		return TRUE;
	case 0x20: // GetQueueStatus
		return TRUE;
	case 0x21: // SetLockForegroundWindow
		return TRUE;
	case 0x22: // LoadLocalFonts, used by LoadRemoteFonts
		return TRUE;
	case NTUCOP_GETWNDPTR: // get the window pointer
		return (ULONG) NtGetWindowPointer( (HWND) Param );
	case 0x24: // MessageBeep
		return TRUE;
	case 0x25: // used by SoftModalMessageBox
		return TRUE;
	case NTUCOP_POSTQUITMESSAGE:
		return NtPostQuitMessage( Param );
	case 0x27: // RealizeUserPalette
		return TRUE;
	case 0x28: // used by ClientThreadSetup
		return TRUE;
	case NTUCOP_RELEASEDC: // used by ReleaseDC + DeleteDC (deref DC?)
		return NtReleaseDC( (HANDLE) Param );
	case 0x2a: // ReplyMessage
		return TRUE;
	case 0x2b: // SetCaretBlinkTime
		return TRUE;
	case 0x2c: // SetDoubleClickTime
		return TRUE;
	case 0x2d: // ShowCursor
		return TRUE;
	case 0x2e: // StartShowGlass
		return TRUE;
	case 0x2f: // SwapMouseButton
		return TRUE;
	case 0x30: // SetMessageExtraInfo
		return TRUE;
	case 0x31: // used by UserRegisterWowHandlers
		return TRUE;
	case 0x33: // GetProcessDefaultLayout
		return TRUE;
	case 0x34: // SetProcessDefaultLayout
		return TRUE;
	case 0x37: // GetWinStationInfo
		return TRUE;
	case 0x38: // ?
		return TRUE;
	default:
		return FALSE;
	}
}

// should be PASCAL calling convention?
ULONG NTAPI NtUserCallTwoParam(ULONG Param2, ULONG Param1, ULONG Index)
{
	switch (Index)
	{
	case 0x53:  // EnableWindow
		trace("EnableWindow (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x55:  // ShowOwnedPopups
		trace("ShowOwnedPopups (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x56:  // SwitchToThisWindow
		trace("SwitchToThisWindow (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x57:  // ValidateRgn
		trace("ValidateRgn (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x59: // GetMonitorInfo
		trace("GetMonitorInfo (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x5b:  // RegisterLogonProcess
		trace("RegisterLogonProcess (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x5c:  // RegisterSystemThread
		trace("RegisterSystemThread (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x5e:  // SetCaretPos
		trace("SetCaretPos (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x5f:  // SetCursorPos
		trace("SetCursorPos (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x60:  // UnhookWindowsHook
		trace("UnhookWindowsHook (%08lx, %08lx)\n", Param1, Param2);
		break;
	case 0x61:  // UserRegisterWowHandlers
		trace("UserRegisterWowHandlers (%08lx, %08lx)\n", Param1, Param2);
		break;
	default:
		trace("%lu (%08lx, %08lx)\n", Index, Param1, Param2);
		break;
	}
	return TRUE;
}

// returns a handle to the thread's desktop
HANDLE NTAPI NtUserGetThreadDesktop(
	ULONG ThreadId,
	ULONG u_arg2)
{
	return (HANDLE) 0xde5;
}

HANDLE NTAPI NtUserFindExistingCursorIcon(PUNICODE_STRING Library, PUNICODE_STRING str2, PVOID p_arg3)
{
	ULONG index;

	CUNICODE_STRING us;
	NTSTATUS r;

	r = us.CopyFromUser( Library );
	if (r == STATUS_SUCCESS)
		trace("Library=\'%pus\'\n", &us);

	r = us.CopyFromUser( str2 );
	if (r == STATUS_SUCCESS)
		trace("str2=\'%pus\'\n", &us);

	r = CopyFromUser( &index, p_arg3, sizeof index );
	if (r == STATUS_SUCCESS)
		trace("index = %lu\n", index);

	return 0;
}

HANDLE NTAPI NtUserGetDC(HANDLE Window)
{
	if (!Window)
		return Win32kManager->AllocScreenDC();

	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	return win->GetDc();
}

HGDIOBJ NtUserSelectPalette(HGDIOBJ hdc, HPALETTE palette, BOOLEAN force_bg)
{
	return AllocGdiObject( FALSE, GDI_OBJECT_PALETTE );
}

BOOLEAN NTAPI NtUserSetCursorIconData(
	HANDLE Handle,
	PVOID Module,
	PUNICODE_STRING ResourceName,
	PICONINFO IconInfo)
{
	return TRUE;
}

BOOLEAN NTAPI NtUserGetIconInfo(
	HANDLE Icon,
	PICONINFO IconInfo,
	PUNICODE_STRING lpInstName,
	PUNICODE_STRING lpResName,
	LPDWORD pbpp,
	BOOL bInternal)
{
	return TRUE;
}

void* WNDCLS::operator new(size_t sz)
{
	trace("allocating window\n");
	assert( sz == sizeof (WNDCLS));
	return user_shared_bitmap.Alloc( sz );
}

void WNDCLS::operator delete(void *p)
{
	user_shared_bitmap.Free( (unsigned char*) p, sizeof (WNDCLS) );
}

WNDCLS::WNDCLS( NTWNDCLASSEX& ClassInfo, const UNICODE_STRING& ClassName, const UNICODE_STRING& MenuName, ATOM a ) :
	Name( ClassName ),
	Menu( MenuName ),
	Info( ClassInfo ),
	RefCount( 0 )
{
	memset( this, 0, sizeof (WNDCLASS) );
	atomWindowType = a;
	pSelf = this;
}

WNDCLS* WNDCLS::FromName( const UNICODE_STRING& wndcls_name )
{
	for (WNDCLS_ITER i(wndcls_list); i; i.Next())
	{
		WNDCLS *cls = i;
		if (cls->GetName().IsEqual( wndcls_name ))
			return cls;
	}
	return NULL;
}

ATOM NTAPI NtUserRegisterClassExWOW(
	PNTWNDCLASSEX ClassInfo,
	PUNICODE_STRING ClassName,
	PNTCLASSMENUNAMES MenuNames,
	USHORT,
	ULONG Flags,
	ULONG)
{
	NTWNDCLASSEX clsinfo;

	NTSTATUS r;
	r = CopyFromUser( &clsinfo, ClassInfo, sizeof clsinfo );
	if (r < STATUS_SUCCESS)
		return 0;

	if (clsinfo.Size != sizeof clsinfo)
		return 0;

	CUNICODE_STRING clsstr;
	r = clsstr.CopyFromUser( ClassName );
	if (r < STATUS_SUCCESS)
		return 0;

	// for some reason, a structure with three of the same name is passed...
	NTCLASSMENUNAMES menu_strings;
	r = CopyFromUser( &menu_strings, MenuNames, sizeof menu_strings );
	if (r < STATUS_SUCCESS)
		return 0;

	CUNICODE_STRING menuname;
	r = menuname.CopyFromUser( menu_strings.name_us );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("window class = %pus  menu = %pus\n", &clsstr, &menuname);

	static ATOM atom = 0xc001;
	WNDCLS* cls = new WNDCLS( clsinfo, clsstr, menuname, atom );
	if (!cls)
		return 0;

	wndcls_list.Append( cls );

	return cls->GetAtom();
}

NTSTATUS NTAPI NtUserSetInformationThread(
	HANDLE ThreadHandle,
	ULONG InfoClass,
	PVOID Buffer,
	ULONG BufferLength)
{
	trace("%p %08lx %p %08lx\n", ThreadHandle, InfoClass, Buffer, BufferLength);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtUserGetKeyboardLayoutList(ULONG x1, ULONG x2)
{
	trace("%08lx, %08lx\n", x1, x2);
	return STATUS_SUCCESS;
}

static int g_hack_desktop = 0xf00d2001;

HANDLE NTAPI NtUserCreateWindowStation(
	POBJECT_ATTRIBUTES WindowStationName,
	ACCESS_MASK DesiredAccess,
	HANDLE ObjectDirectory,
	ULONG x1,
	PVOID x2,
	ULONG Locale)
{
	trace("%p %08lx %p %08lx %p %08lx\n",
		  WindowStationName, DesiredAccess, ObjectDirectory, x1, x2, Locale);

	// print out the name
	OBJECT_ATTRIBUTES oa;

	NTSTATUS r;
	r = CopyFromUser( &oa, WindowStationName, sizeof oa );
	if (r < STATUS_SUCCESS)
		return 0;

	CUNICODE_STRING us;
	r = us.CopyFromUser( oa.ObjectName );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("name = %pus\n", &us );

	return (HANDLE) g_hack_desktop++;
}

HANDLE NTAPI NtUserCreateDesktop(
	POBJECT_ATTRIBUTES DesktopName,
	ULONG x1,
	ULONG x2,
	ULONG x3,
	ACCESS_MASK DesiredAccess)
{
	// print out the name
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	r = oa.CopyFromUser( DesktopName );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("name = %pus\n", oa.ObjectName );
	trace("root = %p\n", oa.RootDirectory );

	return (HANDLE) g_hack_desktop++;
}

HANDLE NTAPI NtUserOpenDesktop(POBJECT_ATTRIBUTES DesktopName, ULONG, ACCESS_MASK DesiredAccess)
{
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	r = oa.CopyFromUser( DesktopName );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("name = %pus\n", oa.ObjectName );
	trace("root = %p\n", oa.RootDirectory );

	return (HANDLE) g_hack_desktop++;
}

BOOLEAN NTAPI NtUserSetProcessWindowStation(HANDLE WindowStation)
{
	trace("\n");
	Current->Process->WindowStation = WindowStation;
	return TRUE;
}

HANDLE NTAPI NtUserGetProcessWindowStation(void)
{
	trace("\n");
	return Current->Process->WindowStation;
}

BOOLEAN NTAPI NtUserSetThreadDesktop(HANDLE Desktop)
{
	trace("\n");
	return TRUE;
}

BOOLEAN NTAPI NtUserSetImeHotKey(ULONG x1, ULONG x2, ULONG x3, ULONG x4, ULONG x5)
{
	trace("\n");
	return TRUE;
}

BOOLEAN NTAPI NtUserLoadKeyboardLayoutEx(
	HANDLE File,
	ULONG x1,
	ULONG x2,
	PVOID x3,
	ULONG locale,
	ULONG flags)
{
	trace("\n");
	return TRUE;
}

BOOLEAN NTAPI NtUserUpdatePerUserSystemParameters(ULONG x1, ULONG x2)
{
	trace("\n");
	return TRUE;
}

BOOLEAN NTAPI NtUserSystemParametersInfo(ULONG x1, ULONG x2, ULONG x3, ULONG x4)
{
	trace("\n");
	return TRUE;
}

BOOLEAN NTAPI NtUserSetWindowStationUser(HANDLE WindowStation, PVOID, ULONG, ULONG)
{
	trace("\n");
	return TRUE;
}

ULONG NTAPI NtUserGetCaretBlinkTime(void)
{
	trace("\n");
	return 100;
}

ULONG message_no = 0xc001;

ULONG NTAPI NtUserRegisterWindowMessage(PUNICODE_STRING Message)
{
	trace("\n");
	CUNICODE_STRING us;

	NTSTATUS r = us.CopyFromUser( Message );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("message = %pus -> %04lx\n", &us, message_no);

	return message_no++;
}

class user32_unicode_string_t : public CUNICODE_STRING
{
public:
	NTSTATUS copy_from_user( PUSER32_UNICODE_STRING String );
};

NTSTATUS user32_unicode_string_t::copy_from_user( PUSER32_UNICODE_STRING String )
{
	USER32_UNICODE_STRING str;
	NTSTATUS r = ::CopyFromUser( &str, String, sizeof str );
	if (r < STATUS_SUCCESS)
		return r;
	return CopyWStrFromUser( str.Buffer, str.Length );
}

WINDOW::WINDOW()
{
	memset( this, 0, sizeof *this );
}

void WINDOW::LinkWindow( WINDOW* parent_win )
{
	assert( next == NULL );
	assert( parent == NULL );
	assert( parent_win != NULL );
	parent = parent_win;
	next = parent->first_child;
	parent->first_child = this;
	assert( next != this );
}

void WINDOW::UnlinkWindow()
{
	// special behaviour for desktop window
	// should replace window_tt::first with desktop...
	if (this == desktop_window)
	{
		desktop_window = NULL;
		return;
	}
	WND **p;
	assert (parent != NULL);
	p = &parent->first_child;

	while (*p != this)
		p = &((*p)->next);
	assert (*p);
	*p = next;
	next = NULL;
}

void* WINDOW::operator new(size_t sz)
{
	trace("allocating window\n");
	assert( sz == sizeof (WINDOW));
	return user_shared_bitmap.Alloc( sz );
}

void WINDOW::operator delete(void *p)
{
	user_shared_bitmap.Free( (unsigned char*) p, sizeof (WINDOW) );
}

// return true if address is in this window's shared memory
bool WINDOW::OnAccess( BYTE *address, ULONG eip )
{
	BYTE *user_ptr = (BYTE*) GetWininfo();
	if (user_ptr > address)
		return false;

	ULONG ofs = address - user_ptr;
	ULONG sz = sizeof (WND) /*+ cbWndClsExtra + cbWndExtra */;
	if (ofs > sz)
		return false;
	const char* field = "";
	switch (ofs)
	{
#define f(n, x) case n: field = #x; break;
		f( 0, handle )
		f( 0x10, self )
		f( 0x14, dwFlags )
		f( 0x16, dwFlags )
		f( 0x18, exstyle )
		f( 0x1c, style )
		f( 0x20, hInstance )
		f( 0x28, next )
		f( 0x2c, parent )
		f( 0x30, first_child )
		f( 0x34, owner )
		f( 0x5c, wndproc )
		f( 0x60, wndcls )
#undef f
	}
	fprintf(stderr, "%04lx: accessed window[%p][%04lx] %s from %08lx\n", Current->TraceId(), handle, ofs, field, eip);
	return true;
}

WINDOW::~WINDOW()
{
	UnlinkWindow();
	free_user_handle( handle );
	trace("active window = %p this = %p\n", active_window, this);
	if (active_window == this)
	{
		trace("cleared active window handle\n");
		active_window = 0;
	}
}

PWND WINDOW::GetWininfo()
{
	ULONG ofs = (BYTE*)this - (BYTE*)user_shared;
	return (PWND) (Current->Process->Win32kInfo->user_shared_mem + ofs);
}

NTSTATUS WINDOW::Send( MESSAGE& msg )
{
	THREAD*& thread = GetWinThread();
	if (thread->IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;

	PTEB teb = thread->GetTEB();
	teb->CachedWindowHandle = handle;
	teb->CachedWindowPointer = GetWininfo();

	trace("sending %s\n", msg.Description());

	msg.SetWindowInfo( this );

	void *address = thread->Push( msg.GetSize() );

	NTSTATUS r = msg.CopyToUser( address );
	if (r >= STATUS_SUCCESS)
	{
		ULONG ret_len = 0;
		PVOID ret_buf = 0;

		r = thread->DoUserCallback( msg.GetCallbackNum(), ret_len, ret_buf );
	}

	if (thread->IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;

	thread->Pop( msg.GetSize() );
	teb->CachedWindowHandle = 0;
	teb->CachedWindowPointer = 0;

	return r;
}

BOOLEAN WINDOW::Show( INT Show )
{
	// send a WM_SHOWWINDOW message
	SHOWWINDOW_MSG sw( TRUE );
	Send( sw );
	style |= WS_VISIBLE;

	return TRUE;
}

HANDLE NTAPI NtUserCreateWindowEx(
	ULONG ExStyle,
	PUSER32_UNICODE_STRING ClassName,
	PUSER32_UNICODE_STRING WindowName,
	ULONG Style,
	LONG x,
	LONG y,
	LONG Width,
	LONG Height,
	HANDLE Parent,
	HANDLE Menu,
	PVOID Instance,
	PVOID Param,
	//ULONG ShowMode,
	BOOL UnicodeWindow)
{
	NTSTATUS r;

	user32_unicode_string_t window_name;
#if 0
	r = window_name.CopyFromUser( WindowName );
	if (r < STATUS_SUCCESS)
		return 0;
#endif

	user32_unicode_string_t wndcls_name;
	r = wndcls_name.copy_from_user( ClassName );
	if (r < STATUS_SUCCESS)
		return 0;

	NTCREATESTRUCT cs;

	cs.lpCreateParams = Param;
	cs.hInstance = Instance;
	cs.hwndParent = (HWND) Parent;
	cs.hMenu = Menu;
	cs.cx = Width;
	cs.cy = Height;
	cs.x = x;
	cs.y = y;
	cs.style = Style;
	cs.lpszName = NULL;
	cs.lpszClass = NULL;
	cs.dwExStyle = ExStyle;

	WINDOW* win = WINDOW::DoCreate( window_name, wndcls_name, cs );
	if (!win)
		return NULL;
	return win->handle;
}

WINDOW* WINDOW::DoCreate( CUNICODE_STRING& name, CUNICODE_STRING& cls, NTCREATESTRUCT& cs )
{
	trace("window = %pus class = %pus\n", &name, &cls );

	WINDOW* parent_win = 0;
	if (cs.hwndParent)
	{
		parent_win = WindowFromHandle( cs.hwndParent );
		if (!parent_win)
			return FALSE;
	}
	else
		parent_win = desktop_window;

	WNDCLS* wndcls = WNDCLS::FromName( cls );
	if (!wndcls)
		return 0;

	// tweak the styles
	cs.dwExStyle |= WS_EX_WINDOWEDGE;
	cs.dwExStyle &= ~0x80000000;

	if (cs.x == CW_USEDEFAULT)
		cs.x = 0;
	if (cs.y == CW_USEDEFAULT)
		cs.y = 0;

	if (cs.cx == CW_USEDEFAULT)
		cs.cx = 100;
	if (cs.cy == CW_USEDEFAULT)
		cs.cy = 100;

	// allocate a window
	WINDOW *win = new WINDOW;
	trace("new window %p\n", win);
	if (!win)
		return NULL;

	win->GetWinThread() = Current;
	win->self = win;
	win->wndcls = wndcls;
	win->style = cs.style;
	win->exstyle = cs.dwExStyle;
	win->rcWnd.left = cs.x;
	win->rcWnd.top = cs.y;
	win->rcWnd.right = cs.x + cs.cx;
	win->rcWnd.bottom = cs.y + cs.cy;
	win->hInstance = cs.hInstance;

	win->LinkWindow( parent_win );

	win->handle = (HWND) alloc_user_handle( win, USER_HANDLE_WINDOW, Current->Process );
	win->wndproc = wndcls->GetWndproc();

	// create a thread message queue if necessary
	if (!Current->Queue)
		Current->Queue = new THREAD_MESSAGE_QUEUE;

	REGION*& region = win->GetInvalidRegion();
	region = REGION::Alloc();
	region->EmptyRegion();

	// send WM_GETMINMAXINFO
	GETMINMAXINFO_MESSAGE minmax;
	win->Send( minmax );

	// send WM_NCCREATE
	NCCREATE_MESSAGE nccreate( cs, cls, name );
	win->Send( nccreate );

	win->rcWnd.left = cs.x;
	win->rcWnd.top = cs.y;
	win->rcWnd.right = cs.x + cs.cx;
	win->rcWnd.bottom = cs.y + cs.cy;

	// FIXME: not always correct
	win->rcClient = win->rcWnd;

	// send WM_NCCALCSIZE
	NCCALCULATE_MESSAGE nccalcsize( FALSE, win->rcWnd );
	win->Send( nccalcsize );

	win->style |= WS_CLIPSIBLINGS;

	// send WM_CREATE
	CREATE_MESSAGE create( cs, cls, name );
	win->Send( create );

	if (win->style & WS_VISIBLE)
	{
		trace("Window has WS_VISIBLE\n");
		win->SetWindowPos( SWP_SHOWWINDOW | SWP_NOMOVE );

		// move manually afterwards
		MOVE_MSG move( win->rcWnd.left, win->rcWnd.top );
		win->Send( move );
	}

	return win;
}


WINDOW* WINDOW::FindWindowToRepaint( HWND window, THREAD* thread )
{
	WINDOW *win;
	if (window)
	{
		win = WindowFromHandle( window );
		if (!win)
			return FALSE;
	}
	else
		win = desktop_window;

	return FindWindowToRepaint( win, thread );
}

WINDOW* WINDOW::FindWindowToRepaint( WINDOW* win, THREAD* thread )
{
	// special case the desktop window for the moment
	if (win->parent)
	{
		REGION*& region = win->GetInvalidRegion();
		if (region->GetRegionType() != NULLREGION)
			return win;
	}

	for (WND *p = win->first_child; p; p = p->next)
	{
		win = FindWindowToRepaint( p->handle, thread );
		if (win)
			return win;
	}

	return NULL;
}

void WINDOW::SetWindowPos( UINT flags )
{
	if (!(style & WS_VISIBLE))
		return;

	if (flags & SWP_SHOWWINDOW)
	{
		Show( SW_SHOW );

		REGION*& rgn = GetInvalidRegion();
		rgn->SetRect( rcClient );
	}

	WINDOWPOS wp;
	memset( &wp, 0, sizeof wp );
	wp.hwnd = handle;
	if (!(flags & SWP_NOMOVE))
	{
		wp.x = rcWnd.left;
		wp.y = rcWnd.right;
		wp.cx = rcWnd.right - rcWnd.left;
		wp.cy = rcWnd.bottom - rcWnd.top;
	}

	if (flags & (SWP_SHOWWINDOW | SWP_HIDEWINDOW))
	{
		WINPOSCHANGING_MSG poschanging( wp );
		Send( poschanging );
	}

	// send activate messages
	if (!(flags & SWP_NOACTIVATE))
	{
		Activate();

		// painting probably should be done elsewhere
		NCPAINT_MSG ncpaint;
		Send( ncpaint );

		ERASEBKG_MSG erase( GetDc() );
		Send( erase );
	}

	if (style & WS_VISIBLE)
	{
		WINPOSCHANGED_MSG poschanged( wp );
		Send( poschanged );
	}

	if (flags & SWP_HIDEWINDOW)
	{
		// deactivate
		NCACTIVATE_MSG ncact;
		Send( ncact );
	}

	if (!(flags & SWP_NOSIZE))
	{
		SIZE_MSG size( rcWnd.right - rcWnd.left,
						 rcWnd.bottom - rcWnd.top );
		Send( size );
	}

	if (!(flags & SWP_NOMOVE))
	{
		MOVE_MSG move( rcWnd.left, rcWnd.top );
		Send( move );
	}
}

HGDIOBJ WINDOW::GetDc()
{
	DEVICE_CONTEXT *dc = Win32kManager->AllocScreenDcPtr();
	if (!dc)
		return 0;

	dc->set_bounds_rect( rcClient );
	return dc->get_handle();
}

void WINDOW::Activate()
{
	if (active_window == this)
		return;

	if (active_window)
	{
		APPACT_MSG aa( WA_INACTIVE );
		active_window->Send( aa );
	}

	active_window = this;
	APPACT_MSG aa( WA_ACTIVE );
	Send( aa );

	NCACTIVATE_MSG ncact;
	Send( ncact );

	ACTIVATE_MSG act;
	Send( act );

	SETFOCUS_MSG setfocus;
	Send( setfocus );
}

BOOLEAN WINDOW::Destroy()
{
	// set the window to zero size
	SetWindowPos( SWP_NOMOVE | SWP_NOSIZE |
					SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW );

	DESTROY_MSG destroy;
	Send( destroy );

	NCDESTROY_MSG ncdestroy;
	Send( ncdestroy );

	delete this;
	return TRUE;
}

BOOLEAN NTAPI NtUserSetLogonNotifyWindow( HWND Window )
{
	return TRUE;
}

LONG NTAPI NtUserGetClassInfo(
	PVOID Module,
	PUNICODE_STRING ClassName,
	PVOID Buffer,
	PULONG Length,
	ULONG Unknown)
{
	CUNICODE_STRING class_name;
	NTSTATUS r = class_name.CopyFromUser( ClassName );
	if (r < STATUS_SUCCESS)
		return r;
	trace("%pus\n", &class_name );

	return 0;
}

BOOLEAN NTAPI NtUserNotifyProcessCreate( ULONG NewProcessId, ULONG CreatorId, ULONG, ULONG )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserConsoleControl( ULONG Id, PVOID Information, ULONG Length )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserGetObjectInformation( HANDLE Object, ULONG InformationClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
{
	return TRUE;
}

BOOLEAN NTAPI NtUserResolveDesktop(HANDLE Process, PVOID, PVOID, PHANDLE Desktop )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserShowWindow( HWND Window, INT Show )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	return win->Show( Show );
}

HANDLE NTAPI NtUserCreateAcceleratorTable( PVOID Accelerators, UINT Count )
{
	static UINT accelerator = 1;
	return (HANDLE) accelerator++;
}

BOOLEAN NTAPI NtUserMoveWindow( HWND Window, int x, int y, int width, int height, BOOLEAN repaint )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	return win->MoveWindow( x, y, width, height, repaint );
}

BOOLEAN WINDOW::MoveWindow( int x, int y, int width, int height, BOOLEAN repaint )
{
	WINDOWPOS wp;
	memset( &wp, 0, sizeof wp );
	wp.hwnd = handle;

	wp.x = x;
	wp.y = y;
	wp.cx = width;
	wp.cy = height;

	WINPOSCHANGING_MSG poschanging( wp );
	Send( poschanging );

	rcWnd.left = x;
	rcWnd.top = y;
	rcWnd.right = x + width;
	rcWnd.bottom = y + height;

	rcClient = rcWnd;

	NCCALCULATE_MESSAGE nccalcsize( TRUE, rcWnd );
	Send( nccalcsize );

	WINPOSCHANGED_MSG poschanged( wp );
	Send( poschanged );

	return TRUE;
}

BOOLEAN NTAPI NtUserRedrawWindow( HWND Window, RECT *Update, HANDLE Region, UINT Flags )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	if (!(win->style & WS_VISIBLE))
		return TRUE;

	RECT rect;
	if (Update)
	{
		NTSTATUS r = CopyFromUser( &rect, Update );
		if (r < STATUS_SUCCESS)
			return FALSE;
	}
	else
	{
		rect = win->rcClient;
	}

	REGION*& region = win->GetInvalidRegion();
	region->SetRect( rect );

	return TRUE;
}

ULONG NTAPI NtUserGetAsyncKeyState( ULONG Key )
{
	return Win32kManager->GetAsyncKeyState( Key );
}

LRESULT NTAPI NtUserDispatchMessage( PMSG Message )
{
	MSG msg;
	NTSTATUS r;
	r = CopyFromUser( &msg, Message );
	if (r < STATUS_SUCCESS)
		return 0;

	WINDOW *win = WindowFromHandle( msg.hwnd );
	if (!win)
		return 0;

	switch (msg.message)
	{
		case WM_PAINT:
		{
			PAINT_MSG msg;
			win->Send( msg );
		}
		break;
	default:
		trace("unknown message %04x\n", msg.message);
	}

	return 0;
}

BOOLEAN NTAPI NtUserInvalidateRect( HWND Window, const RECT* Rectangle, BOOLEAN Erase )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	if (!(win->style & WS_VISIBLE))
		return TRUE;

	RECT rect;
	if (Rectangle)
	{
		NTSTATUS r = CopyFromUser( &rect, Rectangle );
		if (r < STATUS_SUCCESS)
			return FALSE;
	}
	else
	{
		rect = win->rcClient;
	}

	REGION*& region = win->GetInvalidRegion();
	region->SetRect( rect );

	return TRUE;
}

BOOLEAN NTAPI NtUserMessageCall( HWND Window, ULONG, ULONG, PVOID, ULONG, ULONG, ULONG)
{
	return TRUE;
}

BOOLEAN NTAPI NtUserDestroyWindow( HWND Window )
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return FALSE;

	return win->Destroy();
}

BOOLEAN NTAPI NtUserValidateRect( HWND Window, PRECT Rect )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserGetUpdateRgn( HWND Window, HRGN Region, BOOLEAN Erase )
{
	return TRUE;
}

HDC NTAPI NtUserBeginPaint( HWND Window, PAINTSTRUCT* pps)
{
	WINDOW *win = WindowFromHandle( Window );
	if (!win)
		return NULL;

	PAINTSTRUCT ps;
	memset( &ps, 0, sizeof ps );
	ps.rcPaint.left = 0;
	ps.rcPaint.top = 0;
	ps.rcPaint.bottom = win->rcClient.bottom - win->rcClient.top;
	ps.rcPaint.right = win->rcClient.right - win->rcClient.left;
	NTSTATUS r = CopyToUser( pps, &ps );
	if (r < STATUS_SUCCESS)
		return NULL;

	REGION*& region = win->GetInvalidRegion();
	region->EmptyRegion();

	return (HDC) win->GetDc();
}

BOOLEAN NTAPI NtUserEndPaint( HWND Window, PAINTSTRUCT* pps )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserCallHwnd( HWND Window, ULONG )
{
	return TRUE;
}

BOOLEAN NTAPI NtUserSetMenu( HWND Window, ULONG, ULONG )
{
	return TRUE;
}

HWND NTAPI NtUserSetCapture( HWND Window )
{
	return 0;
}

int NTAPI NtUserTranslateAccelerator( HWND Window, HACCEL AcceleratorTable, PMSG Message )
{
	return 0;
}

BOOLEAN NTAPI NtUserTranslateMessage( PMSG Message, ULONG )
{
	return 0;
}

HWND WINDOW::FromPoint( POINT& pt )
{
	for (PWND win = first_child; win; win = win->next)
	{
		CRECT r( win->rcWnd );
		if (r.ContainsPoint( pt ))
			return win->handle;
	}
	return handle;
}

HWND NTAPI NtUserWindowFromPoint( POINT pt )
{
	WINDOW *win = desktop_window;
	if (!win)
		return 0;
	return win->FromPoint( pt );
}
