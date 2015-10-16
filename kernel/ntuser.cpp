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

WNDCLS_LIST WndclsList;
WINDOW *ActiveWindow;
WINDOW *DesktopWindow;

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
		void *Object;
		USHORT NextFree;
	};
	void *Owner;
	USHORT Type;
	USHORT Highpart;
};

struct USER_SHARED_MEM
{
	ULONG X1;
	ULONG X2;
	ULONG MaxWindowHandle;
	ULONG X3[459];
	COLORREF ButtonHilight;
	COLORREF ButtonDkShadow;
};

static const ULONG UserSharedMemSize = 0x20000;
static const ULONG UserSharedMemReserve = 0x10000;

// section for user handle table
static SECTION *UserHandleTableSection = 0;

// kernel address for user handle table (shared)
static USER_HANDLE_ENTRY *UserHandleTable;

// section for user shared memory
static SECTION *UserSharedSection = 0;

// kernel address for memory shared with the user process
static USER_SHARED_MEM *UserShared;

// bitmap of free memory
ALLOCATION_BITMAP UserSharedBitmap;

MESSAGE_MAP_SHARED_MEMORY MessageMaps[NUMBER_OF_MESSAGE_MAPS];

static USHORT NextUserHandle = 1;

#define MAX_USER_HANDLES 0x200

void CheckMaxWindowHandle( ULONG n )
{
	n++;
	if (UserShared->MaxWindowHandle<n)
		UserShared->MaxWindowHandle = n;
	trace("max_window_handle = %04lx\n", UserShared->MaxWindowHandle);
}

void InitUserHandleTable()
{
	USHORT i;
	NextUserHandle = 1;
	for ( i=NextUserHandle; i<(MAX_USER_HANDLES-1); i++ )
	{
		UserHandleTable[i].Object = (void*) (i+1);
		UserHandleTable[i].Owner = 0;
		UserHandleTable[i].Type = 0;
		UserHandleTable[i].Highpart = 1;
	}
}

ULONG AllocUserHandle( void* obj, ULONG type, PROCESS *owner )
{
	assert( type != 0 );
	ULONG ret = NextUserHandle;
	ULONG next = UserHandleTable[ret].NextFree;
	assert( next != ret );
	assert( UserHandleTable[ret].Type == 0 );
	assert( UserHandleTable[ret].Owner == 0 );
	assert( next <= MAX_USER_HANDLES );
	UserHandleTable[ret].Object = obj;
	UserHandleTable[ret].Type = type;
	UserHandleTable[ret].Owner = (void*) owner;
	NextUserHandle = next;
	CheckMaxWindowHandle( ret );
	return (UserHandleTable[ret].Highpart << 16) | ret;
}

void FreeUserHandle( HANDLE handle )
{
	UINT n = (UINT) handle;
	USHORT lowpart = n&0xffff;

	trace("freeing handle %08x\n", n);
	UserHandleTable[lowpart].Type = 0;
	UserHandleTable[lowpart].Owner = 0;
	UserHandleTable[lowpart].Object = 0;

	// update the free handle list
	UserHandleTable[lowpart].NextFree = NextUserHandle;
	NextUserHandle = lowpart;

	// FIXME: maybe decrease max_window_handle?
}

void DeleteUserObject( ULONG i )
{
	USER_HANDLE_ENTRY *entry = UserHandleTable+i;
	trace("deleting user handle %ld\n", i);
	assert(entry->Object != NULL);
	switch (entry->Type)
	{
	case USER_HANDLE_WINDOW:
		delete (WINDOW*) entry->Object;
		break;
	default:
		trace("object %ld (%p), type = %08x owner = %p\n",
			  i, entry->Object, entry->Type, entry->Owner);
		assert(0);
	}
}

void FreeUser32Handles( PROCESS *p )
{
	ULONG i;
	assert( p != NULL );
	if (!UserHandleTable)
		return;
	for (i=0; i<UserShared->MaxWindowHandle; i++)
	{
		if (p == (PROCESS*) UserHandleTable[i].Owner)
			DeleteUserObject( i );
	}
}

void* UserObjFromHandle( HANDLE handle, ULONG type )
{
	UINT n = (UINT) handle;
	USHORT lowpart = n&0xffff;
	//USHORT highpart = (n>>16);

	if (lowpart == 0 || lowpart > UserShared->MaxWindowHandle)
		return NULL;
	if (type != UserHandleTable[lowpart].Type)
		return NULL;
	//FIXME: check high part and type
	//if (user_handle_table[].highpart != highpart)
	return UserHandleTable[lowpart].Object;
}

WINDOW *WindowFromHandle( HANDLE handle )
{
	void *obj = UserObjFromHandle( handle, 1 );
	if (!obj)
		return NULL;
	return (WINDOW*) obj;
}

void *InitUserSharedMemory()
{
	// read/write for the kernel and read only for processes
	if (!UserShared)
	{
		LARGE_INTEGER sz;
		NTSTATUS r;

		sz.QuadPart = sizeof (USER_HANDLE_ENTRY) * MAX_USER_HANDLES;
		r = CreateSection( &UserHandleTableSection, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return 0;

		UserHandleTable = (USER_HANDLE_ENTRY*) UserHandleTableSection->GetKernelAddress();

		InitUserHandleTable();

		sz.QuadPart = UserSharedMemSize;
		r = CreateSection( &UserSharedSection, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return 0;

		UserShared = (USER_SHARED_MEM*) UserSharedSection->GetKernelAddress();

		// setup the allocation bitmap for user objects (eg. windows)
		void *object_area = (void*) ((BYTE*) UserShared + UserSharedMemReserve);
		UserSharedBitmap.SetArea( object_area,
									 UserSharedMemSize - UserSharedMemReserve );

		// create the window stations directory too
		CreateDirectoryObject( (PWSTR) L"\\Windows\\WindowStations" );

		// see wine/dlls/user32/sysparams.c
		UserShared->ButtonHilight = RGB(255,255,255);
		UserShared->ButtonDkShadow = RGB(64,64,64);
	}

	trace("user_handle_table at %p\n", UserHandleTable );
	trace("user_shared at %p\n", UserShared );

	return UserShared;
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

bool MessageMapOnAccess( BYTE *address, ULONG eip )
{
	for (ULONG i=0; i<NUMBER_OF_MESSAGE_MAPS; i++)
	{
		if (!MessageMaps[i].Bitmap)
			continue;
		if (address < MessageMaps[i].Bitmap)
			continue;
		ULONG ofs = address - MessageMaps[i].Bitmap;
		if (ofs > MessageMaps[i].MaxMessage/8)
			continue;
		fprintf(stderr, "%04lx: accessed message map[%ld][%04lx] from %08lx\n",
				Current->TraceId(), i, ofs, eip);
		return true;
	}
	return false;
}

bool WindowOnAccess( BYTE *address, ULONG eip )
{
	for (ULONG i=0; i<UserShared->MaxWindowHandle; i++)
	{
		switch (UserHandleTable[i].Type)
		{
			case USER_HANDLE_WINDOW:
			{
				// window shared memory structures are variable size
				// have the window check itself
				WINDOW* wnd = reinterpret_cast<WINDOW*>( UserHandleTable[i].Object);
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
	if (ofs < UserSharedMemReserve)
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

	if (MessageMapOnAccess( address, eip ))
		return;

	if (WindowOnAccess( address, eip ))
		return;

	fprintf(stderr, "%04lx: accessed ushm[%04lx] from %08lx\n",
			Current->TraceId(), ofs, eip);
}

static NTUSERSHM_TRACER NtUserShmTrace;

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
		f( 0, Owner )
		f( 4, Object )
		f( 8, Type )
		f( 10, Highpart )
#undef f
	default:
		field = "unknown";
	}

	fprintf(stderr, "%04lx: accessed user handle[%04lx]+%s (%ld) from %08lx\n",
			Current->TraceId(), number, field, ofs%sz, eip);
}
static NTUSERHANDLE_TRACER NtUserHandleTrace;

BYTE* AllocMessageBitmap( PROCESS* proc, MESSAGE_MAP_SHARED_MEMORY& map, ULONG last_message )
{
	ULONG sz = (last_message+7)/8;
	BYTE *msg_map = UserSharedBitmap.Alloc( sz );
	memset( msg_map, 0, sz );
	ULONG ofs = (BYTE*)msg_map - (BYTE*)UserShared;
	map.Bitmap = (BYTE*) (proc->Win32kInfo->UserSharedMem + ofs);
	map.MaxMessage = last_message;
	trace("bitmap = %p last = %ld\n", map.Bitmap, map.MaxMessage);
	return msg_map;
}

NTUSERINFO *AllocUserInfo()
{
	NTUSERINFO *info = (NTUSERINFO*) UserSharedBitmap.Alloc( sizeof (NTUSERINFO) );
	info->DesktopWindow = DesktopWindow;
	ULONG ofs = (BYTE*)info - (BYTE*)UserShared;
	return (NTUSERINFO*) (Current->Process->Win32kInfo->UserSharedMem + ofs);
}

void CreateDesktopWindow()
{
	if (DesktopWindow)
		return;

	DesktopWindow = new WINDOW;
	if (!DesktopWindow)
		return;

	memset( DesktopWindow, 0, sizeof (WINDOW) );
	DesktopWindow->rcWnd.left = 0;
	DesktopWindow->rcWnd.top = 0;
	DesktopWindow->rcWnd.right = 640;
	DesktopWindow->rcWnd.bottom = 480;
	DesktopWindow->rcClient = DesktopWindow->rcWnd;

	DesktopWindow->handle = (HWND) AllocUserHandle( DesktopWindow, USER_HANDLE_WINDOW, Current->Process );
}

// should be called from NtGdiInit to map the user32 shared memory
NTSTATUS MapUserSharedMemory( PROCESS *proc )
{
	NTSTATUS r;

	assert( proc->Win32kInfo );
	BYTE*& user_shared_mem = proc->Win32kInfo->UserSharedMem;
	BYTE*& user_handles = proc->Win32kInfo->UserHandles;

	// map the user shared memory block into the process's memory
	if (!InitUserSharedMemory())
		return STATUS_UNSUCCESSFUL;

	// already mapped into this process?
	if (user_shared_mem)
		return STATUS_SUCCESS;

	r = UserSharedSection->Mapit( proc->Vm, user_shared_mem, 0,
									MEM_COMMIT, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	if (OptionTrace)
	{
		proc->Vm->SetTracer( user_shared_mem, NtUserShmTrace );
		proc->Vm->SetTracer( user_handles, NtUserHandleTrace );
	}

	// map the shared handle table
	r = UserHandleTableSection->Mapit( proc->Vm, user_handles, 0,
										  MEM_COMMIT, PAGE_READONLY );
	if (r < STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

	trace("user shared at %p\n", user_shared_mem);

	return STATUS_SUCCESS;
}

BOOLEAN DoGdiInit()
{
	NTSTATUS r;
	r = MapUserSharedMemory( Current->Process );
	if (r < STATUS_SUCCESS)
		return FALSE;

	// check set the offset
	BYTE*& user_shared_mem = Current->Process->Win32kInfo->UserSharedMem;
	Current->GetTEB()->KernelUserPointerOffset = (BYTE*) UserShared - user_shared_mem;

	// create the desktop window for alloc_user_info
	CreateDesktopWindow();
	Current->GetTEB()->NtUserInfo = AllocUserInfo();

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

	r = MapUserSharedMemory( proc );
	if (r < STATUS_SUCCESS)
		return r;

	info.win2k.Ptr[0] = (void*)proc->Win32kInfo->UserSharedMem;
	info.win2k.Ptr[1] = (void*)proc->Win32kInfo->UserHandles;
	info.win2k.Ptr[2] = (void*)0xbee30000;
	info.win2k.Ptr[3] = (void*)0xbee40000;

	for (ULONG i=0; i<NUMBER_OF_MESSAGE_MAPS; i++ )
	{
		info.win2k.MessageMap[i].MaxMessage = 0;
		info.win2k.MessageMap[i].Bitmap = (BYTE*)i;
	}

	AllocMessageBitmap( proc, info.win2k.MessageMap[0x1b], 0x400 );
	MessageMaps[0x1b] = info.win2k.MessageMap[0x1b];
	AllocMessageBitmap( proc, info.win2k.MessageMap[0x1c], 0x400 );
	MessageMaps[0x1c] = info.win2k.MessageMap[0x1c];

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
	return UserSharedBitmap.Alloc( sz );
}

void WNDCLS::operator delete(void *p)
{
	UserSharedBitmap.Free( (unsigned char*) p, sizeof (WNDCLS) );
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
	for (WNDCLS_ITER i(WndclsList); i; i.Next())
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

	WndclsList.Append( cls );

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

static int g_HackDesktop = 0xf00d2001;

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

	return (HANDLE) g_HackDesktop++;
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

	return (HANDLE) g_HackDesktop++;
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

	return (HANDLE) g_HackDesktop++;
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

ULONG MessageNo = 0xc001;

ULONG NTAPI NtUserRegisterWindowMessage(PUNICODE_STRING Message)
{
	trace("\n");
	CUNICODE_STRING us;

	NTSTATUS r = us.CopyFromUser( Message );
	if (r < STATUS_SUCCESS)
		return 0;

	trace("message = %pus -> %04lx\n", &us, MessageNo);

	return MessageNo++;
}

class CUSER32_UNICODE_STRING : public CUNICODE_STRING
{
public:
	NTSTATUS CopyFromUser( PUSER32_UNICODE_STRING String );
};

NTSTATUS CUSER32_UNICODE_STRING::CopyFromUser( PUSER32_UNICODE_STRING String )
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
	if (this == DesktopWindow)
	{
		DesktopWindow = NULL;
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
	return UserSharedBitmap.Alloc( sz );
}

void WINDOW::operator delete(void *p)
{
	UserSharedBitmap.Free( (unsigned char*) p, sizeof (WINDOW) );
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
		f( 0x34, Owner )
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
	FreeUserHandle( handle );
	trace("active window = %p this = %p\n", ActiveWindow, this);
	if (ActiveWindow == this)
	{
		trace("cleared active window handle\n");
		ActiveWindow = 0;
	}
}

PWND WINDOW::GetWininfo()
{
	ULONG ofs = (BYTE*)this - (BYTE*)UserShared;
	return (PWND) (Current->Process->Win32kInfo->UserSharedMem + ofs);
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

	CUSER32_UNICODE_STRING window_name;
#if 0
	r = window_name.CopyFromUser( WindowName );
	if (r < STATUS_SUCCESS)
		return 0;
#endif

	CUSER32_UNICODE_STRING wndcls_name;
	r = wndcls_name.CopyFromUser( ClassName );
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
		parent_win = DesktopWindow;

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

	win->handle = (HWND) AllocUserHandle( win, USER_HANDLE_WINDOW, Current->Process );
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
		win = DesktopWindow;

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

	dc->SetBoundsRect( rcClient );
	return dc->GetHandle();
}

void WINDOW::Activate()
{
	if (ActiveWindow == this)
		return;

	if (ActiveWindow)
	{
		APPACT_MSG aa( WA_INACTIVE );
		ActiveWindow->Send( aa );
	}

	ActiveWindow = this;
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
    ps.hdc = (HDC)win->GetDc();
	NTSTATUS r = CopyToUser( pps, &ps );
	if (r < STATUS_SUCCESS)
		return NULL;

	REGION*& region = win->GetInvalidRegion();
	region->EmptyRegion();

	return ps.hdc;
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
	WINDOW *win = DesktopWindow;
	if (!win)
		return 0;
	return win->FromPoint( pt );
}
