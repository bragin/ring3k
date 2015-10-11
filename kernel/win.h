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

#ifndef __RING3K_WIN_H__
#define __RING3K_WIN_H__

#include "ntwin32.h"
#include "region.h"

struct WINDOW;
class WNDCLS;
class MESSAGE;

typedef LIST_ANCHOR<WNDCLS, 0> WNDCLS_LIST;
typedef LIST_ELEMENT<WNDCLS> WNDCLS_ENTRY;
typedef LIST_ITER<WNDCLS, 0> WNDCLS_ITER;

class WNDCLS : public CLASSINFO
{
	// FIXME: all these have to go
	friend class LIST_ANCHOR<WNDCLS, 0>;
	friend class LIST_ITER<WNDCLS, 0>;
	WNDCLS_ENTRY Entry[1];
	CUNICODE_STRING Name;
	CUNICODE_STRING Menu;
	NTWNDCLASSEX Info;
	ULONG RefCount;
public:
	void* operator new(size_t sz);
	void operator delete(void *p);
	WNDCLS( NTWNDCLASSEX& ClassInfo, const UNICODE_STRING& ClassName, const UNICODE_STRING& MenuName, ATOM a );
	static WNDCLS* FromName( const UNICODE_STRING& wndcls_name );
	ATOM GetAtom() const
	{
		return atomWindowType;
	}
	const CUNICODE_STRING& GetName() const
	{
		return Name;
	}
	void AddRef()
	{
		RefCount++;
	}
	void Release()
	{
		RefCount--;
	}
	PVOID GetWndproc() const
	{
		return Info.WndProc;
	}
};

class WINDOW : public WND
{
	// no virtual functions here, binary compatible with user side WND struct
public:
	void* operator new(size_t sz);
	void operator delete(void *p);
	WINDOW();
	~WINDOW();
	static WINDOW* DoCreate( CUNICODE_STRING& name, CUNICODE_STRING& cls, NTCREATESTRUCT& cs );
	NTSTATUS Send( MESSAGE& msg );
	void *GetWndproc()
	{
		return wndproc;
	}
	PWND GetWininfo();
	THREAD* &GetWinThread()
	{
		return (THREAD*&)unk1;
	}
	REGION* &GetInvalidRegion()
	{
		return (REGION*&)unk2;
	}
	BOOLEAN Show( INT Show );
	void Activate();
	HGDIOBJ GetDc();
	BOOLEAN Destroy();
	void SetWindowPos( UINT flags );
	static WINDOW* FindWindowToRepaint( HWND window, THREAD* thread );
	static WINDOW* FindWindowToRepaint( WINDOW* win, THREAD* thread );
	void LinkWindow( WINDOW *parent );
	void UnlinkWindow();
	BOOLEAN MoveWindow( int x, int y, int width, int height, BOOLEAN repaint );
	HWND FromPoint( POINT& pt );
	bool OnAccess( BYTE* address, ULONG ip );
};

WINDOW *WindowFromHandle( HANDLE handle );

// system wide callback functions registered with kernel by user32.dll
extern PVOID g_Funcs[9];
extern PVOID g_FuncsW[20];
extern PVOID g_FuncsA[20];

#endif // __RING3K_WIN_H__
