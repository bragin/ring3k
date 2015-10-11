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
#include "ntwin32.h"
#include "message.h"
#include "debug.h"
#include "queue.h"
#include "spy.h"

template<class Pack>
GENERIC_MESSAGE<Pack>::GENERIC_MESSAGE()
{
	memset( &Info, 0, sizeof Info );
}

template<class Pack>
ULONG GENERIC_MESSAGE<Pack>::GetSize() const
{
	return sizeof Info;
}

template<class Pack>
NTSTATUS GENERIC_MESSAGE<Pack>::CopyToUser( void *ptr ) const
{
	return ::CopyToUser( ptr, &Info, sizeof Info );
}

template<class Pack>
void GENERIC_MESSAGE<Pack>::SetWindowInfo( WINDOW *win )
{
	Info.wininfo = win->GetWininfo();
	Info.wndproc = win->GetWndproc();
	Info.func = (typeof(Info.func)) g_FuncsW[17];
}

template<class Pack>
const char *GENERIC_MESSAGE<Pack>::Description()
{
	return GetMessageName( Info.msg );
}

NCCREATE_MESSAGE::NCCREATE_MESSAGE( NTCREATESTRUCT& cs, const UNICODE_STRING& cls, const UNICODE_STRING& name ) :
	CREATE_MESSAGE( cs, cls, name )
{
	Info.msg = WM_NCCREATE;
}

CREATE_MESSAGE::CREATE_MESSAGE( NTCREATESTRUCT& cs,
									  const UNICODE_STRING& _cls, const UNICODE_STRING& _name ) :
	cls( _cls ),
	name( _name )
{
	memset( &Info, 0, sizeof Info );

	Info.pi.x = 0;
	Info.pi.count = 0;
	Info.pi.kernel_address = 0;
	Info.pi.adjust_info_ofs = 0;
	Info.pi.no_adjust = 0;

	Info.pi.sz = sizeof Info;
	Info.wininfo = NULL;
	Info.msg = WM_CREATE;
	Info.wparam = 0;
	Info.cs_nonnull = TRUE;
	Info.cs = cs;
}

ULONG CREATE_MESSAGE::GetCallbackNum() const
{
	return NTWIN32_CREATE_CALLBACK;
}

GETMINMAXINFO_MESSAGE::GETMINMAXINFO_MESSAGE()
{
	Info.msg = WM_GETMINMAXINFO;
}

ULONG GETMINMAXINFO_MESSAGE::GetCallbackNum() const
{
	return NTWIN32_MINMAX_CALLBACK;
}

NCCALCULATE_MESSAGE::NCCALCULATE_MESSAGE( BOOLEAN wparam, RECT& new_rect )
{
	Info.msg = WM_NCCALCSIZE;
	Info.wparam = wparam;
	Info.params.rgrc[0] = new_rect;
}

ULONG NCCALCULATE_MESSAGE::GetCallbackNum() const
{
	return NTWIN32_NCCALC_CALLBACK;
}

BASIC_MSG::BASIC_MSG()
{
}

BASIC_MSG::BASIC_MSG( INT message )
{
	Info.msg = message;
}

ULONG BASIC_MSG::GetCallbackNum() const
{
	return NTWIN32_BASICMSG_CALLBACK;
}

SHOWWINDOW_MSG::SHOWWINDOW_MSG( bool show )
{
	Info.msg = WM_SHOWWINDOW;
	Info.wparam = show;
	Info.lparam = 0;
}

WINPOSCHANGE_MSG::WINPOSCHANGE_MSG( ULONG message, WINDOWPOS& pos )
{
	memcpy( &Info.winpos, &pos, sizeof pos );
	Info.msg = message;
}

// comes BEFORE a window's position changes
WINPOSCHANGING_MSG::WINPOSCHANGING_MSG( WINDOWPOS& pos ) :
	WINPOSCHANGE_MSG( WM_WINDOWPOSCHANGING, pos )
{
}

ULONG WINPOSCHANGING_MSG::GetCallbackNum() const
{
	return NTWIN32_POSCHANGING_CALLBACK;
}

// comes AFTER a window's position changes
WINPOSCHANGED_MSG::WINPOSCHANGED_MSG( WINDOWPOS& pos ) :
	WINPOSCHANGE_MSG( WM_WINDOWPOSCHANGED, pos )
{
}

ULONG WINPOSCHANGED_MSG::GetCallbackNum() const
{
	return NTWIN32_POSCHANGED_CALLBACK;
}

APPACT_MSG::APPACT_MSG( UINT type )
{
	Info.msg = WM_ACTIVATEAPP;
	Info.wparam = type;
}

NCACTIVATE_MSG::NCACTIVATE_MSG()
{
	Info.msg = WM_NCACTIVATE;
}

ACTIVATE_MSG::ACTIVATE_MSG()
{
	Info.msg = WM_ACTIVATE;
}

SETFOCUS_MSG::SETFOCUS_MSG()
{
	Info.msg = WM_SETFOCUS;
}

NCPAINT_MSG::NCPAINT_MSG() :
	BASIC_MSG( WM_NCPAINT )
{
}

PAINT_MSG::PAINT_MSG() :
	BASIC_MSG( WM_PAINT )
{
}

ERASEBKG_MSG::ERASEBKG_MSG( HANDLE dc ) :
	BASIC_MSG( WM_ERASEBKGND )
{
	Info.wparam = (WPARAM) dc;
}

KEYUP_MSG::KEYUP_MSG( UINT key )
{
	Info.msg = WM_KEYUP;
	Info.wparam = key;
}

KEYDOWN_MSG::KEYDOWN_MSG( UINT key )
{
	Info.msg = WM_KEYDOWN;
	Info.wparam = key;
}

SIZE_MSG::SIZE_MSG( INT cx, INT cy ) :
	BASIC_MSG( WM_SIZE )
{
	Info.lparam = MAKELONG( cx, cy );
}

MOVE_MSG::MOVE_MSG( INT x, INT y ) :
	BASIC_MSG( WM_MOVE )
{
	Info.lparam = MAKELONG( x, y );
}

NCDESTROY_MSG::NCDESTROY_MSG() :
	BASIC_MSG( WM_NCDESTROY )
{
}

DESTROY_MSG::DESTROY_MSG() :
	BASIC_MSG( WM_DESTROY )
{
}

