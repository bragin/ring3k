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

#ifndef __RING3K_MESSAGE__
#define __RING3K_MESSAGE__

#include "ntwin32.h"
#include "win.h"

// a message sent to a window via a callback
// the message information needs to be copied to user space
class MESSAGE
{
public:
	virtual ULONG GetSize() const = 0;
	virtual NTSTATUS CopyToUser( void *ptr ) const = 0;
	virtual ULONG GetCallbackNum() const = 0;
	virtual void SetWindowInfo( WINDOW *win ) = 0;
	virtual const char *Description() = 0;
	virtual ~MESSAGE() {}
};

// message with the piece of packed information to be sent
// one fixed size piece of data to send named 'info'
template<class Pack> class GENERIC_MESSAGE : public MESSAGE
{
public:
	Pack Info;
public:
	GENERIC_MESSAGE();
	virtual ULONG GetSize() const;
	virtual NTSTATUS CopyToUser( void *ptr ) const;
	virtual ULONG GetCallbackNum() const = 0;
	virtual void SetWindowInfo( WINDOW *win );
	virtual const char *Description();
};

// WM_CREATE and WM_NCCREATE
class CREATE_MESSAGE : public GENERIC_MESSAGE<NTCREATEPACKEDINFO>
{
protected:
	const UNICODE_STRING& cls;
	const UNICODE_STRING& name;
public:
	CREATE_MESSAGE( NTCREATESTRUCT& cs, const UNICODE_STRING& cls, const UNICODE_STRING& name );
	virtual ULONG GetCallbackNum() const;
};

class NCCREATE_MESSAGE : public CREATE_MESSAGE
{
public:
	NCCREATE_MESSAGE( NTCREATESTRUCT& cs, const UNICODE_STRING& cls, const UNICODE_STRING& name );
};

// WM_GETMINMAXINFO
class GETMINMAXINFO_MESSAGE : public GENERIC_MESSAGE<NTMINMAXPACKEDINFO>
{
public:
	GETMINMAXINFO_MESSAGE();
	virtual ULONG GetCallbackNum() const;
};

// WM_NCCALCSIZE
class NCCALCULATE_MESSAGE : public GENERIC_MESSAGE<NTNCCALCSIZEPACKEDINFO>
{
public:
	NCCALCULATE_MESSAGE( BOOLEAN wparam, RECT& new_rect );
	virtual ULONG GetCallbackNum() const;
};

// basic messages where lparam and wparam aren't pointers
class BASIC_MSG : public GENERIC_MESSAGE<NTSIMPLEMESSAGEPACKEDINFO>
{
public:
	BASIC_MSG();
	BASIC_MSG( INT message );
	virtual ULONG GetCallbackNum() const;
};

class SHOWWINDOW_MSG : public BASIC_MSG
{
public:
	SHOWWINDOW_MSG( bool show );
};

// WM_WINDOWPOSCHANGING and WM_WINDOWPOSCHANGED
class WINPOSCHANGE_MSG : public GENERIC_MESSAGE<NTPOSCHANGINGPACKEDINFO>
{
public:
	WINPOSCHANGE_MSG( ULONG message, WINDOWPOS& pos );
	virtual ULONG GetCallbackNum() const = 0;
};

class WINPOSCHANGING_MSG : public WINPOSCHANGE_MSG
{
public:
	WINPOSCHANGING_MSG( WINDOWPOS& _pos );
	virtual ULONG GetCallbackNum() const;
};

class WINPOSCHANGED_MSG : public WINPOSCHANGE_MSG
{
public:
	WINPOSCHANGED_MSG( WINDOWPOS& _pos );
	virtual ULONG GetCallbackNum() const;
};

// WM_ACTIVATEAPP
class APPACT_MSG : public BASIC_MSG
{
public:
	APPACT_MSG( UINT type );
};

// WM_NCACTIVATE
class NCACTIVATE_MSG : public BASIC_MSG
{
public:
	NCACTIVATE_MSG();
};

// WM_ACTIVATE
class ACTIVATE_MSG : public BASIC_MSG
{
public:
	ACTIVATE_MSG();
};

// WM_SETFOCUS
class SETFOCUS_MSG : public BASIC_MSG
{
public:
	SETFOCUS_MSG();
};

class PAINT_MSG : public BASIC_MSG
{
public:
	PAINT_MSG();
};

class NCPAINT_MSG : public BASIC_MSG
{
public:
	NCPAINT_MSG();
};

class ERASEBKG_MSG : public BASIC_MSG
{
public:
	ERASEBKG_MSG( HANDLE dc );
};

class KEYUP_MSG : public BASIC_MSG
{
public:
	KEYUP_MSG( UINT key );
};

class KEYDOWN_MSG : public BASIC_MSG
{
public:
	KEYDOWN_MSG( UINT key );
};

class SIZE_MSG : public BASIC_MSG
{
public:
	SIZE_MSG( INT cx, INT cy );
};

class MOVE_MSG : public BASIC_MSG
{
public:
	MOVE_MSG( INT x, INT y );
};

class NCDESTROY_MSG : public BASIC_MSG
{
public:
	NCDESTROY_MSG();
};

class DESTROY_MSG : public BASIC_MSG
{
public:
	DESTROY_MSG();
};

#endif // __RING3K_MESSAGE__
