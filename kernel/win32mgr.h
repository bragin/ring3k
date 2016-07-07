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

#ifndef __WIN32K_MANAGER__
#define __WIN32K_MANAGER__

#include "ntwin32.h"
#include "alloc_bitmap.h"

// the freetype project certainly has their own way of doing things :/
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H

template<typename T> static inline void Swap( T& a, T& b )
{
	T x = a;
	a = b;
	b = x;
}

class WIN32K_INFO
{
public:
	WIN32K_INFO();
	~WIN32K_INFO();
	// address that device context shared memory is mapped to
	BYTE* DcSharedMem;
	BYTE* UserSharedMem;
	BYTE* UserHandles;
	HANDLE StockObject[STOCK_LAST + 1];
};

class BRUSH;
class PEN;
class CBITMAP;
class DEVICE_CONTEXT;

class WIN32K_MANAGER
{
	ULONG KeyState[0x100];
	FT_Library Ftlib;
	FT_Face Face;
public:
	WIN32K_MANAGER();
	void InitStockObjects();
	HANDLE GetStockObject( ULONG Index );
	HANDLE CreateSolidBrush( COLORREF color );
	HANDLE CreatePen( UINT style, UINT width, COLORREF color );
	virtual ~WIN32K_MANAGER();
	virtual BOOL Init() = 0;
	virtual void Fini() = 0;
	virtual HGDIOBJ AllocCompatibleDc();
	virtual HGDIOBJ AllocScreenDC();
	virtual DEVICE_CONTEXT* AllocScreenDcPtr() = 0;
	virtual BOOL ReleaseDC( HGDIOBJ dc );
	WIN32K_INFO* AllocWin32kInfo();
	virtual void SendInput( INPUT* input );
	ULONG GetAsyncKeyState( ULONG Key );
	virtual int GetCaps( int index ) = 0;
	FT_Face GetFace();
};

extern WIN32K_MANAGER* Win32kManager;

class GDI_OBJECT
{
protected:
	HGDIOBJ Handle;
	ULONG RefCount;

	static SECTION *g_GdiSection;
	static BYTE *g_GdiSharedMemory;
	static ALLOCATION_BITMAP* g_GdiSharedBitmap;

	static void InitGdiSharedMem();
	static BYTE *AllocGdiSharedMemory( size_t len, BYTE** kernel_shm = NULL );
	static void FreeGdiSharedMemory( BYTE* ptr );
protected:
	GDI_OBJECT();
public:
	HGDIOBJ GetHandle()
	{
		return Handle;
	}
	virtual ~GDI_OBJECT() {};
	virtual BOOL Release();
	void Select()
	{
		RefCount++;
	}
	void Deselect()
	{
		RefCount--;
	}
	static HGDIOBJ Alloc( BOOL stock, ULONG type );
	BYTE *GetSharedMem() const;
	template<typename T> static T* KernelToUser( T* kernel_ptr )
	{
		ULONG ofs = (BYTE*) kernel_ptr - (BYTE*) g_GdiSharedMemory;
		return (T*) (Current->Process->Win32kInfo->DcSharedMem + ofs);
	}
	template<typename T> static T* UserToKernel( T* user_ptr )
	{
		ULONG ofs = (BYTE*) user_ptr - (BYTE*) Current->Process->Win32kInfo->DcSharedMem;
		return (T*) (g_GdiSharedMemory + ofs);
	}
	BYTE *GetUserSharedMem() const;
};

struct StretchDiBitsArgs
{
	int DestX, DestY, DestWidth, DestHeight;
	int SrcX, SrcY, SrcWidth, SrcHeight;
	const VOID *Bits;
	BITMAPINFOHEADER *Info;
	UINT Usage;
	DWORD Rop;
	RGBQUAD* Colors;
};

class BRUSH : public GDI_OBJECT
{
	ULONG Style;
	COLORREF Color;
	ULONG Hatch;
public:
	BRUSH( UINT style, COLORREF color, ULONG hatch );
	static HANDLE Alloc( UINT style, COLORREF color, ULONG hatch, BOOL stock = FALSE );
	COLORREF GetColor()
	{
		return Color;
	}
};

class PEN : public GDI_OBJECT
{
	ULONG Style;
	ULONG Width;
	COLORREF Color;
public:
	PEN( UINT style, UINT width, COLORREF color );
	static HANDLE Alloc( UINT style, UINT width, COLORREF color, BOOL stock = FALSE );
	COLORREF GetColor()
	{
		return Color;
	}
	ULONG GetWidth()
	{
		return Width;
	}
};

class CBITMAP : public GDI_OBJECT
{
	friend CBITMAP* AllocBitmap( int width, int height, int depth );
	static const int MagicVal = 0xbb11aa22;
	int Magic;
protected:
	unsigned char *Bits;
	int Width;
	int Height;
	int Planes;
	int Bpp;
protected:
	void Dump();
	virtual void Lock();
	virtual void Unlock();
public:
	CBITMAP( int _width, int _height, int _planes, int _bpp );
	virtual ~CBITMAP();
	ULONG BitmapSize();
	int GetWidth()
	{
		return Width;
	}
	int GetHeight()
	{
		return Height;
	}
	//int get_planes() {return planes;}
	ULONG GetRowsize();
	virtual COLORREF GetPixel( int x, int y ) = 0;
	virtual BOOL SetPixel( INT x, INT y, COLORREF color );
	bool IsValid() const
	{
		return Magic == MagicVal;
	}
	NTSTATUS CopyPixels( void* pixels );
	virtual BOOL BitBlt( INT xDest, INT yDest, INT cx, INT cy,
						 CBITMAP *src, INT xSrc, INT ySrc, ULONG rop );
	virtual BOOL Rectangle(INT left, INT top, INT right, INT bottom, BRUSH* brush);
	virtual BOOL Line( INT x1, INT y1, INT x2, INT y2, PEN *pen );
protected:
	BOOL PenDot( INT x, INT y, PEN *pen );
	virtual BOOL SetPixelL( INT x, INT y, COLORREF color );
	virtual void DrawHLine(INT left, INT y, INT right, COLORREF color);
	virtual void DrawVLine(INT x, INT top, INT bottom, COLORREF color);
	virtual BOOL LineBresenham( INT x0, INT y0, INT x1, INT y1, PEN *pen );
	virtual BOOL LineWide( INT x0, INT y0, INT x1, INT y1, PEN *pen );
	static INT LineError(INT x0, INT y0, INT x1, INT y1, INT x, INT y);
};

template<const int DEPTH>
class BitmapImpl : public CBITMAP
{
public:
	BitmapImpl( int _width, int _height );
	virtual ~BitmapImpl();
	virtual COLORREF GetPixel( int x, int y );
	//virtual BOOL SetPixel( INT x, INT y, COLORREF color );
};

template<const int DEPTH>
BitmapImpl<DEPTH>::BitmapImpl( int _width, int _height ) :
	CBITMAP( _width, _height, 1, DEPTH )
{
}

template<const int DEPTH>
BitmapImpl<DEPTH>::~BitmapImpl()
{
}

class DcState
{
public:
	DcState *Next;
	RECT BoundsRect;
};

class DEVICE_CONTEXT : public GDI_OBJECT
{
	CBITMAP* SelectedBitmap;
	RECT BoundsRect;
	DcState *SavedDc;
	INT SaveLevel;
public:
	static const ULONG MaxDeviceContexts = 0x100;
	static const ULONG DcSize = 0x100;

public:
	DEVICE_CONTEXT();
	GDI_DEVICE_CONTEXT_SHARED* GetDcSharedMem() const;
	virtual BOOL Release();
	virtual BRUSH* GetSelectedBrush();
	virtual CBITMAP* GetBitmap();
	virtual PEN* GetSelectedPen();
	POINT& GetCurrentPenPos();
	POINT& GetWindowOffset();
	void SetBoundsRect( RECT& r )
	{
		BoundsRect = r;
	}
	RECT& GetBoundsRect()
	{
		return BoundsRect;
	}
	int SaveDC();
	BOOL RestoreDC( int level );
	virtual BOOL SetPixel( INT x, INT y, COLORREF color );
	virtual BOOL Rectangle( INT x, INT y, INT width, INT height );
	virtual BOOL ExtTextOut( INT x, INT y, UINT options,
							 LPRECT rect, UNICODE_STRING& text );
	virtual HANDLE SelectBitmap( CBITMAP *bitmap );
	virtual BOOL BitBlt( INT xDest, INT yDest, INT cx, INT cy,
						 DEVICE_CONTEXT* src, INT xSrc, INT ySrc, ULONG rop );
	virtual COLORREF GetPixel( INT x, INT y );
	virtual BOOL PolypatBlt( ULONG Rop, PRECT rect );
	virtual int GetCaps( int index ) = 0;
	virtual BOOL StretchDiBits( StretchDiBitsArgs& args );
	virtual BOOL LineTo( INT xpos, INT ypos );
	virtual BOOL MoveTo( INT xpos, INT ypos, POINT& pt );
};

class MEMORY_DEVICE_CONTEXT : public DEVICE_CONTEXT
{
public:
	MEMORY_DEVICE_CONTEXT();
	virtual int GetCaps( int index );
};

class WINDOW;

class WINDOW;
extern WINDOW* ActiveWindow;
void FreeUser32Handles( PROCESS *p );
HGDIOBJ AllocGdiHandle( BOOL stock, ULONG type, void *user_info, GDI_OBJECT* obj );
HGDIOBJ AllocGdiObject( BOOL stock, ULONG type );
GDI_HANDLE_TABLE_ENTRY *GetHandleTableEntry(HGDIOBJ handle);
BOOLEAN DoGdiInit();
CBITMAP* BitmapFromHandle( HANDLE handle );
CBITMAP* AllocBitmap( int width, int height, int depth );

#endif // __WIN32K_MANAGER__
