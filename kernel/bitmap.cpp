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

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "ntwin32.h"
#include "mem.h"
#include "debug.h"
#include "win32mgr.h"

template<>
COLORREF BitmapImpl<1>::GetPixel( int x, int y )
{
	ULONG row_size = GetRowsize();
	if ((Bits[row_size * y + x/8 ]>> (7 - (x%8))) & 1)
		return RGB( 255, 255, 255 );
	else
		return RGB( 0, 0, 0 );
}

template<>
COLORREF BitmapImpl<2>::GetPixel( int x, int y )
{
	assert(0);
	return RGB( 0, 0, 0 );
}

template<>
COLORREF BitmapImpl<16>::GetPixel( int x, int y )
{
	ULONG row_size = GetRowsize();
	USHORT val = *(USHORT*) &Bits[row_size * y + x*2 ];
	return RGB( (val & 0xf800) >> 8, (val & 0x07e0) >> 3, (val & 0x1f) << 3 );
}

template<>
COLORREF BitmapImpl<24>::GetPixel( int x, int y )
{
	ULONG row_size = GetRowsize();
	ULONG val = *(ULONG*) &Bits[row_size * y + x*3 ];
	return val&0xffffff;
}

CBITMAP::~CBITMAP()
{
	assert( Magic == MagicVal );
	delete Bits;
}

ULONG CBITMAP::GetRowsize()
{
	assert( Magic == MagicVal );
	ULONG row_size = (Width*Bpp)/8;
	return (row_size + 1)& ~1;
}

ULONG CBITMAP::BitmapSize()
{
	assert( Magic == MagicVal );
	return Height * GetRowsize();
}

void CBITMAP::Dump()
{
	assert( Magic == MagicVal );
	for (int j=0; j<Height; j++)
	{
		for (int i=0; i<Width; i++)
			fprintf(stderr,"%c", GetPixel(i, j)? 'X' : ' ');
		fprintf(stderr, "\n");
	}
}

CBITMAP::CBITMAP( int _width, int _height, int _planes, int _bpp ) :
	Magic( MagicVal ),
	Bits( 0 ),
	Width( _width ),
	Height( _height ),
	Planes( _planes ),
	Bpp( _bpp )
{
}

void CBITMAP::Lock()
{
}

void CBITMAP::Unlock()
{
}

COLORREF CBITMAP::GetPixel( int x, int y )
{
	assert( Magic == MagicVal );
	if (x < 0 || x >= Width)
		return 0;
	if (y < 0 || y >= Height)
		return 0;
	ULONG row_size = GetRowsize();
	switch (Bpp)
	{
	case 1:
		if ((Bits[row_size * y + x/8 ]>> (7 - (x%8))) & 1)
			return RGB( 255, 255, 255 );
		else
			return RGB( 0, 0, 0 );
	case 16:
	{
		USHORT val = *(USHORT*) &Bits[row_size * y + x*2 ];
		return RGB( (val & 0xf800) >> 8, (val & 0x07e0) >> 3, (val & 0x1f) << 3 );
	}
	default:
		trace("%d bpp not implemented\n", Bpp);
	}
	return 0;
}

BOOL CBITMAP::SetPixel( int x, int y, COLORREF color )
{
	return SetPixelL( x, y, color );
}

BOOL CBITMAP::SetPixelL( int x, int y, COLORREF color )
{
	assert( Magic == MagicVal );
	assert( Width != 0 );
	assert( Height != 0 );
	if (x < 0 || x >= Width)
		return FALSE;
	if (y < 0 || y >= Height)
		return FALSE;
	ULONG row_size = GetRowsize();
	switch (Bpp)
	{
	case 1:
		if (color == RGB( 0, 0, 0 ))
			Bits[row_size * y + x/8 ] &= ~ (1 << (7 - (x%8)));
		else if (color == RGB( 255, 255, 255 ))
			Bits[row_size * y + x/8 ] |= (1 << (7 - (x%8)));
		else
			// implement color translation
			assert(0);
		break;
	case 16:
		*((USHORT*) &Bits[row_size * y + x*2 ]) =
			((GetRValue(color)&0xf8) << 8) |
			((GetGValue(color)&0xfc) << 3) |
			((GetBValue(color)&0xf8) >> 3);
		break;
	default:
		trace("%d bpp not implemented\n", Bpp);
	}
	return TRUE;
}

NTSTATUS CBITMAP::CopyPixels( void *pixels )
{
	return CopyFromUser( Bits, pixels, BitmapSize() );
}

BOOL CBITMAP::BitBlt(
	INT xDest, INT yDest,
	INT cx, INT cy,
	CBITMAP *src,
	INT xSrc, INT ySrc, ULONG rop )
{
	trace("%d,%d %dx%d <- %d,%d\n", xDest, yDest, cx, cy, xSrc, ySrc );
	if (rop != SRCCOPY)
		trace("ROP %ld not supported\n", rop);

	// copy the pixels
	COLORREF pixel;
	for (int i=0; i<cy; i++)
	{
		for (int j=0; j<cx; j++)
		{
			pixel = src->GetPixel( xSrc+j, ySrc+i );
			SetPixelL( xDest+j, yDest+i, pixel );
		}
	}
	return TRUE;
}

void CBITMAP::DrawHLine(INT x, INT y, INT right, COLORREF color)
{
	if (x > right)
		Swap(x, right);
	for ( ; x <= right; x++)
		SetPixelL( x, y, color );
}

void CBITMAP::DrawVLine(INT x, INT y, INT bottom, COLORREF color)
{
	if (y > bottom)
		Swap(y, bottom);
	for ( ; y <= bottom; y++)
		SetPixelL( x, y, color );
}

BOOL CBITMAP::PenDot( INT x, INT y, PEN *pen )
{
	ULONG width = pen->GetWidth();
	COLORREF color = pen->GetColor();

	if (width == 1)
		return SetPixelL(y, x, color);

	// FIXME: avoid redrawing dots
	for (ULONG i=0; i<width; i++)
		for (ULONG j=0; j<width; j++)
			SetPixelL(y+i-width/2, x+j-width/2, color);

	return TRUE;
}

// http://en.wikipedia.org/wiki/Bresenham's_line_algorithm
BOOL CBITMAP::LineBresenham( INT x0, INT y0, INT x1, INT y1, PEN *pen )
{
	INT dx = x1 - x0;
	INT dy = y1 - y0;
	INT steep = (abs(dy) >= abs(dx));
	if (steep)
	{
		Swap(x0, y0);
		Swap(x1, y1);
		// recompute dx, dy after Swap
		dx = x1 - x0;
		dy = y1 - y0;
	}
	INT xstep = 1;
	if (dx < 0)
	{
		xstep = -1;
		dx = -dx;
	}
	INT ystep = 1;
	if (dy < 0)
	{
		ystep = -1;
		dy = -dy;
	}
	INT E = 2*dy - dx; //2*dy - dx
	INT y = y0;
	for (int x = x0; x != x1; x += xstep)
	{
		if (steep)
			PenDot(y, x, pen);
		else
			PenDot(x, y, pen);

		// next
		if (E > 0)
		{
			E += 2*dy - 2*dx; //E += 2*Dy - 2*dx;
			y = y + ystep;
		}
		else
		{
			E += 2*dy; //E += 2*Dy;
		}
	}
	return TRUE;
}

/* see http://mathworld.wolfram.com/Point-LineDistance2-Dimensional.html */
INT CBITMAP::LineError(INT x0, INT y0, INT x1, INT y1, INT x, INT y)
{
	INT top = (x1 - x0)*(y0 - y) - (x0 - x)*(y1 - y0);
	INT bottom = (x1 - x0)*(x1 - x0) + (y1 - y0)*(y1 - y0);
	return (top*top)/bottom;
}

BOOL CBITMAP::LineWide( INT x0, INT y0, INT x1, INT y1, PEN *pen )
{
	if (x0 > x1)
	{
		Swap(x0, x1);
		Swap(y0, y1);
	}

	int ydelta;
	if (y0 > y1)
	{
		// traverse bottom to top
		ydelta = -1;
	}
	else
	{
		// traverse top to bottom
		ydelta = 1;
	}

	trace("%d,%d-%d,%d\n", x0, y0, x1, y1);

	INT width = pen->GetWidth();
	INT color = pen->GetColor();
	INT xstart = x0;
	INT error_next_line = 0;	// starting at x0,y0 gives an error of 0
	INT limit = width*width/4;

	for (INT y=y0; y!=y1; y += ydelta)
	{
		INT x = xstart;
		INT error = error_next_line;
		error_next_line = limit*2;

		// traverse left to right
		while (error <= limit && x < x1)
		{
			SetPixelL(x, y, color);

			// update the error for the next line if it's too big at the moment
			if (error_next_line > limit)
			{
				error_next_line = LineError(x0, y0, x1, y1, x, y+ydelta);
				xstart = x;
			}

			// figure out whether x+1,y is in range
			x++;
			error = LineError(x0, y0, x1, y1, x, y);
		}
	}
	return TRUE;
}

BOOL CBITMAP::Line( INT x0, INT y0, INT x1, INT y1, PEN *pen )
{
	COLORREF color = pen->GetColor();

	//check for simple case
	if (y0 == y1)
	{
		DrawHLine(x0, y0, x1, color);
		return TRUE;
	}

	if (x0 == x1)
	{
		DrawVLine(x0, y0, y1, color);
		return TRUE;
	}

	if (pen->GetWidth() == 1)
		return LineBresenham( x0, y0, x1, y1, pen );

	return LineWide( x0, y0, x1, y1, pen );
}

BOOL CBITMAP::Rectangle(INT left, INT top, INT right, INT bottom, BRUSH* brush)
{
	COLORREF brush_val, pen_val;

	// FIXME: use correct pen color
	pen_val = RGB( 0, 0, 0 );
	brush_val = brush->GetColor();
	trace("brush color = %08lx\n", brush->GetColor());

	// top line
	DrawHLine(left, top, right, pen_val);
	top++;

	while (top < (bottom -1))
	{
		// left border drawn by pen
		SetPixelL( left, top, pen_val );

		// filled by brush
		DrawHLine(left+1, top, right-1, brush_val);

		// right border drawn by pen
		SetPixelL( right - 1, top, pen_val );

		//next line
		top++;
	}

	// bottom line
	DrawHLine(left, bottom-1, right, pen_val);
	return TRUE;
}

CBITMAP* BitmapFromHandle( HANDLE handle )
{
	gdi_handle_table_entry *entry = GetHandleTableEntry( handle );
	if (!entry)
		return FALSE;
	if (entry->Type != GDI_OBJECT_BITMAP)
		return FALSE;
	assert( entry->kernel_info );
	GDI_OBJECT* obj = reinterpret_cast<GDI_OBJECT*>( entry->kernel_info );
	return static_cast<CBITMAP*>( obj );
}

CBITMAP* AllocBitmap( int width, int height, int depth )
{
	CBITMAP *bm = NULL;
	switch (depth)
	{
	case 1:
		bm = new BitmapImpl<1>( width, height );
		break;
	case 2:
		bm = new BitmapImpl<2>( width, height );
		break;
/*
	case 4:
		bm = new BitmapImpl<4>( width, height );
		break;
	case 8:
		bm = new BitmapImpl<8>( width, height );
		break;
*/
	case 16:
		bm = new BitmapImpl<16>( width, height );
		break;
	case 24:
		bm = new BitmapImpl<24>( width, height );
		break;
	default:
		fprintf(stderr, "%d bpp not supported\n", depth);
		assert( 0 );
	}

	bm->Bits = new unsigned char [bm->BitmapSize()];
	if (!bm->Bits)
		throw;
	bm->Handle = AllocGdiHandle( FALSE, GDI_OBJECT_BITMAP, 0, bm );
	if (!bm->Handle)
		throw;

	return bm;
}

// parameters look the same as gdi32.CreateBitmap
HGDIOBJ NTAPI NtGdiCreateBitmap(int Width, int Height, UINT Planes, UINT BitsPerPixel, VOID* Pixels)
{
	// FIXME: handle negative heights
	assert(Height >=0);
	assert(Width >=0);
	CBITMAP *bm = NULL;
	bm = AllocBitmap( Width, Height, BitsPerPixel );
	if (!bm)
		return NULL;
	NTSTATUS r = bm->CopyPixels( Pixels );
	if (r < STATUS_SUCCESS)
	{
		delete bm;
		return 0;
	}
	return bm->GetHandle();
}

