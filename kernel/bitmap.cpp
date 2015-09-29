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
COLORREF bitmap_impl_t<1>::get_pixel( int x, int y )
{
	ULONG row_size = get_rowsize();
	if ((bits[row_size * y + x/8 ]>> (7 - (x%8))) & 1)
		return RGB( 255, 255, 255 );
	else
		return RGB( 0, 0, 0 );
}

template<>
COLORREF bitmap_impl_t<2>::get_pixel( int x, int y )
{
	assert(0);
	return RGB( 0, 0, 0 );
}

template<>
COLORREF bitmap_impl_t<16>::get_pixel( int x, int y )
{
	ULONG row_size = get_rowsize();
	USHORT val = *(USHORT*) &bits[row_size * y + x*2 ];
	return RGB( (val & 0xf800) >> 8, (val & 0x07e0) >> 3, (val & 0x1f) << 3 );
}

template<>
COLORREF bitmap_impl_t<24>::get_pixel( int x, int y )
{
	ULONG row_size = get_rowsize();
	ULONG val = *(ULONG*) &bits[row_size * y + x*3 ];
	return val&0xffffff;
}

CBITMAP::~CBITMAP()
{
	assert( magic == magic_val );
	delete bits;
}

ULONG CBITMAP::get_rowsize()
{
	assert( magic == magic_val );
	ULONG row_size = (width*bpp)/8;
	return (row_size + 1)& ~1;
}

ULONG CBITMAP::bitmap_size()
{
	assert( magic == magic_val );
	return height * get_rowsize();
}

void CBITMAP::dump()
{
	assert( magic == magic_val );
	for (int j=0; j<height; j++)
	{
		for (int i=0; i<width; i++)
			fprintf(stderr,"%c", get_pixel(i, j)? 'X' : ' ');
		fprintf(stderr, "\n");
	}
}

CBITMAP::CBITMAP( int _width, int _height, int _planes, int _bpp ) :
	magic( magic_val ),
	bits( 0 ),
	width( _width ),
	height( _height ),
	planes( _planes ),
	bpp( _bpp )
{
}

void CBITMAP::lock()
{
}

void CBITMAP::unlock()
{
}

COLORREF CBITMAP::get_pixel( int x, int y )
{
	assert( magic == magic_val );
	if (x < 0 || x >= width)
		return 0;
	if (y < 0 || y >= height)
		return 0;
	ULONG row_size = get_rowsize();
	switch (bpp)
	{
	case 1:
		if ((bits[row_size * y + x/8 ]>> (7 - (x%8))) & 1)
			return RGB( 255, 255, 255 );
		else
			return RGB( 0, 0, 0 );
	case 16:
	{
		USHORT val = *(USHORT*) &bits[row_size * y + x*2 ];
		return RGB( (val & 0xf800) >> 8, (val & 0x07e0) >> 3, (val & 0x1f) << 3 );
	}
	default:
		trace("%d bpp not implemented\n", bpp);
	}
	return 0;
}

BOOL CBITMAP::set_pixel( int x, int y, COLORREF color )
{
	return set_pixel_l( x, y, color );
}

BOOL CBITMAP::set_pixel_l( int x, int y, COLORREF color )
{
	assert( magic == magic_val );
	assert( width != 0 );
	assert( height != 0 );
	if (x < 0 || x >= width)
		return FALSE;
	if (y < 0 || y >= height)
		return FALSE;
	ULONG row_size = get_rowsize();
	switch (bpp)
	{
	case 1:
		if (color == RGB( 0, 0, 0 ))
			bits[row_size * y + x/8 ] &= ~ (1 << (7 - (x%8)));
		else if (color == RGB( 255, 255, 255 ))
			bits[row_size * y + x/8 ] |= (1 << (7 - (x%8)));
		else
			// implement color translation
			assert(0);
		break;
	case 16:
		*((USHORT*) &bits[row_size * y + x*2 ]) =
			((GetRValue(color)&0xf8) << 8) |
			((GetGValue(color)&0xfc) << 3) |
			((GetBValue(color)&0xf8) >> 3);
		break;
	default:
		trace("%d bpp not implemented\n", bpp);
	}
	return TRUE;
}

NTSTATUS CBITMAP::copy_pixels( void *pixels )
{
	return copy_from_user( bits, pixels, bitmap_size() );
}

BOOL CBITMAP::bitblt(
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
			pixel = src->get_pixel( xSrc+j, ySrc+i );
			set_pixel_l( xDest+j, yDest+i, pixel );
		}
	}
	return TRUE;
}

void CBITMAP::draw_hline(INT x, INT y, INT right, COLORREF color)
{
	if (x > right)
		swap(x, right);
	for ( ; x <= right; x++)
		set_pixel_l( x, y, color );
}

void CBITMAP::draw_vline(INT x, INT y, INT bottom, COLORREF color)
{
	if (y > bottom)
		swap(y, bottom);
	for ( ; y <= bottom; y++)
		set_pixel_l( x, y, color );
}

BOOL CBITMAP::pen_dot( INT x, INT y, pen_t *pen )
{
	ULONG width = pen->get_width();
	COLORREF color = pen->get_color();

	if (width == 1)
		return set_pixel_l(y, x, color);

	// FIXME: avoid redrawing dots
	for (ULONG i=0; i<width; i++)
		for (ULONG j=0; j<width; j++)
			set_pixel_l(y+i-width/2, x+j-width/2, color);

	return TRUE;
}

// http://en.wikipedia.org/wiki/Bresenham's_line_algorithm
BOOL CBITMAP::line_bresenham( INT x0, INT y0, INT x1, INT y1, pen_t *pen )
{
	INT dx = x1 - x0;
	INT dy = y1 - y0;
	INT steep = (abs(dy) >= abs(dx));
	if (steep)
	{
		swap(x0, y0);
		swap(x1, y1);
		// recompute dx, dy after swap
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
			pen_dot(y, x, pen);
		else
			pen_dot(x, y, pen);

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
INT CBITMAP::line_error(INT x0, INT y0, INT x1, INT y1, INT x, INT y)
{
	INT top = (x1 - x0)*(y0 - y) - (x0 - x)*(y1 - y0);
	INT bottom = (x1 - x0)*(x1 - x0) + (y1 - y0)*(y1 - y0);
	return (top*top)/bottom;
}

BOOL CBITMAP::line_wide( INT x0, INT y0, INT x1, INT y1, pen_t *pen )
{
	if (x0 > x1)
	{
		swap(x0, x1);
		swap(y0, y1);
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

	INT width = pen->get_width();
	INT color = pen->get_color();
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
			set_pixel_l(x, y, color);

			// update the error for the next line if it's too big at the moment
			if (error_next_line > limit)
			{
				error_next_line = line_error(x0, y0, x1, y1, x, y+ydelta);
				xstart = x;
			}

			// figure out whether x+1,y is in range
			x++;
			error = line_error(x0, y0, x1, y1, x, y);
		}
	}
	return TRUE;
}

BOOL CBITMAP::line( INT x0, INT y0, INT x1, INT y1, pen_t *pen )
{
	COLORREF color = pen->get_color();

	//check for simple case
	if (y0 == y1)
	{
		draw_hline(x0, y0, x1, color);
		return TRUE;
	}

	if (x0 == x1)
	{
		draw_vline(x0, y0, y1, color);
		return TRUE;
	}

	if (pen->get_width() == 1)
		return line_bresenham( x0, y0, x1, y1, pen );

	return line_wide( x0, y0, x1, y1, pen );
}

BOOL CBITMAP::rectangle(INT left, INT top, INT right, INT bottom, brush_t* brush)
{
	COLORREF brush_val, pen_val;

	// FIXME: use correct pen color
	pen_val = RGB( 0, 0, 0 );
	brush_val = brush->get_color();
	trace("brush color = %08lx\n", brush->get_color());

	// top line
	draw_hline(left, top, right, pen_val);
	top++;

	while (top < (bottom -1))
	{
		// left border drawn by pen
		set_pixel_l( left, top, pen_val );

		// filled by brush
		draw_hline(left+1, top, right-1, brush_val);

		// right border drawn by pen
		set_pixel_l( right - 1, top, pen_val );

		//next line
		top++;
	}

	// bottom line
	draw_hline(left, bottom-1, right, pen_val);
	return TRUE;
}

CBITMAP* bitmap_from_handle( HANDLE handle )
{
	gdi_handle_table_entry *entry = get_handle_table_entry( handle );
	if (!entry)
		return FALSE;
	if (entry->Type != GDI_OBJECT_BITMAP)
		return FALSE;
	assert( entry->kernel_info );
	gdi_object_t* obj = reinterpret_cast<gdi_object_t*>( entry->kernel_info );
	return static_cast<CBITMAP*>( obj );
}

CBITMAP* alloc_bitmap( int width, int height, int depth )
{
	CBITMAP *bm = NULL;
	switch (depth)
	{
	case 1:
		bm = new bitmap_impl_t<1>( width, height );
		break;
	case 2:
		bm = new bitmap_impl_t<2>( width, height );
		break;
/*
	case 4:
		bm = new bitmap_impl_t<4>( width, height );
		break;
	case 8:
		bm = new bitmap_impl_t<8>( width, height );
		break;
*/
	case 16:
		bm = new bitmap_impl_t<16>( width, height );
		break;
	case 24:
		bm = new bitmap_impl_t<24>( width, height );
		break;
	default:
		fprintf(stderr, "%d bpp not supported\n", depth);
		assert( 0 );
	}

	bm->bits = new unsigned char [bm->bitmap_size()];
	if (!bm->bits)
		throw;
	bm->handle = alloc_gdi_handle( FALSE, GDI_OBJECT_BITMAP, 0, bm );
	if (!bm->handle)
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
	bm = alloc_bitmap( Width, Height, BitsPerPixel );
	if (!bm)
		return NULL;
	NTSTATUS r = bm->copy_pixels( Pixels );
	if (r < STATUS_SUCCESS)
	{
		delete bm;
		return 0;
	}
	return bm->get_handle();
}

