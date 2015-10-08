/*
 * GDI region objects. Shamelessly ripped out from the X11 distribution
 * Thanks for the nice licence.
 *
 * Copyright 1993, 1994, 1995 Alexandre Julliard
 * Modifications and additions: Copyright 1998 Huw Davies
 *					  1999 Alex Korobka
 *                              Copyright 2009 Mike McCormack
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

/************************************************************************

Copyright (c) 1987, 1988  X Consortium

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Consortium shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from the X Consortium.


Copyright 1987, 1988 by Digital Equipment Corporation, Maynard, Massachusetts.

			All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Digital not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

************************************************************************/
/*
 * The functions in this file implement the Region abstraction, similar to one
 * used in the X11 sample server. A Region is simply an area, as the name
 * implies, and is implemented as a "y-x-banded" array of rectangles. To
 * explain: Each Region is made up of a certain number of rectangles sorted
 * by y coordinate first, and then by x coordinate.
 *
 * Furthermore, the rectangles are banded such that every rectangle with a
 * given upper-left y coordinate (y1) will have the same lower-right y
 * coordinate (y2) and vice versa. If a rectangle has scanlines in a band, it
 * will span the entire vertical distance of the band. This means that some
 * areas that could be merged into a taller rectangle will be represented as
 * several shorter rectangles to account for shorter rectangles to its left
 * or right but within its "vertical scope".
 *
 * An added constraint on the rectangles is that they must cover as much
 * horizontal area as possible. E.g. no two rectangles in a band are allowed
 * to touch.
 *
 * Whenever possible, bands will be merged together to cover a greater vertical
 * distance (and thus reduce the number of rectangles). Two bands can be merged
 * only if the bottom of one touches the top of the other and they have
 * rectangles in the same places (of the same width, of course). This maintains
 * the y-x-banding that's so nice to have...
 */


#include "config.h"

#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "ntwin32.h"
#include "debug.h"
#include "win32mgr.h"
#include "region.h"

const int region_tt::RGN_DEFAULT_RECTS = 2;

void rect_tt::clear()
{
	left = 0;
	top = 0;
	right = 0;
	bottom = 0;
}

void rect_tt::set( int l, int t, int r, int b )
{
	left = l;
	top = t;
	right = r;
	bottom = b;
}

void rect_tt::dump() const
{
	trace("%ld,%ld-%ld,%ld\n", left, top, right, bottom);
}

void rect_tt::fix()
{
	if (left > right)
		swap( left, right );
	if (top > bottom)
		swap( top, bottom );
}

BOOL rect_tt::equal( const RECT& other ) const
{
	return (left == other.left) && (right == other.right) &&
		   (top == other.top) && (bottom == other.bottom);
}

void rect_tt::offset( INT x, INT y )
{
	left += x;
	right += x;
	top += y;
	bottom += y;
}

BOOL rect_tt::overlaps( const RECT& other ) const
{
	return (right > other.left) && (left < other.right) &&
		   (bottom > other.top) && (top < other.bottom);
}

BOOL rect_tt::contains_point( int x, int y ) const
{
	return (top <= y) && (bottom > y) &&
		   (left <= x) && (right > x);
}

void rect_tt::intersect( const RECT& other )
{
	top = max( top, other.top );
	left = max( left, other.left );
	bottom = min( bottom, other.bottom );
	right = min( right, other.right );
	if (top >= bottom || left >= right)
		clear();
}

bool rect_tt::is_empty() const
{
	return (left == right || top == bottom);
}

region_tt::region_tt()
{
}

region_tt::~region_tt()
{
	FreeGdiSharedMemory( (BYTE*) rgn );
	delete[] rects;
}

void region_tt::empty_region()
{
	numRects = 0;
	rgn->extents.clear();
	rgn->type = NULLREGION;
}

region_tt* region_tt::alloc()
{
	size_t len = sizeof (gdi_region_shared_tt);
	BYTE *shm = AllocGdiSharedMemory( len );
	if (!shm)
		return NULL;
	BYTE *user_shm = kernel_to_user( shm );

	region_tt* region = new region_tt;
	if (!region)
		return NULL;
	region->handle = AllocGdiHandle( FALSE, GDI_OBJECT_REGION, user_shm, region );
	if (!region->handle)
	{
		delete region;
		return 0;
	}

	region->rgn = (gdi_region_shared_tt*) shm;
	region->empty_region();
	region->rgn->flags = 0;
	region->rgn->type = 0;
	region->maxRects = RGN_DEFAULT_RECTS;
	region->rects = new rect_tt[ region->maxRects ];

	return region;
}

bool region_tt::validate()
{
	if ((rgn->flags & 0x11) != 0x10)
		return false;
	switch (rgn->type)
	{
	case NULLREGION:
		numRects = 0;
		break;
	case SIMPLEREGION:
		numRects = 1;
		rects[0] = rgn->extents;
		break;
	//default:
		//return false;
	}
	rgn->flags &= ~0x20;
	return true;
}

region_tt* region_from_handle( HGDIOBJ handle )
{
	gdi_handle_table_entry *entry = GetHandleTableEntry( handle );
	if (!entry)
		return NULL;
	if (entry->Type != GDI_OBJECT_REGION)
		return NULL;
	region_tt* region = (region_tt*) entry->kernel_info;
	if (!region->validate())
		return NULL;
	return region;
}

INT region_tt::update_type()
{
	if (rgn->extents.is_empty())
	{
		rgn->type = NULLREGION;
		numRects = 0;
	}
	else
		rgn->type = SIMPLEREGION;
	return get_region_type();
}

void region_tt::set_rect( const RECT& rect )
{
	return set_rect( rect.left, rect.top, rect.right, rect.bottom );
}

void region_tt::set_rect( int left, int top, int right, int bottom )
{
	if ((left != right) && (top != bottom))
	{
		rgn->extents.set( left, top, right, bottom );
		rgn->extents.fix();
		numRects = 1;
		rects[0] = rgn->extents;
		update_type();
	}
	else
		empty_region();
}

INT region_tt::get_region_type() const
{
	return rgn->type;
}

INT region_tt::get_num_rects() const
{
	return numRects;
}

rect_tt* region_tt::get_rects() const
{
	return rects;
}

void region_tt::get_bounds_rect( RECT& rcBounds ) const
{
	rcBounds = rgn->extents;
}

INT region_tt::get_region_box( RECT* rect )
{
	*rect = rgn->extents;
	return get_region_type();
}

BOOL region_tt::equal( region_tt *other )
{

	if (numRects != other->numRects)
		return FALSE;

	if (numRects == 0)
		return TRUE;

	if (!rgn->extents.equal( other->rgn->extents ))
		return FALSE;

	for (ULONG i = 0; i < numRects; i++ )
		if (!rects[i].equal( other->rects[i] ))
			return FALSE;

	return TRUE;
}

INT region_tt::offset( INT x, INT y )
{
	ULONG nbox = numRects;
	rect_tt *pbox = rects;

	while (nbox--)
	{
		pbox->offset( x, y );
		pbox++;
	}
	rgn->extents.offset( x, y );
	return get_region_type();
}

BOOL region_tt::contains_point( int x, int y )
{
	if (numRects == 0)
		return FALSE;

	if (!rgn->extents.contains_point( x, y ))
		return FALSE;

	for (ULONG i = 0; i < numRects; i++)
		if (rects[i].contains_point( x, y ))
			return TRUE;

	return FALSE;
}

BOOL region_tt::overlaps_rect( const RECT& rect )
{
	if (numRects == 0)
		return FALSE;

	if (!rgn->extents.overlaps( rect ))
		return FALSE;

	for (ULONG i = 0; i < numRects; i++)
		if (rects[i].overlaps( rect ))
			return TRUE;

	return FALSE;
}

INT region_tt::intersect_rgn( region_tt *reg1, region_tt *reg2 )
{
	trace("%ld %ld\n", reg1->numRects, reg2->numRects);
	/* check for trivial reject */
	if ( !reg1->numRects || !reg2->numRects ||
		!reg1->rgn->extents.overlaps( reg2->rgn->extents ))
	{
		empty_region();
		return rgn->type;
	}

	// FIXME: implement more complicated regions
	assert(reg1->rgn->type == SIMPLEREGION);
	assert(reg2->rgn->type == SIMPLEREGION);

	rgn->extents = reg1->rgn->extents;
	rgn->extents.dump();
	rgn->extents.intersect( reg2->rgn->extents );
	rgn->extents.dump();

	return update_type();
}

INT region_tt::union_rgn( region_tt *src1, region_tt *src2 )
{
	return ERROR;
}

INT region_tt::xor_rgn( region_tt *src1, region_tt *src2 )
{
	return ERROR;
}

INT region_tt::diff_rgn( region_tt *src1, region_tt *src2 )
{
	return ERROR;
}

INT region_tt::combine( region_tt* src1, region_tt* src2, INT mode )
{
	INT (region_tt::*op)( region_tt*, region_tt* );
	switch (mode)
	{
	case RGN_AND:
		op = &region_tt::intersect_rgn;
		break;
	case RGN_OR:
		op = &region_tt::union_rgn;
		break;
	case RGN_XOR:
		op = &region_tt::xor_rgn;
		break;
	case RGN_DIFF:
		op = &region_tt::diff_rgn;
		break;
	default:
		return ERROR;
	}
	return (this->*op)( src1, src2 );
}

HRGN NTAPI NtGdiCreateRectRgn( int, int, int, int )
{
	region_tt* region = region_tt::alloc();
	if (!region)
		return 0;
	return (HRGN) region->get_handle();
}

HRGN NTAPI NtGdiCreateEllipticRgn( int left, int top, int right, int bottom )
{
	return 0;
}

int NTAPI NtGdiGetRgnBox( HRGN Region, PRECT Rect )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;

	RECT box;
	int region_type = region->get_region_box( &box );

	NTSTATUS r;
	r = CopyToUser( Rect, &box, sizeof box );
	if (r < STATUS_SUCCESS)
		return ERROR;

	return region_type;
}

int NTAPI NtGdiCombineRgn( HRGN Dest, HRGN Source1, HRGN Source2, int CombineMode )
{
	region_tt* rgn_src1 = region_from_handle( Source1 );
	if (!rgn_src1)
		return ERROR;

	region_tt* rgn_src2 = region_from_handle( Source2 );
	if (!rgn_src2)
		return ERROR;

	region_tt* rgn_dst = region_from_handle( Dest );
	if (!rgn_dst)
		return ERROR;

	return rgn_dst->combine( rgn_src1, rgn_src2, CombineMode );
}

BOOL NTAPI NtGdiEqualRgn( HRGN Source1, HRGN Source2 )
{
	region_tt* rgn1 = region_from_handle( Source1 );
	if (!rgn1)
		return ERROR;

	region_tt* rgn2 = region_from_handle( Source2 );
	if (!rgn2)
		return ERROR;

	return rgn1->equal( rgn2 );
}

int NTAPI NtGdiOffsetRgn( HRGN Region, int x, int y )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;
	return region->offset( x, y );
}

BOOL NTAPI NtGdiSetRectRgn( HRGN Region, int left, int top, int right, int bottom )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;
	region->set_rect( left, top, right, bottom );
	return TRUE;
}

ULONG NTAPI NtGdiGetRegionData( HRGN Region, ULONG Count, PRGNDATA Data )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;

	ULONG size = region->get_num_rects() * sizeof(RECT);
	if (Count < (size + sizeof(RGNDATAHEADER)) || Data == NULL)
	{
		if (Data)	/* buffer is too small, signal it by return 0 */
			return 0;
		else		/* user requested buffer size with rgndata NULL */
			return size + sizeof(RGNDATAHEADER);
	}

	RGNDATAHEADER rdh;

	rdh.dwSize = sizeof(RGNDATAHEADER);
	rdh.iType = RDH_RECTANGLES;
	rdh.nCount = region->get_num_rects();
	rdh.nRgnSize = size;
	region->get_bounds_rect( rdh.rcBound );

	NTSTATUS r;
	r = CopyToUser( Data, &rdh, sizeof rdh );
	if (r < STATUS_SUCCESS)
		return ERROR;

	r = CopyToUser( Data->Buffer, region->get_rects(), size );
	if (r < STATUS_SUCCESS)
		return ERROR;

	return size + sizeof(RGNDATAHEADER);
}

BOOLEAN NTAPI NtGdiPtInRegion( HRGN Region, int x, int y )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;

	return region->contains_point( x, y );
}

BOOLEAN NTAPI NtGdiRectInRegion( HRGN Region, const RECT *rect )
{
	region_tt* region = region_from_handle( Region );
	if (!region)
		return ERROR;

	rect_tt overlap;
	NTSTATUS r;
	r = CopyFromUser( &overlap, rect, sizeof *rect );
	if (r < STATUS_SUCCESS)
		return ERROR;

	overlap.fix();

	return region->overlaps_rect( overlap );
}
