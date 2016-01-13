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

DEFAULT_DEBUG_CHANNEL(region);

const int REGION::RGN_DEFAULT_RECTS = 2;

void CRECT::Clear()
{
	left = 0;
	top = 0;
	right = 0;
	bottom = 0;
}

void CRECT::Set( int l, int t, int r, int b )
{
	left = l;
	top = t;
	right = r;
	bottom = b;
}

void CRECT::Dump() const
{
	TRACE("%ld,%ld-%ld,%ld\n", left, top, right, bottom);
}

void CRECT::Fix()
{
	if (left > right)
		Swap( left, right );
	if (top > bottom)
		Swap( top, bottom );
}

BOOL CRECT::Equal( const RECT& other ) const
{
	return (left == other.left) && (right == other.right) &&
		   (top == other.top) && (bottom == other.bottom);
}

void CRECT::Offset( INT x, INT y )
{
	left += x;
	right += x;
	top += y;
	bottom += y;
}

BOOL CRECT::Overlaps( const RECT& other ) const
{
	return (right > other.left) && (left < other.right) &&
		   (bottom > other.top) && (top < other.bottom);
}

BOOL CRECT::ContainsPoint( int x, int y ) const
{
	return (top <= y) && (bottom > y) &&
		   (left <= x) && (right > x);
}

void CRECT::Intersect( const RECT& other )
{
	top = max( top, other.top );
	left = max( left, other.left );
	bottom = min( bottom, other.bottom );
	right = min( right, other.right );
	if (top >= bottom || left >= right)
		Clear();
}

bool CRECT::IsEmpty() const
{
	return (left == right || top == bottom);
}

REGION::REGION()
{
}

REGION::~REGION()
{
	FreeGdiSharedMemory( (BYTE*) Rgn );
	delete[] Rects;
}

void REGION::EmptyRegion()
{
	NumRects = 0;
	Rgn->Extents.Clear();
	Rgn->Type = NULLREGION;
}

REGION* REGION::Alloc()
{
	size_t len = sizeof (GDI_REGION_SHARED);
	BYTE *shm = AllocGdiSharedMemory( len );
	if (!shm)
		return NULL;
	BYTE *user_shm = KernelToUser( shm );

	REGION* region = new REGION;
	if (!region)
		return NULL;
	region->Handle = AllocGdiHandle( FALSE, GDI_OBJECT_REGION, user_shm, region );
	if (!region->Handle)
	{
		delete region;
		return 0;
	}

	region->Rgn = (CGDI_REGION_SHARED*) shm;
	region->EmptyRegion();
	region->Rgn->Flags = 0;
	region->Rgn->Type = 0;
	region->MaxRects = RGN_DEFAULT_RECTS;
	region->Rects = new CRECT[ region->MaxRects ];

	return region;
}

bool REGION::Validate()
{
	if ((Rgn->Flags & 0x11) != 0x10)
		return false;
	switch (Rgn->Type)
	{
	case NULLREGION:
		NumRects = 0;
		break;
	case SIMPLEREGION:
		NumRects = 1;
		Rects[0] = Rgn->Extents;
		break;
	//default:
		//return false;
	}
	Rgn->Flags &= ~0x20;
	return true;
}

REGION* RegionFromHandle( HGDIOBJ handle )
{
	gdi_handle_table_entry *entry = GetHandleTableEntry( handle );
	if (!entry)
		return NULL;
	if (entry->Type != GDI_OBJECT_REGION)
		return NULL;
	REGION* region = (REGION*) entry->kernel_info;
	if (!region->Validate())
		return NULL;
	return region;
}

INT REGION::UpdateType()
{
	if (Rgn->Extents.IsEmpty())
	{
		Rgn->Type = NULLREGION;
		NumRects = 0;
	}
	else
		Rgn->Type = SIMPLEREGION;
	return GetRegionType();
}

void REGION::SetRect( const RECT& rect )
{
	return SetRect( rect.left, rect.top, rect.right, rect.bottom );
}

void REGION::SetRect( int left, int top, int right, int bottom )
{
	if ((left != right) && (top != bottom))
	{
		Rgn->Extents.Set( left, top, right, bottom );
		Rgn->Extents.Fix();
		NumRects = 1;
		Rects[0] = Rgn->Extents;
		UpdateType();
	}
	else
		EmptyRegion();
}

INT REGION::GetRegionType() const
{
	return Rgn->Type;
}

INT REGION::GetNumRects() const
{
	return NumRects;
}

CRECT* REGION::GetRects() const
{
	return Rects;
}

void REGION::GetBoundsRect( RECT& rcBounds ) const
{
	rcBounds = Rgn->Extents;
}

INT REGION::GetRegionBox( RECT* rect )
{
	*rect = Rgn->Extents;
	return GetRegionType();
}

BOOL REGION::Equal( REGION *other )
{

	if (NumRects != other->NumRects)
		return FALSE;

	if (NumRects == 0)
		return TRUE;

	if (!Rgn->Extents.Equal( other->Rgn->Extents ))
		return FALSE;

	for (ULONG i = 0; i < NumRects; i++ )
		if (!Rects[i].Equal( other->Rects[i] ))
			return FALSE;

	return TRUE;
}

INT REGION::Offset( INT x, INT y )
{
	ULONG nbox = NumRects;
	CRECT *pbox = Rects;

	while (nbox--)
	{
		pbox->Offset( x, y );
		pbox++;
	}
	Rgn->Extents.Offset( x, y );
	return GetRegionType();
}

BOOL REGION::ContainsPoint( int x, int y )
{
	if (NumRects == 0)
		return FALSE;

	if (!Rgn->Extents.ContainsPoint( x, y ))
		return FALSE;

	for (ULONG i = 0; i < NumRects; i++)
		if (Rects[i].ContainsPoint( x, y ))
			return TRUE;

	return FALSE;
}

BOOL REGION::OverlapsRect( const RECT& rect )
{
	if (NumRects == 0)
		return FALSE;

	if (!Rgn->Extents.Overlaps( rect ))
		return FALSE;

	for (ULONG i = 0; i < NumRects; i++)
		if (Rects[i].Overlaps( rect ))
			return TRUE;

	return FALSE;
}

INT REGION::IntersectRgn( REGION *reg1, REGION *reg2 )
{
	TRACE("%ld %ld\n", reg1->NumRects, reg2->NumRects);
	/* check for trivial reject */
	if ( !reg1->NumRects || !reg2->NumRects ||
		!reg1->Rgn->Extents.Overlaps( reg2->Rgn->Extents ))
	{
		EmptyRegion();
		return Rgn->Type;
	}

	// FIXME: implement more complicated regions
	assert(reg1->Rgn->Type == SIMPLEREGION);
	assert(reg2->Rgn->Type == SIMPLEREGION);

	Rgn->Extents = reg1->Rgn->Extents;
	Rgn->Extents.Dump();
	Rgn->Extents.Intersect( reg2->Rgn->Extents );
	Rgn->Extents.Dump();

	return UpdateType();
}

INT REGION::UnionRgn( REGION *src1, REGION *src2 )
{
	return ERROR;
}

INT REGION::XorRgn( REGION *src1, REGION *src2 )
{
	return ERROR;
}

INT REGION::DiffRgn( REGION *src1, REGION *src2 )
{
	return ERROR;
}

INT REGION::Combine( REGION* src1, REGION* src2, INT mode )
{
	INT (REGION::*op)( REGION*, REGION* );
	switch (mode)
	{
	case RGN_AND:
		op = &REGION::IntersectRgn;
		break;
	case RGN_OR:
		op = &REGION::UnionRgn;
		break;
	case RGN_XOR:
		op = &REGION::XorRgn;
		break;
	case RGN_DIFF:
		op = &REGION::DiffRgn;
		break;
	default:
		return ERROR;
	}
	return (this->*op)( src1, src2 );
}

HRGN NTAPI NtGdiCreateRectRgn( int, int, int, int )
{
	REGION* region = REGION::Alloc();
	if (!region)
		return 0;
	return (HRGN) region->GetHandle();
}

HRGN NTAPI NtGdiCreateEllipticRgn( int left, int top, int right, int bottom )
{
	return 0;
}

int NTAPI NtGdiGetRgnBox( HRGN Region, PRECT Rect )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;

	RECT box;
	int region_type = region->GetRegionBox( &box );

	NTSTATUS r;
	r = CopyToUser( Rect, &box, sizeof box );
	if (r < STATUS_SUCCESS)
		return ERROR;

	return region_type;
}

int NTAPI NtGdiCombineRgn( HRGN Dest, HRGN Source1, HRGN Source2, int CombineMode )
{
	REGION* rgn_src1 = RegionFromHandle( Source1 );
	if (!rgn_src1)
		return ERROR;

	REGION* rgn_src2 = RegionFromHandle( Source2 );
	if (!rgn_src2)
		return ERROR;

	REGION* rgn_dst = RegionFromHandle( Dest );
	if (!rgn_dst)
		return ERROR;

	return rgn_dst->Combine( rgn_src1, rgn_src2, CombineMode );
}

BOOL NTAPI NtGdiEqualRgn( HRGN Source1, HRGN Source2 )
{
	REGION* rgn1 = RegionFromHandle( Source1 );
	if (!rgn1)
		return ERROR;

	REGION* rgn2 = RegionFromHandle( Source2 );
	if (!rgn2)
		return ERROR;

	return rgn1->Equal( rgn2 );
}

int NTAPI NtGdiOffsetRgn( HRGN Region, int x, int y )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;
	return region->Offset( x, y );
}

BOOL NTAPI NtGdiSetRectRgn( HRGN Region, int left, int top, int right, int bottom )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;
	region->SetRect( left, top, right, bottom );
	return TRUE;
}

ULONG NTAPI NtGdiGetRegionData( HRGN Region, ULONG Count, PRGNDATA Data )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;

	ULONG size = region->GetNumRects() * sizeof(RECT);
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
	rdh.nCount = region->GetNumRects();
	rdh.nRgnSize = size;
	region->GetBoundsRect( rdh.rcBound );

	NTSTATUS r;
	r = CopyToUser( Data, &rdh, sizeof rdh );
	if (r < STATUS_SUCCESS)
		return ERROR;

	r = CopyToUser( Data->Buffer, region->GetRects(), size );
	if (r < STATUS_SUCCESS)
		return ERROR;

	return size + sizeof(RGNDATAHEADER);
}

BOOLEAN NTAPI NtGdiPtInRegion( HRGN Region, int x, int y )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;

	return region->ContainsPoint( x, y );
}

BOOLEAN NTAPI NtGdiRectInRegion( HRGN Region, const RECT *rect )
{
	REGION* region = RegionFromHandle( Region );
	if (!region)
		return ERROR;

	CRECT overlap;
	NTSTATUS r;
	r = CopyFromUser( &overlap, rect, sizeof *rect );
	if (r < STATUS_SUCCESS)
		return ERROR;

	overlap.Fix();

	return region->OverlapsRect( overlap );
}
