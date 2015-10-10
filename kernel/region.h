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

#ifndef __RING3K_REGION__
#define __RING3K_REGION__

#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "win32mgr.h"

class CRECT : public RECT
{
public:
	CRECT()
	{
		Clear();
	}
	CRECT( RECT& r )
	{
		left = r.left;
		top = r.top;
		right = r.right;
		bottom = r.bottom;
	}
	void Clear();
	void Set( int left, int top, int right, int bottom );
	BOOL Equal( const RECT& other ) const;
	BOOL ContainsPoint( int x, int y ) const;
	BOOL ContainsPoint( POINT& pt ) const
	{
		return ContainsPoint( pt.x, pt.y );
	}
	BOOL Overlaps( const RECT& other ) const;
	void Offset( INT x, INT y );
	void Dump() const;
	void Fix();
	void Intersect( const RECT& other );
	bool IsEmpty() const;
};

class CGDI_REGION_SHARED
{
public:
	// must be compatible with GDI_REGION_SHARED
	ULONG Flags;
	ULONG Type;
	CRECT Extents;
};

class REGION : public GDI_OBJECT
{
	static const int RGN_DEFAULT_RECTS;
	CGDI_REGION_SHARED *Rgn;
	ULONG NumRects;
	ULONG MaxRects;
	CRECT *Rects;
public:
	REGION();
	~REGION();
	static REGION* Alloc();
	void SetRect( int left, int top, int right, int bottom );
	void SetRect( const RECT& rect );
	INT GetRegionBox( RECT* rect );
	INT GetRegionType() const;
	BOOL Equal( REGION *other );
	INT Offset( INT x, INT y );
	INT GetNumRects() const;
	CRECT* GetRects() const;
	void GetBoundsRect( RECT& rcBounds ) const;
	BOOL ContainsPoint( int x, int y );
	BOOL OverlapsRect( const RECT& overlap );
	void EmptyRegion();
	bool IsEmpty() const;
	bool Validate();
	INT UpdateType();
	INT Combine( REGION* src1, REGION* src2, INT mode );
	INT IntersectRgn( REGION *src1, REGION *src2 );
	INT UnionRgn( REGION *src1, REGION *src2 );
	INT XorRgn( REGION *src1, REGION *src2 );
	INT DiffRgn( REGION *src1, REGION *src2 );
};

#endif // __RING3K_REGION__
