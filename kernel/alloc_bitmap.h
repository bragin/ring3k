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

#ifndef __ALLOC_BITMAP__
#define __ALLOC_BITMAP__

#include <stddef.h>

// TODO: optimize
class ALLOCATION_BITMAP
{
	static const size_t allocation_granularity = 8;
	size_t size;
	size_t array_size;
	size_t max_bits;
	unsigned char *bitmap;
	unsigned char *ptr;
protected:
	bool bit_value( size_t n )
	{
		return bitmap[n/8] & (1 << (n%8));
	}
	void set_bit( size_t n )
	{
		bitmap[n/8] |= (1 << (n%8));
	}
	void clear_bit( size_t n )
	{
		bitmap[n/8] &= ~(1 << (n%8));
	}
	size_t CountZeroBits( size_t start, size_t max );
	size_t CountOneBits( size_t start, size_t max );
	void SetBits( size_t start, size_t count );
	void ClearBits( size_t start, size_t count );
	size_t BitsRequired( size_t len );
public:
	ALLOCATION_BITMAP();
	void SetArea( void *_ptr, size_t _size );
	unsigned char *Alloc( size_t len );
	void Free( unsigned char *start );
	void Free( unsigned char *mem, size_t len );
	void GetInfo( size_t& total, size_t& used, size_t& free );
	static void Test(); // unit test for validating the code
};

#endif // __ALLOC_BITMAP__

