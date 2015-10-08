/*
 * nt loader
 *
 * Copyright 2009 Mike McCormack
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

#include "alloc_bitmap.h"
#include <string.h>
#include <assert.h>

#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#else
#define VALGRIND_MALLOCLIKE_BLOCK( addr, sizeB, rzB, is_zeroed )
#define VALGRIND_FREELIKE_BLOCK( start, rzB )
#endif

ALLOCATION_BITMAP::ALLOCATION_BITMAP() :
	size(0),
	array_size(0),
	max_bits(0),
	bitmap(0),
	ptr(0)
{
}

void ALLOCATION_BITMAP::SetArea( void *_ptr, size_t _size )
{
	ptr = reinterpret_cast<unsigned char*>( _ptr );
	size = _size;
	array_size = size / (8 * allocation_granularity);
	max_bits = array_size * 8;
	bitmap = new unsigned char[ array_size ];
	memset( bitmap, 0, array_size );
}

size_t ALLOCATION_BITMAP::CountZeroBits( size_t start, size_t max )
{
	if (max > (max_bits - start))
		max = max_bits - start;
	size_t i = 0;
	while ( i<max && !bit_value(start + i) )
		i++;
	return i;
}

size_t ALLOCATION_BITMAP::CountOneBits( size_t start, size_t max )
{
	if (max > (max_bits - start))
		max = max_bits - start;
	size_t i = 0;
	while ( i<max && bit_value(start + i) )
		i++;
	return i;
}

void ALLOCATION_BITMAP::SetBits( size_t start, size_t count )
{
	assert( start + count < max_bits );
	for (size_t i = 0; i<count; i++ )
		set_bit( start + i );
}

void ALLOCATION_BITMAP::ClearBits( size_t start, size_t count )
{
	assert( start + count < max_bits );
	for (size_t i = 0; i<count; i++ )
		clear_bit( start + i );
}

size_t ALLOCATION_BITMAP::BitsRequired( size_t len )
{
	return (len + allocation_granularity - 1) / allocation_granularity;
}

unsigned char* ALLOCATION_BITMAP::Alloc( size_t len )
{
	assert( ptr != 0 );
	size_t i = 0;

	size_t required = BitsRequired( len + sizeof len );

	while (i < max_bits )
	{
		size_t free, used;
		free = CountZeroBits( i, required );
		assert( free <= required );
		if (free == required)
		{
			// mark as allocated
			SetBits( i, required );

			// check that we allocated the bits correctly
			assert( required == CountOneBits( i, required ) );
			size_t *ret = (size_t*) &ptr[ i * allocation_granularity ];
			*ret++ = len;
			VALGRIND_MALLOCLIKE_BLOCK( ret, len, 0, 0 );
			return (unsigned char*) ret;
		}

		i += free;
		if (i == max_bits)
			break;

		used = CountOneBits( i, max_bits - i );
		assert( used > 0 );
		i += used;
	}
	return NULL;
}

void ALLOCATION_BITMAP::Free( unsigned char *start )
{
	size_t ofs = (start - sizeof (size_t) - ptr);
	assert( ofs %allocation_granularity == 0 );
	ofs /= allocation_granularity;
	assert( ofs < max_bits );
	Free( start, ((size_t*)start)[-1]);
}

void ALLOCATION_BITMAP::Free( unsigned char *start, size_t len )
{
	assert( ptr != 0 );

	// check the pointer is within bounds
	size_t ofs = (start - sizeof len - ptr);
	assert( ofs % allocation_granularity == 0 );
	ofs /= allocation_granularity;
	assert( ofs < max_bits );
	assert( len == ((size_t*) start)[-1] );

	// assert the memory is allocated
	size_t required = BitsRequired( len + sizeof len );
	size_t n = CountOneBits( ofs, required );
	assert( required == n );

	// mark the memory as being clear
	ClearBits( ofs, required );

	VALGRIND_FREELIKE_BLOCK( start, 0 );
}

void ALLOCATION_BITMAP::GetInfo( size_t& total, size_t& used, size_t& free )
{
	size_t n;
	used = 0;
	free = 0;
	size_t i = 0;
	bool ones = false;
	while ( i<max_bits )
	{
		if (!ones)
		{
			n = CountZeroBits( i, max_bits );
			free += n;
		}
		else
		{
			n = CountOneBits( i, max_bits );
			used += n;
		}
		i += n;
		ones = !ones;
	}
	assert (free + used == max_bits );
	used *= allocation_granularity;
	free *= allocation_granularity;
	total = max_bits * allocation_granularity;
}

void ALLOCATION_BITMAP::Test()
{
	size_t test_size = 0x1000;
	size_t used, free, total;
	unsigned char *test_buffer;
	static const int num_pointers = 0x10;
	unsigned char *ptr[num_pointers];
	ALLOCATION_BITMAP *abm;
	int i;
	size_t test_alloc_sz = allocation_granularity * 0x10;

	// create a new buffer to manage
	test_buffer = new unsigned char[test_size];
	abm = new ALLOCATION_BITMAP;

	abm->SetArea( test_buffer, test_size );

	// check everything is free
	abm->GetInfo( total, used, free );
	assert( used == 0 );
	assert( free == total );

	// allocate a number of blocks
	for (i=0; i<num_pointers; i++)
		ptr[i] = abm->Alloc( test_alloc_sz );

	// check the blocks are as big as we asked for
	for (i=0; i<(num_pointers-1); i++)
		assert( (size_t)(ptr[i+1] - ptr[i]) >= test_alloc_sz );

	// check there's some used memory
	abm->GetInfo( total, used, free );
	assert( used != 0 );

	for (i=0; i<num_pointers; i++)
		abm->Free( ptr[i], test_alloc_sz );

	// check everything is free again
	abm->GetInfo( total, used, free );
	assert( used == 0 );
	assert( free == total );

	// free the memory
	delete abm;
	delete[] test_buffer;
}
