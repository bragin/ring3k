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

template<typename T> static inline void swap( T& a, T& b )
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
	BYTE* dc_shared_mem;
	BYTE* user_shared_mem;
	BYTE* user_handles;
	HANDLE stock_object[STOCK_LAST + 1];
};

class brush_t;
class pen_t;
class CBITMAP;
class DEVICE_CONTEXT;

class WIN32K_MANAGER
{
	ULONG key_state[0x100];
	FT_Library ftlib;
	FT_Face face;
public:
	WIN32K_MANAGER();
	void init_stock_objects();
	HANDLE get_stock_object( ULONG Index );
	HANDLE create_solid_brush( COLORREF color );
	HANDLE create_pen( UINT style, UINT width, COLORREF color );
	virtual ~WIN32K_MANAGER();
	virtual BOOL init() = 0;
	virtual void fini() = 0;
	virtual HGDIOBJ alloc_compatible_dc();
	virtual HGDIOBJ alloc_screen_dc();
	virtual DEVICE_CONTEXT* alloc_screen_dc_ptr() = 0;
	virtual BOOL release_dc( HGDIOBJ dc );
	WIN32K_INFO* alloc_win32k_info();
	virtual void send_input( INPUT* input );
	ULONG get_async_key_state( ULONG Key );
	virtual int getcaps( int index ) = 0;
	FT_Face get_face();
};

extern WIN32K_MANAGER* win32k_manager;

class GDI_OBJECT
{
protected:
	HGDIOBJ handle;
	ULONG refcount;

	static section_t *g_gdi_section;
	static BYTE *g_gdi_shared_memory;
	static ALLOCATION_BITMAP* g_gdi_shared_bitmap;

	static void init_gdi_shared_mem();
	static BYTE *alloc_gdi_shared_memory( size_t len, BYTE** kernel_shm = NULL );
	static void free_gdi_shared_memory( BYTE* ptr );
protected:
	GDI_OBJECT();
public:
	HGDIOBJ get_handle()
	{
		return handle;
	}
	virtual ~GDI_OBJECT() {};
	virtual BOOL release();
	void select()
	{
		refcount++;
	}
	void deselect()
	{
		refcount--;
	}
	static HGDIOBJ alloc( BOOL stock, ULONG type );
	BYTE *get_shared_mem() const;
	template<typename T> static T* kernel_to_user( T* kernel_ptr )
	{
		ULONG ofs = (BYTE*) kernel_ptr - (BYTE*) g_gdi_shared_memory;
		return (T*) (current->process->win32k_info->dc_shared_mem + ofs);
	}
	template<typename T> static T* user_to_kernel( T* user_ptr )
	{
		ULONG ofs = (BYTE*) user_ptr - (BYTE*) current->process->win32k_info->dc_shared_mem;
		return (T*) (g_gdi_shared_memory + ofs);
	}
	BYTE *get_user_shared_mem() const;
};

struct stretch_di_bits_args
{
	int dest_x, dest_y, dest_width, dest_height;
	int src_x, src_y, src_width, src_height;
	const VOID *bits;
	BITMAPINFOHEADER *info;
	UINT usage;
	DWORD rop;
	RGBQUAD* colors;
};

class brush_t : public GDI_OBJECT
{
	ULONG style;
	COLORREF color;
	ULONG hatch;
public:
	brush_t( UINT style, COLORREF color, ULONG hatch );
	static HANDLE alloc( UINT style, COLORREF color, ULONG hatch, BOOL stock = FALSE );
	COLORREF get_color()
	{
		return color;
	}
};

class pen_t : public GDI_OBJECT
{
	ULONG style;
	ULONG width;
	COLORREF color;
public:
	pen_t( UINT style, UINT width, COLORREF color );
	static HANDLE alloc( UINT style, UINT width, COLORREF color, BOOL stock = FALSE );
	COLORREF get_color()
	{
		return color;
	}
	ULONG get_width()
	{
		return width;
	}
};

class CBITMAP : public GDI_OBJECT
{
	friend CBITMAP* alloc_bitmap( int width, int height, int depth );
	static const int magic_val = 0xbb11aa22;
	int magic;
protected:
	unsigned char *bits;
	int width;
	int height;
	int planes;
	int bpp;
protected:
	void dump();
	virtual void lock();
	virtual void unlock();
public:
	CBITMAP( int _width, int _height, int _planes, int _bpp );
	virtual ~CBITMAP();
	ULONG bitmap_size();
	int get_width()
	{
		return width;
	}
	int get_height()
	{
		return height;
	}
	//int get_planes() {return planes;}
	ULONG get_rowsize();
	virtual COLORREF get_pixel( int x, int y ) = 0;
	virtual BOOL set_pixel( INT x, INT y, COLORREF color );
	bool is_valid() const
	{
		return magic == magic_val;
	}
	NTSTATUS copy_pixels( void* pixels );
	virtual BOOL bitblt( INT xDest, INT yDest, INT cx, INT cy,
						 CBITMAP *src, INT xSrc, INT ySrc, ULONG rop );
	virtual BOOL rectangle(INT left, INT top, INT right, INT bottom, brush_t* brush);
	virtual BOOL line( INT x1, INT y1, INT x2, INT y2, pen_t *pen );
protected:
	BOOL pen_dot( INT x, INT y, pen_t *pen );
	virtual BOOL set_pixel_l( INT x, INT y, COLORREF color );
	virtual void draw_hline(INT left, INT y, INT right, COLORREF color);
	virtual void draw_vline(INT x, INT top, INT bottom, COLORREF color);
	virtual BOOL line_bresenham( INT x0, INT y0, INT x1, INT y1, pen_t *pen );
	virtual BOOL line_wide( INT x0, INT y0, INT x1, INT y1, pen_t *pen );
	static INT line_error(INT x0, INT y0, INT x1, INT y1, INT x, INT y);
};

template<const int DEPTH>
class bitmap_impl_t : public CBITMAP
{
public:
	bitmap_impl_t( int _width, int _height );
	virtual ~bitmap_impl_t();
	virtual COLORREF get_pixel( int x, int y );
	//virtual BOOL set_pixel( INT x, INT y, COLORREF color );
};

template<const int DEPTH>
bitmap_impl_t<DEPTH>::bitmap_impl_t( int _width, int _height ) :
	CBITMAP( _width, _height, 1, DEPTH )
{
}

template<const int DEPTH>
bitmap_impl_t<DEPTH>::~bitmap_impl_t()
{
}

class dc_state_tt
{
public:
	dc_state_tt *next;
	RECT BoundsRect;
};

class DEVICE_CONTEXT : public GDI_OBJECT
{
	CBITMAP* selected_bitmap;
	RECT BoundsRect;
	dc_state_tt *saved_dc;
	INT saveLevel;
public:
	static const ULONG max_device_contexts = 0x100;
	static const ULONG dc_size = 0x100;

public:
	DEVICE_CONTEXT();
	GDI_DEVICE_CONTEXT_SHARED* get_dc_shared_mem() const;
	virtual BOOL release();
	virtual brush_t* get_selected_brush();
	virtual CBITMAP* get_bitmap();
	virtual pen_t* get_selected_pen();
	POINT& get_current_pen_pos();
	POINT& get_window_offset();
	void set_bounds_rect( RECT& r )
	{
		BoundsRect = r;
	}
	RECT& get_bounds_rect()
	{
		return BoundsRect;
	}
	int save_dc();
	BOOL restore_dc( int level );
	virtual BOOL set_pixel( INT x, INT y, COLORREF color );
	virtual BOOL rectangle( INT x, INT y, INT width, INT height );
	virtual BOOL exttextout( INT x, INT y, UINT options,
							 LPRECT rect, UNICODE_STRING& text );
	virtual HANDLE select_bitmap( CBITMAP *bitmap );
	virtual BOOL bitblt( INT xDest, INT yDest, INT cx, INT cy,
						 DEVICE_CONTEXT* src, INT xSrc, INT ySrc, ULONG rop );
	virtual COLORREF get_pixel( INT x, INT y );
	virtual BOOL polypatblt( ULONG Rop, PRECT rect );
	virtual int getcaps( int index ) = 0;
	virtual BOOL stretch_di_bits( stretch_di_bits_args& args );
	virtual BOOL lineto( INT xpos, INT ypos );
	virtual BOOL moveto( INT xpos, INT ypos, POINT& pt );
};

class memory_device_context_t : public DEVICE_CONTEXT
{
public:
	memory_device_context_t();
	virtual int getcaps( int index );
};

class window_tt;

class window_tt;
extern window_tt* active_window;
void free_user32_handles( PROCESS *p );
HGDIOBJ alloc_gdi_handle( BOOL stock, ULONG type, void *user_info, GDI_OBJECT* obj );
HGDIOBJ alloc_gdi_object( BOOL stock, ULONG type );
gdi_handle_table_entry *get_handle_table_entry(HGDIOBJ handle);
BOOLEAN do_gdi_init();
CBITMAP* bitmap_from_handle( HANDLE handle );
CBITMAP* alloc_bitmap( int width, int height, int depth );

#endif // __WIN32K_MANAGER__
