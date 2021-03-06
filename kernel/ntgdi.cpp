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
#include "section.h"
#include "debug.h"
#include "win32mgr.h"
#include "sdl.h"
#include "null_display.h"
#include "win.h"
#include "queue.h"
#include "alloc_bitmap.h"

DEFAULT_DEBUG_CHANNEL(ntgdi);

extern SECTION *gdi_ht_section;
extern void *GdiHandleTable;
extern gdishm_tracer GdishmTrace;
extern NTGDISHM_TRACER ntgdishm_trace;


WIN32K_MANAGER* (*Win32kManagerCreate)();

struct graphics_driver_list
{
	const char *name;
	WIN32K_MANAGER* (*create)();
};

struct graphics_driver_list graphics_drivers[] =
{
	{ "sdl", &InitSdlWin32kManager, },
	{ "null", &InitNullWin32kManager, },
	{ NULL, NULL, },
};

bool SetGraphicsDriver( const char *driver )
{
	int i;

	for (i=0; graphics_drivers[i].name; i++)
	{
		if (!strcmp(graphics_drivers[i].name, driver))
		{
			Win32kManagerCreate = graphics_drivers[i].create;
			return true;
		}
	}

	return false;
}

void ListGraphicsDrivers()
{
	int i;

	for (i=0; graphics_drivers[i].name; i++)
		printf("%s ", graphics_drivers[i].name);
}

WIN32K_MANAGER *Win32kManager;

BOOLEAN NTAPI NtGdiInit()
{
	return DoGdiInit();
}

WIN32K_MANAGER::WIN32K_MANAGER()
{
	memset( KeyState, 0, sizeof KeyState );

	FT_Error r = FT_Init_FreeType( &Ftlib );
	if (r)
		throw;
}

WIN32K_MANAGER::~WIN32K_MANAGER()
{
	FT_Done_FreeType( Ftlib );
}

WIN32K_INFO::WIN32K_INFO() :
	DcSharedMem( 0 ),
	UserSharedMem( 0 ),
	UserHandles( 0 )
{
	memset( &StockObject, 0, sizeof StockObject );
}

WIN32K_INFO::~WIN32K_INFO()
{
}

WIN32K_INFO *WIN32K_MANAGER::AllocWin32kInfo()
{
	return new WIN32K_INFO;
}

void WIN32K_MANAGER::SendInput(INPUT* input)
{
	THREAD_MESSAGE_QUEUE *queue = 0;
	ULONG pos;

	if (ActiveWindow)
	{
		THREAD *t = ActiveWindow->GetWinThread();
		assert(t != NULL);
		queue = t->Queue;
	}

	TRACE("active window = %p\n", ActiveWindow);

	// keyboard activity
	switch (input->type)
	{
	case INPUT_KEYBOARD:
		// check for dud keycodes
		assert (input->ki.wVk <= 254);

		if (input->ki.dwFlags & KEYEVENTF_KEYUP)
		{
			KeyState[input->ki.wVk] = 0;
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_KEYUP, input->ki.wVk, 0 );
		}
		else
		{
			KeyState[input->ki.wVk] = 0x8000;
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_KEYDOWN, input->ki.wVk, 0 );
		}

		break;

	case INPUT_MOUSE:
		// FIXME: need to send a WM_NCHITTEST to figure out whether to send NC messages or not
		pos = MAKELPARAM(input->mi.dx, input->mi.dy);
		if (input->mi.dwFlags & MOUSEEVENTF_LEFTDOWN)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_LBUTTONDOWN, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_LEFTUP)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_LBUTTONUP, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_RIGHTDOWN)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_RBUTTONDOWN, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_RIGHTUP)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_RBUTTONUP, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_MIDDLEDOWN)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_MBUTTONDOWN, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_MIDDLEUP)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_MBUTTONUP, 0, pos );
		}

		if (input->mi.dwFlags & MOUSEEVENTF_MOVE)
		{
			if (queue)
				queue->PostMessage( ActiveWindow->handle, WM_MOUSEMOVE, 0, pos );
		}

		break;
	default:
		FIXME("unknown input %ld\n", input->type);
	}

}

ULONG WIN32K_MANAGER::GetAsyncKeyState( ULONG Key )
{
	if (Key > 254)
		return 0;
	return KeyState[ Key ];
}

void NtGdiFini()
{
	if (Win32kManager)
		Win32kManager->Fini();
}

NTSTATUS Win32kProcessInit(PROCESS *process)
{
	NTSTATUS r;

	if (process->Win32kInfo)
		return STATUS_SUCCESS;

	TRACE("\n");

	if (!Win32kManager)
	{
		if (Win32kManagerCreate)
			Win32kManager = Win32kManagerCreate();
		else
		{
			for (int i=0; graphics_drivers[i].name && !Win32kManager; i++)
				Win32kManager = graphics_drivers[i].create();
		}
	}

	if (!Win32kManager)
		Die("failed to allocate graphics driver\n");

	process->Win32kInfo = Win32kManager->AllocWin32kInfo();

	PPEB ppeb = (PPEB) process->PebSection->GetKernelAddress();

	// only do this once per process
	if (ppeb->GdiSharedHandleTable)
		return TRUE;

	if (!GdiHandleTable)
	{
		LARGE_INTEGER sz;
		sz.QuadPart = GDI_SHARED_HANDLE_TABLE_SIZE;
		r = CreateSection( &gdi_ht_section, NULL, &sz, SEC_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;

		GdiHandleTable = (BYTE*) gdi_ht_section->GetKernelAddress();
	}

	// read/write for the kernel and read only for processes
	BYTE *p = GDI_SHARED_HANDLE_TABLE_ADDRESS;

	// unreserve memory so mapit doesn't get a conflicting address
	process->Vm->FreeVirtualMemory( p, GDI_SHARED_HANDLE_TABLE_SIZE, MEM_FREE );

	r = gdi_ht_section->Mapit( process->Vm, p, 0, MEM_COMMIT, PAGE_READWRITE );
	if (r < STATUS_SUCCESS)
	{
		ERR("r = %08lx\n", r);
		assert(0);
		return FALSE;
	}

	ppeb->GdiSharedHandleTable = (void*) p;

	if (!Win32kManager->Init())
		Die("unable to allocate screen\n");

	process->Vm->SetTracer( p, ntgdishm_trace );

	return r;
}

NTSTATUS Win32kThreadInit(THREAD *thread)
{
	NTSTATUS r;

	if (thread->Win32kInitComplete())
		return STATUS_SUCCESS;

	r = Win32kProcessInit( thread->Process );
	if (r < STATUS_SUCCESS)
		return r;

	ULONG size = 0;
	PVOID buffer = 0;
	r = thread->DoUserCallback( NTWIN32_THREAD_INIT_CALLBACK, size, buffer );

	return r;
}

ULONG NTAPI NtGdiQueryFontAssocInfo( HANDLE hdc )
{
	return 0;
}

// returns same as AddFontResourceW
BOOLEAN NTAPI NtGdiAddFontResourceW(
	PVOID Filename,
	ULONG FilenameLength,
	ULONG u_arg3,
	ULONG u_arg4,
	PVOID p_arg5,
	ULONG u_arg6)
{
	WCHAR buf[0x100];

	FilenameLength *= 2;
	if (FilenameLength > sizeof buf)
		return FALSE;
	NTSTATUS r = CopyFromUser( buf, Filename, FilenameLength );
	if (r < STATUS_SUCCESS)
		return FALSE;
	TRACE("filename = %pws\n", buf);
	return TRUE;
}

HGDIOBJ WIN32K_MANAGER::AllocCompatibleDc()
{
	DEVICE_CONTEXT* dc = new MEMORY_DEVICE_CONTEXT;
	if (!dc)
		return NULL;
	return dc->GetHandle();
}

HGDIOBJ WIN32K_MANAGER::AllocScreenDC()
{
	DEVICE_CONTEXT* dc = AllocScreenDcPtr();
	if (!dc)
		return NULL;
	return dc->GetHandle();
}

// see SaveDC in wine/dlls/gdi32/dc.c
int DEVICE_CONTEXT::SaveDC()
{
	DcState *dcs = new DcState;
	dcs->Next = SavedDc;
	SavedDc = dcs;

	// FIXME: actually copy the state

	return ++SaveLevel;
}

// see RestoreDC in wine/dlls/gdi32/dc.c
BOOL DEVICE_CONTEXT::RestoreDC( int level )
{
	if (level == 0)
		return FALSE;

	if (abs(level) > SaveLevel)
		return FALSE;

	if (level < 0)
		level = SaveLevel + level + 1;

	BOOL success=TRUE;
	while (SaveLevel >= level)
	{
		DcState *dcs = SavedDc;
		SavedDc = dcs->Next;
		dcs->Next = 0;
		if (--SaveLevel < level)
		{
			// FIXME: actually restore the state
			//set_dc_state( hdc, hdcs );
		}
		delete dcs;
	}
	return success;
}

GDI_DEVICE_CONTEXT_SHARED* DEVICE_CONTEXT::GetDcSharedMem() const
{
	return (GDI_DEVICE_CONTEXT_SHARED*) GetSharedMem();
}

DEVICE_CONTEXT::DEVICE_CONTEXT() :
	SelectedBitmap( 0 ),
	SavedDc( 0 ),
	SaveLevel( 0 )
{
	// calculate user side pointer to the chunk
	BYTE *shm = AllocGdiSharedMemory( sizeof (GDI_DEVICE_CONTEXT_SHARED) );
	if (!shm)
		throw;

	TRACE("dc offset %08x\n", shm - g_GdiSharedMemory );
	BYTE *user_shm = GDI_OBJECT::KernelToUser( shm );

	Handle = AllocGdiHandle( FALSE, GDI_OBJECT_DC, user_shm, this );
	if (!Handle)
		throw;

	GDI_DEVICE_CONTEXT_SHARED *dcshm = GetDcSharedMem();
	dcshm->Brush = (HBRUSH) Win32kManager->GetStockObject( WHITE_BRUSH );
	dcshm->Pen = (HPEN) Win32kManager->GetStockObject( WHITE_PEN );
	dcshm->TextColor = RGB( 0, 0, 0 );
	dcshm->BackgroundColor = RGB( 255, 255, 255 );
	dcshm->CurrentPenPos.x = 0;
	dcshm->CurrentPenPos.y = 0;
}

BOOL DEVICE_CONTEXT::Release()
{
	GDI_DEVICE_CONTEXT_SHARED *shm = GetDcSharedMem();
	g_GdiSharedBitmap->Free( (unsigned char*) shm, sizeof *shm );
	GDI_OBJECT::Release();
	return TRUE;
}

HANDLE DEVICE_CONTEXT::SelectBitmap( CBITMAP *bitmap )
{
	assert( bitmap->IsValid() );
	CBITMAP* old = SelectedBitmap;
	SelectedBitmap = bitmap;
	bitmap->Select();
	if (!old)
		return NULL;
	assert( old->IsValid() );
	old->Deselect();
	return old->GetHandle();
}

CBITMAP* DEVICE_CONTEXT::GetBitmap()
{
	if (SelectedBitmap)
		assert( SelectedBitmap->IsValid() );
	return SelectedBitmap;
}

BOOL DEVICE_CONTEXT::BitBlt(
	INT xDest, INT yDest,
	INT cx, INT cy,
	DEVICE_CONTEXT *src,
	INT xSrc, INT ySrc, ULONG rop )
{
	CBITMAP* dest_bm = GetBitmap();
	if (!dest_bm)
		return FALSE;

	CBITMAP* src_bm = src->GetBitmap();
	if (!src_bm)
		return FALSE;

	// keep everything on the destination bitmap
	xDest = max( xDest, 0 );
	yDest = max( yDest, 0 );
	if ((xDest + cx) > dest_bm->GetWidth())
		cx = dest_bm->GetWidth() - xDest;
	if ((yDest + cy) > dest_bm->GetHeight())
		cy = dest_bm->GetHeight() - yDest;

	// keep everything on the source bitmap
	xSrc = max( xSrc, 0 );
	ySrc = max( ySrc, 0 );
	if ((xSrc + cx) > src_bm->GetWidth())
		cx = src_bm->GetWidth() - xSrc;
	if ((ySrc + cy) > src_bm->GetHeight())
		cy = src_bm->GetHeight() - ySrc;

	// FIXME translate coordinates
	return dest_bm->BitBlt( xDest, yDest, cx, cy, src_bm, xSrc, ySrc, rop );
}

BOOL DEVICE_CONTEXT::Rectangle(INT left, INT top, INT right, INT bottom)
{
	BRUSH *brush = GetSelectedBrush();
	if (!brush)
		return FALSE;
	CBITMAP *bm = GetBitmap();
	if (!bm)
		return FALSE;

	if (left > right)
		Swap( left, right );
	if (top > bottom)
		Swap( top, bottom );

	// clip to the size of the rectangle
	top = max( 0, top );
	left = max( 0, left );
	right = min( bm->GetWidth() - 1, right );
	bottom = min( bm->GetHeight() - 1, bottom );

	return bm->Rectangle( left, top, right, bottom, brush );
}

MEMORY_DEVICE_CONTEXT::MEMORY_DEVICE_CONTEXT()
{
}

BOOL DEVICE_CONTEXT::LineTo(INT x, INT y)
{
	CBITMAP *bm = GetBitmap();
	if (!bm)
		return FALSE;
	PEN *pen = GetSelectedPen();
	if (!pen)
		return FALSE;

	POINT& cur = GetCurrentPenPos();
	POINT& winofs = GetWindowOffset();

	bm->Line(cur.x + winofs.x, cur.y + winofs.y, x + winofs.x, y + winofs.y, pen);

	// update the position
	cur.x = x;
	cur.y = y;

	return TRUE;
}

BOOL DEVICE_CONTEXT::MoveTo(INT x, INT y, POINT& pt)
{
	POINT& cur = GetCurrentPenPos();
	pt = cur;

	// update the position
	cur.x = x;
	cur.y = y;

	return TRUE;
}

BOOL DEVICE_CONTEXT::SetPixel( INT x, INT y, COLORREF color )
{
	CBITMAP* bitmap = GetBitmap();
	if (bitmap)
		return bitmap->SetPixel( x, y, color );
	return TRUE;
}

COLORREF DEVICE_CONTEXT::GetPixel( INT x, INT y )
{
	CBITMAP* bitmap = GetBitmap();
	if (bitmap)
		return bitmap->GetPixel( x, y );
	return 0;
}

/* FIXME: derive the freetype bitmap from a CBITMAP and use bitblt here */
static COLORREF FreetypeGetPixel( int x, int y, FT_Bitmap* ftbm )
{
	int bytes_per_row;
	int val;
	switch (ftbm->pixel_mode)
	{
	case FT_PIXEL_MODE_MONO:
		bytes_per_row = ftbm->pitch;
		val = (ftbm->buffer[bytes_per_row*y + (x>>3)] << (x&7)) & 0x80;
		return val ? RGB( 255, 255, 255 ) : RGB( 0, 0, 0 );
	default:
		FIXME("unknown freetype pixel mode %d\n", ftbm->pixel_mode);
		return 0;
	}
}

static void freetype_bitblt( CBITMAP* bm, int x, int y, FT_Bitmap* ftbm )
{
	INT bmpX, bmpY;
	INT j, i;

	TRACE("glyph is %dx%d\n", ftbm->rows, ftbm->width);
	TRACE("pixel mode is %d\n", ftbm->pixel_mode);
	TRACE("destination is %d,%d\n", x, y);
	TRACE("pitch is %d\n", ftbm->pitch);

	/* loop for every pixel in bitmap */
	for (bmpY = 0, i = y; bmpY < ftbm->rows; bmpY++, i++)
	{
		for (bmpX = 0, j = x; bmpX < ftbm->width; bmpX++, j++)
		{
			// FIXME: assumes text color is black
			COLORREF color = FreetypeGetPixel( bmpX, bmpY, ftbm );
			bm->SetPixel( j, i, color );
		}
	}
}

FT_Face WIN32K_MANAGER::GetFace()
{
	static char vgasys[] = "drive/winnt/system32/vgasys.fon";

	if (!Face)
	{
		FT_Open_Args args;
		memset( &args, 0, sizeof args );
		args.flags = FT_OPEN_PATHNAME;
		args.pathname = vgasys;

		FT_Error r = FT_Open_Face( Ftlib, &args, 0, &Face );
		if (r)
			Face = NULL;
	}
	return Face;
}

BOOL DEVICE_CONTEXT::ExtTextOut( INT x, INT y, UINT options,
								   LPRECT rect, UNICODE_STRING& text )
{
	TRACE("text: %pus\n", &text);

	CBITMAP *bitmap = GetBitmap();
	if (!bitmap)
		return FALSE;

	FT_Face face = Win32kManager->GetFace();
	//if (SDL_MUSTLOCK(screen) && SDL_LockSurface(screen) < 0)
		//return FALSE;

	int dx = 0, dy = 0;
	for (int i=0; i<text.Length/2; i++)
	{
		WCHAR ch = text.Buffer[i];
		FT_UInt glyph_index = FT_Get_Char_Index( face, ch );

		FT_Error r = FT_Load_Glyph( face, glyph_index, FT_LOAD_DEFAULT );
		if (r)
			continue;

		FT_Glyph glyph;
		r = FT_Get_Glyph( face->glyph, &glyph );
		if (r)
			continue;

		if (glyph->format != FT_GLYPH_FORMAT_BITMAP )
			continue;

		FT_BitmapGlyph ftbmg = (FT_BitmapGlyph) glyph;
		freetype_bitblt( bitmap, x+dx+ftbmg->left, y+dy+ftbmg->top, &ftbmg->bitmap );

		dx += ftbmg->bitmap.width;
		dy += 0;

		FT_Done_Glyph( glyph );
	}

	//if ( SDL_MUSTLOCK(screen) )
		//SDL_UnlockSurface(screen);

	//SDL_UpdateRect( screen, x, y, x+dx, y+dy);

	return TRUE;
}

BOOL DEVICE_CONTEXT::PolypatBlt( ULONG Rop, PRECT rect )
{
	CBITMAP *bm = GetBitmap();
	if (!bm)
		return FALSE;

	BRUSH black(0,0,0);

	LONG &left = rect->left;
	LONG &right = rect->right;
	LONG &top = rect->top;
	LONG &bottom = rect->bottom;

	if (left > right)
		Swap( left, right );
	if (top > bottom)
		Swap( top, bottom );

	// clip to the size of the rectangle
	top = max( 0, top );
	left = max( 0, left );
	right = min( bm->GetWidth() - 1, right );
	bottom = min( bm->GetHeight() - 1, bottom );

	return bm->Rectangle( left, top, right, bottom, &black );
}

int MEMORY_DEVICE_CONTEXT::GetCaps( int index )
{
	FIXME("%d\n", index );
	return 0;
}

BRUSH::BRUSH( UINT _style, COLORREF _color, ULONG _hatch ) :
	Style( _style ),
	Color( _color ),
	Hatch( _hatch )
{
}

HANDLE BRUSH::Alloc( UINT style, COLORREF color, ULONG hatch, BOOL stock )
{
	BRUSH* brush = new BRUSH( style, color, hatch );
	if (!brush)
		return NULL;
	brush->Handle = AllocGdiHandle( stock, GDI_OBJECT_BRUSH, NULL, brush );
	TRACE("created brush %p with color %08lx\n", brush->Handle, color);
	return brush->Handle;
}

BRUSH* BrushFromHandle( HGDIOBJ handle )
{
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry( handle );
	if (!entry)
		return FALSE;
	if (entry->Type != GDI_OBJECT_BRUSH)
		return FALSE;
	GDI_OBJECT* obj = reinterpret_cast<GDI_OBJECT*>( entry->kernel_info );
	return static_cast<BRUSH*>( obj );
}

PEN::PEN( UINT _style, UINT _width, COLORREF _color ) :
	Style( _style ),
	Width( _width ),
	Color( _color )
{
}

HANDLE PEN::Alloc( UINT style, UINT width, COLORREF color, BOOL stock )
{
	PEN* pen = new PEN( style, width, color );
	if (!pen)
		return NULL;

	// strangeness: handle indicates pen, but it's a brush in the table
	pen->Handle = AllocGdiHandle( stock, GDI_OBJECT_PEN, NULL, pen );
	TRACE("created pen %p with color %08lx\n", pen->Handle, color);
	return pen->Handle;
}

PEN* PenFromHandle( HGDIOBJ handle )
{
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry( handle );
	if (!entry)
		return NULL;

	if (entry->Type != GDI_OBJECT_BRUSH)
		return NULL;

	GDI_OBJECT* obj = reinterpret_cast<GDI_OBJECT*>( entry->kernel_info );
	return static_cast<PEN*>( obj );
}

BRUSH* DEVICE_CONTEXT::GetSelectedBrush()
{
	GDI_DEVICE_CONTEXT_SHARED *dcshm = GetDcSharedMem();
	if (!dcshm)
		return NULL;
	return BrushFromHandle( dcshm->Brush );
}

PEN* DEVICE_CONTEXT::GetSelectedPen()
{
	GDI_DEVICE_CONTEXT_SHARED *dcshm = GetDcSharedMem();
	if (!dcshm)
		return NULL;

	return PenFromHandle( dcshm->Pen );;
}

POINT& DEVICE_CONTEXT::GetCurrentPenPos()
{
	GDI_DEVICE_CONTEXT_SHARED *dcshm = GetDcSharedMem();
	assert(dcshm != NULL);
	return dcshm->CurrentPenPos;
}

POINT& DEVICE_CONTEXT::GetWindowOffset()
{
	GDI_DEVICE_CONTEXT_SHARED *dcshm = GetDcSharedMem();
	assert(dcshm != NULL);
	return dcshm->WindowOriginOffset;
}

DEVICE_CONTEXT* dc_from_handle( HGDIOBJ handle )
{
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry( handle );
	if (!entry)
		return FALSE;
	if (entry->Type != GDI_OBJECT_DC)
		return FALSE;
	GDI_OBJECT* obj = reinterpret_cast<GDI_OBJECT*>( entry->kernel_info );
	return static_cast<DEVICE_CONTEXT*>( obj );
}

COLORREF get_di_pixel_4bpp( StretchDiBitsArgs& args, int x, int y )
{
	int bytes_per_line = ((args.Info->biWidth+3)&~3)>>1;
	int ofs = (args.Info->biHeight - y - 1) * bytes_per_line + (x>>1);

	// slow!
	BYTE pixel = 0;
	NTSTATUS r;
	r = CopyFromUser( &pixel, (BYTE*) args.Bits + ofs, 1 );
	if ( r < STATUS_SUCCESS)
	{
		ERR("copy failed\n");
		return 0;
	}

	BYTE val = (pixel >> (x&1?0:4)) & 0x0f;

	assert( val < 16);

	return RGB( args.Colors[val].rgbRed,
				args.Colors[val].rgbGreen,
				args.Colors[val].rgbBlue );
}

COLORREF get_di_pixel( StretchDiBitsArgs& args, int x, int y )
{
	switch (args.Info->biBitCount)
	{
	case 4:
		return get_di_pixel_4bpp( args, x, y );
	default:
		FIXME("%d bpp\n", args.Info->biBitCount);
	}
	return 0;
}

BOOL DEVICE_CONTEXT::StretchDiBits( StretchDiBitsArgs& args )
{
	CBITMAP* bitmap = GetBitmap();
	if (!bitmap)
		return FALSE;

	args.SrcX = max( args.SrcX, 0 );
	args.SrcY = max( args.SrcY, 0 );
	args.SrcX = min( args.SrcX, args.Info->biWidth );
	args.SrcY = min( args.SrcY, args.Info->biHeight );

	args.SrcWidth = max( args.SrcWidth, 0 );
	args.SrcHeight = max( args.SrcHeight, 0 );
	args.SrcWidth = min( args.SrcWidth, args.Info->biWidth - args.SrcX );
	args.SrcHeight = min( args.SrcHeight, args.Info->biHeight - args.SrcY );

	TRACE("w,h %ld,%ld\n", args.Info->biWidth, args.Info->biHeight);
	TRACE("bits, planes %d,%d\n", args.Info->biBitCount, args.Info->biPlanes);
	TRACE("compression %08lx\n", args.Info->biCompression);
	TRACE("size %08lx\n", args.Info->biSize);

	// copy the pixels
	COLORREF pixel;
	for (int i=0; i<args.SrcHeight; i++)
	{
		for (int j=0; j<args.SrcWidth; j++)
		{
			pixel = get_di_pixel( args, args.SrcX+j, args.SrcY+i );
			SetPixel( args.DestX+j, args.DestY+i, pixel );
		}
	}

	return TRUE;
}

BOOL WIN32K_MANAGER::ReleaseDC( HGDIOBJ handle )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;
	return dc->Release();
}

HGDIOBJ NTAPI NtGdiGetStockObject(ULONG Index)
{
	return Win32kManager->GetStockObject( Index );
}

HANDLE WIN32K_MANAGER::CreateSolidBrush( COLORREF color )
{
	return BRUSH::Alloc( BS_SOLID, color, 0 );
}

HANDLE WIN32K_MANAGER::CreatePen( UINT style, UINT width, COLORREF color )
{
	return PEN::Alloc( style, width, color );
}

HANDLE WIN32K_MANAGER::GetStockObject( ULONG Index )
{
	if (Index > STOCK_LAST)
		return 0;
	HANDLE& handle = Current->Process->Win32kInfo->StockObject[Index];
	if (handle)
		return handle;

	switch (Index)
	{
	case WHITE_BRUSH:
		handle = BRUSH::Alloc( 0, RGB(255,255,255), 0, TRUE);
		break;
	case BLACK_BRUSH:
		handle = BRUSH::Alloc( 0, RGB(0,0,0), 0, TRUE);
		break;
	case LTGRAY_BRUSH:
	case GRAY_BRUSH:
	case DKGRAY_BRUSH:
	case NULL_BRUSH: //case HOLLOW_BRUSH:
	case DC_BRUSH: // FIXME: probably per DC
		handle = AllocGdiObject( TRUE, GDI_OBJECT_BRUSH );
		break;
	case WHITE_PEN:
		handle = PEN::Alloc( PS_SOLID, 1, RGB(255, 255, 255), TRUE );
		break;
	case BLACK_PEN:
	case NULL_PEN:
	case DC_PEN: // FIXME: probably per DC
		handle = AllocGdiObject( TRUE, GDI_OBJECT_PEN );
		break;
	case OEM_FIXED_FONT:
	case ANSI_FIXED_FONT:
	case ANSI_VAR_FONT:
	case SYSTEM_FONT:
	case DEVICE_DEFAULT_FONT:
	case SYSTEM_FIXED_FONT:
	case DEFAULT_GUI_FONT:
		handle = AllocGdiObject( TRUE, GDI_OBJECT_FONT );
		break;
	case DEFAULT_PALETTE:
		handle = AllocGdiObject( TRUE, GDI_OBJECT_PALETTE );
		break;
	}
	return handle;
}

// gdi32.CreateComptabibleDC
HGDIOBJ NTAPI NtGdiCreateCompatibleDC(HGDIOBJ hdc)
{
	return Win32kManager->AllocCompatibleDc();
}

// has one more parameter than gdi32.CreateSolidBrush
HGDIOBJ NTAPI NtGdiCreateSolidBrush(COLORREF Color, ULONG u_arg2)
{
	return Win32kManager->CreateSolidBrush( Color );
}

// looks like CreateDIBitmap, with BITMAPINFO unpacked
HGDIOBJ NTAPI NtGdiCreateDIBitmapInternal(
	HDC hdc,
	ULONG Width,
	ULONG Height,
	ULONG Bpp,
	ULONG,
	PVOID,
	ULONG,
	ULONG,
	ULONG,
	ULONG,
	ULONG)
{
	CBITMAP *bm = AllocBitmap( Width, Height, Bpp );
	if (!bm)
		return NULL;
	return bm->GetHandle();
}

HGDIOBJ NTAPI NtGdiGetDCforBitmap(HGDIOBJ Bitmap)
{
	return Win32kManager->AllocScreenDC();
}

BOOLEAN NTAPI NtGdiDeleteObjectApp(HGDIOBJ Object)
{
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry(Object);
	if (!entry)
		return FALSE;
	if (entry->ProcessId != Current->Process->Id)
	{
		ERR("pirate deletion! %p\n", Object);
		return FALSE;
	}

	GDI_OBJECT *obj = reinterpret_cast<GDI_OBJECT*>( entry->kernel_info );
	assert( obj );

	return obj->Release();
}

HGDIOBJ NTAPI NtGdiSelectBitmap( HGDIOBJ hdc, HGDIOBJ hbm )
{
	DEVICE_CONTEXT* dc = dc_from_handle( hdc );
	if (!dc)
		return FALSE;

	CBITMAP* bitmap = BitmapFromHandle( hbm );
	if (!bitmap)
		return FALSE;

	assert( bitmap->IsValid() );

	return dc->SelectBitmap( bitmap );
}

HGDIOBJ NTAPI NtGdiSelectPen( HGDIOBJ hdc, HGDIOBJ hbm )
{
	FIXME("\n");
	return NULL;
}

// Info
//  1 Long font name
//  2 LOGFONTW
//  4 Full path name
BOOLEAN NTAPI NtGdiGetFontResourceInfoInternalW(
	LPWSTR Files,
	ULONG cwc,
	ULONG cFiles,
	UINT cjIn,
	PULONG BufferSize,
	PVOID Buffer,
	ULONG Info)
{
	FIXME("\n");
	return FALSE;
}

BOOLEAN NTAPI NtGdiFlush(void)
{
	FIXME("\n");
	return 0x93;
}

int NTAPI NtGdiSaveDC(HGDIOBJ hdc)
{
	DEVICE_CONTEXT* dc = dc_from_handle( hdc );
	if (!dc)
		return 0;

	return dc->SaveDC();
}

BOOLEAN NTAPI NtGdiRestoreDC( HGDIOBJ hdc, int level )
{
	DEVICE_CONTEXT* dc = dc_from_handle( hdc );
	if (!dc)
		return FALSE;

	return dc->RestoreDC( level );
}

HGDIOBJ NTAPI NtGdiGetDCObject(HGDIOBJ hdc, ULONG object_type)
{
	ERR("\n");
	return Win32kManager->AllocScreenDC();
}

// fun...
ULONG NTAPI NtGdiSetDIBitsToDeviceInternal(
	HGDIOBJ hdc, int xDest, int yDest, ULONG cx, ULONG cy,
	int xSrc, int ySrc, ULONG StartScan, ULONG ScanLines,
	PVOID Bits, PVOID bmi, ULONG Color, ULONG, ULONG, ULONG, ULONG)
{
	FIXME("\n");
	return cy;
}

ULONG NTAPI NtGdiExtGetObjectW(HGDIOBJ Object, ULONG Size, PVOID Buffer)
{
	union
	{
		BITMAP bm;
	} info;
	ULONG len = 0;

	memset( &info, 0, sizeof info );
	switch (GDI_HANDLE_GET_TYPE(Object))
	{
	case GDI_OBJECT_BITMAP:
		TRACE("GDI_OBJECT_BITMAP\n");
		len = sizeof info.bm;
		info.bm.bmType = 0;
		info.bm.bmWidth = 0x10;
		info.bm.bmHeight = 0x10;
		info.bm.bmWidthBytes = 2;
		info.bm.bmPlanes = 1;  // monocrome
		info.bm.bmBits = (PBYTE) 0xbbbb0001;
		break;
	default:
		FIXME("should return data for ?\n");
	}

	if (Size < len)
		return 0;

	NTSTATUS r = CopyToUser( Buffer, &info, len );
	if (r < STATUS_SUCCESS)
		return 0;

	return len;
}

BOOLEAN NTAPI NtGdiBitBlt(HGDIOBJ hdcDest, INT xDest, INT yDest, INT cx, INT cy, HGDIOBJ hdcSrc, INT xSrc, INT ySrc, ULONG rop, ULONG, ULONG)
{
	DEVICE_CONTEXT* dest = dc_from_handle( hdcDest );
	if (!dest)
		return FALSE;

	DEVICE_CONTEXT* src = dc_from_handle( hdcSrc );
	if (!src)
		return FALSE;

	return dest->BitBlt( xDest, yDest, cx, cy, src, xSrc, ySrc, rop );
}

HANDLE NTAPI NtGdiCreateDIBSection(
	HDC DeviceContext,
	HANDLE SectionHandle,
	ULONG Offset,
	PBITMAPINFO bmi,
	ULONG Usage,
	ULONG HeaderSize,
	ULONG Unknown,
	ULONG_PTR ColorSpace,
	PVOID Bits)
{
	return AllocGdiObject( FALSE, GDI_OBJECT_BITMAP );
}

ULONG NTAPI NtGdiSetFontEnumeration(ULONG Unknown)
{
	FIXME("\n");
	return 0;
}

HANDLE NTAPI NtGdiOpenDCW(ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,PVOID)
{
	return Win32kManager->AllocScreenDC();
}

typedef struct _font_enum_entry
{
	ULONG size;
	ULONG offset;
	ULONG fonttype;
	ENUMLOGFONTEXW elfew;
	ULONG pad1[2];
	ULONG pad2;
	ULONG flags;
	NEWTEXTMETRICEXW ntme;
	ULONG pad3[2];
} font_enum_entry;

void FillFont( font_enum_entry* fee, LPWSTR name, ULONG height, ULONG width, ULONG paf, ULONG weight, ULONG flags, ULONG charset )
{
	memset( fee, 0, sizeof *fee );
	fee->size = sizeof *fee;
	fee->fonttype = RASTER_FONTTYPE;
	fee->offset = FIELD_OFFSET( font_enum_entry, pad2 );
	fee->elfew.elfLogFont.lfHeight = height;
	fee->elfew.elfLogFont.lfWidth = width;
	fee->elfew.elfLogFont.lfWeight = weight;
	fee->elfew.elfLogFont.lfPitchAndFamily = paf;
	memcpy( fee->elfew.elfLogFont.lfFaceName, name, StrLenW(name)*2 );
	memcpy( fee->elfew.elfFullName, name, StrLenW(name)*2 );
	fee->flags = flags;

	fee->ntme.ntmTm.tmHeight = height;
	fee->ntme.ntmTm.tmAveCharWidth = width;
	fee->ntme.ntmTm.tmMaxCharWidth = width;
	fee->ntme.ntmTm.tmWeight = weight;
	fee->ntme.ntmTm.tmPitchAndFamily = paf;
	fee->ntme.ntmTm.tmCharSet = charset;
}

void FillSystem( font_enum_entry* fee )
{
	WCHAR sys[] = { 'S','y','s','t','e','m',0 };
	FillFont( fee, sys, 16, 7, FF_SWISS | VARIABLE_PITCH, FW_BOLD, 0x2080ff20, ANSI_CHARSET );
}

void FillTerminal( font_enum_entry* fee )
{
	WCHAR trm[] = { 'T','e','r','m','i','n','a','l',0 };
	FillFont( fee, trm, 12, 8, FF_MODERN | FIXED_PITCH, FW_REGULAR, 0x2020fe01, OEM_CHARSET );
}

HANDLE NTAPI NtGdiEnumFontOpen(
	HANDLE DeviceContext,
	ULONG,
	ULONG,
	ULONG,
	ULONG,
	ULONG,
	PULONG DataLength)
{
	ULONG len = sizeof (font_enum_entry)*2;
	NTSTATUS r = CopyToUser( DataLength, &len, sizeof len );
	if (r < STATUS_SUCCESS)
		return 0;

	return AllocGdiObject( FALSE, 0x3f );
}

BOOLEAN NTAPI NtGdiEnumFontChunk(
	HANDLE DeviceContext,
	HANDLE FontEnumeration,
	ULONG BufferLength,
	PULONG ReturnLength,
	PVOID Buffer)
{
	font_enum_entry fee[2];
	ULONG len = sizeof fee;

	if (BufferLength < len)
		return FALSE;

	FillSystem( &fee[0] );
	FillTerminal( &fee[1] );

	NTSTATUS r = CopyToUser( Buffer, &fee, len );
	if (r < STATUS_SUCCESS)
		return FALSE;

	r = CopyToUser( ReturnLength, &len, sizeof len );
	if (r < STATUS_SUCCESS)
		return FALSE;

	return TRUE;
}

BOOLEAN NTAPI NtGdiEnumFontClose(HANDLE FontEnumeration)
{
	FIXME("\n");
	return TRUE;
}

BOOLEAN NTAPI NtGdiGetTextMetricsW(HANDLE DeviceContext, PVOID Buffer, ULONG Length)
{
	font_enum_entry fee;
	NTSTATUS r;

	FillSystem( &fee );

	if (Length < sizeof (TEXTMETRICW))
		return FALSE;

	r = CopyToUser( Buffer, &fee.ntme, sizeof (TEXTMETRICW) );
	if (r < STATUS_SUCCESS)
		return FALSE;

	return TRUE;
}

BOOLEAN NTAPI NtGdiSetIcmMode(HANDLE DeviceContext, ULONG, ULONG)
{
	FIXME("\n");
	return TRUE;
}

BOOLEAN NTAPI NtGdiComputeXformCoefficients( HANDLE DeviceContext )
{
	if (GDI_HANDLE_GET_TYPE(DeviceContext) != GDI_OBJECT_DC)
		return FALSE;

	FIXME("\n");
	return TRUE;
}

BOOLEAN NTAPI NtGdiSetPixel( HANDLE handle, INT x, INT y, COLORREF color )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;
	return dc->SetPixel( x, y, color );
}

BOOLEAN NTAPI NtGdiRectangle( HANDLE handle, INT left, INT top, INT right, INT bottom )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	return dc->Rectangle( left, top, right, bottom );
}

BOOLEAN NTAPI NtGdiExtTextOutW( HANDLE handle, INT x, INT y, UINT options,
								LPRECT rect, WCHAR* string, UINT length, INT *dx, UINT )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;
	RECT rectangle;
	NTSTATUS r;
	if (rect)
	{
		r = CopyFromUser( &rectangle, rect, sizeof *rect );
		if (r < STATUS_SUCCESS)
			return FALSE;
		rect = &rectangle;
	}

	CUNICODE_STRING text;
	r = text.CopyWStrFromUser( string, length*2 );
	if (r < STATUS_SUCCESS)
		return FALSE;

	if (dx)
		FIXME("character spacing provided but ignored\n");

	return dc->ExtTextOut( x, y, options, rect, text );
}

HANDLE NTAPI NtGdiCreateCompatibleBitmap( HANDLE DeviceContext, int width, int height )
{
	DEVICE_CONTEXT* dc = dc_from_handle( DeviceContext );
	if (!dc)
		return FALSE;

	int bpp = dc->GetCaps( BITSPIXEL );
	if (!bpp)
		return FALSE;

	CBITMAP *bm = AllocBitmap( width, height, bpp );
	return bm->GetHandle();
}

int NTAPI NtGdiGetAppClipBox( HANDLE handle, RECT* rectangle )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	NTSTATUS r = CopyToUser( rectangle, &dc->GetBoundsRect(), sizeof *rectangle );
	if (r < STATUS_SUCCESS)
		return ERROR;

	return SIMPLEREGION;
}

BOOLEAN NTAPI NtGdiPolyPatBlt( HANDLE handle, ULONG Rop, PRECT Rectangle, ULONG, ULONG)
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	// copy the rectangle
	RECT rect;
	NTSTATUS r;
	r = CopyFromUser( &rect, Rectangle, sizeof rect );
	if (r < STATUS_SUCCESS)
		return FALSE;

	return dc->PolypatBlt( Rop, &rect );
}

BOOLEAN NTAPI NtGdiMoveTo( HDC handle, int xpos, int ypos, LPPOINT pptOut)
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	POINT pt;
	BOOL ret = dc->MoveTo( xpos, ypos, pt );
	if (!ret)
		return FALSE;

	/* copy the original point back */
	if (pptOut)
	{
		NTSTATUS r = CopyToUser( pptOut, &pt );
		if (r < STATUS_SUCCESS)
			return FALSE;
	}

	return ret;
}

BOOLEAN NTAPI NtGdiLineTo( HDC handle, int xpos, int ypos )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	return dc->LineTo( xpos, ypos );
}

int NTAPI NtGdiGetDeviceCaps( HDC handle, int index )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	return dc->GetCaps( index );
}

HPEN NTAPI NtGdiCreatePen(int style, int width, COLORREF color, ULONG)
{
	return (HPEN) Win32kManager->CreatePen( style, width, color );
}

BOOLEAN NTAPI NtGdiStretchDIBitsInternal(
	HDC handle,
	int dest_x, int dest_y, int dest_width, int dest_height,
	int src_x, int src_y, int src_width, int src_height,
	const VOID *bits, const BITMAPINFO *info, UINT usage, DWORD rop,
	ULONG, ULONG, ULONG )
{
	DEVICE_CONTEXT* dc = dc_from_handle( handle );
	if (!dc)
		return FALSE;

	BITMAPINFOHEADER bmi;
	NTSTATUS r;
	RGBQUAD colors[0x100];

	r = CopyFromUser( &bmi, &info->bmiHeader );
	if (r < STATUS_SUCCESS)
		return FALSE;

	StretchDiBitsArgs args;
	args.DestX = dest_x;
	args.DestY = dest_y;
	args.DestWidth = dest_width;
	args.DestHeight = dest_height;
	args.SrcX = src_x;
	args.SrcY = src_y;
	args.SrcWidth = src_width;
	args.SrcHeight = src_height;
	args.Bits = bits;
	args.Info = &bmi;
	args.Usage = usage;
	args.Rop = rop;

	if (bmi.biBitCount <= 8)
	{
		TRACE("copying %d colors\n",  bmi.biBitCount);
		r = CopyFromUser( colors, &info->bmiColors, (1 << bmi.biBitCount) * sizeof (RGBQUAD));
		if (r < STATUS_SUCCESS)
			return FALSE;
		args.Colors = colors;
	}
	else
		args.Colors = NULL;

	return dc->StretchDiBits( args );
}

BOOLEAN NTAPI NtGdiScaleViewportExtEx(HDC handle, int xnum, int ynum,
									  int xdiv, int ydiv, PSIZE pSize)
{
	FIXME("\n");
	return FALSE;
}

BOOLEAN NTAPI NtGdiScaleWindowExtEx(HDC handle, int xnum, int ynum,
									int xdiv, int ydiv, PSIZE pSize)
{
	FIXME("\n");
	return FALSE;
}
