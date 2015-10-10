/*
 * nt loader
 *
 * Copyright 2006-2009 Mike McCormack
 *
 * Portions based upon Wine DIB engine implementation by:
 *
 *  Copyright 2007 Jesse Allen
 *  Copyright 2008 Massimo Del Fedele
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "debug.h"
#include "win32mgr.h"
#include "ntwin32.h"
#include "sdl.h"

#if defined (HAVE_SDL) && defined (HAVE_SDL_SDL_H) || true
#include <SDL/SDL.h>

class SDL_16BPP_BITMAP : public BitmapImpl<16>
{
	SDL_Surface *Surface;
public:
	SDL_16BPP_BITMAP( SDL_Surface *s );
	void Lock();
	void Unlock();
	virtual BOOL SetPixel( INT x, INT y, COLORREF color );
	virtual COLORREF GetPixel( INT x, INT y );
	virtual BOOL BitBlt( INT xDest, INT yDest, INT cx, INT cy,
						 CBITMAP *src, INT xSrc, INT ySrc, ULONG rop );
	virtual BOOL Rectangle( INT x, INT y, INT width, INT height, BRUSH* brush );
	virtual BOOL Line( INT x1, INT y1, INT x2, INT y2, PEN *pen );
protected:
	virtual ULONG MapColorref( COLORREF color );
};

class SDL_DEVICE_CONTEXT : public DEVICE_CONTEXT
{
public:
	CBITMAP *SdlBitmap;
	window_tt *Win;
public:
	SDL_DEVICE_CONTEXT( CBITMAP *b );
	virtual CBITMAP* GetBitmap();
	virtual HANDLE SelectBitmap( CBITMAP *bitmap );
	virtual int GetCaps( int index );
};

class SDL_SLEEPER : public SLEEPER
{
	WIN32K_MANAGER *Manager;
public:
	SDL_SLEEPER( WIN32K_MANAGER* mgr );
	virtual bool CheckEvents( bool wait );
	static Uint32 TimeoutCallback( Uint32 interval, void *arg );
	bool HandleSdlEvent( SDL_Event& event );
	WORD SdlKeysumToVkey( SDLKey sym );
	ULONG GetMouseButton( Uint8 button, bool up );
};

class WIN32K_SDL : public WIN32K_MANAGER
{
protected:
	SDL_Surface *Screen;
	SDL_SLEEPER SdlSleeper;
	CBITMAP* SdlBitmap;
public:
	virtual BOOL Init();
	virtual void Fini();
	WIN32K_SDL();
	virtual DEVICE_CONTEXT* AllocScreenDcPtr();

protected:
	Uint16 MapColorref( COLORREF );
	virtual SDL_Surface* SetMode() = 0;
	virtual int GetCaps( int index );
};

WIN32K_SDL::WIN32K_SDL() :
	SdlSleeper( this )
{
}

BOOL SDL_16BPP_BITMAP::SetPixel( INT x, INT y, COLORREF color )
{
	BOOL r;
	Lock();
	r = CBITMAP::SetPixel( x, y, color );
	SDL_UpdateRect(Surface, x, y, 1, 1);
	Unlock();
	return r;
}

COLORREF SDL_16BPP_BITMAP::GetPixel( INT x, INT y )
{
	BOOL r;
	Lock();
	r = CBITMAP::GetPixel(x, y);
	Unlock();
	return r;
}

BOOL SDL_16BPP_BITMAP::Rectangle(INT left, INT top, INT right, INT bottom, BRUSH* brush )
{
	trace("sdl_16bpp_bitmap_t::rectangle\n");
	Lock();
	CBITMAP::Rectangle( left, top, right, bottom, brush );
	Unlock();
	SDL_UpdateRect( Surface, left, top, right - left, bottom - top );
	return TRUE;
}

BOOL SDL_16BPP_BITMAP::BitBlt( INT xDest, INT yDest, INT cx, INT cy, CBITMAP *src, INT xSrc, INT ySrc, ULONG rop )
{
	BOOL r;
	Lock();
	assert(cx>=0);
	assert(cy>=0);
	r = CBITMAP::BitBlt(xDest, yDest, cx, cy, src, xSrc, ySrc, rop);
	SDL_UpdateRect(Surface, xDest, yDest, xDest + cx, yDest + cy);
	Unlock();
	return r;
}

BOOL SDL_16BPP_BITMAP::Line( INT x1, INT y1, INT x2, INT y2, PEN *pen )
{
	BOOL r;
	Lock();
	r = CBITMAP::Line(x1, y1, x2, y2, pen);
	// FIXME: possible optimization when updating?
	if (x1 > x2)
		swap(x1, x2);
	if (y1 > y2)
		swap(y1, y2);
	SDL_UpdateRect(Surface, x1, y1, x2 - x1 + 1, y2 - y1 + 1);
	Unlock();
	return r;
}

SDL_SLEEPER::SDL_SLEEPER( WIN32K_MANAGER* mgr ) :
	Manager( mgr )
{
}

Uint32 SDL_SLEEPER::TimeoutCallback( Uint32 interval, void *arg )
{
	SDL_Event event;
	event.type = SDL_USEREVENT;
	event.user.code = 0;
	event.user.data1 = 0;
	event.user.data2 = 0;
	SDL_PushEvent( &event );
	return 0;
}

WORD SDL_SLEEPER::SdlKeysumToVkey( SDLKey sym )
{
	assert ( SDLK_a == 'a' );
	assert ( SDLK_1 == '1' );
	if ((sym >= 'A' && sym <= 'Z') || (sym >= '0' && sym <= '9'))
		return (WORD) sym;

	switch (sym)
	{
#define mk(k) case SDLK_##k: return VK_##k;
		mk(SPACE)
		mk(UP)
		mk(DOWN)
		mk(LEFT)
		mk(RIGHT)
		//mk(ESCAPE)
		case SDLK_ESCAPE:
			trace("escape!\n");
			return VK_ESCAPE;
#undef mk
		default:
			trace("%d unhandled\n", sym);
			return 0;
	}
}

ULONG SDL_SLEEPER::GetMouseButton( Uint8 button, bool up )
{
	switch (button)
	{
	case SDL_BUTTON_LEFT:
		return up ? MOUSEEVENTF_LEFTUP : MOUSEEVENTF_LEFTDOWN;
	case SDL_BUTTON_RIGHT:
		return up ? MOUSEEVENTF_RIGHTUP : MOUSEEVENTF_RIGHTDOWN;
	case SDL_BUTTON_MIDDLE:
		return up ? MOUSEEVENTF_MIDDLEUP : MOUSEEVENTF_MIDDLEDOWN;
	default:
		trace("unknown mouse button %d\n", button );
		return 0;
	}
}

bool SDL_SLEEPER::HandleSdlEvent( SDL_Event& event )
{
	INPUT input;

	switch (event.type)
	{
	case SDL_QUIT:
		return true;

	case SDL_KEYDOWN:
	case SDL_KEYUP:
		trace("got SDL keyboard event\n");
		input.type = INPUT_KEYBOARD;
		input.ki.time = timeout_t::get_tick_count();
		input.ki.wVk = SdlKeysumToVkey( event.key.keysym.sym );
		input.ki.wScan = event.key.keysym.scancode;
		input.ki.dwFlags = (event.type == SDL_KEYUP) ? KEYEVENTF_KEYUP : 0;
		input.ki.dwExtraInfo = 0;
		Manager->SendInput( &input );
		break;

	case SDL_MOUSEBUTTONDOWN:
	case SDL_MOUSEBUTTONUP:
		trace("got SDL mouse button event\n");
		input.type = INPUT_MOUSE;
		input.mi.dx = event.button.x;
		input.mi.dy = event.button.y;
		input.mi.mouseData = 0;
		input.mi.dwFlags = GetMouseButton( event.button.button, event.type == SDL_MOUSEBUTTONUP );
		input.mi.time = timeout_t::get_tick_count();
		input.mi.dwExtraInfo = 0;
		Manager->SendInput( &input );
		break;

	case SDL_MOUSEMOTION:
		trace("got SDL mouse motion event\n");
		input.type = INPUT_MOUSE;
		input.mi.dx = event.motion.x;
		input.mi.dy = event.motion.y;
		input.mi.mouseData = 0;
		input.mi.dwFlags = MOUSEEVENTF_MOVE;
		input.mi.time = timeout_t::get_tick_count();
		input.mi.dwExtraInfo = 0;
		Manager->SendInput( &input );
		break;
	}

	return false;
}

// wait for timers or input
// return true if we're quitting
bool SDL_SLEEPER::CheckEvents( bool wait )
{
	LARGE_INTEGER timeout;
	SDL_Event event;
	bool quit = false;

	bool timers_left = timeout_t::check_timers(timeout);

	// quit if we got an SDL_QUIT
	if (SDL_PollEvent( &event ) && HandleSdlEvent( event ))
		return true;

	// Check for a deadlock and quit.
	//  This happens if we're the only active thread,
	//  there's no more timers, nobody listening for input and we're asked to wait.
	if (!timers_left && !active_window && wait && FIBER::LastFiber())
		return true;

	// only wait if asked to
	if (!wait)
		return false;

	// wait for a timer, if there is one
	SDL_TimerID id = 0;
	Uint32 interval = 0;
	if (timers_left)
	{
		interval = GetIntTimeout( timeout );
		id = SDL_AddTimer( interval, SDL_SLEEPER::TimeoutCallback, 0 );
	}

	if (SDL_WaitEvent( &event ))
	{
		if (event.type == SDL_USEREVENT && event.user.code == 0)
		{
			// timer has expired, no need to cancel it
			id = NULL;
		}
		else
		{
			quit = HandleSdlEvent( event );
		}
	}
	else
	{
		trace("SDL_WaitEvent returned error\n");
		quit = true;
	}

	if (id != NULL)
		SDL_RemoveTimer( id );
	return quit;
}

int WIN32K_SDL::GetCaps( int index )
{
	switch (index)
	{
	case NUMCOLORS:
		return 1 << Screen->format->BitsPerPixel;
	case BITSPIXEL:
		return Screen->format->BitsPerPixel;
	default:
		trace("%d\n", index );
		return 0;
	}
}

BOOL WIN32K_SDL::Init()
{
	if ( SDL_WasInit(SDL_INIT_VIDEO) )
		return TRUE;

	if ( SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_NOPARACHUTE) < 0 )
		return FALSE;

	Screen = SetMode();

	SdlBitmap = new SDL_16BPP_BITMAP( Screen );

	// FIXME: move this to caller
	BRUSH light_blue(0, RGB(0x3b, 0x72, 0xa9), 0);
	SdlBitmap->Rectangle( 0, 0, Screen->w, Screen->h, &light_blue );

	::Sleeper = &SdlSleeper;

	return TRUE;
}

void WIN32K_SDL::Fini()
{
	if ( !SDL_WasInit(SDL_INIT_VIDEO) )
		return;
	SDL_Quit();
}

SDL_16BPP_BITMAP::SDL_16BPP_BITMAP( SDL_Surface *s ) :
	BitmapImpl<16>( s->w, s->h ),
	Surface( s )
{
	bits = reinterpret_cast<unsigned char*>( s->pixels );
}

void SDL_16BPP_BITMAP::Lock()
{
	if ( SDL_MUSTLOCK(Surface) )
		SDL_LockSurface(Surface);
}

void SDL_16BPP_BITMAP::Unlock()
{
	if ( SDL_MUSTLOCK(Surface) )
		SDL_UnlockSurface(Surface);
}

ULONG SDL_16BPP_BITMAP::MapColorref( COLORREF color )
{
	return SDL_MapRGB(Surface->format, GetRValue(color), GetGValue(color), GetBValue(color));
}

class WIN32K_SDL_16BPP : public WIN32K_SDL
{
public:
	virtual SDL_Surface* SetMode();
	Uint16 MapColorref( COLORREF color );
};

SDL_Surface* WIN32K_SDL_16BPP::SetMode()
{
	return SDL_SetVideoMode( 640, 480, 16, SDL_SWSURFACE );
}

Uint16 WIN32K_SDL_16BPP::MapColorref( COLORREF color )
{
	return SDL_MapRGB(Screen->format, GetRValue(color), GetGValue(color), GetBValue(color));
}

WIN32K_SDL_16BPP Win32kManagerSdl16bpp;

WIN32K_MANAGER* InitSdlWin32kManager()
{
	return &Win32kManagerSdl16bpp;
}

SDL_DEVICE_CONTEXT::SDL_DEVICE_CONTEXT( CBITMAP *b ) :
	SdlBitmap( b ),
	Win( 0 )
{
}

CBITMAP* SDL_DEVICE_CONTEXT::GetBitmap()
{
	return SdlBitmap;
}

HANDLE SDL_DEVICE_CONTEXT::SelectBitmap( CBITMAP *bitmap )
{
	trace("trying to change device's bitmap...\n");
	return 0;
}


int SDL_DEVICE_CONTEXT::GetCaps( int index )
{
	return Win32kManager->GetCaps( index );
}

DEVICE_CONTEXT* WIN32K_SDL::AllocScreenDcPtr()
{
	trace("allocating SDL DC sdl_bitmap = %p\n", SdlBitmap);
	return new SDL_DEVICE_CONTEXT( SdlBitmap );
}

#else

WIN32K_MANAGER* InitSdlWin32kManager()
{
	return NULL;
}

#endif

