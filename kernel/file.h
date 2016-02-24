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

#ifndef __NTNATIVE_FILE_H__
#define __NTNATIVE_FILE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "object.h"
#include "event.h"

class COMPLETION_PORT : public SYNC_OBJECT
{
public:
	virtual ~COMPLETION_PORT() = 0;
	virtual BOOLEAN IsSignalled( void ) = 0;
	virtual BOOLEAN Satisfy( void ) = 0;
	virtual void Set(ULONG key, ULONG value, NTSTATUS status, ULONG info) = 0;
	virtual NTSTATUS Remove(ULONG& key, ULONG& value, NTSTATUS& status, ULONG& info, PLARGE_INTEGER timeout) = 0;
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle ) = 0;
};

void CheckCompletions( void );

class IO_OBJECT : virtual public OBJECT
{
	COMPLETION_PORT *completion_port;
	ULONG completion_key;
public:
	IO_OBJECT();
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read ) = 0;
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written ) = 0;
	void SetCompletionPort( COMPLETION_PORT *port, ULONG key );
	virtual NTSTATUS SetPosition( LARGE_INTEGER& ofs );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	virtual NTSTATUS SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info );
};

class CFILE : public IO_OBJECT
{
	int fd;
	CUNICODE_STRING FileName;
public:
	CFILE( int fd, UNICODE_STRING *path );
	~CFILE();
	virtual NTSTATUS QueryInformation( FILE_STANDARD_INFORMATION& std_info );
	virtual NTSTATUS Read( PVOID Buffer, ULONG Length, ULONG *read );
	virtual NTSTATUS Write( PVOID Buffer, ULONG Length, ULONG *written );
	virtual NTSTATUS QueryInformation( FILE_BASIC_INFORMATION& info );
	virtual NTSTATUS QueryInformation( FILE_ATTRIBUTE_TAG_INFORMATION& info );
	virtual NTSTATUS QueryInformation( FILE_NETWORK_OPEN_INFORMATION& info );
	virtual NTSTATUS QueryInformation( FILE_POSITION_INFORMATION& info );
	virtual NTSTATUS SetPosition( LARGE_INTEGER& ofs );
	virtual NTSTATUS Remove();
	int GetFD();
	const CUNICODE_STRING &GetFileName() { return FileName; };
};

NTSTATUS OpenFile( CFILE *&file, UNICODE_STRING& us );
void CheckCompletions( void );
void InitDrives();

#endif // __NTNATIVE_FILE_H__
