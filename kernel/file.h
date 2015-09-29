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

class COMPLETION_PORT : public sync_object_t
{
public:
	virtual ~COMPLETION_PORT() = 0;
	virtual BOOLEAN is_signalled( void ) = 0;
	virtual BOOLEAN satisfy( void ) = 0;
	virtual void set(ULONG key, ULONG value, NTSTATUS status, ULONG info) = 0;
	virtual NTSTATUS remove(ULONG& key, ULONG& value, NTSTATUS& status, ULONG& info, PLARGE_INTEGER timeout) = 0;
	virtual bool access_allowed( ACCESS_MASK required, ACCESS_MASK handle ) = 0;
};

void check_completions( void );

class IO_OBJECT : virtual public OBJECT
{
	COMPLETION_PORT *completion_port;
	ULONG completion_key;
public:
	IO_OBJECT();
	virtual NTSTATUS read( PVOID buffer, ULONG length, ULONG *read ) = 0;
	virtual NTSTATUS write( PVOID buffer, ULONG length, ULONG *written ) = 0;
	void set_completion_port( COMPLETION_PORT *port, ULONG key );
	virtual NTSTATUS set_position( LARGE_INTEGER& ofs );
	virtual NTSTATUS fs_control( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	virtual NTSTATUS set_pipe_info( FILE_PIPE_INFORMATION& pipe_info );
};

class CFILE : public IO_OBJECT
{
	int fd;
public:
	CFILE( int fd );
	~CFILE();
	virtual NTSTATUS query_information( FILE_STANDARD_INFORMATION& std_info );
	virtual NTSTATUS read( PVOID Buffer, ULONG Length, ULONG *read );
	virtual NTSTATUS write( PVOID Buffer, ULONG Length, ULONG *written );
	virtual NTSTATUS query_information( FILE_BASIC_INFORMATION& info );
	virtual NTSTATUS query_information( FILE_ATTRIBUTE_TAG_INFORMATION& info );
	virtual NTSTATUS set_position( LARGE_INTEGER& ofs );
	virtual NTSTATUS remove();
	int get_fd();
};

NTSTATUS open_file( CFILE *&file, UNICODE_STRING& us );
void check_completions( void );
void init_drives();

#endif // __NTNATIVE_FILE_H__
