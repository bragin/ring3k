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


#include <unistd.h>

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <sys/syscall.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"

#include "debug.h"
#include "object.h"
#include "object.inl"
#include "mem.h"
#include "ntcall.h"
#include "file.h"
#include "symlink.h"

// FIXME: use unicode tables
WCHAR Lowercase(const WCHAR ch)
{
	if (ch >= 'A' && ch <='Z')
		return ch | 0x20;
	return ch;
}

IO_OBJECT::IO_OBJECT() :
	completion_port( 0 ),
	completion_key( 0 )
{
}

void IO_OBJECT::SetCompletionPort( COMPLETION_PORT *port, ULONG key )
{
	if (completion_port)
	{
		release( completion_port );
		completion_port = 0;
	}
	completion_port = port;
	completion_key = 0;
}

NTSTATUS IO_OBJECT::SetPosition( LARGE_INTEGER& ofs )
{
	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS IO_OBJECT::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								  PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS IO_OBJECT::SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info )
{
	return STATUS_OBJECT_TYPE_MISMATCH;
}

CFILE::~CFILE()
{
	close( fd );
}

CFILE::CFILE( int f ) :
	fd( f )
{
}

class FILE_CREATE_INFO : public OPEN_INFO
{
public:
	ULONG FileAttributes;
	ULONG CreateOptions;
	ULONG CreateDisposition;
	bool created;
public:
	FILE_CREATE_INFO( ULONG _Attributes, ULONG _CreateOptions, ULONG _CreateDisposition );
	virtual NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
};

FILE_CREATE_INFO::FILE_CREATE_INFO( ULONG _Attributes, ULONG _CreateOptions, ULONG _CreateDisposition ) :
	FileAttributes( _Attributes ),
	CreateOptions( _CreateOptions ),
	CreateDisposition( _CreateDisposition ),
	created( false )
{
}

NTSTATUS FILE_CREATE_INFO::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	trace("FILE_CREATE_INFO::on_open()\n");
	if (!obj)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::Read( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	NTSTATUS r = STATUS_SUCCESS;
	ULONG ofs = 0;
	while (ofs < Length)
	{
		BYTE *p = (BYTE*)Buffer+ofs;
		size_t len = Length - ofs;

		r = Current->process->vm->GetKernelAddress( &p, &len );
		if (r < STATUS_SUCCESS)
			break;

		int ret = ::read( fd, p, len );
		if (ret < 0)
		{
			r = STATUS_IO_DEVICE_ERROR;
			break;
		}

		ofs += len;
	}

	*bytes_read = ofs;

	return r;
}

NTSTATUS CFILE::Write( PVOID Buffer, ULONG Length, ULONG *written )
{
	NTSTATUS r = STATUS_SUCCESS;
	ULONG ofs = 0;
	while (ofs< Length)
	{
		BYTE *p = (BYTE*)Buffer+ofs;
		size_t len = Length - ofs;

		NTSTATUS r = Current->process->vm->GetKernelAddress( &p, &len );
		if (r < STATUS_SUCCESS)
			break;

		int ret = ::write( fd, p, len );
		if (ret < 0)
		{
			r = STATUS_IO_DEVICE_ERROR;
			break;
		}

		ofs += len;
	}

	*written = ofs;

	return r;
}

NTSTATUS CFILE::SetPosition( LARGE_INTEGER& ofs )
{
	int ret;

	ret = lseek( fd, ofs.QuadPart, SEEK_SET );
	if (ret < 0)
	{
		trace("seek failed\n");
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::Remove()
{
	char name[40];
	char path[255];
	int r;

	// get the file's name
	sprintf( name, "/proc/self/fd/%d", GetFD() );
	r = readlink( name, path, sizeof path - 1 );
	if (r < 0)
		return STATUS_ACCESS_DENIED;
	path[r] = 0;

	// remove it
	if (0 > unlink( path ) &&
		0 > rmdir( path ))
	{
		fprintf(stderr, "Failed to delete %s\n", path);
		// FIXME: check errno
		return STATUS_ACCESS_DENIED;
	}

	return STATUS_SUCCESS;
}

class DIRECTORY_ENTRY;

typedef LIST_ANCHOR<DIRECTORY_ENTRY,0> DIRLIST;
typedef LIST_ITER<DIRECTORY_ENTRY,0> DIRLIST_ITER;
typedef LIST_ELEMENT<DIRECTORY_ENTRY> DIRLIST_ELEMENT;

class DIRECTORY_ENTRY
{
public:
	DIRLIST_ELEMENT Entry[1];
	unicode_string_t name;
	struct stat st;
};

class DIRECTORY : public CFILE
{
	int count;
	DIRECTORY_ENTRY *ptr;
	DIRLIST entries;
	unicode_string_t mask;
protected:
	void Reset();
	void AddEntry(const char *name);
	int OpenUnicodeFile( const char *unix_path, int flags, bool& created );
	int OpenUnicodeDir( const char *unix_path, int flags, bool& created );
public:
	DIRECTORY( int fd );
	~DIRECTORY();
	NTSTATUS QueryDirectoryFile();
	NTSTATUS Read( PVOID Buffer, ULONG Length, ULONG *bytes_read );
	NTSTATUS Write( PVOID Buffer, ULONG Length, ULONG *bytes_read );
	virtual NTSTATUS QueryInformation( FILE_ATTRIBUTE_TAG_INFORMATION& info );
	DIRECTORY_ENTRY* GetNext();
	bool Match(unicode_string_t &name) const;
	void ScanDir();
	bool IsFirstScan() const;
	NTSTATUS SetMask(unicode_string_t *mask);
	int GetNumEntries() const;
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	NTSTATUS OpenFile( CFILE *&file, UNICODE_STRING& path, ULONG Attributes,
						ULONG Options, ULONG CreateDisposition, bool &created, bool case_insensitive );
};

class DIRECTORY_FACTORY : public OBJECT_FACTORY
{
	int fd;
public:
	DIRECTORY_FACTORY( int _fd );
	NTSTATUS AllocObject(OBJECT** obj);
};

DIRECTORY_FACTORY::DIRECTORY_FACTORY( int _fd ) :
	fd( _fd )
{
}

NTSTATUS DIRECTORY_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new DIRECTORY( fd );
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}


DIRECTORY::DIRECTORY( int fd ) :
	CFILE(fd),
	count(-1),
	ptr(0)
{
}

DIRECTORY::~DIRECTORY()
{
}

NTSTATUS DIRECTORY::Read( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS DIRECTORY::Write( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	return STATUS_OBJECT_TYPE_MISMATCH;
}

// getdents64 borrowed from wine/dlls/ntdll/directory.c

typedef struct
{
	ULONG64        d_ino;
	LONG64         d_off;
	unsigned short d_reclen;
	unsigned char  d_type;
	char           d_name[256];
} KERNEL_DIRENT64;

int Getdents64( int fd, unsigned char *de, unsigned int size )
{
	int ret;
	__asm__( "pushl %%ebx; movl %2,%%ebx; int $0x80; popl %%ebx"
			 : "=a" (ret)
			 : "0" (220 /*NR_getdents64*/), "r" (fd), "c" (de), "d" (size)
			 : "memory" );
	if (ret < 0)
	{
		errno = -ret;
		ret = -1;
	}
	return ret;
}

#ifndef HAVE_FSTATAT
int Fstatat64( int dirfd, const char *path, struct stat64 *buf, int flags )
{
	int ret;

	__asm__(
		"pushl %%ebx\n"
		"\tmovl %2,%%ebx\n"
		"\tint $0x80\n"
		"\tpopl %%ebx\n"
		: "=a"(ret)
		: "0"(300 /*NR_fstatat64*/), "r"( dirfd ), "c"( path ), "d"( buf ), "S"(flags)
		: "memory" );
	if (ret < 0)
	{
		errno = -ret;
		ret = -1;
	}
	return ret;
}

int Fstatat( int dirfd, const char *path, struct stat *buf, int flags )
{
	struct stat64 st;
	int ret;

	ret = Fstatat64( dirfd, path, &st, flags );
	if (ret >= 0)
	{
		buf->st_dev = st.st_dev;
		buf->st_ino = st.st_ino;
		buf->st_mode = st.st_mode;
		buf->st_nlink = st.st_nlink;
		buf->st_uid = st.st_uid;
		buf->st_gid = st.st_gid;
		buf->st_rdev = st.st_rdev;
		if (st.st_size < 0x100000000LL)
			buf->st_size = st.st_size;
		else
			buf->st_size = ~0;
		buf->st_blksize = st.st_blksize;
		buf->st_blocks = st.st_blocks;
		buf->st_atime = st.st_atime;
		buf->st_mtime = st.st_mtime;
		buf->st_ctime = st.st_ctime;
	}
	return ret;
}

#endif

void DIRECTORY::Reset()
{
	ptr = 0;
	count = 0;

	while (!entries.Empty())
	{
		DIRECTORY_ENTRY *x = entries.Head();
		entries.Unlink(x);
		delete x;
	}
}

bool DIRECTORY::Match(unicode_string_t &name) const
{
	if (mask.Length == 0)
		return true;

	// check for dot pseudo files
	bool pseudo_file = (name.Length == 2 && name.Buffer[0] == '.') ||
					   (name.Length == 4 && name.Buffer[0] == '.' && name.Buffer[1] == '.' );

	int i = 0, j = 0;
	while (i < mask.Length/2 && j < name.Length/2)
	{
		// asterisk matches everything
		if (mask.Buffer[i] == '*')
			return true;

		// question mark matches one character
		if (mask.Buffer[i] == '?')
		{
			if (pseudo_file)
				return false;
			i++;
			j++;
			continue;
		}

		// double quote matches separator
		if (mask.Buffer[i] == '"' && j != 0 && name.Buffer[j] == '.')
		{
			i++;
			j++;
			continue;
		}

		// right angle matches anything except a dot
		if (mask.Buffer[i] == '>' && name.Buffer[j] != '.')
		{
			i++;
			j++;
			continue;
		}

		// right angle matches strings without a dot
		if (mask.Buffer[i] == '<')
		{
			while (name.Buffer[j] != '.' && j < name.Length)
				j++;
			i++;
			continue;
		}

		if (pseudo_file)
			return false;

		// match characters
		//trace("%c <> %c\n", mask.Buffer[i], name.Buffer[j]);
		if (Lowercase(mask.Buffer[i]) != Lowercase(name.Buffer[j]))
			return false;

		i++;
		j++;
	}

	// left over characters are a mismatch
	if (i != mask.Length/2 || j != name.Length/2)
		return false;

	return true;
}

void DIRECTORY::AddEntry(const char *name)
{
	trace("adding dir entry: %s\n", name);
	DIRECTORY_ENTRY *ent = new DIRECTORY_ENTRY;
	ent->name.copy(name);
	/* FIXME: Should symlinks be deferenced?
	   AT_SYMLINK_NOFOLLOW */
	if (0 != Fstatat(GetFD(), name, &ent->st, 0))
	{
		delete ent;
		return;
	}
	if (!Match(ent->name))
	{
		delete ent;
		return;
	}
	trace("matched mask %pus\n", &mask);
	//trace("mode = %o\n", ent->st.st_mode);
	entries.Append(ent);
	count++;
}

int DIRECTORY::GetNumEntries() const
{
	return count;
}

void DIRECTORY::ScanDir()
{
	unsigned char buffer[0x1000];
	int r;

	Reset();
	r = lseek( GetFD(), 0, SEEK_SET );
	if (r == -1)
	{
		trace("lseek failed (%d)\n", errno);
		return;
	}

	trace("reading entries:\n");
	// . and .. always come first
	AddEntry(".");
	AddEntry("..");

	do
	{
		r = ::Getdents64( GetFD(), buffer, sizeof buffer );
		if (r < 0)
		{
			trace("getdents64 failed (%d)\n", r);
			break;
		}

		int ofs = 0;
		while (ofs<r)
		{
			KERNEL_DIRENT64* de = (KERNEL_DIRENT64*) &buffer[ofs];
			//fprintf(stderr, "%ld %d %s\n", de->d_off, de->d_reclen, de->d_name);
			if (de->d_off <= 0)
				break;
			if (de->d_reclen <=0 )
				break;
			ofs += de->d_reclen;
			if (!strcmp(de->d_name,".") || !strcmp(de->d_name, ".."))
				continue;
			AddEntry(de->d_name);
		}
	} while (0);
}

NTSTATUS DIRECTORY::SetMask(unicode_string_t *string)
{
	mask.copy(string);
	return STATUS_SUCCESS;
}

// scan for the first time after construction
bool DIRECTORY::IsFirstScan() const
{
	return (count == -1);
}

DIRECTORY_ENTRY* DIRECTORY::GetNext()
{
	if (!ptr)
	{
		ptr = entries.Head();
		return ptr;
	}

	if (ptr == entries.Tail())
		return 0;

	ptr = ptr->Entry[0].GetNext();

	return ptr;
}

NTSTATUS DIRECTORY::QueryInformation( FILE_ATTRIBUTE_TAG_INFORMATION& info )
{
	info.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
	info.ReparseTag = 0;
	return STATUS_SUCCESS;
}

int CFILE::GetFD()
{
	return fd;
}

NTSTATUS CFILE::QueryInformation( FILE_BASIC_INFORMATION& info )
{
	info.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::QueryInformation( FILE_STANDARD_INFORMATION& info )
{
	struct stat st;
	if (0<fstat( fd, &st ))
		return STATUS_UNSUCCESSFUL;
	info.EndOfFile.QuadPart = st.st_size;
	info.AllocationSize.QuadPart = (st.st_size+0x1ff)&~0x1ff;
	if (S_ISDIR(st.st_mode))
		info.Directory = TRUE;
	else
		info.Directory = FALSE;
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::QueryInformation( FILE_ATTRIBUTE_TAG_INFORMATION& info )
{
	info.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	info.ReparseTag = 0;
	return STATUS_SUCCESS;
}

char *BuildPath( int fd, const UNICODE_STRING *us )
{
	char *str, *p;
	int i;
	int len = us->Length/2 + 1;
	const char fd_prefix[] = "/proc/self/fd/%d/";

	if (fd >= 0)
		len += sizeof fd_prefix + 10;

	str = new char[ len ];
	if (!str)
		return str;

	str[0] = 0;
	if (fd >= 0)
		sprintf( str, fd_prefix, fd );

	p = &str[strlen( str )];
	for (i=0; i<us->Length/2; i++)
		*p++ = us->Buffer[i];
	*p = 0;

	return str;
}

char *GetUnixPath( int fd, UNICODE_STRING& str, bool case_insensitive )
{
	char *file;
	int i;

	file = BuildPath( fd, &str );
	if (!file)
		return NULL;

	for (i=0; file[i]; i++)
	{
		if (file[i] == '\\')
		{
			file[i] = '/';
			continue;
		}

		// make filename lower case if necessary
		if (!case_insensitive)
			continue;
		file[i] = Lowercase(file[i]);
	}

	return file;
}

int DIRECTORY::OpenUnicodeFile( const char *unix_path, int flags, bool &created )
{
	int r = -1;

	trace("open file : %s\n", unix_path);
	r = ::open( unix_path, flags&~O_CREAT );
	if (r < 0 && (flags & O_CREAT))
	{
		trace("create file : %s\n", unix_path);
		r = ::open( unix_path, flags, 0666 );
		if (r >= 0)
			created = true;
	}
	return r;
}

int DIRECTORY::OpenUnicodeDir( const char *unix_path, int flags, bool &created )
{
	int r = -1;

	if (flags & O_CREAT)
	{
		trace("create dir : %s\n", unix_path);
		r = ::mkdir( unix_path, 0777 );
		if (r == 0)
			created = true;
	}
	trace("open name : %s\n", unix_path);
	r = ::open( unix_path, flags & ~O_CREAT );
	trace("r = %d\n", r);
	return r;
}

NTSTATUS DIRECTORY::OpenFile(
	CFILE *&file,
	UNICODE_STRING& path,
	ULONG Attributes,
	ULONG Options,
	ULONG CreateDisposition,
	bool &created,
	bool case_insensitive )
{
	int file_fd;

	trace("name = %pus\n", &path );

	int mode = O_RDONLY;
	switch (CreateDisposition)
	{
	case FILE_OPEN:
		mode = O_RDONLY;
		break;
	case FILE_CREATE:
		mode = O_CREAT;
		break;
	case FILE_OPEN_IF:
		mode = O_CREAT;
		break;
	default:
		trace("CreateDisposition = %ld\n", CreateDisposition);
		return STATUS_NOT_IMPLEMENTED;
	}

	char *unix_path = GetUnixPath( GetFD(), path, case_insensitive );
	if (!unix_path)
		return STATUS_OBJECT_PATH_NOT_FOUND;

	if (Options & FILE_DIRECTORY_FILE)
	{
		file_fd = OpenUnicodeDir( unix_path, mode, created );
		delete[] unix_path;
		if (file_fd == -1)
			return STATUS_OBJECT_PATH_NOT_FOUND;

		trace("file_fd = %d\n", file_fd );
		file = new DIRECTORY( file_fd );
		if (!file)
		{
			::close( file_fd );
			return STATUS_NO_MEMORY;
		}
	}
	else
	{
		file_fd = OpenUnicodeFile( unix_path, mode, created );
		delete[] unix_path;
		if (file_fd == -1)
			return STATUS_OBJECT_PATH_NOT_FOUND;

		file = new CFILE( file_fd );
		if (!file)
		{
			::close( file_fd );
			return STATUS_NO_MEMORY;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DIRECTORY::Open( OBJECT *&out, OPEN_INFO& info )
{
	CFILE *file = 0;

	trace("DIRECTORY::open %pus\n", &info.path );

	FILE_CREATE_INFO *file_info = dynamic_cast<FILE_CREATE_INFO*>( &info );
	if (!file_info)
		return STATUS_OBJECT_TYPE_MISMATCH;

	NTSTATUS r = OpenFile( file, info.path, file_info->Attributes, file_info->CreateOptions,
							file_info->CreateDisposition, file_info->created, info.case_insensitive() );
	if (r < STATUS_SUCCESS)
		return r;
	out = file;
	return r;
}

NTSTATUS OpenFile( CFILE *&file, UNICODE_STRING& name )
{
	FILE_CREATE_INFO info( 0, 0, FILE_OPEN );
	info.path.set( name );
	info.Attributes = OBJ_CASE_INSENSITIVE;
	OBJECT *obj = 0;
	NTSTATUS r = open_root( obj, info );
	if (r < STATUS_SUCCESS)
		return r;
	file = dynamic_cast<CFILE*>( obj );
	assert( file != NULL );
	return STATUS_SUCCESS;
}

void InitDrives()
{
	int fd = open( "drive", O_RDONLY );
	if (fd < 0)
		Die("drive does not exist");
	DIRECTORY_FACTORY factory( fd );
	unicode_string_t dirname;
	dirname.copy( L"\\Device\\HarddiskVolume1" );
	OBJECT *obj = 0;
	NTSTATUS r;
	r = factory.create_kernel( obj, dirname );
	if (r < STATUS_SUCCESS)
	{
		trace( "failed to create %pus\n", &dirname);
		Die("fatal\n");
	}

	unicode_string_t c_link;
	c_link.set( L"\\??\\c:" );
	r = create_symlink( c_link, dirname );
	if (r < STATUS_SUCCESS)
	{
		trace( "failed to create symlink %pus (%08lx)\n", &c_link, r);
		Die("fatal\n");
	}
}

NTSTATUS NTAPI NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG Attributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength )
{
	object_attributes_t oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS r;

	r = oa.copy_from_user( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	trace("root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( FileHandle, sizeof *FileHandle );
	if (r < STATUS_SUCCESS)
		return r;

	if (!(CreateOptions & FILE_DIRECTORY_FILE))
		Attributes &= ~FILE_ATTRIBUTE_DIRECTORY;

	if (!oa.ObjectName)
		return STATUS_OBJECT_PATH_NOT_FOUND;

	FILE_CREATE_INFO info( Attributes, CreateOptions, CreateDisposition );

	info.path.set( *oa.ObjectName );
	info.Attributes = oa.Attributes;

	OBJECT *obj = 0;
	r = open_root( obj, info );
	if (r >= STATUS_SUCCESS)
	{
		r = AllocUserHandle( obj, DesiredAccess, FileHandle );
		release( obj );
	}

	iosb.Status = r;
	iosb.Information = info.created ? FILE_CREATED : FILE_OPENED;

	CopyToUser( IoStatusBlock, &iosb, sizeof iosb );

	return r;
}

NTSTATUS NTAPI NtOpenFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions )
{
	return NtCreateFile( FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
						 0, 0, ShareAccess, FILE_OPEN, OpenOptions, 0, 0 );
}

NTSTATUS NTAPI NtFsControlFile(
	HANDLE FileHandle,
	HANDLE EventHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG FsControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength )
{
	trace("%p %p %p %p %p %08lx %p %lu %p %lu\n", FileHandle,
		  EventHandle, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode,
		  InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	IO_STATUS_BLOCK iosb;
	IO_OBJECT *io = 0;
	EVENT *event = 0;
	NTSTATUS r;

	r = object_from_handle( io, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

#if 0
	if (EventHandle)
	{
		r = object_from_handle( event, EventHandle, SYNCHRONIZE );
		if (r < STATUS_SUCCESS)
			return r;
	}
#endif

	r = io->FSControl( event, iosb, FsControlCode,
						InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	iosb.Status = r;

	CopyToUser( IoStatusBlock, &iosb, sizeof iosb );

	return r;
}

NTSTATUS NTAPI NtDeviceIoControlFile(
	HANDLE File,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength )
{
	trace("%p %p %p %p %p %08lx %p %lu %p %lu\n",
		  File, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
		  InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtWriteFile(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key )
{

	trace("%p %p %p %p %p %p %lu %p %p\n", FileHandle, Event, ApcRoutine,
		  ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	IO_OBJECT *io = 0;
	NTSTATUS r;

	r = object_from_handle( io, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	ULONG ofs = 0;
	r = io->Write( Buffer, Length, &ofs );
	if (r < STATUS_SUCCESS)
		return r;

	IO_STATUS_BLOCK iosb;
	iosb.Status = r;
	iosb.Information = ofs;

	CopyToUser( IoStatusBlock, &iosb, sizeof iosb );

	return r;
}

NTSTATUS NTAPI NtQueryAttributesFile(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_BASIC_INFORMATION FileInformation )
{
	object_attributes_t oa;
	NTSTATUS r;
	FILE_BASIC_INFORMATION info;

	trace("%p %p\n", ObjectAttributes, FileInformation);

	r = oa.copy_from_user( ObjectAttributes );
	if (r)
		return r;

	trace("root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	if (!oa.ObjectName || !oa.ObjectName->Buffer)
		return STATUS_INVALID_PARAMETER;

	// FIXME: use oa.RootDirectory
	OBJECT *obj = 0;
	FILE_CREATE_INFO open_info( 0, 0, FILE_OPEN );
	open_info.path.set( *oa.ObjectName );
	open_info.Attributes = oa.Attributes;
	r = open_root( obj, open_info );
	if (r < STATUS_SUCCESS)
		return r;

	CFILE *file = dynamic_cast<CFILE*>(obj );
	if (file)
	{

		memset( &info, 0, sizeof info );
		r = file->QueryInformation( info );
	}
	else
		r = STATUS_OBJECT_TYPE_MISMATCH;
	release( obj );

	return r;
}

NTSTATUS NTAPI NtQueryVolumeInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID VolumeInformation,
	ULONG VolumeInformationLength,
	FS_INFORMATION_CLASS VolumeInformationClass )
{
	trace("%p %p %p %lu %u\n", FileHandle, IoStatusBlock, VolumeInformation,
		  VolumeInformationLength, VolumeInformationClass );
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtReadFile(
	HANDLE FileHandle,
	HANDLE EventHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID Buffer,
	ULONG Length,
	PLARGE_INTEGER ByteOffset,
	PULONG Key)
{
	trace("%p %p %p %p %p %p %lu %p %p\n", FileHandle, EventHandle,
		  ApcRoutine, ApcContext, IoStatusBlock,
		  Buffer, Length, ByteOffset, Key);

	NTSTATUS r;
	IO_OBJECT *io = 0;

	r = object_from_handle( io, FileHandle, GENERIC_READ );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	ULONG ofs = 0;
	r = io->Read( Buffer, Length, &ofs );
	if (r < STATUS_SUCCESS)
		return r;

	IO_STATUS_BLOCK iosb;
	iosb.Status = r;
	iosb.Information = ofs;

	r = CopyToUser( IoStatusBlock, &iosb, sizeof iosb );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtDeleteFile(
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	object_attributes_t oa;
	NTSTATUS r;

	trace("%p\n", ObjectAttributes);

	r = oa.copy_from_user( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	trace("root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	if (!oa.ObjectName || !oa.ObjectName->Buffer)
		return STATUS_INVALID_PARAMETER;

	// FIXME: use oa.RootDirectory
	OBJECT *obj = 0;
	FILE_CREATE_INFO open_info( 0, 0, FILE_OPEN );
	open_info.path.set( *oa.ObjectName );
	open_info.Attributes = oa.Attributes;
	r = open_root( obj, open_info );
	if (r < STATUS_SUCCESS)
		return r;

	CFILE *file = dynamic_cast<CFILE*>(obj );
	if (file)
		r = file->Remove();
	else
		r = STATUS_OBJECT_TYPE_MISMATCH;
	release( obj );
	return r;
}

NTSTATUS NTAPI NtFlushBuffersFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock)
{
	trace("%p %p\n", FileHandle, IoStatusBlock);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtCancelIoFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock)
{
	trace("%p %p\n", FileHandle, IoStatusBlock);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtSetInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG FileInformationLength,
	FILE_INFORMATION_CLASS FileInformationClass)
{
	IO_OBJECT *file = 0;
	NTSTATUS r;
	ULONG len = 0;
	union
	{
		FILE_DISPOSITION_INFORMATION dispos;
		FILE_COMPLETION_INFORMATION completion;
		FILE_POSITION_INFORMATION position;
		FILE_PIPE_INFORMATION pipe;
	} info;

	r = object_from_handle( file, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	switch (FileInformationClass)
	{
	case FileDispositionInformation:
		len = sizeof info.dispos;
		break;
	case FileCompletionInformation:
		len = sizeof info.completion;
		break;
	case FilePositionInformation:
		len = sizeof info.position;
		break;
	case FilePipeInformation:
		len = sizeof info.pipe;
		break;
	default:
		trace("Unknown information class %d\n", FileInformationClass );
		return STATUS_INVALID_PARAMETER;
	}

	r = CopyFromUser( &info, FileInformation, len );
	if (r < STATUS_SUCCESS)
		return r;

	COMPLETION_PORT *completion_port = 0;

	switch (FileInformationClass)
	{
	case FileDispositionInformation:
		trace("delete = %d\n", info.dispos.DeleteFile);
		break;
	case FileCompletionInformation:
		r = object_from_handle( completion_port, info.completion.CompletionPort, IO_COMPLETION_MODIFY_STATE );
		if (r < STATUS_SUCCESS)
			return r;
		file->SetCompletionPort( completion_port, info.completion.CompletionKey );
		break;
	case FilePositionInformation:
		r = file->SetPosition( info.position.CurrentByteOffset );
		break;
	case FilePipeInformation:
		r = file->SetPipeInfo( info.pipe );
		break;
	default:
		break;
	}

	return r;
}

NTSTATUS NTAPI NtQueryInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG FileInformationLength,
	FILE_INFORMATION_CLASS FileInformationClass)
{
	trace("%p %p %p %lu %u\n", FileHandle, IoStatusBlock,
		  FileInformation, FileInformationLength, FileInformationClass);

	CFILE *file = 0;
	NTSTATUS r;

	r = object_from_handle( file, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	union
	{
		FILE_BASIC_INFORMATION basic_info;
		FILE_STANDARD_INFORMATION std_info;
		FILE_ATTRIBUTE_TAG_INFORMATION attrib_info;
	} info;
	ULONG len;
	memset( &info, 0, sizeof info );

	switch (FileInformationClass)
	{
	case FileBasicInformation:
		len = sizeof info.basic_info;
		r = file->QueryInformation( info.basic_info );
		break;
	case FileStandardInformation:
		len = sizeof info.std_info;
		r = file->QueryInformation( info.std_info );
		break;
	case FileAttributeTagInformation:
		len = sizeof info.attrib_info;
		r = file->QueryInformation( info.attrib_info );
		break;
	default:
		trace("Unknown information class %d\n", FileInformationClass );
		r = STATUS_INVALID_PARAMETER;
	}

	if (r < STATUS_SUCCESS)
		return r;

	if (len > FileInformationLength)
		len = FileInformationLength;

	return CopyToUser( FileInformation, &info, len );
}

NTSTATUS NTAPI NtSetQuotaInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PFILE_USER_QUOTA_INFORMATION FileInformation,
	ULONG FileInformationLength)
{
	trace("%p %p %p %lu\n", FileHandle, IoStatusBlock,
		  FileInformation, FileInformationLength);

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQueryQuotaInformationFile(HANDLE,PIO_STATUS_BLOCK,PFILE_USER_QUOTA_INFORMATION,ULONG,BOOLEAN,PFILE_QUOTA_LIST_INFORMATION,ULONG,PSID,BOOLEAN)
{
	trace("\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtLockFile(
	HANDLE FileHandle,
	HANDLE EventHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PULARGE_INTEGER LockOffset,
	PULARGE_INTEGER LockLength,
	ULONG Key,
	BOOLEAN FailImmediately,
	BOOLEAN ExclusiveLock)
{
	trace("just returns success...\n");
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtUnlockFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PULARGE_INTEGER LockOffset,
	PULARGE_INTEGER LockLength,
	ULONG Key)
{
	trace("just returns success...\n");
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryDirectoryFile(
	HANDLE DirectoryHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG FileInformationLength,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartScan)
{
	NTSTATUS r;

	DIRECTORY *dir = 0;
	r = object_from_handle( dir, DirectoryHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	// default (empty) mask matches all...
	unicode_string_t mask;
	if (FileName)
	{
		r = mask.copy_from_user( FileName );
		if (r < STATUS_SUCCESS)
			return r;

		trace("Filename = %pus (len=%d)\n", &mask, mask.Length);
	}

	if (FileInformationClass != FileBothDirectoryInformation)
	{
		trace("unimplemented FileInformationClass %d\n", FileInformationClass);
		return STATUS_NOT_IMPLEMENTED;
	}

	if (dir->IsFirstScan())
	{
		r = dir->SetMask(&mask);
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (dir->IsFirstScan() || RestartScan)
		dir->ScanDir();

	if (dir->GetNumEntries() == 0)
		return STATUS_NO_SUCH_FILE;

	DIRECTORY_ENTRY *de = dir->GetNext();
	if (!de)
		return STATUS_NO_MORE_FILES;

	FILE_BOTH_DIRECTORY_INFORMATION info;
	memset( &info, 0, sizeof info );

	if (S_ISDIR(de->st.st_mode))
		info.FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
	else
		info.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	info.FileNameLength = de->name.Length;
	info.EndOfFile.QuadPart = de->st.st_size;
	info.AllocationSize.QuadPart = de->st.st_blocks * 512;

	r = CopyToUser( FileInformation, &info, sizeof info );
	if (r < STATUS_SUCCESS)
		return r;

	const ULONG ofs = FIELD_OFFSET(FILE_BOTH_DIRECTORY_INFORMATION, FileName);
	PWSTR p = (PWSTR)((PBYTE)FileInformation + ofs);
	r = CopyToUser( p, de->name.Buffer, de->name.Length );
	if (r < STATUS_SUCCESS)
		return r;

	IO_STATUS_BLOCK iosb;
	iosb.Status = r;
	iosb.Information = ofs + de->name.Length;

	CopyToUser( IoStatusBlock, &iosb, sizeof iosb );

	return r;
}

NTSTATUS NTAPI NtQueryFullAttributesFile(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
	object_attributes_t oa;
	NTSTATUS r;

	r = oa.copy_from_user( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	trace("name = %pus\n", oa.ObjectName);

	return STATUS_NOT_IMPLEMENTED;
}
