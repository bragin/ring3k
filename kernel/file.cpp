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
#include <wchar.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/statfs.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"

#include "debug.h"
#include "object.h"

#include <unistd.h>
#include <sys/types.h>

DEFAULT_DEBUG_CHANNEL(file);

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

int lstrlenW(const wchar_t *a)
{
	short n = 0;
	while (a[n])
		n++;
	return n;
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
		Release( completion_port );
		completion_port = 0;
	}
	completion_port = port;
	completion_key = 0;
}

NTSTATUS IO_OBJECT::SetPosition( LARGE_INTEGER& ofs )
{
	ERR("\n");
	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS IO_OBJECT::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								  PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	FIXME("\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS IO_OBJECT::SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info )
{
	ERR("\n");
	return STATUS_OBJECT_TYPE_MISMATCH;
}

CFILE::~CFILE()
{
	TRACE("Closing file %d\n", fd);
	close( fd );
}

CFILE::CFILE(int f, UNICODE_STRING *Path) :
	fd( f )
{
	// Extract file name and save it in the object
	PWCHAR Source = NULL;
	USHORT Length = 0;
	if (Path && Path->Buffer)
	{
		Source = (PWCHAR)((PCHAR)Path->Buffer + Path->Length);

		/* Loop the file name*/
		while (Source > Path->Buffer)
		{
			/* Make sure this isn't a backslash */
			if (*--Source == L'\\')
			{
				/* If so, stop it here */
				Source++;
				break;
			}
			else
			{
				/* Otherwise, keep going */
				Length++;
			}
		}
	}

	PWCHAR Buf = new WCHAR[Length + 1];
	PWCHAR Destination = Buf;
	while (Length--) *Destination++ = (UCHAR)*Source++;
	*Destination = 0;

	FileName.Set(Buf);
	FileName.MaximumLength = FileName.Length + sizeof(WCHAR);
}

class FILE_CREATE_INFO : public OPEN_INFO
{
public:
	ACCESS_MASK DesiredAccess;
	ULONG FileAttributes;
	ULONG CreateOptions;
	ULONG CreateDisposition;
	bool created;
public:
	FILE_CREATE_INFO( ACCESS_MASK _DesiredAccess, ULONG _Attributes, ULONG _CreateOptions, ULONG _CreateDisposition );
	virtual NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
};

FILE_CREATE_INFO::FILE_CREATE_INFO( ACCESS_MASK _DesiredAccess, ULONG _Attributes, ULONG _CreateOptions, ULONG _CreateDisposition ) :
	DesiredAccess( _DesiredAccess ),
	FileAttributes( _Attributes ),
	CreateOptions( _CreateOptions ),
	CreateDisposition( _CreateDisposition ),
	created( false )
{
}

NTSTATUS FILE_CREATE_INFO::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	TRACE("FILE_CREATE_INFO::on_open()\n");
	if (!obj)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::Read( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	NTSTATUS r = STATUS_SUCCESS;
	ULONG ofs = 0;
	int ret = 1;

	while (ofs < Length && ret)
	{
		BYTE *p = (BYTE*)Buffer+ofs;
		size_t len = Length - ofs;

		r = Current->Process->Vm->GetKernelAddress( &p, &len );
		if (r < STATUS_SUCCESS)
			break;

		ret = ::read( fd, p, len );

#ifdef VERBOSE_DEBUG_OUTPUT
		char filePath[500];
		char test[500];
		sprintf(test, "/proc/self/fd/%d", fd);

		memset(filePath, 0, sizeof(filePath));
		readlink(test, filePath, sizeof(filePath) - 1);
		TRACE("file name %s\n", filePath);

		TRACE("Reading fd %d, read: %ld, len %d\n", fd, ret, len);
#endif

		if (ret < 0)
		{
			r = STATUS_IO_DEVICE_ERROR;
			break;
		}

		ofs += ret;

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

		r = Current->Process->Vm->GetKernelAddress( &p, &len );
		if (r < STATUS_SUCCESS)
			break;

		int ret = ::write( fd, p, len );
		if (ret < 0)
		{
			ERR("Write failed %d\n", errno);
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
		ERR("seek failed\n");
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
		ERR("Failed to delete %s\n", path);
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
	CUNICODE_STRING name;
	struct stat st;
};

class DIRECTORY : public CFILE
{
	int count;
	DIRECTORY_ENTRY *ptr;
	DIRLIST entries;
	CUNICODE_STRING mask;
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
	virtual NTSTATUS QueryInformation( FILE_BASIC_INFORMATION& info );
	DIRECTORY_ENTRY* GetNext();
	bool Match(CUNICODE_STRING &name) const;
	void ScanDir();
	bool IsFirstScan() const;
	NTSTATUS SetMask(CUNICODE_STRING *mask);
	int GetNumEntries() const;
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	NTSTATUS OpenFile( CFILE *&file, UNICODE_STRING& path, ACCESS_MASK DesiredAccess, ULONG Attributes,
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
	CFILE(fd, NULL),
	count(-1),
	ptr(0)
{
}

DIRECTORY::~DIRECTORY()
{
}

NTSTATUS DIRECTORY::Read( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	ERR("\n");
	return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS DIRECTORY::Write( PVOID Buffer, ULONG Length, ULONG *bytes_read )
{
	ERR("\n");
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

bool DIRECTORY::Match(CUNICODE_STRING &name) const
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
	TRACE("adding dir entry: %s\n", name);
	DIRECTORY_ENTRY *ent = new DIRECTORY_ENTRY;
	ent->name.Copy(name);
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
	TRACE("matched mask %pus\n", &mask);
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
		ERR("lseek failed (%d)\n", errno);
		return;
	}

	TRACE("reading entries:\n");
	// . and .. always come first
	AddEntry(".");
	AddEntry("..");

	do
	{
		r = ::Getdents64( GetFD(), buffer, sizeof buffer );
		if (r < 0)
		{
			ERR("getdents64 failed (%d)\n", r);
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

NTSTATUS DIRECTORY::SetMask(CUNICODE_STRING *string)
{
	mask.Copy(string);
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

NTSTATUS DIRECTORY::QueryInformation( FILE_BASIC_INFORMATION& info )
{
	NTSTATUS r;
	r = CFILE::QueryInformation( info );
	info.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
	return r;
}

int CFILE::GetFD()
{
	return fd;
}

NTSTATUS CFILE::QueryInformation( FILE_BASIC_INFORMATION& info )
{
	struct stat st;
	if (fstat( fd, &st ))
	{
		ERR("Cannot get stats for file fd %d\n", fd);
		return STATUS_UNSUCCESSFUL;
	}

	info.LastAccessTime.QuadPart = st.st_atime;
	info.LastWriteTime.QuadPart = st.st_mtime;
	info.ChangeTime.QuadPart = st.st_ctime;
	info.CreationTime.QuadPart = st.st_ctime;		//fixme
	info.FileAttributes = 0;

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

NTSTATUS CFILE::QueryInformation(FILE_NETWORK_OPEN_INFORMATION& info)
{
	struct stat st;
	if (0<fstat(fd, &st))
	{
		ERR("Cannot get stats for file fd %d\n", fd);
		return STATUS_UNSUCCESSFUL;
	}
	info.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	info.EndOfFile.QuadPart = st.st_size;
	info.AllocationSize.QuadPart = (st.st_size + 0x1ff)&~0x1ff;

	// TODO: Times are broken
	FIXME("Not returning times for the file. EndOfFile: %lld!\n", info.EndOfFile.QuadPart);

	return STATUS_SUCCESS;
}

NTSTATUS CFILE::QueryInformation( FILE_ATTRIBUTE_TAG_INFORMATION& info )
{
	info.FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	info.ReparseTag = 0;
	return STATUS_SUCCESS;
}

NTSTATUS CFILE::QueryInformation( FILE_POSITION_INFORMATION& info )
{
	off_t position = lseek(fd, 0, SEEK_CUR);
	info.CurrentByteOffset.QuadPart = position;
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

void PrintFlags( int flags )
{
	TRACE("flags:\n");
	if (flags & O_RDONLY) 	TRACE("	O_RDONLY\n");
	if (flags & O_WRONLY) 	TRACE("	O_WRONLY\n");
	if (flags & O_RDWR) 	TRACE("	O_RDWR\n");
	if (flags & O_APPEND) 	TRACE("	O_APPEND\n");
	if (flags & O_CREAT) 	TRACE("	O_CREAT\n");
	if (flags & O_DSYNC) 	TRACE("	O_DSYNC\n");
	if (flags & O_EXCL) 	TRACE("	O_EXCL\n");
	if (flags & O_NOCTTY) 	TRACE("	O_NOCTTY\n");
	if (flags & O_NONBLOCK) TRACE("	O_NONBLOCK\n");
	if (flags & O_RSYNC) 	TRACE("	O_RSYNC\n");
	if (flags & O_SYNC) 	TRACE("	O_SYNC\n");
	if (flags & O_TRUNC) 	TRACE("	O_TRUNC\n");
}

int DIRECTORY::OpenUnicodeFile( const char *unix_path, int flags, bool &created )
{
	int r = -1;

	TRACE("file %s\n", unix_path);
	PrintFlags(flags);
	r = ::open( unix_path, flags&~O_CREAT );
	if (r < 0 && (flags & O_CREAT))
	{
		TRACE("create file : %s\n", unix_path);
		r = ::open( unix_path, flags, 0666 );
		TRACE("file fd = %d\n", r);
		if (r >= 0)
			created = true;
	}
	return r;
}

int DIRECTORY::OpenUnicodeDir( const char *unix_path, int flags, bool &created )
{
	int r = -1;
	TRACE("folder %s\n", unix_path);
	PrintFlags(flags);

	if (flags & O_CREAT)
	{
		TRACE("create dir : %s\n", unix_path);
		r = ::mkdir( unix_path, 0777 );
		if (r == 0)
			created = true;
	}
	TRACE("open name : %s\n", unix_path);
	r = ::open( unix_path, flags & ~O_CREAT );
	TRACE("r = %d created = %s\n", r, created? "true":"false");
	return r;
}

int ProcessDesiredAccess(int mode, ACCESS_MASK DesiredAccess)
{
	if ( DesiredAccess & FILE_LIST_DIRECTORY)
		return mode;

	if (( DesiredAccess & FILE_WRITE_DATA ) || ( DesiredAccess & GENERIC_WRITE ))
	{
		if (( DesiredAccess & FILE_READ_DATA ) || ( DesiredAccess & GENERIC_READ ))
			mode |= O_RDWR;
		else
			mode |= O_WRONLY;
	}

	return mode;
}

NTSTATUS DIRECTORY::OpenFile(
	CFILE *&file,
	UNICODE_STRING& path,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options,
	ULONG CreateDisposition,
	bool &created,
	bool case_insensitive )
{
	int file_fd;
	NTSTATUS r;

	TRACE("name = %pus\n", &path);

	int mode = 0;
	switch (CreateDisposition)
	{
	case FILE_OPEN:
		mode = O_RDONLY;
		break;
	case FILE_CREATE:
		mode = O_CREAT;
		break;
	case FILE_OPEN_IF:
		mode = O_CREAT | O_RDONLY;
		break;
	case FILE_OVERWRITE:
		mode = O_RDWR | O_TRUNC;
		break;
	case FILE_OVERWRITE_IF:
		mode = O_RDWR | O_TRUNC | O_CREAT;
		break;
	default:
		FIXME("CreateDisposition = %ld\n", CreateDisposition);
		return STATUS_NOT_IMPLEMENTED;
	}

	mode = ProcessDesiredAccess(mode, DesiredAccess);

	char *unix_path = GetUnixPath( GetFD(), path, case_insensitive );
	if (!unix_path)
		return STATUS_OBJECT_PATH_NOT_FOUND;

	if (Options & FILE_DIRECTORY_FILE)
	{
		file_fd = OpenUnicodeDir( unix_path, mode, created );
		delete[] unix_path;
		if (file_fd == -1)
			return STATUS_OBJECT_PATH_NOT_FOUND;

		TRACE("file_fd = %d\n", file_fd);
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

		if (file_fd == -1) {
			//need to check, is directory doesn't exists, or only file
			int idx = strlen(unix_path) - 1;
			while (idx >= 0 && unix_path[idx] != '/') {
				unix_path[idx] = '\0';
				idx--;
			}
			TRACE("check path %s\n", unix_path);
			if (access(unix_path, F_OK) != -1) {
				r = STATUS_OBJECT_NAME_NOT_FOUND;
			} else {
				r = STATUS_OBJECT_PATH_NOT_FOUND;
			}
		}
		delete[] unix_path;
		if (file_fd == -1) {
			return r;
		}

		file = new CFILE( file_fd, &path);
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

	TRACE("DIRECTORY::open %pus\n", &info.Path);

	FILE_CREATE_INFO *file_info = dynamic_cast<FILE_CREATE_INFO*>( &info );
	if (!file_info)
		return STATUS_OBJECT_TYPE_MISMATCH;

	NTSTATUS r = OpenFile( file, info.Path, file_info->DesiredAccess, file_info->Attributes, file_info->CreateOptions,
							file_info->CreateDisposition, file_info->created, info.CaseInsensitive() );
	if (r < STATUS_SUCCESS)
		return r;
	out = file;
	return r;
}

NTSTATUS OpenFile( CFILE *&file, UNICODE_STRING& name )
{
	FILE_CREATE_INFO info( 0, 0, 0, FILE_OPEN );
	info.Path.Set( name );
	info.Attributes = OBJ_CASE_INSENSITIVE;
	OBJECT *obj = 0;
	NTSTATUS r = OpenRoot( obj, info );
	if (r < STATUS_SUCCESS)
		return r;
	file = dynamic_cast<CFILE*>( obj );
	assert( file != NULL );
	return STATUS_SUCCESS;
}

void InitCdrom()
{
	int fd = open("cdrom", O_RDONLY);
	if (fd < 0)
		Die("cdrom does not exist");
	DIRECTORY_FACTORY factory(fd);
	CUNICODE_STRING dirname;
	dirname.Copy(L"\\Device\\CdRom0");
	OBJECT *obj = 0;
	NTSTATUS r;
	r = factory.CreateKernel(obj, dirname);
	if (r < STATUS_SUCCESS)
	{
		ERR("failed to create %pus\n", &dirname);
		Die("fatal\n");
	}
}

void InitDrives()
{
	int fd = open( "drive", O_RDONLY );
	if (fd < 0)
		Die("drive does not exist");
	DIRECTORY_FACTORY factory( fd );
	CUNICODE_STRING dirname;
	dirname.Copy( L"\\Device\\HarddiskVolume1" );
	OBJECT *obj = 0;
	NTSTATUS r;
	r = factory.CreateKernel( obj, dirname );
	if (r < STATUS_SUCCESS)
	{
		ERR("failed to create %pus\n", &dirname);
		Die("fatal\n");
	}

	CUNICODE_STRING c_link;
	c_link.Set( L"\\??\\c:" );
	r = CreateSymlink( c_link, dirname );
	if (r < STATUS_SUCCESS)
	{
		ERR( "failed to create symlink %pus (%08lx)\n", &c_link, r);
		Die("fatal\n");
	}

	//InitCdrom();
}

NTSTATUS GetFsAttributeInformation(CFILE* File, FILE_FS_ATTRIBUTE_INFORMATION* FsAttribbute, const wchar_t** FilesystemName)
{
	struct statfs Buf;

	if (fstatfs(File->GetFD(), &Buf) < 0)
		return STATUS_UNSUCCESSFUL;

	switch (Buf.f_type)
	{
	case EXT2_SUPER_MAGIC:
		*FilesystemName = L"Ext2";
		break;
	default:
		*FilesystemName = L"Unknown";
		FIXME("Cannot get filesystem name");
	}

	FsAttribbute->FileSystemNameLength = sizeof(wchar_t) * lstrlenW(*FilesystemName);

	FIXME("Get real params instead of hardcored\n");
	FsAttribbute->MaximumComponentNameLength = Buf.f_namelen;
	FsAttribbute->FileSystemAttribute = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_UNICODE_ON_DISK;

	return STATUS_SUCCESS;
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
	COBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	NTSTATUS r;

	r = oa.CopyFromUser( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	TRACE("DesiredAccess:\n");
	ACCESS_MASK _DesiredAccess = DesiredAccess;

#define CHECK(val, flag) if (val & flag) {TRACE(#flag"\n");val &= ~flag;}

	CHECK(_DesiredAccess, DELETE);
	CHECK(_DesiredAccess, FILE_READ_DATA);
	CHECK(_DesiredAccess, FILE_READ_ATTRIBUTES);
	CHECK(_DesiredAccess, FILE_READ_EA);
	CHECK(_DesiredAccess, READ_CONTROL);
	CHECK(_DesiredAccess, FILE_WRITE_DATA);
	CHECK(_DesiredAccess, FILE_WRITE_ATTRIBUTES);
	CHECK(_DesiredAccess, FILE_WRITE_EA);
	CHECK(_DesiredAccess, FILE_APPEND_DATA);
	CHECK(_DesiredAccess, WRITE_DAC);
	CHECK(_DesiredAccess, WRITE_OWNER);
	CHECK(_DesiredAccess, SYNCHRONIZE);
	CHECK(_DesiredAccess, FILE_EXECUTE);
	CHECK(_DesiredAccess, GENERIC_READ);
	CHECK(_DesiredAccess, GENERIC_WRITE);
	CHECK(_DesiredAccess, GENERIC_EXECUTE);
	CHECK(_DesiredAccess, GENERIC_ALL);


	if (_DesiredAccess != 0) {
		TRACE("ALSO DesiredAccess %x\n", _DesiredAccess);
	}

	TRACE("ObjectAttributes root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	ULONG _Attributes = Attributes;
	TRACE("FileAttributes:\n");
	CHECK(_Attributes, FILE_ATTRIBUTE_READONLY);
	CHECK(_Attributes, FILE_ATTRIBUTE_HIDDEN);
	CHECK(_Attributes, FILE_ATTRIBUTE_SYSTEM);
	CHECK(_Attributes, FILE_ATTRIBUTE_DIRECTORY);
	CHECK(_Attributes, FILE_ATTRIBUTE_ARCHIVE);
	CHECK(_Attributes, FILE_ATTRIBUTE_NORMAL);
	CHECK(_Attributes, FILE_ATTRIBUTE_TEMPORARY);
	CHECK(_Attributes, FILE_ATTRIBUTE_SPARSE_FILE);
	CHECK(_Attributes, FILE_ATTRIBUTE_REPARSE_POINT);
	CHECK(_Attributes, FILE_ATTRIBUTE_COMPRESSED);
	CHECK(_Attributes, FILE_ATTRIBUTE_OFFLINE);
	CHECK(_Attributes, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	CHECK(_Attributes, FILE_ATTRIBUTE_ENCRYPTED);

	if (_Attributes != 0) {
		TRACE("ALSO Attributes %x\n", _Attributes);
	}

	ULONG _ShareAccess = ShareAccess;
	TRACE("ShareAccess:\n");
	CHECK(_ShareAccess, FILE_SHARE_READ);
	CHECK(_ShareAccess, FILE_SHARE_WRITE);
	CHECK(_ShareAccess, FILE_SHARE_DELETE);

	if (_ShareAccess != 0) {
		TRACE("ALSO %x\n", _ShareAccess);
	}

	ULONG _CreateDisposition = CreateDisposition;
	TRACE("CreateDisposition:\n");
	CHECK(_CreateDisposition, FILE_SUPERSEDE);
	CHECK(_CreateDisposition, FILE_CREATE);
	CHECK(_CreateDisposition, FILE_OPEN);
	CHECK(_CreateDisposition, FILE_OPEN_IF);
	CHECK(_CreateDisposition, FILE_OVERWRITE);
	CHECK(_CreateDisposition, FILE_OVERWRITE_IF);

	if (_CreateDisposition != 0) {
		TRACE("ALSO %x\n", _CreateDisposition);
	}

	ULONG _CreateOptions = CreateOptions;
	TRACE("CreateOptions:\n");
	CHECK(_CreateOptions, FILE_DIRECTORY_FILE);
	CHECK(_CreateOptions, FILE_WRITE_THROUGH);
	CHECK(_CreateOptions, FILE_SEQUENTIAL_ONLY);
	CHECK(_CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
	CHECK(_CreateOptions, FILE_SYNCHRONOUS_IO_ALERT);
	CHECK(_CreateOptions, FILE_SYNCHRONOUS_IO_NONALERT);
	CHECK(_CreateOptions, FILE_NON_DIRECTORY_FILE);
	CHECK(_CreateOptions, FILE_CREATE_TREE_CONNECTION);
	CHECK(_CreateOptions, FILE_COMPLETE_IF_OPLOCKED);
	CHECK(_CreateOptions, FILE_NO_EA_KNOWLEDGE);
	CHECK(_CreateOptions, FILE_OPEN_FOR_RECOVERY);

	if (_CreateOptions != 0) {
		TRACE("ALSO %x\n", _CreateOptions);
	}

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

	FILE_CREATE_INFO info( DesiredAccess, Attributes, CreateOptions, CreateDisposition );

	info.Path.Set( *oa.ObjectName );
	info.Attributes = oa.Attributes;

	// Check for NPFS aliases (hardcoded here for now)
	CUNICODE_STRING NpfsLsassAlias[4];
	NpfsLsassAlias[0].Set(L"\\??\\PIPE\\protected_storage");
	NpfsLsassAlias[1].Set(L"\\??\\PIPE\\netlogon");
	NpfsLsassAlias[2].Set(L"\\??\\PIPE\\lsarpc");
	NpfsLsassAlias[3].Set(L"\\??\\PIPE\\samr");

	CUNICODE_STRING NpfsNtsvcsAlias;
	NpfsNtsvcsAlias.Set(L"\\??\\PIPE\\svcctl");

	if (info.Path.IsEqual(NpfsNtsvcsAlias))
	{
		info.Path.Set(L"\\??\\PIPE\\ntsvcs");
	}
	else
	{
		for (ULONG i = 0; i < sizeof(NpfsLsassAlias) / sizeof(NpfsLsassAlias[0]); i++)
		{
			if (info.Path.IsEqual(NpfsLsassAlias[i]))
			{
				info.Path.Set(L"\\??\\PIPE\\lsass");
				break;
			}
		}
	}

	OBJECT *obj = 0;
	r = OpenRoot( obj, info );
	if (r >= STATUS_SUCCESS)
	{
		r = AllocUserHandle( obj, DesiredAccess, FileHandle );
		Release( obj );
	}

	iosb.Status = r;
	if ( ( CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF ) && !info.created )
		iosb.Information = FILE_OVERWRITTEN;
	else
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
	TRACE("%p %p %p %p %p %08lx %p %lu %p %lu\n", FileHandle,
		  EventHandle, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode,
		  InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	ULONG FsCcDeviceType = FsControlCode >> 16;
	ULONG FsCcAccess = (FsControlCode >> 14) & 0x3;
	ULONG FsCcFunction = (FsControlCode >> 2) & 0xFFF;
	ULONG FsCcMethod = FsControlCode & 0x3;

	TRACE("Device Type: 0x%lx, Access: %ld, Function: %ld, Method: %ld\n", FsCcDeviceType, FsCcAccess, FsCcFunction, FsCcMethod);

	IO_STATUS_BLOCK iosb;
	IO_OBJECT *io = 0;
	EVENT *event = 0;
	NTSTATUS r;

	r = ObjectFromHandle( io, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	if (EventHandle)
	{
		FIXME("\n");
#if 0
		r = ObjectFromHandle( event, EventHandle, SYNCHRONIZE );
		if (r < STATUS_SUCCESS)
			return r;
#endif
	}

	// Just return success
	if (FsControlCode == FSCTL_IS_VOLUME_MOUNTED)
	{
		r = STATUS_SUCCESS;
	}
	else
	{
		r = io->FSControl(event, iosb, FsControlCode,
			InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	}

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
	FIXME("%p %p %p %p %p %08lx %p %lu %p %lu\n",
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

	TRACE("%p %p %p %p %p %p %lu %p %p\n", FileHandle, Event, ApcRoutine,
		  ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	IO_OBJECT *io = 0;
	NTSTATUS r;

	r = ObjectFromHandle( io, FileHandle, 0 );
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
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	FILE_BASIC_INFORMATION info;

	TRACE("%p %p\n", ObjectAttributes, FileInformation);

	r = oa.CopyFromUser( ObjectAttributes );
	if (r)
		return r;

	TRACE("root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	if (!oa.ObjectName || !oa.ObjectName->Buffer)
		return STATUS_INVALID_PARAMETER;

	// FIXME: use oa.RootDirectory
	OBJECT *obj = 0;
	FILE_CREATE_INFO open_info( 0, 0, 0, FILE_OPEN );
	open_info.Path.Set( *oa.ObjectName );
	open_info.Attributes = oa.Attributes;
	r = OpenRoot( obj, open_info );
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
	Release( obj );

	r = CopyToUser( FileInformation, &info, sizeof info );
	if (r < STATUS_SUCCESS)
		return r;

	return r;
}

NTSTATUS NTAPI NtQueryFullAttributesFile(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	FILE_NETWORK_OPEN_INFORMATION info;

	TRACE("%p %p\n", ObjectAttributes, FileInformation);

	r = oa.CopyFromUser(ObjectAttributes);
	if (r)
		return r;

	TRACE("root %p attr %08lx %pus\n",
		oa.RootDirectory, oa.Attributes, oa.ObjectName);

	if (!oa.ObjectName || !oa.ObjectName->Buffer)
		return STATUS_INVALID_PARAMETER;

	// FIXME: use oa.RootDirectory
	OBJECT *obj = 0;
	FILE_CREATE_INFO open_info(0, 0, 0, FILE_OPEN);
	open_info.Path.Set(*oa.ObjectName);
	open_info.Attributes = oa.Attributes;
	r = OpenRoot(obj, open_info);
	if (r < STATUS_SUCCESS)
		return r;

	CFILE *file = dynamic_cast<CFILE*>(obj);
	if (file)
	{

		memset(&info, 0, sizeof info);
		r = file->QueryInformation(info);
	}
	else
		r = STATUS_OBJECT_TYPE_MISMATCH;
	Release(obj);

	r = CopyToUser( FileInformation, &info, sizeof info );
	if (r < STATUS_SUCCESS)
		return r;

	return r;
}

NTSTATUS NTAPI NtQueryVolumeInformationFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID VolumeInformation,
	ULONG VolumeInformationLength,
	FS_INFORMATION_CLASS VolumeInformationClass )
{

	TRACE("%x %p %p %ld %x\n", FileHandle, IoStatusBlock, VolumeInformation, VolumeInformationLength, VolumeInformationClass);
	NTSTATUS r;
	IO_OBJECT *io = 0;
	IO_STATUS_BLOCK iosb;
	iosb.Status = STATUS_SUCCESS;
	iosb.Information = 0;

	r = ObjectFromHandle( io, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	CFILE *File = dynamic_cast<CFILE*>( io );
	if (!File) {
		FIXME("Check is volume or external storage\n");
		return STATUS_OBJECT_TYPE_MISMATCH;
	}

	r = VerifyForWrite( IoStatusBlock, sizeof *IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	switch (VolumeInformationClass)
	{
	case FileFsAttributeInformation:
		{
			const wchar_t *FilesystemName;
			FILE_FS_ATTRIBUTE_INFORMATION Info;
			r = GetFsAttributeInformation(File, &Info, &FilesystemName);
			if (r < STATUS_SUCCESS)
				return r;

			r = CopyToUser( VolumeInformation, &Info, sizeof Info );
			if (r < STATUS_SUCCESS)
				return r;

			const ULONG ofs = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
			PWSTR p = (PWSTR)((PBYTE)VolumeInformation + ofs);
			r = CopyToUser( p, FilesystemName, Info.FileSystemNameLength );
			if (r < STATUS_SUCCESS)
				return r;

			iosb.Information = ofs + Info.FileSystemNameLength;
			r = CopyToUser( IoStatusBlock, &iosb, sizeof iosb );
			if (r < STATUS_SUCCESS)
				return r;
		}
		break;
	case FileFsDeviceInformation:
		{
			FIXME("Fake data returned\n");
			FILE_FS_DEVICE_INFORMATION Info;
			Info.DeviceType = FILE_DEVICE_DISK;
			Info.Characteristics = FILE_DEVICE_IS_MOUNTED;

			r = CopyToUser( VolumeInformation, &Info, sizeof Info );
			if (r < STATUS_SUCCESS)
				return r;

			iosb.Information = sizeof Info;
			r = CopyToUser( IoStatusBlock, &iosb, sizeof iosb );
			if (r < STATUS_SUCCESS)
				return r;
		}
		break;
	default:
		FIXME("Unknown VolumeInformationClass %x\n", VolumeInformationClass);
		r = STATUS_NOT_IMPLEMENTED;
	}



	return r;
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
	TRACE("%p %p %p %p %p %p %lu %p %p\n", FileHandle, EventHandle,
		  ApcRoutine, ApcContext, IoStatusBlock,
		  Buffer, Length, ByteOffset, Key);

	NTSTATUS r;
	IO_OBJECT *io = 0;

	r = ObjectFromHandle( io, FileHandle, GENERIC_READ );
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

	if ( ofs != Length ) {
		ERR("Need to read %ld, but read %ld bytes\n", Length, ofs);
		return STATUS_END_OF_FILE;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtDeleteFile(
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;

	TRACE("%p\n", ObjectAttributes);

	r = oa.CopyFromUser( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	TRACE("root %p attr %08lx %pus\n",
		  oa.RootDirectory, oa.Attributes, oa.ObjectName);

	if (!oa.ObjectName || !oa.ObjectName->Buffer)
		return STATUS_INVALID_PARAMETER;

	// FIXME: use oa.RootDirectory
	OBJECT *obj = 0;
	FILE_CREATE_INFO open_info( 0, 0, 0, FILE_OPEN );
	open_info.Path.Set( *oa.ObjectName );
	open_info.Attributes = oa.Attributes;
	r = OpenRoot( obj, open_info );
	if (r < STATUS_SUCCESS)
		return r;

	CFILE *file = dynamic_cast<CFILE*>(obj );
	if (file)
		r = file->Remove();
	else
		r = STATUS_OBJECT_TYPE_MISMATCH;
	Release( obj );
	return r;
}

NTSTATUS NTAPI NtFlushBuffersFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock)
{
	FIXME("%p %p\n", FileHandle, IoStatusBlock);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtCancelIoFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock)
{
	FIXME("%p %p\n", FileHandle, IoStatusBlock);
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

	r = ObjectFromHandle( file, FileHandle, 0 );
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
		FIXME("Unknown information class %d\n", FileInformationClass );
		return STATUS_INVALID_PARAMETER;
	}

	r = CopyFromUser( &info, FileInformation, len );
	if (r < STATUS_SUCCESS)
		return r;

	COMPLETION_PORT *completion_port = 0;

	switch (FileInformationClass)
	{
	case FileDispositionInformation:
		FIXME("delete = %d\n", info.dispos.DeleteFile);
		break;
	case FileCompletionInformation:
		r = ObjectFromHandle( completion_port, info.completion.CompletionPort, IO_COMPLETION_MODIFY_STATE );
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
		FIXME("Unknown FileInformationClass\n");
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
	TRACE("%p %p %p %lu %u\n", FileHandle, IoStatusBlock,
		  FileInformation, FileInformationLength, FileInformationClass);

	CFILE *file = 0;
	NTSTATUS r;

	r = ObjectFromHandle( file, FileHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	union
	{
		FILE_BASIC_INFORMATION basic_info;
		FILE_STANDARD_INFORMATION std_info;
		FILE_ATTRIBUTE_TAG_INFORMATION attrib_info;
		FILE_POSITION_INFORMATION position_info;
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
	case FilePositionInformation:
		len = sizeof info.position_info;
		r = file->QueryInformation( info.position_info );
		break;
	default:
		FIXME("Unknown information class %d\n", FileInformationClass );
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
	FIXME("%p %p %p %lu\n", FileHandle, IoStatusBlock,
		  FileInformation, FileInformationLength);

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQueryQuotaInformationFile(HANDLE,PIO_STATUS_BLOCK,PFILE_USER_QUOTA_INFORMATION,ULONG,BOOLEAN,PFILE_QUOTA_LIST_INFORMATION,ULONG,PSID,BOOLEAN)
{
	FIXME("\n");
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
	TRACE("just returns success...\n");
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtUnlockFile(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PULARGE_INTEGER LockOffset,
	PULARGE_INTEGER LockLength,
	ULONG Key)
{
	TRACE("just returns success...\n");
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
	r = ObjectFromHandle( dir, DirectoryHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	// default (empty) mask matches all...
	CUNICODE_STRING mask;
	if (FileName)
	{
		r = mask.CopyFromUser( FileName );
		if (r < STATUS_SUCCESS)
			return r;

		TRACE("Filename = %pus (len=%d)\n", &mask, mask.Length);
	}

	if (FileInformationClass != FileBothDirectoryInformation)
	{
		FIXME("unimplemented FileInformationClass %d\n", FileInformationClass);
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


