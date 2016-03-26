/*
 * native test suite
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

#include "ntapi.h"
#include "rtlapi.h"
#include "log.h"

void test_rtl_path( void )
{
	BOOLEAN r;
	UNICODE_STRING path;
	WCHAR pathbuf[MAX_PATH], *name = NULL;
	CURDIR dir;
	WCHAR str[] = L"c:\\winnt\\system32\\ntdll.dll";
	WCHAR result[] = L"\\??\\c:\\winnt\\system32\\ntdll.dll";

	init_us(&path, pathbuf);

	dir.Handle = NULL;
	dir.DosPath.Buffer = NULL;
	dir.DosPath.Length = 0;
	dir.DosPath.MaximumLength = 0;

	r = RtlDosPathNameToNtPathName_U( str, &path, &name, &dir );
	ok( r == TRUE, "return wrong\n");

	ok( !memcmp( &str[18], name, sizeof str - 18*2), "namepart wrong\n");

	ok( path.Length = sizeof result - 2, "nt path MaximumLength wrong\n");
	ok( path.MaximumLength = sizeof result - 2, "nt path MaximumLength wrong\n");
	ok( !memcmp( path.Buffer, result, sizeof result - 2 ), "nt path wrong\n");

	ok( dir.Handle == NULL, "Handle not null\n");
	ok( dir.DosPath.Buffer == NULL, "Buffer not null\n");
	ok( dir.DosPath.Length == 0, "Length not zero\n");
	ok( dir.DosPath.MaximumLength == 0, "MaximumLength not zero\n");
}

void test_file_open( void )
{
	WCHAR ntdll[] = L"\\??\\c:\\winnt\\system32\\NTDLL.DLL";
	UNICODE_STRING path;
	OBJECT_ATTRIBUTES oa;
	HANDLE file;
	IO_STATUS_BLOCK iosb;
	NTSTATUS r;

	init_us(&path, ntdll);

	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &path;
	oa.Attributes = 0;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	r = NtOpenFile( &file, GENERIC_READ, NULL, NULL, FILE_SHARE_READ, 0 );
	ok( r == STATUS_ACCESS_VIOLATION, "failed to open file %08lx\n", r);

	r = NtOpenFile( &file, GENERIC_READ, &oa, NULL, FILE_SHARE_READ, 0 );
	ok( r == STATUS_ACCESS_VIOLATION, "failed to open file %08lx\n", r);

	r = NtOpenFile( NULL, GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, 0 );
	ok( r == STATUS_ACCESS_VIOLATION, "failed to open file %08lx\n", r);

	r = NtOpenFile( &file, GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, 0 );
	ok( r == STATUS_OBJECT_NAME_NOT_FOUND, "failed to open file %08lx\n", r);

	oa.Attributes = OBJ_CASE_INSENSITIVE;

	r = NtOpenFile( &file, GENERIC_READ, &oa, NULL, 0, 0 );
	ok( r == STATUS_ACCESS_VIOLATION, "failed to open file %08lx\n", r);

	r = NtOpenFile( &file, GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, 0 );
	ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r);

	r = NtClose( file );
	ok( r == STATUS_SUCCESS, "failed to close handle %08lx\n", r);

	r = NtOpenFile( &file, 0, &oa, &iosb, FILE_SHARE_READ, 0 );
	ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r);

	r = NtClose( file );
	ok( r == STATUS_SUCCESS, "failed to close handle %08lx\n", r);
}

void check_dot(PIO_STATUS_BLOCK iosb, BYTE *buffer)
{
	PFILE_BOTH_DIRECTORY_INFORMATION info = (void*) buffer;

	ok( iosb->Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb->Status);
	ok( iosb->Information == 0x60, "information wrong %08lx\n", iosb->Information);

	ok( info->NextEntryOffset == 0, "NextEntryOffset not zero\n" );
	ok( info->ShortNameLength == 0, "ShortNameLength wrong %d\n", info->ShortNameLength );
	ok( info->ShortName[0] == 0, "ShortName wrong\n" );
	ok( info->FileNameLength == 2, "FileNameLength wrong %ld\n", info->FileNameLength );
	ok( info->FileName[0] == '.', "FileName wrong\n" );
	ok( info->FileAttributes == FILE_ATTRIBUTE_DIRECTORY, "FileAttributes wrong %08lx\n", info->FileAttributes );
}

void check_dotdot(PIO_STATUS_BLOCK iosb, BYTE *buffer)
{
	PFILE_BOTH_DIRECTORY_INFORMATION info = (void*) buffer;

	ok( iosb->Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb->Status);
	ok( iosb->Information == 0x62, "information wrong %08lx\n", iosb->Information);

	ok( info->NextEntryOffset == 0, "NextEntryOffset not zero\n" );
	ok( info->ShortNameLength == 0, "ShortNameLength wrong %d\n", info->ShortNameLength );
	ok( info->ShortName[0] == 0, "ShortName wrong\n" );
	ok( info->FileNameLength == 4, "FileNameLength wrong %ld\n", info->FileNameLength );
	ok( info->FileName[0] == '.' && info->FileName[1] == '.', "FileName wrong\n" );
	ok( info->FileAttributes == FILE_ATTRIBUTE_DIRECTORY, "FileAttributes wrong %08lx\n", info->FileAttributes );
}

void check_edb(PIO_STATUS_BLOCK iosb, BYTE *buffer)
{
	PFILE_BOTH_DIRECTORY_INFORMATION info = (void*) buffer;

	ok( iosb->Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb->Status);
	ok( iosb->Information == 0x6c, "information wrong %08lx\n", iosb->Information);

	ok( info->NextEntryOffset == 0, "NextEntryOffset not zero\n" );
	ok( info->ShortNameLength == 0, "ShortNameLength wrong %d\n", info->ShortNameLength );
	ok( info->ShortName[0] == 0, "ShortName wrong\n" );
	ok( info->FileNameLength == 14, "FileNameLength wrong %ld\n", info->FileNameLength );
	ok( info->FileName[0] == 'e' && info->FileName[1] == 'd', "FileName wrong\n" );
	ok( info->FileAttributes == FILE_ATTRIBUTE_ARCHIVE, "FileAttributes wrong %08lx\n", info->FileAttributes );
}

NTSTATUS query_one(POBJECT_ATTRIBUTES oa, PWSTR mask_str, BYTE *buffer, ULONG len, PIO_STATUS_BLOCK iosb)
{
	UNICODE_STRING mask;
	HANDLE dir = 0;
	NTSTATUS r;

	init_us(&mask, mask_str);

	r = NtOpenFile( &dir, GENERIC_READ | FILE_LIST_DIRECTORY, oa, iosb,
				FILE_SHARE_READ, FILE_DIRECTORY_FILE );
	if( r != STATUS_SUCCESS)
		return r;

	r = NtQueryDirectoryFile( dir, 0, 0, 0, iosb, buffer, len, FileBothDirectoryInformation, TRUE, &mask, TRUE);

	NtClose( dir );
	return r;
}

void test_query_directory( void )
{
	WCHAR dirname[] = L"\\??\\c:\\filetest";
	WCHAR filename[] = L"\\??\\c:\\filetest\\edb.chk";
	WCHAR edb[] = L"edb<\"*";
	UNICODE_STRING path, mask;
	OBJECT_ATTRIBUTES oa;
	HANDLE dir, file;
	IO_STATUS_BLOCK iosb;
	BYTE buffer[0x100];
	NTSTATUS r;

	iosb.Status = ~0;
	iosb.Information = ~0;

	init_us(&mask, edb);

	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &path;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	init_us(&path, filename);
	r = NtDeleteFile( &oa );

	// delete the file to ensure preconditions
	init_us(&path, dirname);
	r = NtDeleteFile( &oa );

	// create a test directory
	r = NtCreateFile( &dir, GENERIC_READ | GENERIC_WRITE | FILE_LIST_DIRECTORY, &oa, &iosb,
			0, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, FILE_CREATE, FILE_DIRECTORY_FILE, 0, 0 );
	ok( r == STATUS_SUCCESS, "failed to create dir %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	// add a file to the directory
	init_us(&path, filename);

	r = NtCreateFile( &file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb,
			0, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ, FILE_CREATE, 0, 0, 0 );
	ok( r == STATUS_SUCCESS, "failed to create file %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	r = NtClose( file );
	ok( r == STATUS_SUCCESS, "status wrong %08lx\n", r);

	// query first file... should be "."
	r = NtQueryDirectoryFile( dir, 0, 0, 0, &iosb, buffer, sizeof buffer, FileBothDirectoryInformation, TRUE, 0, 0);
	ok( r == STATUS_SUCCESS, "failed to query directory %08lx\n", r);
	check_dot(&iosb, buffer);

	// query second file... should be ".."
	r = NtQueryDirectoryFile( dir, 0, 0, 0, &iosb, buffer, sizeof buffer, FileBothDirectoryInformation, TRUE, 0, 0);
	ok( r == STATUS_SUCCESS, "failed to query directory %08lx\n", r);
	check_dotdot(&iosb, buffer);

	// query third file... should be "edb.chk"
	r = NtQueryDirectoryFile( dir, 0, 0, 0, &iosb, buffer, sizeof buffer, FileBothDirectoryInformation, TRUE, 0, 0);
	ok( r == STATUS_SUCCESS, "failed to query directory %08lx\n", r);
	check_edb(&iosb, buffer);

	// no more files...
	r = NtQueryDirectoryFile( dir, 0, 0, 0, &iosb, buffer, sizeof buffer, FileBothDirectoryInformation, TRUE, 0, 0);
	ok( r == STATUS_NO_MORE_FILES, "failed to query directory %08lx\n", r);

	// try with a mask
	r = NtQueryDirectoryFile( dir, 0, 0, 0, &iosb, buffer, sizeof buffer, FileBothDirectoryInformation, TRUE, &mask, TRUE);
	ok( r == STATUS_SUCCESS, "failed to query directory %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	check_dot(&iosb, buffer);

	r = NtClose( dir );
	ok( r == STATUS_SUCCESS, "failed to close handle %08lx\n", r);

	// set oa to point the the directory again
	init_us(&path, dirname);

	// re-open the file and scan with a mask
	// looks like the mask is set on the first scan after opening the directory
	r = query_one(&oa, edb, buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_edb(&iosb, buffer);

	// what happens if the mask is present but empty?
	r = query_one(&oa, L"", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_dot(&iosb, buffer);

	// how does * work?
	r = query_one(&oa, L"*", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_dot(&iosb, buffer);

	// how does * work?
	r = query_one(&oa, L"*.*", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_dot(&iosb, buffer);

	// what does *e return?
	r = query_one(&oa, L"e*", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_edb(&iosb, buffer);

	// can we get back ..
	r = query_one(&oa, L"..", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// what about ... ?
	r = query_one(&oa, L"...", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// does ? work
	r = query_one(&oa, L"??", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// does ? work
	r = query_one(&oa, L"?.", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// exact match
	r = query_one(&oa, L"edb.chk", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_edb(&iosb, buffer);

	// almost exact match
	r = query_one(&oa, L"edb.ch", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// case insensitive match
	r = query_one(&oa, L"EDB.CHK", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_edb(&iosb, buffer);

	// dot star?
	r = query_one(&oa, L"edb.*", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_SUCCESS, "query failed %08lx\n", r);
	check_edb(&iosb, buffer);

	// bad masks
	r = query_one(&oa, L"|", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);
	r = query_one(&oa, L":", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);
	r = query_one(&oa, L"/", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);
	r = query_one(&oa, L"\\", buffer, sizeof buffer, &iosb);
	ok( r == STATUS_NO_SUCH_FILE, "query failed %08lx\n", r);

	// delete the file
	init_us(&path, filename);
	r = NtDeleteFile( &oa );
	ok( r == STATUS_SUCCESS, "failed to delete directory %08lx\n", r);

	// delete the directory
	init_us(&path, dirname);
	r = NtDeleteFile( &oa );
	ok( r == STATUS_SUCCESS, "failed to delete directory %08lx\n", r);
}


void test_file_create( void )
{
	WCHAR filename[] = L"\\??\\c:\\testfile.txt";
    char szWrite[] = {"Test String"};
	OBJECT_ATTRIBUTES oa;
	HANDLE file;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING path;
	NTSTATUS r;

	init_us(&path, filename);
	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &path;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	//error, no such file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	ok( r == STATUS_OBJECT_NAME_NOT_FOUND, "failed to check file existance %08lx\n", r);

	//ok, creating file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
	ok( r == STATUS_SUCCESS, "failed to create file %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

	//not implemented
	//error, file already opened
	//r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
    //            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
	//ok( r == STATUS_OBJECT_NAME_COLLISION, "error, opening already opened file %08lx\n", r);

	//ok, opening file
    r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_OPENED, "information wrong %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

    //ok, file exists FILE_OPEN_IF
    r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_OPENED, "information wrong %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

	r = NtDeleteFile(&oa);
	ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);

	//ok, file doesn't exist, but we create one
    r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

	r = NtDeleteFile(&oa);
	ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);

	//error, no such file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ok( r == STATUS_OBJECT_NAME_NOT_FOUND, "failed to check file existance %08lx\n", r );

	//ok, create file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

    //ok, write some data
    r = NtWriteFile(file, NULL, NULL, NULL, &iosb, szWrite, strlen(szWrite), 0, 0);
    ok( r == STATUS_SUCCESS, "failed to write in file %08lx\n", r);
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
    ok( iosb.Information == strlen(szWrite), "information wrong %ld, strlen %d\n", iosb.Information, strlen(szWrite));

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

	//ok, now we should overwrite file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_OVERWRITTEN, "information wrong %08lx\n", iosb.Information);

    //ok, file must be empty
    char data[100];
    memset(data, 0, 100);
    r = NtReadFile(file, NULL, NULL, NULL, &iosb, data, 100, NULL, NULL);
    ok( r == STATUS_END_OF_FILE, "failed to read file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == 0, "wrong size %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);
	r = NtDeleteFile(&oa);
	ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);

	//ok, we create new file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);
	r = NtDeleteFile(&oa);
	ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);


	//ok, create new file with only read rights
	r = NtCreateFile(&file, FILE_GENERIC_READ, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

    //error, no access
    r = NtWriteFile(file, NULL, NULL, NULL, &iosb, szWrite, strlen(szWrite), 0, 0);
    //not correct, should return STATUS_ACCESS_DENIED
	ok( r == STATUS_IO_DEVICE_ERROR, "failed to check access rights %08lx\n", r );

	//ok
	r = NtReadFile(file, NULL, NULL, NULL, &iosb, data, 0, NULL, NULL);
    ok( r == STATUS_SUCCESS, "failed to open file %08lx\n", r );
    ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status );
    ok( iosb.Information == 0, "information wrong %08lx\n", iosb.Information);



	r = NtClose(file);
	ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);
	r = NtDeleteFile(&oa);
	ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);

}

void test_query_volume()
{
	WCHAR filename[] = L"\\??\\c:\\testfile.txt";
	OBJECT_ATTRIBUTES oa;
	HANDLE file;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING path;
	NTSTATUS r;

	init_us(&path, filename);
	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &path;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	//create file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
	ok( r == STATUS_SUCCESS, "failed to create file %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	//bad way to allocate 
	const int size = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + 64;
	char data[size];
    FILE_FS_ATTRIBUTE_INFORMATION* fs_attr = (FILE_FS_ATTRIBUTE_INFORMATION*) data;

    r = NtQueryVolumeInformationFile(0, &iosb, fs_attr, size, FileFsAttributeInformation);
    ok( r == STATUS_INVALID_HANDLE, "wrong status %08lx\n", r);

    r = NtQueryVolumeInformationFile(file, 0, fs_attr, size, FileFsAttributeInformation);
    ok( r == STATUS_ACCESS_VIOLATION, "wrong status %08lx\n", r);

    r = NtQueryVolumeInformationFile(file, &iosb, 0, size, FileFsAttributeInformation);
    ok( r == STATUS_ACCESS_VIOLATION, "wrong status %08lx\n", r);

    //ok
    r = NtQueryVolumeInformationFile(file, &iosb, fs_attr, size, FileFsAttributeInformation);
    ok( r == STATUS_SUCCESS, "failed to get volume information %08lx\n", r);

    FILE_FS_DEVICE_INFORMATION* fs_device = (FILE_FS_DEVICE_INFORMATION*) data;
    r = NtQueryVolumeInformationFile(file, &iosb, fs_device, size, FileFsDeviceInformation);
    ok( r == STATUS_SUCCESS, "failed to get device info %08lx\n", r);

    

    r = NtClose(file);
    ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

    r = NtDeleteFile(&oa);
    ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);

}

void test_query_file()
{
	WCHAR filename[] = L"\\??\\c:\\testfile.txt";
	OBJECT_ATTRIBUTES oa;
	HANDLE file;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING path;
	NTSTATUS r;

	init_us(&path, filename);
	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = &path;
	oa.Attributes = OBJ_CASE_INSENSITIVE;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	//create file
	r = NtCreateFile(&file, GENERIC_READ | GENERIC_WRITE, &oa, &iosb, 0,
                FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
	ok( r == STATUS_SUCCESS, "failed to create file %08lx\n", r);
	ok( iosb.Status == STATUS_SUCCESS, "status wrong %08lx\n", iosb.Status);
	ok( iosb.Information == FILE_CREATED, "information wrong %08lx\n", iosb.Information);

	FILE_BASIC_INFORMATION info;
    memset(&info, 0, sizeof info);
    r = NtQueryAttributesFile(&oa, &info);
    ok( r == STATUS_SUCCESS, "failed to get basic attributes %08lx\n", r);
    ok( info.CreationTime.QuadPart != 0, "time attributes must be non zero %08lx\n", info.CreationTime.QuadPart);
    ok( info.FileAttributes == 0, "file attributes should be zero %08lx\n", info.FileAttributes);

    r = NtClose(file);
    ok( r == STATUS_SUCCESS, "failed to close file %08lx\n", r);

    r = NtDeleteFile(&oa);
    ok( r == STATUS_SUCCESS, "failed to delete file %08lx\n", r);
}

void NtProcessStartup( void )
{
	log_init();

	test_rtl_path();
	test_file_create();
	test_file_open();
	test_query_file();
	test_query_directory();
	test_query_volume();

	log_fini();
}
