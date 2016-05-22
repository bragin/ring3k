/*
 * UNICODE_STRING helper
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

#ifndef __UNICODE_H__
#define __UNICODE_H__

#include "winternl.h"

class CUNICODE_STRING : public UNICODE_STRING
{
	WCHAR *Buf;
protected:
	NTSTATUS CopyWStrFromUser();
	ULONG Utf8ToWChar( const unsigned char *str, ULONG len, WCHAR *buf );
public:
	CUNICODE_STRING();
	CUNICODE_STRING( CUNICODE_STRING& source );
	CUNICODE_STRING( const CUNICODE_STRING& source );
	CUNICODE_STRING( const UNICODE_STRING& source );
	void Set( PCWSTR str );
	void Set( const wchar_t* str )
	{
		Set( (PCWSTR) str );
	}
	void Set( UNICODE_STRING& us );
	NTSTATUS CopyFromUser(PUNICODE_STRING ptr);
	NTSTATUS Copy( const UNICODE_STRING* ptr );
	NTSTATUS Copy( const char *ptr );
	NTSTATUS Copy( const unsigned char *ptr );
	NTSTATUS Copy( PCWSTR str );
	NTSTATUS Copy( const wchar_t* str )
	{
		return Copy( (PCWSTR) str );
	}
	bool IsEqual( const UNICODE_STRING& ptr ) const;
	bool IsEmpty() const;
	bool Compare( const UNICODE_STRING* b, BOOLEAN case_insensitive ) const;
	~CUNICODE_STRING();
	CUNICODE_STRING& operator=(const CUNICODE_STRING& in);
	bool operator==(const CUNICODE_STRING& in) const;
	bool operator<(const CUNICODE_STRING& in) const;
	void Clear();
	NTSTATUS CopyWStrFromUser( PWSTR String, ULONG Length );
	ULONG WCharToUtf8( char *str, ULONG max ) const;
	NTSTATUS Concat( const CUNICODE_STRING& str );
	NTSTATUS Concat( const UNICODE_STRING& str );
	NTSTATUS Concat( PCWSTR str );
	NTSTATUS Concat( const wchar_t* str )
	{
		return Concat( (PCWSTR) str);
	}
	void ReplaceChar( wchar_t which, wchar_t to );
	ULONG SkipSlashes();
	void ToLowerCase();

private:
	NTSTATUS Concat( PCWSTR str, LONG size);
};

ULONG SkipSlashes(UNICODE_STRING* name);

class COBJECT_ATTRIBUTES : public OBJECT_ATTRIBUTES
{
	CUNICODE_STRING us;
public:
	explicit COBJECT_ATTRIBUTES();
	explicit COBJECT_ATTRIBUTES( const WCHAR *str );
	~COBJECT_ATTRIBUTES();
	NTSTATUS CopyFromUser( POBJECT_ATTRIBUTES oa );
	COBJECT_ATTRIBUTES& operator=(const COBJECT_ATTRIBUTES& in);
};

UINT StrLenW( LPCWSTR str );
LPWSTR StrCpyW( LPWSTR dest, LPCWSTR src );
LPWSTR StrCatW( LPWSTR dest, LPCWSTR src );
INT StrnCmpW( WCHAR *a, WCHAR *b, ULONG n );
#endif // __UNICODE_H__
