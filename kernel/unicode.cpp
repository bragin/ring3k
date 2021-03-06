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


#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "unicode.h"
#include "ntcall.h"
#include "debug.h"

DEFAULT_DEBUG_CHANNEL(unicode);

UINT StrLenW(LPCWSTR str)
{
	UINT n = 0;
	while(str[n]) n++;
	return n;
}

LPWSTR StrCpyW( LPWSTR dest, LPCWSTR src )
{
	while ((*dest++ = *src++))
		;
	return dest;
}

LPWSTR StrCatW( LPWSTR dest, LPCWSTR src )
{
	while (*dest) dest++;
	while ((*dest++ = *src++))
		;
	return dest;
}
#include <stdio.h>
CUNICODE_STRING::CUNICODE_STRING() :
	Buf(0)
{
	Buffer = 0;
	Length = 0;
	MaximumLength = 0;
}

CUNICODE_STRING::CUNICODE_STRING( const UNICODE_STRING& source ) :
	Buf(0)
{
	Buffer = 0;
	Length = 0;
	MaximumLength = 0;
	assert (STATUS_SUCCESS == Copy( &source ));
}

CUNICODE_STRING::CUNICODE_STRING( CUNICODE_STRING& source ) :
	Buf(0)
{
	Buffer = 0;
	Length = 0;
	MaximumLength = 0;
	assert (STATUS_SUCCESS == Copy( &source ));
}

CUNICODE_STRING::CUNICODE_STRING( const CUNICODE_STRING& source ) :
	Buf(0)
{
	Buffer = 0;
	Length = 0;
	MaximumLength = 0;
	assert (STATUS_SUCCESS == Copy( &source ));
}

void CUNICODE_STRING::Set( UNICODE_STRING& us )
{
	Clear();
	Buffer = us.Buffer;
	Length = us.Length;
	MaximumLength = us.MaximumLength;
}

void CUNICODE_STRING::Set( PCWSTR str )
{
	Clear();
	Buffer = const_cast<PWSTR>( str );
	Length = StrLenW( str ) * sizeof(WCHAR);
	MaximumLength = 0;
}

NTSTATUS CUNICODE_STRING::CopyFromUser(PUNICODE_STRING ptr)
{
	NTSTATUS r = ::CopyFromUser( static_cast<UNICODE_STRING*>(this), ptr, sizeof (UNICODE_STRING) );
	if (r < STATUS_SUCCESS)
		return r;
	return CopyWStrFromUser();
}

NTSTATUS CUNICODE_STRING::CopyWStrFromUser()
{
	if (Buf)
		delete[] Buf;
	Buf = 0;
	if (Length&1)
		return STATUS_INVALID_PARAMETER;
	if (Buffer)
	{
		Buf = new WCHAR[ Length/sizeof(WCHAR) ];
		if (!Buf)
			return STATUS_NO_MEMORY;
		NTSTATUS r = ::CopyFromUser( Buf, Buffer, Length );
		if (r < STATUS_SUCCESS)
		{
			delete[] Buf;
			Buf = 0;
			return r;
		}
		Buffer = Buf;
	}
	return STATUS_SUCCESS;
}

NTSTATUS CUNICODE_STRING::CopyWStrFromUser( PWSTR String, ULONG _Length )
{
	Buffer = String;
	Length = _Length;
	return CopyWStrFromUser();
}

NTSTATUS CUNICODE_STRING::Copy( const UNICODE_STRING* ptr )
{
	Clear();
	Length = ptr->Length;
	if (Length&1)
		return STATUS_INVALID_PARAMETER;
	MaximumLength = ptr->MaximumLength;
	if (ptr->Buffer)
	{
		Buf = new WCHAR[ Length/sizeof(WCHAR) ];
		if (!Buf)
			return STATUS_NO_MEMORY;
		memcpy( Buf, ptr->Buffer, Length );
		Buffer = Buf;
	}
	else
		Buffer = 0;
	return STATUS_SUCCESS;
}

// returned size include nul terminator
ULONG CUNICODE_STRING::Utf8ToWChar( const unsigned char *str, ULONG len, WCHAR *buf )
{
	unsigned int i, n;

	i = 0;
	n = 0;
	while (str[i])
	{
		if ((str[i]&0x80) == 0)
		{
			if (buf)
				buf[n] = str[i];
			n++;
			i++;
			continue;
		}
		if ((str[i]&0xc8) == 0xc0 &&
			(str[i+1]&0xc0) == 0x80)
		{
			if (buf)
				buf[n] = ((str[i]&0x3f)<<6) | (str[i+1]&0x3f);
			i+=sizeof(WCHAR);
			n++;
			continue;
		}
		if ((str[i]&0xf0) == 0xe0 &&
			(str[i+1]&0xc0) == 0x80 &&
			(str[i+2]&0xc0) == 0x80)
		{
			if (buf)
				buf[n] = ((str[i]&0x3f)<<12) | ((str[i+1]&0x3f)<<6) | (str[i+2]&0x3f);
			i+=3;
			n++;
			continue;
		}
		ERR("invalid utf8 string %02x %02x %02x\n", str[i], str[i+1], str[i+2]);
		break;
	}
	if (buf)
		buf[n] = 0;

	assert( len == 0 || n <= len );

	return n;
}

bool CUNICODE_STRING::operator==(const CUNICODE_STRING& str) const
{
	return Compare(&str, FALSE);
}

ULONG CUNICODE_STRING::WCharToUtf8( char *str, ULONG max ) const
{
	ULONG n = 0;
	for (ULONG i=0; i<Length/sizeof(WCHAR); i++)
	{
		WCHAR ch = Buffer[i];
		unsigned char ch1, ch2, ch3;
		int needed;

		// calculate the UTF-8 characters needed
		if (ch < 0x80)
		{
			ch1 = ch;
			ch2 = 0;
			ch3 = 0;
			needed = 1;
		}
		else if (ch < 0xfff)
		{
			ch1 = 0xc0 | (ch&0x3f);
			ch2 = 0x80 | ((ch>>6)&0x3f);
			ch3 = 0;
			needed = 2;
		}
		else
		{
			ch1 = 0xe0 | (ch&0x3f);
			ch2 = 0x80 | ((ch>>6)&0x3f);
			ch3 = 0x80 | ((ch>>12)&0x0f);
			needed = 3;
		}

		// don't overflow
		if ((n + needed) >= max)
			break;

		// store the characters
		str[n++] = ch1;
		if (ch2)
			str[n++] = ch2;
		if (ch3)
			str[n++] = ch3;
	}

	// always store a null
	str[n] = 0;
	return n;
}

NTSTATUS CUNICODE_STRING::Copy( const char *str )
{
	const unsigned char *ustr = reinterpret_cast<const unsigned char*>(str);
	return Copy( ustr );
}

void CUNICODE_STRING::Clear()
{
	if (Buf)
		delete[] Buf;
	Buf = 0;
	Length = 0;
	MaximumLength = 0;
	Buffer = 0;
}

NTSTATUS CUNICODE_STRING::Copy( const unsigned char *ustr )
{
	Clear();
	if (!ustr)
		return STATUS_SUCCESS;
	ULONG len = Utf8ToWChar( ustr, 0, 0 );
	Length = len * sizeof (WCHAR);
	Buf = new WCHAR[ len + 1 ];
	if (!Buf)
		return STATUS_NO_MEMORY;
	Utf8ToWChar( ustr, len, Buf );
	Buffer = Buf;
	MaximumLength = 0;
	return STATUS_SUCCESS;
}

NTSTATUS CUNICODE_STRING::Copy( PCWSTR str )
{
	Clear();
	ULONG n = 0;
	while (str[n])
		n++;
	Buf = new WCHAR[n];
	if (!Buf)
		return STATUS_NO_MEMORY;
	Length = n*sizeof(WCHAR);
	MaximumLength = Length;
	Buffer = Buf;
	memcpy( Buffer, str, Length );
	return STATUS_SUCCESS;
}

bool CUNICODE_STRING::IsEqual( const UNICODE_STRING& ptr ) const
{
	if (Length != ptr.Length)
		return false;

	return !memcmp(ptr.Buffer, Buffer, Length);
}

CUNICODE_STRING::~CUNICODE_STRING()
{
	Clear();
}

CUNICODE_STRING& CUNICODE_STRING::operator=(const CUNICODE_STRING& in)
{
	Copy(&in);
	return *this;
}

void CUNICODE_STRING::ReplaceChar( wchar_t which, wchar_t to )
{
	for (ULONG i=0;i<Length;i++)
	{
		if (Buffer[i] == which)
			Buffer[i] = to;
	}
}

void CUNICODE_STRING::ToLowerCase()
{
	for (ULONG i=0;i<Length/sizeof(WCHAR);i++)
	{
		Buffer[i] = tolower(Buffer[i]);
	}
}

bool CUNICODE_STRING::operator<(const CUNICODE_STRING& in) const
{
	if (!Buffer || !in.Buffer) return false;

	if (Length != in.Length)
		return Length < in.Length;

	for (ULONG i=0; i<Length/sizeof(WCHAR) ;i++) {
		if (Buffer[i] != in.Buffer[i])
			return Buffer[i] < in.Buffer[i];
	}

	return false;
}

// returns TRUE if strings are the same
bool CUNICODE_STRING::Compare( const UNICODE_STRING *b, BOOLEAN case_insensitive ) const
{
	if (Length != b->Length)
		return FALSE;
	if (!case_insensitive)
		return (0 == memcmp( Buffer, b->Buffer, Length ));

	// FIXME: should use windows case table
	for ( ULONG i = 0; i < Length/sizeof(WCHAR); i++ )
	{
		WCHAR ai, bi;
		ai = tolower( Buffer[i] );
		bi = tolower( b->Buffer[i] );
		if (ai == bi)
			continue;
		return FALSE;
	}
	return TRUE;
}

NTSTATUS CUNICODE_STRING::Concat(const UNICODE_STRING& str)
{
	assert(str.Length % sizeof(WCHAR) == 0);
	return Concat( str.Buffer, str.Length );
}

NTSTATUS CUNICODE_STRING::Concat(const CUNICODE_STRING& str)
{
	return Concat( dynamic_cast<const UNICODE_STRING&>(str) );
}

NTSTATUS CUNICODE_STRING::Concat(PCWSTR Str)
{
	return Concat( Str, StrLenW(Str)*sizeof(WCHAR) );
}

bool CUNICODE_STRING::IsEmpty() const
{
	return Length == 0;
}

NTSTATUS CUNICODE_STRING::Concat(PCWSTR Str, LONG StrLenInBytes)
{
	assert(Length % sizeof(WCHAR) == 0);
	assert(StrLenInBytes % sizeof(WCHAR) == 0);


	WCHAR *OldBuf = Buf;

	Buf = new WCHAR[Length/sizeof(WCHAR) + StrLenInBytes/sizeof(WCHAR)];
	if (!Buf) {
		delete[] OldBuf;
		return STATUS_NO_MEMORY;
	}

	memcpy(Buf, Buffer, Length);
	memcpy(Buf + Length/sizeof(WCHAR), Str, StrLenInBytes);

	Buffer = Buf;
	Length += StrLenInBytes;
	MaximumLength += Length;

	delete[] OldBuf;
	return STATUS_SUCCESS;
}

ULONG CUNICODE_STRING::SkipSlashes()
{
	ULONG len;

	// skip slashes
	len = 0;
	while ((len*sizeof(WCHAR)) < Length && Buffer[len] == '\\')
	{
		Buffer ++;
		Length -= sizeof (WCHAR);
		len++;
	}
	return len;
}

ULONG SkipSlashes(UNICODE_STRING* str)
{
	ULONG len;

	// skip slashes
	len = 0;
	while ((len*sizeof(WCHAR)) < str->Length && str->Buffer[len] == '\\')
	{
		str->Buffer ++;
		str->Length -= sizeof (WCHAR);
		len++;
	}
	return len;
}

COBJECT_ATTRIBUTES::COBJECT_ATTRIBUTES()
{
	POBJECT_ATTRIBUTES oa = static_cast<OBJECT_ATTRIBUTES*>( this );
	memset( oa, 0, sizeof *oa );
}

COBJECT_ATTRIBUTES::~COBJECT_ATTRIBUTES()
{
}

NTSTATUS COBJECT_ATTRIBUTES::CopyFromUser( POBJECT_ATTRIBUTES oa )
{
	NTSTATUS r;

	r = ::CopyFromUser( static_cast<OBJECT_ATTRIBUTES*>( this ), oa, sizeof *oa );
	if (r < STATUS_SUCCESS)
		return r;

	if (Length != sizeof (OBJECT_ATTRIBUTES))
		return STATUS_INVALID_PARAMETER;

	if (ObjectName)
	{
		r = us.CopyFromUser( ObjectName );
		if (r == STATUS_INVALID_PARAMETER)
			r = STATUS_OBJECT_NAME_INVALID;
		if (r < STATUS_SUCCESS)
			return r;
		ObjectName = &us;
	}

	return STATUS_SUCCESS;
}

COBJECT_ATTRIBUTES& COBJECT_ATTRIBUTES::operator=(const COBJECT_ATTRIBUTES& in)
{
	Length = in.Length;
	RootDirectory = in.RootDirectory;
	Attributes = in.Attributes;
	SecurityDescriptor = in.SecurityDescriptor;
	SecurityQualityOfService = in.SecurityQualityOfService;

	us = in.us;
	if (in.ObjectName)
		ObjectName = &us;
	else
		ObjectName = 0;

	return *this;
}

COBJECT_ATTRIBUTES::COBJECT_ATTRIBUTES( const WCHAR *str )
{
	us.Copy( str );
	Length = sizeof (OBJECT_ATTRIBUTES);
	RootDirectory = 0;
	Attributes = OBJ_CASE_INSENSITIVE;
	SecurityDescriptor = 0;
	SecurityQualityOfService = 0;
	ObjectName = &us;
}

// FIXME: should use windows case table
INT StrnCmpW( WCHAR *a, WCHAR *b, ULONG n )
{
	ULONG i;
	WCHAR ai, bi;

	for ( i = 0; i < n; i++ )
	{
		ai = tolower( a[i] );
		bi = tolower( b[i] );
		if (ai == bi)
			continue;
		return ai < bi ? -1 : 1;
	}
	return 0;
}