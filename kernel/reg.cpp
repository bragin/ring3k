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


#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "mem.h"
#include "ntcall.h"
#include "unicode.h"

#include "list.h"

DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

struct REGVAL;
struct REGKEY;

typedef LIST_ANCHOR<REGVAL,0> REGVAL_ANCHOR;
typedef LIST_ANCHOR<REGKEY,0> REGKEY_ANCHOR;
typedef LIST_ITER<REGVAL,0> REGVAL_ITER;
typedef LIST_ITER<REGKEY,0> REGKEY_ITER;
typedef LIST_ELEMENT<REGVAL> REGVAL_ELEMENT;
typedef LIST_ELEMENT<REGKEY> REGKEY_ELEMENT;

struct REGVAL
{
	REGVAL_ELEMENT Entry[1];
	CUNICODE_STRING Name;
	ULONG Type;
	ULONG Size;
	BYTE *Data;
public:
	REGVAL( UNICODE_STRING *name, ULONG _type, ULONG _size );
	~REGVAL();
};

struct REGKEY : public OBJECT
{
	REGKEY *Parent;
	CUNICODE_STRING Name;
	CUNICODE_STRING Cls;
	REGKEY_ELEMENT Entry[1];
	REGKEY_ANCHOR Children;
	REGVAL_ANCHOR Values;
public:
	REGKEY( REGKEY *_parent, UNICODE_STRING *_name );
	~REGKEY();
	void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls );
	void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr );
	ULONG NumValues(ULONG& max_name_len, ULONG& max_data_len);
	ULONG NumSubkeys(ULONG& max_name_len, ULONG& max_class_len);
	void Delkey();
	REGKEY *GetChild( ULONG Index );
	NTSTATUS Query(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ReturnLength);
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
};

REGKEY *RootKey;

// FIXME: should use windows case table
INT strncmpW( WCHAR *a, WCHAR *b, ULONG n )
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

BOOLEAN UnicodeStringEqual( PUNICODE_STRING a, PUNICODE_STRING b, BOOLEAN case_insensitive )
{
	if (a->Length != b->Length)
		return FALSE;
	if (case_insensitive)
		return (0 == strncmpW( a->Buffer, b->Buffer, a->Length/2 ));
	return (0 == memcmp( a->Buffer, b->Buffer, a->Length ));
}

REGKEY::REGKEY( REGKEY *_parent, UNICODE_STRING *_name ) :
	Parent( _parent)
{
	Name.Copy( _name );
	if (Parent)
		Parent->Children.Append( this );
}

REGKEY::~REGKEY()
{
	REGKEY_ITER i(Children);
	while (i)
	{
		REGKEY *tmp = i;
		i.Next();
		tmp->Parent = NULL;
		Children.Unlink( tmp );
		Release( tmp );
	}

	REGVAL_ITER j(Values);
	while (j)
	{
		REGVAL *tmp = j;
		j.Next();
		Values.Unlink( tmp );
		delete tmp;
	}
}

bool REGKEY::AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return CheckAccess( required, handle,
						 KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS|KEY_NOTIFY,
						 KEY_SET_VALUE|KEY_CREATE_SUB_KEY|KEY_CREATE_LINK,
						 KEY_ALL_ACCESS );
}

ULONG REGKEY::NumValues(ULONG& max_name_len, ULONG& max_data_len)
{
	ULONG n = 0;
	REGVAL_ITER i(Values);
	max_name_len = 0;
	max_data_len = 0;
	while (i)
	{
		REGVAL *val = i;
		max_name_len = max(max_name_len, val->Name.Length );
		max_data_len = max(max_data_len, val->Size );
		i.Next();
		n++;
	}
	return n;
}

ULONG REGKEY::NumSubkeys(ULONG& max_name_len, ULONG& max_class_len)
{
	ULONG n = 0;
	REGKEY_ITER i(Children);
	max_name_len = 0;
	while (i)
	{
		REGKEY *subkey = i;
		max_name_len = max(max_name_len, subkey->Name.Length );
		max_class_len = max(max_class_len, subkey->Cls.Length );
		i.Next();
		n++;
	}
	return n;
}

void REGKEY::Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls )
{
	TRACE("full information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.ClassOffset = FIELD_OFFSET( KEY_FULL_INFORMATION, Class );
	info.ClassLength = Cls.Length;
	info.SubKeys = NumSubkeys(info.MaxNameLen, info.MaxClassLen);
	info.Values = NumValues(info.MaxValueNameLen, info.MaxValueDataLen);
	keycls = Cls;
	TRACE("class = %pus\n", &Cls );
}

void REGKEY::Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr )
{
	TRACE("basic information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.NameLength = Name.Length;

	namestr = Name;
}

void REGKEY::Delkey()
{
	if ( Parent )
	{
		Parent->Children.Unlink( this );
		Parent = NULL;
		Release( this );
	}
}

REGKEY *REGKEY::GetChild( ULONG Index )
{
	REGKEY_ITER i(Children);
	REGKEY *child;
	while ((child = i) && Index)
	{
		i.Next();
		Index--;
	}
	return child;
}

REGVAL::REGVAL( UNICODE_STRING *_name, ULONG _type, ULONG _size ) :
	Type(_type),
	Size(_size)
{
	Name.Copy(_name);
	Data = new BYTE[Size];
}

REGVAL::~REGVAL()
{
	delete[] Data;
}

VOID PrintKey(REGKEY *key)
{
	while (key) {
		if (!key->Name.Buffer)
			break;
		TRACE("%pws\n",key->Name.Buffer);
		key = key->Parent;
	}
}

ULONG SkipSlashes( UNICODE_STRING *str )
{
	ULONG len;

	// skip slashes
	len = 0;
	while ((len*2) < str->Length && str->Buffer[len] == '\\')
	{
		str->Buffer ++;
		str->Length -= sizeof (WCHAR);
		len++;
	}
	return len;
}

ULONG GetNextSegment( UNICODE_STRING *str )
{
	ULONG n = 0;

	while ( n < str->Length/sizeof(WCHAR) && str->Buffer[ n ] != '\\' )
		n++;

	return n * sizeof (WCHAR);
}

ULONG DoOpenSubkey( REGKEY *&key, UNICODE_STRING *name, bool case_insensitive )
{
	ULONG len;

	SkipSlashes( name );

	len = GetNextSegment( name );
	if (!len)
		return len;

	for (REGKEY_ITER i(key->Children); i; i.Next())
	{
		REGKEY *subkey = i;
		if (len != subkey->Name.Length)
			continue;
		if (case_insensitive)
		{
			if (strncmpW( name->Buffer, subkey->Name.Buffer, len/sizeof(WCHAR) ))
				continue;
		}
		else
		{
			if (memcmp( name->Buffer, subkey->Name.Buffer, len/sizeof(WCHAR) ))
				continue;
		}

		// advance
		key = subkey;
		name->Buffer += len/2;
		name->Length -= len;
		return len;
	}

	return 0;
}

NTSTATUS OpenParseKey( REGKEY *&key, UNICODE_STRING *name, bool case_insensitive  )
{
	while (name->Length && DoOpenSubkey( key, name, case_insensitive ))
		/* repeat */ ;

	if (name->Length)
	{
		TRACE("remaining = %pus\n", name);
		if (name->Length == GetNextSegment( name ))
			return STATUS_OBJECT_NAME_NOT_FOUND;

		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS CreateParseKey( REGKEY *&key, UNICODE_STRING *name, bool& opened_existing )
{
	while (name->Length && DoOpenSubkey( key, name, true ))
		/* repeat */ ;

	opened_existing = (name->Length == 0);

	while (name->Length)
	{
		UNICODE_STRING seg;

		SkipSlashes( name );

		seg.Length = GetNextSegment( name );
		seg.Buffer = name->Buffer;

		key = new REGKEY( key, &seg );
		if (!key)
			return STATUS_NO_MEMORY;

		name->Buffer += seg.Length/2;
		name->Length -= seg.Length;
	}

	return STATUS_SUCCESS;
}

NTSTATUS OpenKey( REGKEY **out, OBJECT_ATTRIBUTES *oa )
{
	UNICODE_STRING parsed_name;
	REGKEY *key = RootKey;
	NTSTATUS r;

	if (oa->RootDirectory)
	{
		r = ObjectFromHandle( key, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		key = RootKey;

	PrintKey(key);

	memcpy( &parsed_name, oa->ObjectName, sizeof parsed_name );
	r = OpenParseKey( key, &parsed_name, oa->Attributes & OBJ_CASE_INSENSITIVE );

	if (r == STATUS_SUCCESS)
		*out = key;

	return r;
}

NTSTATUS CreateKey( REGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing )
{
	UNICODE_STRING parsed_name;
	REGKEY *key = RootKey;
	NTSTATUS r;

	if (!oa->ObjectName)
		return STATUS_ACCESS_VIOLATION;

	if (oa->RootDirectory)
	{
		r = ObjectFromHandle( key, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		key = RootKey;

	memcpy( &parsed_name, oa->ObjectName, sizeof parsed_name );
	r = CreateParseKey( key, &parsed_name, opened_existing );

	if (r == STATUS_SUCCESS)
		*out = key;

	return r;
}

REGVAL *KeyFindValue( REGKEY *key, UNICODE_STRING *us )
{

	for (REGVAL_ITER i(key->Values); i; i.Next())
	{
		REGVAL *val = i;
		if (UnicodeStringEqual( &val->Name, us, TRUE ))
			return val;
	}

	return NULL;
}

NTSTATUS DeleteValue( REGKEY *key, UNICODE_STRING *us )
{
	REGVAL *val;

	//trace("%p %pus\n", key, us);

	val = KeyFindValue( key, us );
	if (!val)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	TRACE("deleting %pus\n", &val->Name);
	key->Values.Unlink( val );
	delete val;
	return STATUS_SUCCESS;
}

/* this doesn't set STATUS_MORE_DATA */
NTSTATUS RegQueryValue(
	REGVAL* val,
	ULONG KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG KeyValueInformationLength,
	ULONG& len )
{
	NTSTATUS r = STATUS_SUCCESS;
	union
	{
		KEY_VALUE_FULL_INFORMATION full;
		KEY_VALUE_PARTIAL_INFORMATION partial;
	} info;
	ULONG info_sz;

	len = 0;

	TRACE("%pus\n", &val->Name);

	memset( &info, 0, sizeof info );

	switch( KeyValueInformationClass )
	{
	case KeyValueFullInformation:
		info_sz = FIELD_OFFSET( KEY_VALUE_FULL_INFORMATION, Name );
		// include nul terminator at the end of the Name
		info.full.DataOffset = info_sz + val->Name.Length + 2;
		len = info.full.DataOffset + val->Size;
		if (KeyValueInformationLength < info_sz)
			return STATUS_BUFFER_TOO_SMALL;

		info.full.Type = val->Type;
		info.full.DataLength = val->Size;
		info.full.NameLength = val->Name.Length;

		r = CopyToUser( KeyValueInformation, &info.full, info_sz );
		if (r < STATUS_SUCCESS)
			break;

		if (len > KeyValueInformationLength)
			return STATUS_BUFFER_OVERFLOW;

		r = CopyToUser( (BYTE*)KeyValueInformation + info_sz,
						  val->Name.Buffer, val->Name.Length );
		if (r < STATUS_SUCCESS)
			break;

		r = CopyToUser( (BYTE*)KeyValueInformation + info.full.DataOffset,
						  val->Data, val->Size );
		break;

	case KeyValuePartialInformation:
		info_sz = FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data );
		len = info_sz + val->Size;
		if (KeyValueInformationLength < info_sz)
			return STATUS_BUFFER_TOO_SMALL;

		info.partial.Type = val->Type;
		info.partial.DataLength = val->Size;

		r = CopyToUser( KeyValueInformation, &info.partial, info_sz );
		if (r < STATUS_SUCCESS)
			break;

		if (len > KeyValueInformationLength)
			return STATUS_BUFFER_OVERFLOW;

		r = CopyToUser( (BYTE*)KeyValueInformation + info_sz, val->Data, val->Size );
		break;

	case KeyValueBasicInformation:
	case KeyValueFullInformationAlign64:
	case KeyValuePartialInformationAlign64:
	default:
		FIXME("RegQueryValue: UNIMPLEMENTED case %ld\n", KeyValueInformationClass);
		r = STATUS_NOT_IMPLEMENTED;
	}

	return r;
}

NTSTATUS NTAPI NtCreateKey(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG TitleIndex,
	PUNICODE_STRING Class,
	ULONG CreateOptions,
	PULONG Disposition )
{
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	REGKEY *key = NULL;

	TRACE("%p %08lx %p %lu %p %lu %p\n", KeyHandle, DesiredAccess,
		  ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition );

	if (Disposition)
	{
		r = VerifyForWrite( Disposition, sizeof *Disposition );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = oa.CopyFromUser( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	TRACE("len %08lx root %p attr %08lx %pus\n",
		  oa.Length, oa.RootDirectory, oa.Attributes, oa.ObjectName);

	CUNICODE_STRING cls;
	if (Class)
	{
		r = cls.CopyFromUser( Class );
		if (r < STATUS_SUCCESS)
			return r;
	}

	bool opened_existing = false;
	r = CreateKey( &key, &oa, opened_existing );
	if (r == STATUS_SUCCESS)
	{
		if (Disposition)
		{
			ULONG dispos = opened_existing ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
			CopyToUser( Disposition, &dispos, sizeof *Disposition );
		}
		key->Cls.Copy( &cls );
		r = AllocUserHandle( key, DesiredAccess, KeyHandle );
		//release( event );
	}
	return r;
}

NTSTATUS NTAPI NtOpenKey(
	PHANDLE KeyHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes )
{
	OBJECT_ATTRIBUTES oa;
	CUNICODE_STRING us;
	NTSTATUS r;
	REGKEY *key = NULL;

	TRACE("%p %08lx %p\n", KeyHandle, DesiredAccess, ObjectAttributes);

	// copies the unicode string before validating object attributes struct
	r = CopyFromUser( &oa, ObjectAttributes, sizeof oa );
	if (r < STATUS_SUCCESS)
		return r;

	r = us.CopyFromUser( oa.ObjectName );
	if (r < STATUS_SUCCESS)
		return r;
	oa.ObjectName = &us;

	if (oa.Length != sizeof oa)
		return STATUS_INVALID_PARAMETER;

	TRACE("len %08lx root %p attr %08lx %pus\n",
		  oa.Length, oa.RootDirectory, oa.Attributes, oa.ObjectName);

	r = OpenKey( &key, &oa );

	TRACE("OpenKey returned %08lx\n", r);

	if (r == STATUS_SUCCESS)
	{
		r = AllocUserHandle( key, DesiredAccess, KeyHandle );
		//release( event );
	}

	return r;
}

NTSTATUS NTAPI NtInitializeRegistry(
	BOOLEAN Setup )
{
	FIXME("%d\n", Setup);
	return STATUS_SUCCESS;
}

NTSTATUS check_key_value_info_class( KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass )
{
	switch( KeyValueInformationClass )
	{
	case KeyValueFullInformation:
		break;
	case KeyValuePartialInformation:
		break;
	case KeyValueBasicInformation:
		break;
	case KeyValueFullInformationAlign64:
	case KeyValuePartialInformationAlign64:
		FIXME("not implemented %d\n", KeyValueInformationClass);
		return STATUS_NOT_IMPLEMENTED;
	default:
		return STATUS_INVALID_PARAMETER;
	}
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtQueryValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG KeyValueInformationLength,
	PULONG ResultLength )
{
	CUNICODE_STRING us;
	NTSTATUS r;
	ULONG len;
	REGKEY *key;
	REGVAL *val;

	TRACE("%p %p %d %p %lu %p\n", KeyHandle, ValueName, KeyValueInformationClass,
		  KeyValueInformation, KeyValueInformationLength, ResultLength );

	r = check_key_value_info_class( KeyValueInformationClass );
	if (r < STATUS_SUCCESS)
		return r;

	r = ObjectFromHandle( key, KeyHandle, KEY_QUERY_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	r = us.CopyFromUser( ValueName );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( ResultLength, sizeof *ResultLength );
	if (r < STATUS_SUCCESS)
		return r;

	TRACE("%pus\n", &us);

	val = KeyFindValue( key, &us );
	if (!val)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	r = RegQueryValue( val, KeyValueInformationClass, KeyValueInformation,
						 KeyValueInformationLength, len );

	CopyToUser( ResultLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtSetValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	ULONG TitleIndex,
	ULONG Type,
	PVOID Data,
	ULONG DataSize )
{
	CUNICODE_STRING us;
	REGKEY *key;
	NTSTATUS r;

	TRACE("%p %p %lu %lu %p %lu\n", KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

	r = ObjectFromHandle( key, KeyHandle, KEY_SET_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	r = us.CopyFromUser( ValueName );
	if (r == STATUS_SUCCESS)
	{
		REGVAL *val;

		val = new REGVAL( &us, Type, DataSize );
		if (val)
		{
			r = CopyFromUser( val->Data, Data, DataSize );
			if (r == STATUS_SUCCESS)
			{
				DeleteValue( key, &us );
				key->Values.Append( val );
			}
			else
				delete val;
		}
		else
			r = STATUS_NO_MEMORY;
	}

	return r;
}

NTSTATUS NTAPI NtEnumerateValueKey(
	HANDLE KeyHandle,
	ULONG Index,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG KeyValueInformationLength,
	PULONG ResultLength )
{
	REGKEY *key;
	ULONG len = 0;
	NTSTATUS r = STATUS_SUCCESS;

	TRACE("%p %lu %u %p %lu %p\n", KeyHandle, Index, KeyValueInformationClass,
		  KeyValueInformation, KeyValueInformationLength, ResultLength );

	r = ObjectFromHandle( key, KeyHandle, KEY_QUERY_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( ResultLength, sizeof *ResultLength );
	if (r < STATUS_SUCCESS)
		return r;

	REGVAL_ITER i(key->Values);
	for ( ; i && Index; i.Next())
		Index--;

	if (!i)
		return STATUS_NO_MORE_ENTRIES;

	r = RegQueryValue( i, KeyValueInformationClass, KeyValueInformation,
						 KeyValueInformationLength, len );

	CopyToUser( ResultLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtDeleteValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName )
{
	CUNICODE_STRING us;
	NTSTATUS r;
	REGKEY *key;

	TRACE("%p %p\n", KeyHandle, ValueName);

	r = us.CopyFromUser( ValueName );
	if (r < STATUS_SUCCESS)
		return r;

	r = ObjectFromHandle( key, KeyHandle, KEY_SET_VALUE );
	if (r < STATUS_SUCCESS)
		return r;
	r = DeleteValue( key, &us );

	return r;
}

NTSTATUS NTAPI NtDeleteKey(
	HANDLE KeyHandle)
{
	NTSTATUS r;
	REGKEY *key = 0;
	r = ObjectFromHandle( key, KeyHandle, DELETE );
	if (r < STATUS_SUCCESS)
		return r;

	key->Delkey();

	return r;
}

NTSTATUS NTAPI NtFlushKey(
	HANDLE KeyHandle)
{
	REGKEY *key = 0;
	NTSTATUS r = ObjectFromHandle( key, KeyHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;
	FIXME("flush!\n");
	return r;
}

NTSTATUS NTAPI NtSaveKey(
	HANDLE KeyHandle,
	HANDLE FileHandle)
{
	FIXME("%p %p\n", KeyHandle, FileHandle);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtSaveMergedKeys(
	HANDLE KeyHandle1,
	HANDLE KeyHandle2,
	HANDLE FileHandle)
{
	FIXME("%p %p %p\n", KeyHandle1, KeyHandle2, FileHandle);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtRestoreKey(
	HANDLE KeyHandle,
	HANDLE FileHandle,
	ULONG Flags)
{
	FIXME("%p %p %08lx\n", KeyHandle, FileHandle, Flags);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtLoadKey(
	POBJECT_ATTRIBUTES KeyObjectAttributes,
	POBJECT_ATTRIBUTES FileObjectAttributes)
{
	FIXME("%p %p\n", KeyObjectAttributes, FileObjectAttributes);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtUnloadKey(
	POBJECT_ATTRIBUTES KeyObjectAttributes)
{
	FIXME("%p\n", KeyObjectAttributes);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQueryOpenSubKeys(
	POBJECT_ATTRIBUTES KeyObjectAttributes,
	PULONG NumberOfKeys)
{
	FIXME("%p %p\n", KeyObjectAttributes, NumberOfKeys);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtReplaceKey(
	POBJECT_ATTRIBUTES NewFileObjectAttributes,
	HANDLE KeyHandle,
	POBJECT_ATTRIBUTES OldFileObjectAttributes)
{
	FIXME("%p %p %p\n", NewFileObjectAttributes,
		  KeyHandle, OldFileObjectAttributes);
	return STATUS_NOT_IMPLEMENTED;
}

bool KeyInfoClassValid( KEY_INFORMATION_CLASS cls )
{
	switch (cls)
	{
	case KeyNodeInformation:
	case KeyBasicInformation:
	case KeyFullInformation:
		return true;
	}
	return false;
}

NTSTATUS NTAPI NtEnumerateKey(
	HANDLE KeyHandle,
	ULONG Index,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID KeyInformation,
	ULONG KeyInformationLength,
	PULONG ResultLength)
{
	REGKEY *key = 0;
	NTSTATUS r = ObjectFromHandle( key, KeyHandle, KEY_ENUMERATE_SUB_KEYS );
	if (r < STATUS_SUCCESS)
		return r;

	if (ResultLength)
	{
		r = VerifyForWrite( ResultLength, sizeof *ResultLength );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (!KeyInfoClassValid(KeyInformationClass))
		return STATUS_INVALID_INFO_CLASS;

	REGKEY *child = key->GetChild( Index );
	if (!child)
		return STATUS_NO_MORE_ENTRIES;

	return child->Query( KeyInformationClass, KeyInformation, KeyInformationLength, ResultLength );
}

NTSTATUS NTAPI NtNotifyChangeKey(
	HANDLE KeyHandle,
	HANDLE EventHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG NotifyFilter,
	BOOLEAN WatchSubtree,
	PVOID Buffer,
	ULONG BufferLength,
	BOOLEAN Asynchronous)
{
	REGKEY *key = 0;
	NTSTATUS r = ObjectFromHandle( key, KeyHandle, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	FIXME("does nothing...\n");

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtNotifyChangeMultipleKeys(
	HANDLE KeyHandle,
	ULONG Flags,
	POBJECT_ATTRIBUTES KeyObjectAttributes,
	HANDLE EventHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG NotifyFilter,
	BOOLEAN WatchSubtree,
	PVOID Buffer,
	ULONG BufferLength,
	BOOLEAN Asynchronous)
{
	FIXME("\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtQueryKey(
	HANDLE KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID KeyInformation,
	ULONG KeyInformationLength,
	PULONG ReturnLength)
{
	if (!KeyInfoClassValid(KeyInformationClass))
		return STATUS_INVALID_INFO_CLASS;

	NTSTATUS r;
	r = VerifyForWrite( ReturnLength, sizeof *ReturnLength );
	if (r < STATUS_SUCCESS)
		return r;

	REGKEY *key = 0;
	r = ObjectFromHandle( key, KeyHandle, KEY_QUERY_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	return key->Query( KeyInformationClass, KeyInformation, KeyInformationLength, ReturnLength );
}

NTSTATUS REGKEY::Query(
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID KeyInformation,
	ULONG KeyInformationLength,
	PULONG ReturnLength)
{
	union
	{
		KEY_BASIC_INFORMATION basic;
		KEY_FULL_INFORMATION full;
	} info;
	NTSTATUS r;

	memset( &info, 0, sizeof info );
	ULONG sz = 0;
	UNICODE_STRING keycls, keyname;
	keyname.Length = 0;
	keyname.Buffer = 0;
	keycls.Length = 0;
	keycls.Buffer = 0;

	switch (KeyInformationClass)
	{
	case KeyBasicInformation:
		Query( info.basic, keyname );
		sz = sizeof info.basic + keyname.Length;
		if (sz > KeyInformationLength)
			return STATUS_INFO_LENGTH_MISMATCH;

		r = CopyToUser( KeyInformation, &info, sz );
		if (r < STATUS_SUCCESS)
			break;

		r = CopyToUser( (BYTE*)KeyInformation + FIELD_OFFSET( KEY_BASIC_INFORMATION, Name ), keyname.Buffer, keyname.Length );

		break;

	case KeyFullInformation:
		Query( info.full, keycls );
		sz = sizeof info.full + keycls.Length;
		if (sz > KeyInformationLength)
			return STATUS_INFO_LENGTH_MISMATCH;

		r = CopyToUser( KeyInformation, &info, sz );
		if (r < STATUS_SUCCESS)
			break;

		TRACE("keycls = %pus\n", &keycls);
		r = CopyToUser( (BYTE*)KeyInformation + FIELD_OFFSET( KEY_FULL_INFORMATION, Class ), keycls.Buffer, keycls.Length );

		break;

	case KeyNodeInformation:
		FIXME("KeyNodeInformation\n");
	default:
		assert(0);
	}

	if (r == STATUS_SUCCESS)
		CopyToUser( ReturnLength, &sz, sizeof sz );

	return r;
}

REGKEY *BuildKey( REGKEY *root, CUNICODE_STRING *name )
{
	REGKEY *key;

	key = root;
	bool opened_existing;
	CreateParseKey( key, name, opened_existing );

	return key;
}

BYTE HexChar( xmlChar x )
{
	if (x>='0' && x<='9') return x - '0';
	if (x>='A' && x<='F') return x - 'A' + 10;
	if (x>='a' && x<='f') return x - 'a' + 10;
	return 0xff;
}

ULONG HexToBinary( xmlChar *str, ULONG len, BYTE *buf )
{
	unsigned int i, n;
	BYTE msb, lsb;

	i = 0;
	n = 0;
	while (str[i] && str[i+1])
	{
		msb = HexChar( str[i++] );
		if (msb == 0xff)
			break;
		lsb = HexChar( str[i++] );
		if (lsb == 0xff)
			break;
		if (buf)
			buf[n] = (msb<<4) | lsb;
		//trace("%02x ", (msb<<4) | lsb);
		n++;
	}
	//trace("\n");
	assert( len == 0 || n <= len );
	return n;
}

void NumberToBinary( xmlChar *str, ULONG len, BYTE *buf )
{
	char *valstr = (char*) str;
	ULONG base = 0;
	ULONG val = 0;
	ULONG i;
	BYTE ch;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		// hex
		base = 0x10;
		i = 2;
	}
	else if (str[0] == '0')
	{
		// octal
		base = 8;
		i = 1;
	}
	else
	{
		// decimal
		base = 10;
		i = 0;
	}

	while (str[i])
	{
		ch = HexChar(str[i]);
		if (ch >= base)
			Die("invalid registry value %s\n", valstr);
		val *= base;
		val += ch;
		i++;
	}

	*((ULONG*) buf) = val;
}

void DumpVal( REGVAL *val )
{
	ULONG i;

	TRACE("%pus = ", &val->Name );
	switch( val->Type )
	{
	case 7:
		for (i=0; i<val->Size; i+=2)
		{
			if ((val->Size - i)>1 && !val->Data[i+1] &&
				val->Data[i] >= 0x20 && val->Data[i]<0x80)
			{
				fprintf(stderr,"%c", val->Data[i]);
				continue;
			}
			fprintf(stderr,"\\%02x%02x", val->Data[i+1], val->Data[i]);
		}
		fprintf(stderr,"\n");
		break;
	case 1:
	case 2:
		TRACE("%pws\n", val->Data );
		break;
	}
}

void LoadRegKey( REGKEY *parent, xmlNode *node )
{
	xmlAttr *e;
	xmlChar *contents = NULL;
	const char *type = NULL;
	const char *keycls = NULL;
	CUNICODE_STRING name, data;
	xmlNode *n;
	REGVAL *val;
	ULONG size;
	REGKEY *key;

	if (!node->name[0] || node->name[1])
		return;

	for ( e = node->properties; e; e = e->next )
	{
		if (!strcmp( (const char*)e->name, "n"))
			contents = xmlNodeGetContent( (xmlNode*) e );
		else if (!strcmp( (const char*)e->name, "t"))
			type = (const char*) xmlNodeGetContent( (xmlNode*) e );
		else if (!strcmp( (const char*)e->name, "c"))
			keycls = (const char*) xmlNodeGetContent( (xmlNode*) e );
	}

	if (!contents)
		return;

	name.Copy( contents );

	switch (node->name[0])
	{
	case 'x': // value stored as hex
		// default Type is binary
		if (type == NULL)
			type = "3";
		contents = xmlNodeGetContent( node );
		size = HexToBinary( contents, 0, NULL );
		val = new REGVAL( &name, atoi(type), size );
		HexToBinary( contents, size, val->Data );
		parent->Values.Append( val );
		break;

	case 'n': // number
		// default Type is REG_DWORD
		if (type == NULL)
			type = "4";
		contents = xmlNodeGetContent( node );
		size = sizeof (ULONG);
		val = new REGVAL( &name, atoi(type), size );
		NumberToBinary( contents, size, val->Data );
		parent->Values.Append( val );
		break;

	case 's': // value stored as a string
		// default Type is REG_SZ
		if (type == NULL)
			type = "1";

		data.Copy( xmlNodeGetContent( node ) );
		val = new REGVAL( &name, atoi(type), data.Length + 2 );
		memcpy( val->Data, data.Buffer, data.Length );
		memset( val->Data + data.Length, 0, 2 );
		parent->Values.Append( val );
		break;

	case 'k': // key
		key = BuildKey( parent, &name );
		key->Cls.Copy( keycls );
		for (n = node->children; n; n = n->next)
			LoadRegKey( key, n );

		break;
	}
}

void InitRegistry( void )
{
	xmlDoc *doc;
	xmlNode *root;
	const char *regfile = "reg.xml";
	UNICODE_STRING name;

	memset( &name, 0, sizeof name );
	RootKey = new REGKEY( NULL, &name );

	doc = xmlReadFile( regfile, NULL, 0 );
	if (!doc)
		Die("failed to load registry (%s)\n", regfile );

	root = xmlDocGetRootElement( doc );
	LoadRegKey( RootKey, root );

	xmlFreeDoc( doc );
}

void FreeRegistry( void )
{
	Release( RootKey );
	RootKey = NULL;
}
