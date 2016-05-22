/*
 * kernel functions for registry
 *
 * Copyright 2016 Fedor Zaytsev
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#undef WIN32_NO_STATUS
#include "debug.h"
#include "object.h"
#include "mem.h"
#include "ntcall.h"
#include "unicode.h"
#include "list.h"

DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

#include "registry_interface.h"
#include "regkey_interface.h"
#include "regval_interface.h"

extern IREGISTRY* Registry;

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
	IREGKEY *key = NULL;

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
	r = Registry->CreateKey( &key, &oa, opened_existing );
	if (r == STATUS_SUCCESS)
	{
		if (Disposition)
		{
			ULONG dispos = opened_existing ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
			CopyToUser( Disposition, &dispos, sizeof *Disposition );
		}
		key->SetCls(cls);
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
	IREGKEY *key = NULL;

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

	r = Registry->OpenKey( &key, &oa );

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
	IREGKEY *key;
	IREGVAL *val;

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

	key->PrintDescription( );

	val = key->FindValue( &us );
	if (!val)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	TRACE("val '%pus' type %d size %d\n", &val->Name(), val->Type(), val->Size());
	
	r = key->RegQueryValue( val, KeyValueInformationClass, KeyValueInformation,
						 KeyValueInformationLength, len );

	CopyToUser( ResultLength, &len, sizeof len );

	return r;
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
	IREGKEY *key = 0;
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

	IREGKEY *child = key->GetChild( Index );
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
	IREGKEY *key = 0;
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

	IREGKEY *key = 0;
	r = ObjectFromHandle( key, KeyHandle, KEY_QUERY_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	return key->Query( KeyInformationClass, KeyInformation, KeyInformationLength, ReturnLength );
}

NTSTATUS NTAPI NtSetValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName,
	ULONG TitleIndex,							//FIXME, unused
	ULONG Type,
	PVOID Data,
	ULONG DataSize )
{
	CUNICODE_STRING us;
	IREGKEY *key;
	NTSTATUS r;

	TRACE("%p %p %lu %lu %p %lu\n", KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

	r = ObjectFromHandle( key, KeyHandle, KEY_SET_VALUE );
	if (r < STATUS_SUCCESS)
		return r;

	r = us.CopyFromUser( ValueName );
	if (r == STATUS_SUCCESS)
	{
		r = key->SetValue( us, Type, Data, DataSize );
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
	IREGKEY *key;
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

	r = key->EnumerateValueKey( Index, KeyValueInformationClass, KeyValueInformation,
								KeyValueInformationLength, len );

	if (r != STATUS_NO_MORE_ENTRIES)
		CopyToUser( ResultLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtDeleteValueKey(
	HANDLE KeyHandle,
	PUNICODE_STRING ValueName )
{
	CUNICODE_STRING us;
	NTSTATUS r;
	IREGKEY *key;

	TRACE("%p %p\n", KeyHandle, ValueName);

	r = us.CopyFromUser( ValueName );
	if (r < STATUS_SUCCESS)
		return r;

	r = ObjectFromHandle( key, KeyHandle, KEY_SET_VALUE );
	if (r < STATUS_SUCCESS)
		return r;
	r = key->DeleteValue( &us );

	return r;
}

NTSTATUS NTAPI NtDeleteKey(
	HANDLE KeyHandle)
{
	NTSTATUS r;
	IREGKEY *key = 0;
	r = ObjectFromHandle( key, KeyHandle, DELETE );
	if (r < STATUS_SUCCESS)
		return r;

	r = key->DeleteKey();

	return r;
}

NTSTATUS NTAPI NtFlushKey(
	HANDLE KeyHandle)
{
	IREGKEY *key = 0;
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