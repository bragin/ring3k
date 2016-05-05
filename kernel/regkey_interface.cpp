/*
 * interface registry
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

#include "regkey_interface.h"
#include "regval_interface.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#undef WIN32_NO_STATUS
#include "debug.h"
#include "object.h"
#include "unicode.h"

DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

IREGKEY::IREGKEY(const CUNICODE_STRING& name) :
	m_Name(name)
{
}
#include <stdio.h>

/* this doesn't set STATUS_MORE_DATA */
NTSTATUS IREGKEY::RegQueryValue(
	IREGVAL* val,
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

	TRACE("%pus\n", &val->Name());

	memset( &info, 0, sizeof info );

	switch( KeyValueInformationClass )
	{
	case KeyValueFullInformation:
		info_sz = FIELD_OFFSET( KEY_VALUE_FULL_INFORMATION, Name );
		// include nul terminator at the end of the Name
		info.full.DataOffset = info_sz + val->Name().Length + 2;
		len = info.full.DataOffset + val->Size();
		if (KeyValueInformationLength < info_sz)
			return STATUS_BUFFER_TOO_SMALL;

		info.full.Type = val->Type();
		info.full.DataLength = val->Size();
		info.full.NameLength = val->Name().Length;

		r = CopyToUser( KeyValueInformation, &info.full, info_sz );
		if (r < STATUS_SUCCESS)
			break;

		if (len > KeyValueInformationLength)
			return STATUS_BUFFER_OVERFLOW;

		r = CopyToUser( (BYTE*)KeyValueInformation + info_sz,
						  val->Name().Buffer, val->Name().Length );
		if (r < STATUS_SUCCESS)
			break;

		r = CopyToUser( (BYTE*)KeyValueInformation + info.full.DataOffset,
						  val->Data(), val->Size() );
		break;

	case KeyValuePartialInformation:
		info_sz = FIELD_OFFSET( KEY_VALUE_PARTIAL_INFORMATION, Data );
		len = info_sz + val->Size();
		if (KeyValueInformationLength < info_sz)
			return STATUS_BUFFER_TOO_SMALL;

		info.partial.Type = val->Type();
		info.partial.DataLength = val->Size();

		r = CopyToUser( KeyValueInformation, &info.partial, info_sz );
		if (r < STATUS_SUCCESS)
			break;

		if (len > KeyValueInformationLength)
			return STATUS_BUFFER_OVERFLOW;

		r = CopyToUser( (BYTE*)KeyValueInformation + info_sz, val->Data(), val->Size() );
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

bool IREGKEY::AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle )
{
	return CheckAccess( required, handle,
						 KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS|KEY_NOTIFY,
						 KEY_SET_VALUE|KEY_CREATE_SUB_KEY|KEY_CREATE_LINK,
						 KEY_ALL_ACCESS );
}

