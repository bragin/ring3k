/*
 * registry key interface
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
#ifndef __REGKEY_INTERFACE_H__
#define __REGKEY_INTERFACE_H__
#define WIN32_NO_STATUS
#include "object.h"
#undef WIN32_NO_STATUS

#define MAX_REGKEY_LENGTH (1024)

class IREGVAL;
class IREGKEY : public OBJECT
{
private:
	CUNICODE_STRING m_Cls;
	CUNICODE_STRING m_Name;
public:

	IREGKEY(const CUNICODE_STRING& name);

	virtual void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING* keycls ) = 0;
	virtual void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr ) = 0;
	virtual IREGKEY *GetChild( ULONG Index ) = 0;
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
	virtual NTSTATUS SetValue( const CUNICODE_STRING& name, ULONG Type, PVOID Data, ULONG DataSize ) = 0;
	virtual IREGVAL* FindValue( const UNICODE_STRING *us ) = 0;
	virtual NTSTATUS DeleteValue(const UNICODE_STRING *us ) = 0;
	virtual NTSTATUS DeleteKey() = 0;
	virtual NTSTATUS EnumerateValueKey(	ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, ULONG &len ) = 0;
	virtual NTSTATUS RegQueryValue( IREGVAL* val, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, ULONG& len );
	virtual NTSTATUS Query(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ReturnLength);

	virtual const CUNICODE_STRING& Name() const { return m_Name; };
	virtual const CUNICODE_STRING Cls() const;
	virtual void SetCls(const CUNICODE_STRING& cls) { m_Cls = cls; };
	virtual void PrintDescription() const = 0;
};


#endif // __REGKEY_INTERFACE_H__