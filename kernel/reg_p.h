/*
 * registry private
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
#ifndef __REG_P_H__
#define __REG_P_H__
#define WIN32_NO_STATUS
#include "object.h"
#undef WIN32_NO_STATUS

#define MAX_REGKEY_LENGTH (1024)

struct IREGKEY : public OBJECT
{
public:
	CUNICODE_STRING Cls;
	CUNICODE_STRING Name;

	IREGKEY();

	virtual void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls ) = 0;
	virtual void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr ) = 0;
	virtual void Delkey() = 0;
	virtual IREGKEY *GetChild( ULONG Index ) = 0;
	virtual NTSTATUS Query(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ReturnLength) = 0;
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
};

ULONG SkipSlashes( UNICODE_STRING *str );

#endif // __REG_P_H__