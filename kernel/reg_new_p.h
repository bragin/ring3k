/*
 * new registry with Redis database
 * Private functions
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

#ifndef __REG_NEW_P_H__
#define __REG_NEW_P_H__

#include "reg_p.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

struct REGKEYREDIS : public IREGKEY
{
public:
	REGKEYREDIS(const CUNICODE_STRING& path);
	virtual void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls ) {}
	virtual void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr ) {}
	virtual void Delkey() {}
	virtual IREGKEY *GetChild( ULONG Index ) {}
	virtual NTSTATUS Query(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ReturnLength) {}
};

NTSTATUS CreateKeyRedis( REGKEYREDIS **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing );
NTSTATUS OpenKeyRedis( REGKEYREDIS **out, OBJECT_ATTRIBUTES *oa );

#endif // __REG_NEW_P_H__ 