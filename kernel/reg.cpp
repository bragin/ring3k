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

#if 0





VOID PrintKey(REGKEY *key)
{
	while (key) {
		if (!key->Name.Buffer)
			break;
		TRACE("%pus\n",&key->Name);
		key = key->Parent;
	}
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

#endif
