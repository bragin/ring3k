/*
 * registry interface
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
#ifndef __REGISTRY_INTERFACE_H__
#define __REGISTRY_INTERFACE_H__

#define WIN32_NO_STATUS
#include "object.h"
#undef WIN32_NO_STATUS
#include "regkey_interface.h"
#include "regval_interface.h"

class IREGISTRY : public OBJECT
{
public:

	virtual NTSTATUS CreateKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing ) = 0;
	virtual NTSTATUS OpenKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa ) = 0;
};


#endif // __REGISTRY_INTERFACE_H__


