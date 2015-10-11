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

#ifndef __TOKEN_H__
#define __TOKEN_H__

class CTOKEN_PRIVILEGES;
class CSID;
class CACL;
class CSID_AND_ATTRIBUTES;
class CTOKEN_GROUPS;

class TOKEN : public OBJECT
{
public:
	virtual ~TOKEN() = 0;
	virtual CTOKEN_PRIVILEGES& GetPrivs() = 0;
	virtual CSID& GetOwner() = 0;
	virtual CSID_AND_ATTRIBUTES& GetUser() = 0;
	virtual CSID& GetPrimaryGroup() = 0;
	virtual CTOKEN_GROUPS& GetGroups() = 0;
	virtual CACL& GetDefaultDacl() = 0;
	virtual NTSTATUS Adjust(CTOKEN_PRIVILEGES& privs) = 0;
};

#endif // __TOKEN_H__
