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

#ifndef __NTNATIVE_OBJDIR_H__
#define __NTNATIVE_OBJDIR_H__

#include "object.h"

class OBJECT_DIR : virtual public OBJECT
{
protected:
	friend class OBJECT;
	static void SetObjParent( OBJECT *child, OBJECT_DIR *dir );
	virtual void Unlink( OBJECT *child ) = 0;
public:
	OBJECT_DIR();
	virtual ~OBJECT_DIR();
	virtual bool AccessAllowed( ACCESS_MASK access, ACCESS_MASK handle_access ) = 0;
	virtual OBJECT *Lookup( UNICODE_STRING& name, bool ignore_case ) = 0;
	virtual void Append( OBJECT *child ) = 0;
};

class OBJECT_DIR_IMPL : public OBJECT_DIR
{
	OBJECT_LIST object_list;
public:
	OBJECT_DIR_IMPL();
	virtual ~OBJECT_DIR_IMPL();
	virtual bool AccessAllowed( ACCESS_MASK access, ACCESS_MASK handle_access );
	virtual void Unlink( OBJECT *child );
	virtual void Append( OBJECT *child );
public:
	OBJECT *Lookup( UNICODE_STRING& name, bool ignore_case );
	NTSTATUS Add( OBJECT *obj, UNICODE_STRING& name, bool ignore_case );
	virtual NTSTATUS Open( OBJECT*& obj, OPEN_INFO& info );
};

OBJECT *CreateDirectoryObject( PCWSTR name );
NTSTATUS ParsePath( const OBJECT_ATTRIBUTES& oa, OBJECT_DIR*& dir, UNICODE_STRING& file );

#endif // __NTNATIVE_OBJDIR_H__
