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

#ifndef __OBJECT_H__
#define __OBJECT_H__

#include "list.h"
#include "unicode.h"

class OBJECT;
class OBJECT_DIR;

typedef LIST_ANCHOR<OBJECT, 0> OBJECT_LIST;
typedef LIST_ELEMENT<OBJECT> OBJECT_ENTRY;
typedef LIST_ITER<OBJECT, 0> OBJECT_ITER;

class OBJECT_FACTORY;
class OPEN_INFO;

class OPEN_INFO
{
public:
	ULONG Attributes;
	HANDLE Root;
	unicode_string_t Path;
public:
	OPEN_INFO();
	bool CaseInsensitive()
	{
		return Attributes & OBJ_CASE_INSENSITIVE;
	}
	virtual NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info ) = 0;
	virtual ~OPEN_INFO();
};

class OBJECT
{
	friend class LIST_ANCHOR<OBJECT, 0>;
	friend class LIST_ELEMENT<OBJECT>;
	friend class LIST_ITER<OBJECT, 0>;
	OBJECT_ENTRY Entry[1];
	ULONG RefCount;
public:
	ULONG Attr;
	OBJECT_DIR *Parent;
	unicode_string_t Name;
	friend class OBJECT_DIR;
	void SetParent( OBJECT_DIR *dir );
	unicode_string_t& GetName()
	{
		return Name;
	}
public:
	OBJECT();
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
	virtual ~OBJECT();
	static bool CheckAccess( ACCESS_MASK required, ACCESS_MASK handle, ACCESS_MASK read, ACCESS_MASK write, ACCESS_MASK all );
	static void AddRef( OBJECT *obj );
	static void Release( OBJECT *obj );
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
};

class OBJECT_FACTORY : public OPEN_INFO
{
protected:
	virtual NTSTATUS AllocObject(OBJECT** obj) = 0;
	virtual NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
public:
	NTSTATUS Create(
		PHANDLE Handle,
		ACCESS_MASK AccessMask,
		POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS CreateKernel( OBJECT*& obj, UNICODE_STRING& us );
	virtual ~OBJECT_FACTORY();
};

class WATCH;

typedef LIST_ANCHOR<WATCH, 0> WATCH_LIST;
typedef LIST_ELEMENT<WATCH> WATCH_ENTRY;
typedef LIST_ITER<WATCH, 0> WATCH_ITER;

class WATCH
{
public:
	WATCH_ENTRY Entry[1];
	virtual void Notify() = 0;
	virtual ~WATCH();
};

class SYNC_OBJECT : virtual public OBJECT
{
private:
	WATCH_LIST Watchers;
public:
	SYNC_OBJECT();
	virtual ~SYNC_OBJECT();
	virtual BOOLEAN IsSignalled( void ) = 0;
	virtual BOOLEAN Satisfy( void );
	void AddWatch( WATCH* watcher );
	void RemoveWatch( WATCH* watcher );
	void NotifyWatchers();
};

class OBJECT_INFO
{
public:
	OBJECT *Object;
	ACCESS_MASK Access;
};

class HANDLE_TABLE
{
	static const unsigned int MaxHandles = 0x100;

	//int num_objects;
	OBJECT_INFO Info[MaxHandles];
protected:
	static HANDLE IndexToHandle( ULONG index );
	static ULONG HandleToIndex( HANDLE handle );
public:
	~HANDLE_TABLE();
	void FreeAllHandles();
	HANDLE AllocHandle( OBJECT *obj, ACCESS_MASK access );
	NTSTATUS FreeHandle( HANDLE handle );
	NTSTATUS ObjectFromHandle( OBJECT*& obj, HANDLE handle, ACCESS_MASK access );
};

static inline void AddRef( OBJECT *obj )
{
	OBJECT::AddRef( obj );
}

static inline void Release( OBJECT *obj )
{
	OBJECT::Release( obj );
}

void InitRoot();
void FreeRoot();

NTSTATUS NameObject( OBJECT *obj, const OBJECT_ATTRIBUTES *oa );
NTSTATUS GetNamedObject( OBJECT **out, const OBJECT_ATTRIBUTES *oa );
NTSTATUS FindObjectByName( OBJECT **out, const OBJECT_ATTRIBUTES *oa );

NTSTATUS OpenRoot( OBJECT*& obj, OPEN_INFO& info );

template<typename T> NTSTATUS ObjectFromHandle(T*& out, HANDLE handle, ACCESS_MASK access);

#endif //__OBJECT_H__
