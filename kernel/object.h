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

typedef LIST_ANCHOR<OBJECT, 0> object_list_t;
typedef LIST_ELEMENT<OBJECT> object_entry_t;
typedef LIST_ITER<OBJECT, 0> object_iter_t;

class OBJECT_FACTORY;
class OPEN_INFO;

class OPEN_INFO
{
public:
	ULONG Attributes;
	HANDLE root;
	unicode_string_t path;
public:
	OPEN_INFO();
	bool case_insensitive()
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
	object_entry_t Entry[1];
	ULONG refcount;
public:
	ULONG attr;
	OBJECT_DIR *parent;
	unicode_string_t name;
	friend class OBJECT_DIR;
	void set_parent( OBJECT_DIR *dir );
	unicode_string_t& get_name()
	{
		return name;
	}
public:
	OBJECT();
	virtual bool AccessAllowed( ACCESS_MASK required, ACCESS_MASK handle );
	virtual ~OBJECT();
	static bool check_access( ACCESS_MASK required, ACCESS_MASK handle, ACCESS_MASK read, ACCESS_MASK write, ACCESS_MASK all );
	static void addref( OBJECT *obj );
	static void release( OBJECT *obj );
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
};

class OBJECT_FACTORY : public OPEN_INFO
{
protected:
	virtual NTSTATUS AllocObject(OBJECT** obj) = 0;
	virtual NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
public:
	NTSTATUS create(
		PHANDLE Handle,
		ACCESS_MASK AccessMask,
		POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS create_kernel( OBJECT*& obj, UNICODE_STRING& us );
	virtual ~OBJECT_FACTORY();
};

class watch_t;

typedef LIST_ANCHOR<watch_t, 0> watch_list_t;
typedef LIST_ELEMENT<watch_t> watch_entry_t;
typedef LIST_ITER<watch_t, 0> watch_iter_t;

class watch_t
{
public:
	watch_entry_t Entry[1];
	virtual void notify() = 0;
	virtual ~watch_t();
};

class SYNC_OBJECT : virtual public OBJECT
{
private:
	watch_list_t watchers;
public:
	SYNC_OBJECT();
	virtual ~SYNC_OBJECT();
	virtual BOOLEAN IsSignalled( void ) = 0;
	virtual BOOLEAN Satisfy( void );
	void add_watch( watch_t* watcher );
	void remove_watch( watch_t* watcher );
	void notify_watchers();
};

class object_info_t
{
public:
	OBJECT *object;
	ACCESS_MASK access;
};

class HANDLE_TABLE
{
	static const unsigned int max_handles = 0x100;

	//int num_objects;
	object_info_t info[max_handles];
protected:
	static HANDLE index_to_handle( ULONG index );
	static ULONG handle_to_index( HANDLE handle );
public:
	~HANDLE_TABLE();
	void free_all_handles();
	HANDLE alloc_handle( OBJECT *obj, ACCESS_MASK access );
	NTSTATUS free_handle( HANDLE handle );
	NTSTATUS object_from_handle( OBJECT*& obj, HANDLE handle, ACCESS_MASK access );
};

static inline void addref( OBJECT *obj )
{
	OBJECT::addref( obj );
}

static inline void release( OBJECT *obj )
{
	OBJECT::release( obj );
}

void InitRoot();
void FreeRoot();

NTSTATUS NameObject( OBJECT *obj, const OBJECT_ATTRIBUTES *oa );
NTSTATUS GetNamedObject( OBJECT **out, const OBJECT_ATTRIBUTES *oa );
NTSTATUS FindObjectByName( OBJECT **out, const OBJECT_ATTRIBUTES *oa );

NTSTATUS OpenRoot( OBJECT*& obj, OPEN_INFO& info );

template<typename T> NTSTATUS object_from_handle(T*& out, HANDLE handle, ACCESS_MASK access);

#endif //__OBJECT_H__
