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
class object_dir_t;

typedef list_anchor<OBJECT, 0> object_list_t;
typedef list_element<OBJECT> object_entry_t;
typedef list_iter<OBJECT, 0> object_iter_t;

class OBJECT_FACTORY;
class open_info_t;

class open_info_t
{
public:
	ULONG Attributes;
	HANDLE root;
	unicode_string_t path;
public:
	open_info_t();
	bool case_insensitive()
	{
		return Attributes & OBJ_CASE_INSENSITIVE;
	}
	virtual NTSTATUS on_open( object_dir_t* dir, OBJECT*& obj, open_info_t& info ) = 0;
	virtual ~open_info_t();
};

class OBJECT
{
	friend class list_anchor<OBJECT, 0>;
	friend class list_element<OBJECT>;
	friend class list_iter<OBJECT, 0>;
	object_entry_t entry[1];
	ULONG refcount;
public:
	ULONG attr;
	object_dir_t *parent;
	unicode_string_t name;
	friend class object_dir_t;
	void set_parent( object_dir_t *dir );
	unicode_string_t& get_name()
	{
		return name;
	}
public:
	OBJECT();
	virtual bool access_allowed( ACCESS_MASK required, ACCESS_MASK handle );
	virtual ~OBJECT();
	static bool check_access( ACCESS_MASK required, ACCESS_MASK handle, ACCESS_MASK read, ACCESS_MASK write, ACCESS_MASK all );
	static void addref( OBJECT *obj );
	static void release( OBJECT *obj );
	virtual NTSTATUS open( OBJECT *&out, open_info_t& info );
};

class OBJECT_FACTORY : public open_info_t
{
protected:
	virtual NTSTATUS alloc_object(OBJECT** obj) = 0;
	virtual NTSTATUS on_open( object_dir_t* dir, OBJECT*& obj, open_info_t& info );
public:
	NTSTATUS create(
		PHANDLE Handle,
		ACCESS_MASK AccessMask,
		POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS create_kernel( OBJECT*& obj, UNICODE_STRING& us );
	virtual ~OBJECT_FACTORY();
};

class watch_t;

typedef list_anchor<watch_t, 0> watch_list_t;
typedef list_element<watch_t> watch_entry_t;
typedef list_iter<watch_t, 0> watch_iter_t;

class watch_t
{
public:
	watch_entry_t entry[1];
	virtual void notify() = 0;
	virtual ~watch_t();
};

class sync_object_t : virtual public OBJECT
{
private:
	watch_list_t watchers;
public:
	sync_object_t();
	virtual ~sync_object_t();
	virtual BOOLEAN is_signalled( void ) = 0;
	virtual BOOLEAN satisfy( void );
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

class handle_table_t
{
	static const unsigned int max_handles = 0x100;

	//int num_objects;
	object_info_t info[max_handles];
protected:
	static HANDLE index_to_handle( ULONG index );
	static ULONG handle_to_index( HANDLE handle );
public:
	~handle_table_t();
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

void init_root();
void free_root();

NTSTATUS name_object( OBJECT *obj, const OBJECT_ATTRIBUTES *oa );
NTSTATUS get_named_object( OBJECT **out, const OBJECT_ATTRIBUTES *oa );
NTSTATUS find_object_by_name( OBJECT **out, const OBJECT_ATTRIBUTES *oa );

NTSTATUS open_root( OBJECT*& obj, open_info_t& info );

template<typename T> NTSTATUS object_from_handle(T*& out, HANDLE handle, ACCESS_MASK access);

#endif //__OBJECT_H__
