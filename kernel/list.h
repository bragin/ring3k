/*
 * Lightweight list template
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

#ifndef __LIST_H__
#define __LIST_H__

#include <assert.h>

template<class T, const int X> class list_iter;
template<class T, const int X> class list_anchor;
template<class T> class list_element_accessor;

template<class T> class list_element
{
	friend class list_element_accessor<T>;
protected:
	T *prev;
	T *next;
public:
	void init() { this->prev = (T*)-1; this->next = (T*)-1; }
	explicit list_element() {init();}
	~list_element() {}
	bool is_linked() { return this->prev != (T*)-1; }
	T* get_next() {return this->next;}
	T* get_prev() {return this->prev;}
};

template<class T> class list_element_accessor
{
protected:
	T*& prevptr(list_element<T>& elem) {return elem.prev;}
	T*& nextptr(list_element<T>& elem) {return elem.next;}
};

template<class T, const int X> class list_anchor : public list_element_accessor<T>
{
	T *_head;
	T *_tail;
public:
	explicit list_anchor() { this->_head = 0; this->_tail = 0; }
	~list_anchor() {}
	bool empty() { return !(this->_head || this->_tail); }
	T *head() { return this->_head; }
	T *tail() { return this->_tail; }
	void unlink(T* elem)
	{
		assert(elem->entry[X].is_linked());
		if (this->_head == elem)
			this->_head = list_element_accessor<T>::nextptr(elem->entry[X]);
		else
			list_element_accessor<T>::nextptr(list_element_accessor<T>::prevptr(elem->entry[X])->entry[X]) = list_element_accessor<T>::nextptr(elem->entry[X]);
		if (this->_tail == elem)
			this->_tail = list_element_accessor<T>::prevptr(elem->entry[X]);
		else
			list_element_accessor<T>::prevptr(list_element_accessor<T>::nextptr(elem->entry[X])->entry[X]) = list_element_accessor<T>::prevptr(elem->entry[X]);
		elem->entry[X].init();
	}

	void append( T* elem )
	{
		assert(!elem->entry[X].is_linked());
		if (this->_tail)
			list_element_accessor<T>::nextptr(this->_tail->entry[X]) = elem;
		else
			this->_head = elem;
		list_element_accessor<T>::prevptr(elem->entry[X]) = this->_tail;
		list_element_accessor<T>::nextptr(elem->entry[X]) = 0;
		this->_tail = elem;
	}

	void prepend( T* elem )
	{
		assert(!elem->entry[X].is_linked());
		if (this->_head)
			list_element_accessor<T>::prevptr(this->_head->entry[X]) = elem;
		else
			this->_tail = elem;
		list_element_accessor<T>::nextptr(elem->entry[X]) = this->_head;
		list_element_accessor<T>::prevptr(elem->entry[X]) = 0;
		this->_head = elem;
	}

	void insert_after( T* point, T* elem )
	{
		assert(!elem->entry[X].is_linked());
		if (list_element_accessor<T>::nextptr(point->entry[X]))
			list_element_accessor<T>::prevptr(list_element_accessor<T>::nextptr(point->entry[X])->entry[X]) = elem;
		else
			this->_tail = elem;
		list_element_accessor<T>::nextptr(elem->entry[X]) = list_element_accessor<T>::nextptr(point->entry[X]);
		list_element_accessor<T>::nextptr(point->entry[X]) = elem;
		list_element_accessor<T>::prevptr(elem->entry[X]) = point;
	}

	void insert_before( T* point, T* elem )
	{
		assert(!elem->entry[X].is_linked());
		if (list_element_accessor<T>::prevptr(point->entry[X]))
			list_element_accessor<T>::nextptr(list_element_accessor<T>::prevptr(point->entry[X])->entry[X]) = elem;
		else
			this->_head = elem;
		list_element_accessor<T>::prevptr(elem->entry[X]) = list_element_accessor<T>::prevptr(point->entry[X]);
		list_element_accessor<T>::prevptr(point->entry[X]) = elem;
		list_element_accessor<T>::nextptr(elem->entry[X]) = point;
	}
};

template<class T, const int X> class list_iter : public list_element_accessor<T>
{
	list_anchor<T,X>& list;
	T* i;
public:
	explicit list_iter(list_anchor<T,X>& l) : list(l), i(l.head()) {}
	T* next() { i = list_element_accessor<T>::nextptr(i->entry[X]); return i; }
	T* cur() { return i; }
	operator bool() { return i != 0; }
	operator T*() { return i; }
	void reset() {i = list.head();}
};

#endif // __LIST_H__
