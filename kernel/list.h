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

template<class T, const int X> class LIST_ITER;
template<class T, const int X> class LIST_ANCHOR;
template<class T> class LIST_ELEMENT_ACCESSOR;

template<class T> class LIST_ELEMENT
{
	friend class LIST_ELEMENT_ACCESSOR<T>;
protected:
	T *Prev;
	T *Next;
public:
	void Init()
	{
		this->Prev = (T*)-1;
		this->Next = (T*)-1;
	}
	explicit LIST_ELEMENT()
	{
		Init();
	}
	~LIST_ELEMENT() {}
	bool IsLinked()
	{
		return this->Prev != (T*)-1;
	}
	T* GetNext()
	{
		return this->Next;
	}
	T* GetPrev()
	{
		return this->Prev;
	}
};

template<class T> class LIST_ELEMENT_ACCESSOR
{
protected:
	T*& PrevPtr(LIST_ELEMENT<T>& elem)
	{
		return elem.Prev;
	}
	T*& NextPtr(LIST_ELEMENT<T>& elem)
	{
		return elem.Next;
	}
};

template<class T, const int X> class LIST_ANCHOR : public LIST_ELEMENT_ACCESSOR<T>
{
	T *_Head;
	T *_Tail;
public:
	explicit LIST_ANCHOR()
	{
		this->_Head = 0;
		this->_Tail = 0;
	}
	~LIST_ANCHOR() {}
	bool Empty()
	{
		return !(this->_Head || this->_Tail);
	}
	T *Head()
	{
		return this->_Head;
	}
	T *Tail()
	{
		return this->_Tail;
	}
	void Unlink(T* elem)
	{
		assert(elem->entry[X].IsLinked());
		if (this->_Head == elem)
			this->_Head = LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]);
		else
			LIST_ELEMENT_ACCESSOR<T>::NextPtr(LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X])->entry[X]) = LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]);
		if (this->_Tail == elem)
			this->_Tail = LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]);
		else
			LIST_ELEMENT_ACCESSOR<T>::PrevPtr(LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X])->entry[X]) = LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]);
		elem->entry[X].Init();
	}

	void Append( T* elem )
	{
		assert(!elem->entry[X].IsLinked());
		if (this->_Tail)
			LIST_ELEMENT_ACCESSOR<T>::NextPtr(this->_Tail->entry[X]) = elem;
		else
			this->_Head = elem;
		LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]) = this->_Tail;
		LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]) = 0;
		this->_Tail = elem;
	}

	void Prepend( T* elem )
	{
		assert(!elem->entry[X].IsLinked());
		if (this->_Head)
			LIST_ELEMENT_ACCESSOR<T>::PrevPtr(this->_Head->entry[X]) = elem;
		else
			this->_Tail = elem;
		LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]) = this->_Head;
		LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]) = 0;
		this->_Head = elem;
	}

	void InsertAfter( T* point, T* elem )
	{
		assert(!elem->entry[X].IsLinked());
		if (LIST_ELEMENT_ACCESSOR<T>::NextPtr(point->entry[X]))
			LIST_ELEMENT_ACCESSOR<T>::PrevPtr(LIST_ELEMENT_ACCESSOR<T>::NextPtr(point->entry[X])->entry[X]) = elem;
		else
			this->_Tail = elem;
		LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]) = LIST_ELEMENT_ACCESSOR<T>::NextPtr(point->entry[X]);
		LIST_ELEMENT_ACCESSOR<T>::NextPtr(point->entry[X]) = elem;
		LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]) = point;
	}

	void InsertBefore( T* point, T* elem )
	{
		assert(!elem->entry[X].IsLinked());
		if (LIST_ELEMENT_ACCESSOR<T>::PrevPtr(point->entry[X]))
			LIST_ELEMENT_ACCESSOR<T>::NextPtr(LIST_ELEMENT_ACCESSOR<T>::PrevPtr(point->entry[X])->entry[X]) = elem;
		else
			this->_Head = elem;
		LIST_ELEMENT_ACCESSOR<T>::PrevPtr(elem->entry[X]) = LIST_ELEMENT_ACCESSOR<T>::PrevPtr(point->entry[X]);
		LIST_ELEMENT_ACCESSOR<T>::PrevPtr(point->entry[X]) = elem;
		LIST_ELEMENT_ACCESSOR<T>::NextPtr(elem->entry[X]) = point;
	}
};

template<class T, const int X> class LIST_ITER : public LIST_ELEMENT_ACCESSOR<T>
{
	LIST_ANCHOR<T,X>& List;
	T* i;
public:
	explicit LIST_ITER(LIST_ANCHOR<T,X>& l) : List(l), i(l.Head()) {}
	T* Next()
	{
		i = LIST_ELEMENT_ACCESSOR<T>::NextPtr(i->entry[X]);
		return i;
	}
	T* Current()
	{
		return i;
	}
	operator bool()
	{
		return i != 0;
	}
	operator T*()
	{
		return i;
	}
	void Reset()
	{
		i = List.Head();
	}
};

#endif // __LIST_H__
