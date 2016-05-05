/*
 * registry value interface
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
#ifndef __REGVAL_INTERFACE_H__
#define __REGVAL_INTERFACE_H__

class IREGVAL
{
protected:
	CUNICODE_STRING m_Name;
	ULONG m_Type;
	ULONG m_Size;
	BYTE *m_Data;
public:
	virtual const CUNICODE_STRING& Name() const { return m_Name; };
	virtual ULONG Type() const { return m_Type; };
	virtual ULONG Size() const { return m_Size; };
	virtual BYTE* Data() const { return m_Data; };
};


#endif // __REGVAL_INTERFACE_H__