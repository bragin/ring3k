/*
 * xml registry
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
#ifndef __REGISTRY_XML_H__
#define __REGISTRY_XML_H__

#include "registry_interface.h"
#include "regkey_interface.h"
#include "regval_interface.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

class REGKEY_XML;
class REGVAL_XML;
class REGISTRY_XML;
class REGISTRY_XML : public IREGISTRY
{
public:
	REGISTRY_XML();
	virtual ~REGISTRY_XML();

	virtual NTSTATUS CreateKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing );
	virtual NTSTATUS OpenKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa );

	static IREGISTRY* Create();


private:
	NTSTATUS OpenParseKey( IREGKEY *&key, UNICODE_STRING *name, bool case_insensitive );
	void LoadRegKey( REGKEY_XML *parent, xmlNode *node );
	REGKEY_XML *BuildKey( REGKEY_XML *root, CUNICODE_STRING *name );
	NTSTATUS CreateParseKey( REGKEY_XML *&key, UNICODE_STRING *name, bool& opened_existing );
	ULONG DoOpenSubkey( REGKEY_XML *&key, UNICODE_STRING *name, bool case_insensitive );


private:
	REGKEY_XML *RootKey;

};

typedef LIST_ANCHOR<REGVAL_XML,0> REGVAL_XML_ANCHOR;
typedef LIST_ANCHOR<REGKEY_XML,0> REGKEY_XML_ANCHOR;
typedef LIST_ITER<REGVAL_XML,0> REGVAL_XML_ITER;
typedef LIST_ITER<REGKEY_XML,0> REGKEY_XML_ITER;
typedef LIST_ELEMENT<REGVAL_XML> REGVAL_XML_ELEMENT;
typedef LIST_ELEMENT<REGKEY_XML> REGKEY_XML_ELEMENT;

class REGKEY_XML : public IREGKEY
{
	REGKEY_XML* m_Parent;
public:
	REGKEY_XML( REGKEY_XML *_parent, const UNICODE_STRING *_name );
	virtual ~REGKEY_XML();
	virtual void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls );
	virtual void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr );
	virtual NTSTATUS Query(KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG KeyInformationLength, PULONG ReturnLength);
	virtual IREGKEY *GetChild( ULONG Index );
	virtual NTSTATUS SetValue( const CUNICODE_STRING& name, ULONG Type, PVOID Data, ULONG DataSize );
	virtual IREGVAL *FindValue( const UNICODE_STRING *us );
	virtual NTSTATUS DeleteValue(const UNICODE_STRING *us );
	virtual void DeleteKey();
	virtual NTSTATUS EnumerateValueKey(	ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, ULONG &len );
	ULONG NumValues(ULONG& max_name_len, ULONG& max_data_len);
	ULONG NumSubkeys(ULONG& max_name_len, ULONG& max_class_len);

	REGKEY_XML* Parent() const { return m_Parent; }
	virtual void PrintDescription() const {};
protected:
	void SetParent(REGKEY_XML* Parent) { m_Parent = Parent; };
public:

	REGKEY_XML_ELEMENT Entry[1];
	REGVAL_XML_ANCHOR Values;
	REGKEY_XML_ANCHOR Children;

};

class REGVAL_XML : public IREGVAL
{
public:
	REGVAL_XML( const UNICODE_STRING *name, ULONG _type, ULONG _size );
	virtual ~REGVAL_XML();

public:
	REGVAL_XML_ELEMENT Entry[1];
};


#endif // __REGISTRY_XML_H__


