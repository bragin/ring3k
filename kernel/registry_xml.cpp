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

#include "registry_xml.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#undef WIN32_NO_STATUS
#include "debug.h"
#include "object.h"
#include "unicode.h"


DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

REGISTRY_XML::REGISTRY_XML()
{
	xmlDoc *doc;
	xmlNode *root;
	const char *regfile = "reg.xml";
	UNICODE_STRING name;

	memset( &name, 0, sizeof name );
	RootKey = new REGKEY_XML( NULL, &name );

	doc = xmlReadFile( regfile, NULL, 0 );
	if (!doc)
		Die("failed to load registry (%s)\n", regfile );

	root = xmlDocGetRootElement( doc );
	LoadRegKey( RootKey, root );

	xmlFreeDoc( doc );
}

REGISTRY_XML::~REGISTRY_XML()
{
	Release( RootKey );
	RootKey = NULL;
}

IREGISTRY* REGISTRY_XML::Create()
{
	return new REGISTRY_XML;
}

BYTE HexChar( xmlChar x )
{
	if (x>='0' && x<='9') return x - '0';
	if (x>='A' && x<='F') return x - 'A' + 10;
	if (x>='a' && x<='f') return x - 'a' + 10;
	return 0xff;
}

ULONG HexToBinary( xmlChar *str, ULONG len, BYTE *buf )
{
	unsigned int i, n;
	BYTE msb, lsb;

	i = 0;
	n = 0;
	while (str[i] && str[i+1])
	{
		msb = HexChar( str[i++] );
		if (msb == 0xff)
			break;
		lsb = HexChar( str[i++] );
		if (lsb == 0xff)
			break;
		if (buf)
			buf[n] = (msb<<4) | lsb;
		//trace("%02x ", (msb<<4) | lsb);
		n++;
	}
	//trace("\n");
	assert( len == 0 || n <= len );
	return n;
}

void NumberToBinary( xmlChar *str, ULONG len, BYTE *buf )
{
	char *valstr = (char*) str;
	ULONG base = 0;
	ULONG val = 0;
	ULONG i;
	BYTE ch;

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		// hex
		base = 0x10;
		i = 2;
	}
	else if (str[0] == '0')
	{
		// octal
		base = 8;
		i = 1;
	}
	else
	{
		// decimal
		base = 10;
		i = 0;
	}

	while (str[i])
	{
		ch = HexChar(str[i]);
		if (ch >= base)
			Die("invalid registry value %s\n", valstr);
		val *= base;
		val += ch;
		i++;
	}

	*((ULONG*) buf) = val;
}


void REGISTRY_XML::LoadRegKey( REGKEY_XML *parent, xmlNode *node )
{
	xmlAttr *e;
	xmlChar *contents = NULL;
	const char *type = NULL;
	const char *keycls = NULL;
	CUNICODE_STRING name, data;
	xmlNode *n;
	REGVAL_XML *val;
	ULONG size;
	REGKEY_XML *key;

	if (!node->name[0] || node->name[1])
		return;

	for ( e = node->properties; e; e = e->next )
	{
		if (!strcmp( (const char*)e->name, "n"))
			contents = xmlNodeGetContent( (xmlNode*) e );
		else if (!strcmp( (const char*)e->name, "t"))
			type = (const char*) xmlNodeGetContent( (xmlNode*) e );
		else if (!strcmp( (const char*)e->name, "c"))
			keycls = (const char*) xmlNodeGetContent( (xmlNode*) e );
	}

	if (contents)
		name.Copy( contents );
	else
		name.Copy( L"" );

	switch (node->name[0])
	{
	case 'x': // value stored as hex
		// default Type is binary
		if (type == NULL)
			type = "3";
		contents = xmlNodeGetContent( node );
		size = HexToBinary( contents, 0, NULL );
		val = new REGVAL_XML( &name, atoi(type), size );
		HexToBinary( contents, size, val->Data() );
		parent->Values.Append( val );
		break;

	case 'n': // number
		// default Type is REG_DWORD
		if (type == NULL)
			type = "4";
		contents = xmlNodeGetContent( node );
		size = sizeof (ULONG);
		val = new REGVAL_XML( &name, atoi(type), size );
		NumberToBinary( contents, size, val->Data() );
		parent->Values.Append( val );
		break;

	case 's': // value stored as a string
		// default Type is REG_SZ
		if (type == NULL)
			type = "1";

		data.Copy( xmlNodeGetContent( node ) );
		val = new REGVAL_XML( &name, atoi(type), data.Length + 2 );
		memcpy( val->Data(), data.Buffer, data.Length );
		memset( val->Data() + data.Length, 0, 2 );
		parent->Values.Append( val );
		break;

	case 'k': // key
		key = BuildKey( parent, &name );
		CUNICODE_STRING Cls;
		Cls.Copy(keycls);
		key->SetCls(Cls);
		for (n = node->children; n; n = n->next)
			LoadRegKey( key, n );

		break;
	}
}

REGKEY_XML *REGISTRY_XML::BuildKey( REGKEY_XML *root, CUNICODE_STRING *name )
{
	REGKEY_XML *key;

	key = root;
	bool opened_existing;
	CreateParseKey( key, name, opened_existing );

	return key;
}


ULONG GetNextSegment( UNICODE_STRING *str )
{
	ULONG n = 0;

	while ( n < str->Length/sizeof(WCHAR) && str->Buffer[ n ] != '\\' )
		n++;

	return n * sizeof (WCHAR);
}


NTSTATUS REGISTRY_XML::CreateParseKey( REGKEY_XML *&key, UNICODE_STRING *name, bool& opened_existing )
{
	while (name->Length && DoOpenSubkey( key, name, true ))
		/* repeat */ ;

	opened_existing = (name->Length == 0);

	while (name->Length)
	{
		UNICODE_STRING seg;

		SkipSlashes( name );

		seg.Length = GetNextSegment( name );
		seg.Buffer = name->Buffer;

		key = new REGKEY_XML( key, &seg );
		if (!key)
			return STATUS_NO_MEMORY;

		name->Buffer += seg.Length/2;
		name->Length -= seg.Length;
	}

	return STATUS_SUCCESS;
}

ULONG REGISTRY_XML::DoOpenSubkey( REGKEY_XML *&key, UNICODE_STRING *name, bool case_insensitive )
{
	ULONG len;

	SkipSlashes( name );

	len = GetNextSegment( name );
	if (!len)
		return len;

	for (REGKEY_XML_ITER i(key->Children); i; i.Next())
	{
		REGKEY_XML *subkey = i;
		//TRACE("Comparing %pus %pus\n", name, &subkey->Name());
		if (len != subkey->Name().Length)
			continue;
		if (case_insensitive)
		{
			if (StrnCmpW( name->Buffer, subkey->Name().Buffer, len/sizeof(WCHAR) ))
				continue;
		}
		else
		{
			if (memcmp( name->Buffer, subkey->Name().Buffer, len/sizeof(WCHAR) ))
				continue;
		}

		// advance
		key = subkey;
		name->Buffer += len/2;
		name->Length -= len;
		return len;
	}

	return 0;
}

NTSTATUS REGISTRY_XML::CreateKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing )
{
	UNICODE_STRING parsed_name;
	REGKEY_XML *key = RootKey;
	NTSTATUS r;

	if (!oa->ObjectName)
		return STATUS_ACCESS_VIOLATION;

	if (oa->RootDirectory)
	{
		r = ObjectFromHandle( key, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		key = RootKey;

	memcpy( &parsed_name, oa->ObjectName, sizeof parsed_name );
	r = CreateParseKey( key, &parsed_name, opened_existing );

	if (r == STATUS_SUCCESS)
		*out = key;

	return r;
}


NTSTATUS REGISTRY_XML::OpenKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa )
{
	UNICODE_STRING parsed_name;
	IREGKEY *key = RootKey;
	NTSTATUS r;

	if (oa->RootDirectory)
	{
		r = ObjectFromHandle( key, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
	}
	else
		key = RootKey;

	key->PrintDescription();

	memcpy( &parsed_name, oa->ObjectName, sizeof parsed_name );
	r = OpenParseKey( key, &parsed_name, oa->Attributes & OBJ_CASE_INSENSITIVE );

	if (r == STATUS_SUCCESS)
		*out = key;

	return r;
}

NTSTATUS REGISTRY_XML::OpenParseKey( IREGKEY *&ikey, UNICODE_STRING *name, bool case_insensitive  )
{
	REGKEY_XML *key = dynamic_cast<REGKEY_XML*>(ikey);
	assert(key);
	while (name->Length && DoOpenSubkey( key, name, case_insensitive ))
		/* repeat */ ;

	ikey = key;

	if (name->Length)
	{
		TRACE("remaining = %pus\n", name);
		if (name->Length == GetNextSegment( name ))
			return STATUS_OBJECT_NAME_NOT_FOUND;

		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}


REGKEY_XML::REGKEY_XML( REGKEY_XML *_parent, const UNICODE_STRING *_name ) :
	IREGKEY(CUNICODE_STRING(*_name)), m_Parent(_parent)
{
	if (Parent())
		Parent()->Children.Append( this );
}


REGKEY_XML::~REGKEY_XML()
{
	REGKEY_XML_ITER i(Children);
	while (i)
	{
		REGKEY_XML *tmp = i;
		i.Next();
		tmp->SetParent( NULL );
		Children.Unlink( tmp );
		Release( tmp );
	}

	REGVAL_XML_ITER j(Values);
	while (j)
	{
		REGVAL_XML *tmp = j;
		j.Next();
		Values.Unlink( tmp );
		delete tmp;
	}
}

void REGKEY_XML::PrintDescription() const
{
	const REGKEY_XML* key = this;
	CUNICODE_STRING Path;
	while (key)
	{
		CUNICODE_STRING Temp(key->Name());
		Temp.Concat(L"\\");
		Temp.Concat(Path);
		Path = Temp;
		key = key->Parent();
	}
	TRACE("Root: %pus\n", &Path);
}

NTSTATUS REGKEY_XML::SetValue( const CUNICODE_STRING& name, ULONG Type, PVOID Data, ULONG DataSize )
{
	NTSTATUS r;
	REGVAL_XML *val = new REGVAL_XML( &name, Type, DataSize );
	if (val)
	{
		r = CopyFromUser( val->Data(), Data, DataSize );
		if (r == STATUS_SUCCESS)
		{
			DeleteValue( &name );
			Values.Append( val );
		}
		else
			delete val;
	}
	else
		r = STATUS_NO_MEMORY;

	return r;
}

//ERROR HERE
IREGVAL* REGKEY_XML::FindValue( const UNICODE_STRING *us )
{
	TRACE("%pus\n", us);
	for (REGVAL_XML_ITER i(Values); i; i.Next())
	{
		IREGVAL *val = i;
		if (val->Name().Compare(us, TRUE))
			return val;
	}

	return NULL;
}


NTSTATUS REGKEY_XML::DeleteValue(const UNICODE_STRING *us )
{
	IREGVAL *ival;

	TRACE("%pus\n", us);

	ival = FindValue( us );
	if (!ival)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	REGVAL_XML *val = dynamic_cast<REGVAL_XML*>(ival);
	assert(val);

	TRACE("deleting %pus\n", &val->Name());
	Values.Unlink( val );
	delete val;
	return STATUS_SUCCESS;
}

NTSTATUS REGKEY_XML::EnumerateValueKey(
	ULONG Index,
	KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	PVOID KeyValueInformation,
	ULONG KeyValueInformationLength,
	ULONG &len )
{
	NTSTATUS r;
	REGVAL_XML_ITER i(Values);
	for ( ; i && Index; i.Next())
		Index--;

	if (!i)
		return STATUS_NO_MORE_ENTRIES;

	r = RegQueryValue( i, KeyValueInformationClass, KeyValueInformation,
						 KeyValueInformationLength, len );

	return r;
}

NTSTATUS REGKEY_XML::DeleteKey()
{
	if ( Parent() )
	{
		Parent()->Children.Unlink( this );
		SetParent(NULL);
		Release( this );
	}
	return STATUS_SUCCESS;
}

void REGKEY_XML::Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls )
{
	TRACE("full information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.ClassOffset = FIELD_OFFSET( KEY_FULL_INFORMATION, Class );
	info.ClassLength = Cls().Length;
	info.SubKeys = NumSubkeys(info.MaxNameLen, info.MaxClassLen);
	info.Values = NumValues(info.MaxValueNameLen, info.MaxValueDataLen);
	keycls = Cls();
}

void REGKEY_XML::Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr )
{
	TRACE("basic information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.NameLength = Name().Length;

	namestr = Name();
}


ULONG REGKEY_XML::NumValues(ULONG& max_name_len, ULONG& max_data_len)
{
	ULONG n = 0;
	REGVAL_XML_ITER i(Values);
	max_name_len = 0;
	max_data_len = 0;
	while (i)
	{
		REGVAL_XML *val = i;
		max_name_len = std::max(max_name_len, ULONG(val->Name().Length) );
		max_data_len = std::max(max_data_len, ULONG(val->Size()) );
		i.Next();
		n++;
	}
	return n;
}

ULONG REGKEY_XML::NumSubkeys(ULONG& max_name_len, ULONG& max_class_len)
{
	ULONG n = 0;
	REGKEY_XML_ITER i(Children);
	max_name_len = 0;
	while (i)
	{
		REGKEY_XML *subkey = i;
		max_name_len = std::max(max_name_len, ULONG(subkey->Name().Length) );
		max_class_len = std::max(max_class_len, ULONG(subkey->Cls().Length) );
		i.Next();
		n++;
	}
	return n;
}


IREGKEY *REGKEY_XML::GetChild( ULONG Index )
{
	REGKEY_XML_ITER i(Children);
	REGKEY_XML *child;
	while ((child = i) && Index)
	{
		i.Next();
		Index--;
	}
	return child;
}

REGVAL_XML::REGVAL_XML( const UNICODE_STRING *_name, ULONG _type, ULONG _size )
{
	m_Type = _type;
	m_Size = _size;
	m_Name.Copy(_name);
	m_Data = new BYTE[Size()];
}

REGVAL_XML::~REGVAL_XML()
{
	delete[] m_Data;
}
