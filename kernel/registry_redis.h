/*
 * redis registry
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
#ifndef __REGISTRY_REDIS_H__
#define __REGISTRY_REDIS_H__

#include "registry_interface.h"
#include "regkey_interface.h"
#include "regval_interface.h"
extern "C" {
#include "hiredis.h"
}
#include <map>
#include <list>

#define MAX_PATH_LENGTH (4*1024)
#define MAX_CLASS_LENGTH (256)
#define TYPE_SUFFIX L":info___redis_type"
#define CHILDS_SUFFIX L":info___redis_childs"
#define CLASS_SUFFIX L":info___redis_class"
#define REAL_NAME_SUFFIX L":info___redis_real_name"

class REGISTRY_REDIS;
class REGKEY_REDIS : public IREGKEY
{
public:
	REGKEY_REDIS(REGISTRY_REDIS* Redis, const CUNICODE_STRING& AbsolutePath);

	virtual void Query( KEY_FULL_INFORMATION& info, UNICODE_STRING& keycls );
	virtual void Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr );
	virtual IREGKEY *GetChild( ULONG Index );
	virtual NTSTATUS SetValue( const CUNICODE_STRING& name, ULONG Type, PVOID Data, ULONG DataSize );
	virtual IREGVAL* FindValue( const UNICODE_STRING *us );
	virtual NTSTATUS DeleteValue(const UNICODE_STRING *us );
	virtual NTSTATUS DeleteKey();
	virtual NTSTATUS EnumerateValueKey(	ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, ULONG &len );
	virtual void PrintDescription() const;
	virtual const CUNICODE_STRING Cls() const;
	virtual void SetCls(const CUNICODE_STRING& cls);
	const CUNICODE_STRING &AbsolutePath() const;
private:
	char* DataToUTF8String(PVOID* Data, ULONG Size, ULONG Type);
	void NumSubkeysAndValues(ULONG &MaxNameLen, ULONG &MaxClassLen, ULONG &MaxValueNameLen, ULONG &MaxValueDataLen, ULONG &SubkeysCount, ULONG &ValuesCount);
	void getValueFromReply(redisReply *Reply, redisReply *ReplyType, ULONG &Size, ULONG &Type, BYTE **Data);
private:
	std::list<CUNICODE_STRING> Childs;
	REGISTRY_REDIS* Registry;
	CUNICODE_STRING AbsPath;
};


class REGVAL_REDIS : public IREGVAL
{
public:
	REGVAL_REDIS(const CUNICODE_STRING& Name, ULONG Type, ULONG Size);
	REGVAL_REDIS(const CUNICODE_STRING& Name, ULONG Type, PVOID Data, ULONG Size);
	virtual ~REGVAL_REDIS();

	void SetData(PVOID Data, ULONG Size);
	void SetType(ULONG Type);
};

class REGISTRY_REDIS : public IREGISTRY
{
	friend class REGKEY_REDIS;
	friend class REGVAL_REDIS;
public:
	REGISTRY_REDIS();
	virtual ~REGISTRY_REDIS();

	virtual NTSTATUS CreateKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing );
	virtual NTSTATUS OpenKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa );

	static IREGISTRY* Create();

private:
	bool StartServer();
	NTSTATUS SetRedisValue(const CUNICODE_STRING& Path, PVOID Data, ULONG Size, ULONG Type);

	redisReply* getRedisValue(const CUNICODE_STRING& Path);
	char* getRedisRepresentaiton(PVOID Data, ULONG Size, ULONG Type);

	REGKEY_REDIS* GetOpenedKey(const CUNICODE_STRING& Name);
	REGVAL_REDIS* GetOpenedValue(const CUNICODE_STRING& Name);
	bool CreateKeyPath(CUNICODE_STRING Path, CUNICODE_STRING PathLowercase, bool CaseSensitive);

	bool IsSubkey(const CUNICODE_STRING& Path);
	NTSTATUS CheckPath(CUNICODE_STRING Path, CUNICODE_STRING PathLowercase, bool caseInsensitive);

	REGKEY_REDIS* OpenKeyNoPathCheck(const CUNICODE_STRING& Path, bool &opened_existing);

private:
	redisContext* RedisContext;
	std::map<CUNICODE_STRING, REGKEY_REDIS*> OpenedKeys;
	std::map<CUNICODE_STRING, REGVAL_REDIS*> OpenedValues;
};


#endif // __REGISTRY_REDIS_H__