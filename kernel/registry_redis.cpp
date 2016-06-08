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

#include "registry_redis.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#undef WIN32_NO_STATUS
#include "debug.h"
#include "object.h"
#include "unicode.h"

#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <sys/prctl.h>
#include <errno.h>


DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

const char* StatusIdToString(int id)
{
	switch (id)
	{
		case REDIS_REPLY_STATUS: return "REDIS_REPLY_STATUS";
		case REDIS_REPLY_ERROR: return "REDIS_REPLY_ERROR";
		case REDIS_REPLY_INTEGER: return "REDIS_REPLY_INTEGER";
		case REDIS_REPLY_NIL: return "REDIS_REPLY_NIL";
		case REDIS_REPLY_STRING: return "REDIS_REPLY_STRING";
		case REDIS_REPLY_ARRAY: return "REDIS_REPLY_ARRAY";
		default: return "UNKNOWN";
	}
}

void RemoveLastPart(CUNICODE_STRING& Path)
{
	
	for (int i=Path.Length/2 - 1;i>=0;i--)
	{
		SHORT ch = Path.Buffer[i];
		Path.Buffer[i] = 0;
		Path.Length -= 2;
		if (ch == L'\\')
			break;
	}
}

void GetLocalNameFromPath(const CUNICODE_STRING& Path, CUNICODE_STRING& Result)
{
	int i;
	for (i=Path.Length/2 - 1;i>=0 && Path.Buffer[i] != '\\';i--);
	i++;

	UNICODE_STRING Temp;
	Temp.Buffer = &Path.Buffer[i];
	Temp.Length = Path.Length - i*2;
	Temp.MaximumLength = Temp.Length;

	Result = CUNICODE_STRING(Temp);
}

CUNICODE_STRING ReturnLocalNameFromPath(const CUNICODE_STRING& Path)
{
	CUNICODE_STRING Result;
	GetLocalNameFromPath(Path, Result);
	return Result;
}


REGISTRY_REDIS::REGISTRY_REDIS()
{

	//TRACE("Starting redis\n");
	//if (!StartServer())
	//	Die("Cannot start Redis\n");

	//TRACE("Redis started\n");

	RedisContext = redisConnect("127.0.0.1", 6379);

	if (RedisContext == NULL || RedisContext->err)
	{
	    if (RedisContext)
	    {
	        Die("Error: %s\n", RedisContext->errstr);
	    }
	    else
	    {
	        Die("Can't allocate redis context\n");
	    }
	} else 
		TRACE("Connected to redis\n");

}

REGISTRY_REDIS::~REGISTRY_REDIS()
{
	TRACE("Closing redis...\nEmpty destructor\n");

}

bool REGISTRY_REDIS::StartServer()
{
	pid_t RedisServerPid = 0;
	if ((RedisServerPid = fork()) == 0)
	{
		//child process

		TRACE("SET SIGKILL\n");
		prctl(PR_SET_PDEATHSIG, SIGKILL);

		//execlp function returns only when error occurs
		execlp("redis-server", "redis-server", NULL);

		if (errno == EACCES)
		{
			Die("Cannot found redis-server in $PATH\n");
		}

		Die("execlp(\"redis-server\", NULL) returned with errno = %d\n", errno);
	}

	return true;
}

IREGISTRY* REGISTRY_REDIS::Create()
{
	printf("create redis\n");
	return new REGISTRY_REDIS;
}

bool REGISTRY_REDIS::CreateKeyPath(CUNICODE_STRING Path, CUNICODE_STRING PathLowercase, bool CaseInsensitive)
{
	char UTF8Path[MAX_PATH_LENGTH];
	PathLowercase.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	CUNICODE_STRING LocalNameW;
	GetLocalNameFromPath(Path, LocalNameW);
	char LocalName[MAX_PATH_LENGTH];
	LocalNameW.WCharToUtf8(LocalName, MAX_PATH_LENGTH);




	TRACE("Path '%pus', LocalName '%pus'\n", &Path, &LocalNameW);

	TRACE("EXISTS %s\n", UTF8Path);
	redisReply* Reply = (redisReply*)redisCommand(RedisContext, "EXISTS %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type != REDIS_REPLY_INTEGER) {
		freeReplyObject(Reply);
		return false;
	}

	if (Reply->integer == 1) {
		freeReplyObject(Reply);
		return true;
	}
	freeReplyObject(Reply);

	//key created
	TRACE("SET %s\n", UTF8Path);
	Reply = (redisReply*)redisCommand(RedisContext, "SET %s \"\"", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
	{
		TRACE("reply error %s\n", Reply->str);
		freeReplyObject(Reply);
		return false;
	}
	freeReplyObject(Reply);


	//store real name
	CUNICODE_STRING RealNamePath(PathLowercase);
	RealNamePath.Concat(REAL_NAME_SUFFIX);
	RealNamePath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
	TRACE("SET %s %s\n", UTF8Path, LocalName);
	Reply = (redisReply*)redisCommand(RedisContext, "SET %s %s", UTF8Path, LocalName);
	if (Reply->type == REDIS_REPLY_ERROR)
	{
		TRACE("reply error %s\n", Reply->str);
		freeReplyObject(Reply);
		return false;
	}
	freeReplyObject(Reply);


	RemoveLastPart(Path);
	RemoveLastPart(PathLowercase);

	//Create parent
	if (!CreateKeyPath(Path, PathLowercase, CaseInsensitive))		//error?
		return false;


	//add child in parent class
	CUNICODE_STRING ChildsPath(PathLowercase);
	ChildsPath.Concat(CHILDS_SUFFIX);
	ChildsPath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	//convert local name to lower case
	CUNICODE_STRING LocalNameLowcase(LocalNameW);
	LocalNameLowcase.ToLowerCase();
	LocalNameLowcase.WCharToUtf8(LocalName, MAX_PATH_LENGTH);
	TRACE("LPUSH %s %s\n", UTF8Path, LocalName);
	Reply = (redisReply*)redisCommand(RedisContext, "RPUSH %s %s", UTF8Path, LocalName);
	if (Reply->type == REDIS_REPLY_ERROR)
	{
		TRACE("reply error %s\n", Reply->str);
		freeReplyObject(Reply);
		return false;
	}


	return true;

}

NTSTATUS REGISTRY_REDIS::CreateKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing )
{
	NTSTATUS r;
	CUNICODE_STRING Path;

	if (!oa->ObjectName)
		return STATUS_ACCESS_VIOLATION;

	if (oa->RootDirectory)
	{
		REGKEY_REDIS* Key = NULL;
		r = ObjectFromHandle( Key, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
		Path = Key->Name();
		Path.Concat(L"\\");
	}

	Path.Concat(*oa->ObjectName);
	Path.SkipSlashes();

	CUNICODE_STRING PathLowercase(Path);
	PathLowercase.ToLowerCase();

	CreateKeyPath(Path, PathLowercase, oa->Attributes & OBJ_CASE_INSENSITIVE);

	*out = OpenKeyNoPathCheck(Path, opened_existing);

	return STATUS_SUCCESS;

}

NTSTATUS REGISTRY_REDIS::CheckPath(CUNICODE_STRING Path, CUNICODE_STRING PathLowercase, bool CaseInsensitive)
{
	TRACE("Path '%pus' PathLowercase '%pus'\n",&Path, &PathLowercase);
	//don't create it on stack, because function is recursive
	char* UTF8Path;
	char* RealName;
	try {
		UTF8Path = new char[MAX_PATH_LENGTH];
		RealName = new char[MAX_PATH_LENGTH];
	} catch (std::bad_alloc& e) {
		return STATUS_NO_MEMORY;
	}

	PathLowercase.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
	TRACE("EXISTS %s\n", UTF8Path);
	redisReply *Reply = (redisReply*)redisCommand(RedisContext, "EXISTS %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	if (Reply->type != REDIS_REPLY_INTEGER || Reply->integer != 1) {
		TRACE("Path '%s' doesn't exists\n", UTF8Path);
		delete[] UTF8Path;
		delete[] RealName;
		freeReplyObject(Reply);
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	freeReplyObject(Reply);

	if (CaseInsensitive) {
		RemoveLastPart(Path);
		RemoveLastPart(PathLowercase);
		assert(Path.Length == PathLowercase.Length);

		if (Path.Length == 0)
			return STATUS_SUCCESS;

		return CheckPath(Path, PathLowercase, CaseInsensitive);
	}

	CUNICODE_STRING LocalNameW;
	GetLocalNameFromPath(Path, LocalNameW);
	LocalNameW.WCharToUtf8(RealName, MAX_PATH_LENGTH);

	CUNICODE_STRING PathRealName(PathLowercase);
	PathRealName.Concat(REAL_NAME_SUFFIX);
	PathRealName.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("GET %s\n", UTF8Path);
	Reply = (redisReply*)redisCommand(RedisContext, "GET %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	if (Reply->type != REDIS_REPLY_STRING) {
		ERR("Cannot find info___redis_real_name property for key '%s'\n", UTF8Path);
		delete[] UTF8Path;
		delete[] RealName;
		freeReplyObject(Reply);
		return STATUS_UNSUCCESSFUL;
	}

	if (strcmp(Reply->str, RealName) != 0) {
		TRACE("Real name for key '%s' is not equal for expected name '%s'\n", Reply->str, RealName);
		delete[] UTF8Path;
		delete[] RealName;
		freeReplyObject(Reply);
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	
	delete[] UTF8Path;
	delete[] RealName;
	freeReplyObject(Reply);

	RemoveLastPart(Path);
	RemoveLastPart(PathLowercase);

	assert(Path.Length == PathLowercase.Length);

	if (Path.Length == 0)
		return STATUS_SUCCESS;

	return CheckPath(Path, PathLowercase, CaseInsensitive);

}

NTSTATUS REGISTRY_REDIS::OpenKey( IREGKEY **out, OBJECT_ATTRIBUTES *oa )
{
	NTSTATUS r;
	CUNICODE_STRING Path;

	if (oa->RootDirectory)
	{
		REGKEY_REDIS *rootKey = NULL;
		r = ObjectFromHandle( rootKey, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
		Path = rootKey->AbsolutePath();
		TRACE("root %ls\n", Path.Buffer);
	}

	if (oa->ObjectName)
	{
		if (!Path.IsEmpty())
			Path.Concat(L"\\");

		Path.Concat(*oa->ObjectName);
	}

	Path.SkipSlashes();
	CUNICODE_STRING PathLowercase( Path );
	PathLowercase.ToLowerCase();


	TRACE("Path %pus lowercase %pus\n", &Path, &PathLowercase);


	r = CheckPath(Path, PathLowercase, oa->Attributes & OBJ_CASE_INSENSITIVE);
	if (r == STATUS_OBJECT_PATH_NOT_FOUND)
	{
		RemoveLastPart(Path);
		RemoveLastPart(PathLowercase);
		r = CheckPath(Path, PathLowercase, oa->Attributes & OBJ_CASE_INSENSITIVE);
		if (r == STATUS_SUCCESS)
			return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (r < STATUS_SUCCESS)
		return r;

	bool opened_existing;	//unused
	*out = OpenKeyNoPathCheck(Path, opened_existing);

	return STATUS_SUCCESS;
}

redisReply* REGISTRY_REDIS::getRedisValue(const CUNICODE_STRING& Path)
{
	char UnicodePath[MAX_PATH_LENGTH];
	Path.WCharToUtf8(UnicodePath, MAX_PATH_LENGTH);
	TRACE("GET %s\n", UnicodePath);
	redisReply* Reply = (redisReply*)redisCommand(RedisContext, "GET %s", UnicodePath);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	return Reply;
}

REGKEY_REDIS::REGKEY_REDIS(REGISTRY_REDIS* Redis, const CUNICODE_STRING& AbsolutePath) :
	IREGKEY(ReturnLocalNameFromPath(AbsolutePath))
{
	Registry = Redis;
	CUNICODE_STRING Temp(AbsolutePath);
	Temp.ToLowerCase();
	AbsPath = Temp;
}

void REGKEY_REDIS::getValueFromReply(redisReply *Reply, redisReply *ReplyType, ULONG &Size, ULONG &Type, BYTE **Data)
{
	if (Reply->type != REDIS_REPLY_STRING || Reply->type != REDIS_REPLY_STRING)
		return;

	Type = strtol(ReplyType->str, NULL, 10);

	TRACE("Reply: type %d len %d\n", Type, Reply->len);

	switch (Type) {
		case REG_NONE:
		case REG_BINARY:
		case REG_SZ:
		case REG_EXPAND_SZ:
		case REG_LINK:
		case REG_DWORD:
		case REG_DWORD_BIG_ENDIAN:
		case REG_MULTI_SZ: {
			Size = Reply->len;
			*Data = new BYTE[Size];
			memcpy(*Data, Reply->str, Size);
		} break;
		/*case REG_DWORD:
		//case REG_DWORD_LITTLE_ENDIAN:
		case REG_DWORD_BIG_ENDIAN: {
			Size = sizeof(DWORD);
			DWORD *Temp = new DWORD;
			*Temp = strtol(Reply->str, NULL, 10);
			*Data = (BYTE*)Temp;
		} break;*/
		default:
			ERR("Undefined type %d\n", Type);
	}
}

IREGVAL* REGKEY_REDIS::FindValue( const UNICODE_STRING *us )
{
	CUNICODE_STRING Path(AbsolutePath());
	Path.Concat(L"\\");
	Path.Concat(*us);

	REGVAL_REDIS* val = Registry->GetOpenedValue(Path);
	if (val)
		return val;


	redisReply *Reply = Registry->getRedisValue(Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type != REDIS_REPLY_STRING) {
		freeReplyObject(Reply);
		return NULL;
	}

	CUNICODE_STRING PathType(Path);
	PathType.Concat(TYPE_SUFFIX);

	redisReply *TypeReply = Registry->getRedisValue(PathType);
	if (TypeReply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	//err
	//error memory leak in REGVAL m_Data
	ULONG Size = 0;
	ULONG Type = 0;
	BYTE *Data = NULL;
	getValueFromReply(Reply, TypeReply, Size, Type, &Data);

	freeReplyObject(Reply);
	freeReplyObject(TypeReply);

	val = new REGVAL_REDIS(CUNICODE_STRING(*us), Type, Data, Size);

	Registry->OpenedValues[Path] = val;

	return val;
}

IREGKEY *REGKEY_REDIS::GetChild( ULONG Index )
{
	CUNICODE_STRING Path(AbsolutePath());
	char UTF8Path[MAX_PATH_LENGTH];
	Path.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	redisReply *Reply = (redisReply*)redisCommand(Registry->RedisContext, "LINDEX %s %d", UTF8Path, Index);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	if (Reply->type == REDIS_REPLY_STRING) {
		CUNICODE_STRING ChildName;
		ChildName.Copy(Reply->str);
		Path.Concat(ChildName);
		freeReplyObject(Reply);

		bool opened_existing; //unused
		return Registry->OpenKeyNoPathCheck(Path, opened_existing);
	}
	return NULL;
}

void REGKEY_REDIS::Query( KEY_FULL_INFORMATION& info, UNICODE_STRING* keycls )
{
	TRACE("full information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.ClassOffset = FIELD_OFFSET( KEY_FULL_INFORMATION, Class );
	info.ClassLength = Cls().Length;
	NumSubkeysAndValues(info.MaxNameLen, info.MaxClassLen, info.MaxValueNameLen, info.MaxValueDataLen, info.SubKeys, info.Values);
	
	CUNICODE_STRING cls = Cls();
	if (cls.Buffer) {
		//copy
		USHORT len = std::max(cls.MaximumLength, cls.Length);
		
		keycls->Buffer = new WCHAR[(len + 1)/sizeof(WCHAR)];
		memcpy(keycls->Buffer, cls.Buffer, len);

		keycls->MaximumLength = cls.MaximumLength;
		keycls->Length = cls.Length;
	} else {
		*keycls = cls;
	}
	
	TRACE("class = %pus\n", &keycls );
}

void REGKEY_REDIS::NumSubkeysAndValues(ULONG &MaxNameLen, ULONG &MaxClassLen, ULONG &MaxValueNameLen, ULONG &MaxValueDataLen, ULONG &SubkeysCount, ULONG &ValuesCount)
{
	ValuesCount = 0;
	SubkeysCount = 0;
	MaxNameLen = 0;
	MaxClassLen = 0;
	MaxValueDataLen = 0;
	MaxValueNameLen = 0;

	CUNICODE_STRING ChildsPath(AbsolutePath());
	ChildsPath.Concat(CHILDS_SUFFIX);
	char UTF8Path[MAX_PATH_LENGTH];
	ChildsPath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
	TRACE("LRANGE %s 0 -1\n", UTF8Path);
	redisReply *Reply = (redisReply*)redisCommand(Registry->RedisContext, "LRANGE %s 0 -1", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type == REDIS_REPLY_ARRAY) {

		for (ULONG i=0;i<Reply->elements;i++) {
			assert(Reply->element[i]->type == REDIS_REPLY_STRING);
			CUNICODE_STRING ChildName;
			ChildName.Copy(Reply->element[i]->str);

			CUNICODE_STRING ChildPath(AbsolutePath());
			ChildPath.Concat(L"\\");
			ChildPath.Concat(ChildName);

			
			if ( !Registry->IsSubkey(ChildPath) ) {
				ValuesCount++;
				MaxValueNameLen = std::max((ULONG)ChildName.Length, MaxValueNameLen);

				ChildPath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
				redisReply *ValueLengthReply = (redisReply*)redisCommand(Registry->RedisContext, "STRLEN %s", UTF8Path);
				if (ValueLengthReply->type == REDIS_REPLY_ERROR)
					ERR("error %s\n", ValueLengthReply->str);

				MaxValueDataLen = std::max((ULONG)ValueLengthReply->integer, MaxValueDataLen);
				freeReplyObject(ValueLengthReply);
			} else {
				SubkeysCount++;
				MaxNameLen = std::max((ULONG)ChildName.Length, MaxNameLen);
				MaxClassLen = std::max((ULONG)Cls().Length, MaxClassLen);
			}
		}
	}
	freeReplyObject(Reply);
}

void REGKEY_REDIS::Query( KEY_BASIC_INFORMATION& info, UNICODE_STRING& namestr )
{
	TRACE("basic information\n");
	info.LastWriteTime.QuadPart = 0LL;
	info.TitleIndex = 0;
	info.NameLength = Name().Length;

	namestr = Name();
}

NTSTATUS REGKEY_REDIS::EnumerateValueKey(ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG KeyValueInformationLength, ULONG &len )
{
	CUNICODE_STRING ChildsPath(AbsolutePath());
	ChildsPath.Concat(CHILDS_SUFFIX);
	char UTF8Path[MAX_PATH_LENGTH];
	ChildsPath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("LRANGE %s 0 -1\n", UTF8Path);
	redisReply *Reply = (redisReply*)redisCommand(Registry->RedisContext, "LRANGE %s 0 -1", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type == REDIS_REPLY_ARRAY) {
		for (ULONG i=0;i<Reply->elements;i++) {
			assert(Reply->element[i]->type == REDIS_REPLY_STRING);

			CUNICODE_STRING ChildName;
			ChildName.Copy(Reply->element[i]->str);

			CUNICODE_STRING ChildPath(AbsolutePath());
			ChildPath.Concat(L"\\");
			ChildPath.Concat(ChildName);
			TRACE("Checking %pus\n", &ChildPath);

			if (!Index) {
				IREGVAL *val = FindValue(&ChildName);
				freeReplyObject(Reply);
				return RegQueryValue( val, KeyValueInformationClass, KeyValueInformation,
						 KeyValueInformationLength, len );
			}

			if (!Registry->IsSubkey(ChildPath)) {
				TRACE("VALUE\n");
				Index--;
			}
		}
	}
	freeReplyObject(Reply);

	return STATUS_NO_MORE_ENTRIES;
}

const CUNICODE_STRING REGKEY_REDIS::Cls() const
{
	CUNICODE_STRING PathClass(AbsolutePath());
	PathClass.Concat(CLASS_SUFFIX);
	char UTF8Path[MAX_PATH_LENGTH];
	PathClass.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("GET %s\n", UTF8Path);
	redisReply *Reply = (redisReply*)redisCommand(Registry->RedisContext, "GET %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type == REDIS_REPLY_STRING) {
		CUNICODE_STRING Cls;
		Cls.Copy(Reply->str);
		freeReplyObject(Reply);
		return Cls;
	}
	freeReplyObject(Reply);

	return CUNICODE_STRING();
}
void REGKEY_REDIS::SetCls(const CUNICODE_STRING& cls)
{
	CUNICODE_STRING PathClass(AbsolutePath());
	PathClass.Concat(CLASS_SUFFIX);
	char UTF8Path[MAX_PATH_LENGTH];
	PathClass.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	char UTF8Cls[MAX_PATH_LENGTH];
	cls.WCharToUtf8(UTF8Cls, MAX_PATH_LENGTH);

	TRACE("SET %s %s\n", UTF8Path, UTF8Cls);
	redisReply *Reply = (redisReply*)redisCommand(Registry->RedisContext, "SET %s %s", UTF8Path, UTF8Cls);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	freeReplyObject(Reply);
}

const CUNICODE_STRING &REGKEY_REDIS::AbsolutePath() const
{
	return AbsPath;
}

NTSTATUS REGKEY_REDIS::DeleteValue(const UNICODE_STRING *us )
{
	CUNICODE_STRING Str(*us);
	
	std::map<CUNICODE_STRING, REGVAL_REDIS*>::iterator it = Registry->OpenedValues.find(Str);

	if (it != Registry->OpenedValues.end())
	{
		delete it->second;
	}

	CUNICODE_STRING Path(AbsolutePath());
	Path.Concat(CHILDS_SUFFIX);

	char UTF8Path[MAX_PATH_LENGTH];
	Path.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
	char Name[MAX_PATH_LENGTH];
	Str.WCharToUtf8(Name, MAX_PATH_LENGTH);


	TRACE("LREM %s 0 %s\n", UTF8Path, Name);
	redisReply* Reply = (redisReply*)redisCommand(Registry->RedisContext, "LREM %s 0 %s", UTF8Path, Name);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type != REDIS_REPLY_INTEGER || Reply->integer != 1) {
		freeReplyObject(Reply);
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	freeReplyObject(Reply);
	
	Path.Copy(&AbsolutePath());
	Path.Concat(L"\\");
	Path.Concat(*us);
	Path.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("DEL %s\n", UTF8Path);
	Reply = (redisReply*)redisCommand(Registry->RedisContext, "DEL %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	if (Reply->type != REDIS_REPLY_INTEGER || Reply->integer != 1) {
		freeReplyObject(Reply);
		return STATUS_UNSUCCESSFUL;
	}
	freeReplyObject(Reply);


	return STATUS_SUCCESS;

}

//fix me later, need to delete all recursively
NTSTATUS REGKEY_REDIS::DeleteKey()
{
	char UTF8Path[MAX_PATH_LENGTH];
	AbsolutePath().WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("DEL %s\n", UTF8Path);
	redisReply* Reply = (redisReply*)redisCommand(Registry->RedisContext, "DEL %s", UTF8Path);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);
	if (Reply->type != REDIS_REPLY_INTEGER || Reply->integer != 1) {
		freeReplyObject(Reply);
		return STATUS_UNSUCCESSFUL;
	}
	freeReplyObject(Reply);


	CUNICODE_STRING ParentChilds(AbsolutePath());
	RemoveLastPart(ParentChilds);
	ParentChilds.Concat(CHILDS_SUFFIX);
	ParentChilds.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	CUNICODE_STRING LocalNameW;
	GetLocalNameFromPath(Name(), LocalNameW);
	char LocalName[MAX_PATH_LENGTH];
	LocalNameW.WCharToUtf8(LocalName, MAX_PATH_LENGTH);

	TRACE("LREM %s 0 %s\n", UTF8Path, LocalName);
	Reply = (redisReply*)redisCommand(Registry->RedisContext, "LREM %s 0 %s", UTF8Path, LocalName);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	if (Reply->type != REDIS_REPLY_INTEGER || Reply->integer != 1) {
		freeReplyObject(Reply);
		return STATUS_UNSUCCESSFUL;
	}

	freeReplyObject(Reply);
	return STATUS_SUCCESS;

}

void REGKEY_REDIS::PrintDescription() const
{	
	TRACE("REGKEY Name %pus\n", &Name());
}

NTSTATUS REGKEY_REDIS::SetValue( const CUNICODE_STRING& name, ULONG Type, PVOID Data, ULONG DataSize )
{
	NTSTATUS r;
	
	BYTE KernelData[DataSize];
	r = CopyFromUser( KernelData, Data, DataSize );
	if (r < STATUS_SUCCESS)
		return r;

	CUNICODE_STRING Path(AbsolutePath());
	Path.Concat(L"\\");
	Path.Concat(name);

	Registry->SetRedisValue(Path, KernelData, DataSize, Type);

	return r;
}

REGKEY_REDIS* REGISTRY_REDIS::OpenKeyNoPathCheck(const CUNICODE_STRING& Path, bool &opened_existing)
{
	REGKEY_REDIS* key = NULL;

	std::map<CUNICODE_STRING, REGKEY_REDIS*>::iterator it_key = OpenedKeys.find(Path);
	if (it_key == OpenedKeys.end()) {
		TRACE("Create new key '%pus'\n", &Path);
		key = new REGKEY_REDIS(this, Path);
		if (!key)
			return NULL;

		OpenedKeys[Path] = key;
	} else {
		TRACE("Open created key '%pus'\n", &Path);
		TRACE("%pus\n", &it_key->second->AbsolutePath());
		opened_existing = true;
		key = it_key->second;
	}
	return key;
}

NTSTATUS REGISTRY_REDIS::SetRedisValue(const CUNICODE_STRING& Path, PVOID Data, ULONG Size, ULONG Type)
{
	CUNICODE_STRING PathLowercase(Path);
	PathLowercase.ToLowerCase();
	char UTF8Path[MAX_PATH_LENGTH];
	PathLowercase.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	//set value

	char* representation = getRedisRepresentaiton(Data, Size, Type);
	TRACE("SET %s %s\n", UTF8Path, representation);
	redisReply *Reply = (redisReply*)redisCommand(RedisContext, "SET %s %b", UTF8Path, representation, (size_t)Size);

	if (Reply->type == REDIS_REPLY_ERROR) {
		ERR("%s\n", Reply->str);
		freeReplyObject(Reply);
		delete[] representation;
		return STATUS_UNSUCCESSFUL;
	}

	REGVAL_REDIS* val = GetOpenedValue(PathLowercase);
	if (val) {
		TRACE("Updating data to %d\n", representation[0]);
		val->SetData(representation, Size);
	}

	delete[] representation;
	freeReplyObject(Reply);

	//set object type
	CUNICODE_STRING TypePath(PathLowercase);
	TypePath.Concat(TYPE_SUFFIX);
	TypePath.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);
	TRACE("SET %s %d\n", UTF8Path, Type);
	Reply = (redisReply*)redisCommand(RedisContext, "SET %s %d", UTF8Path, Type);

	if (Reply->type == REDIS_REPLY_ERROR) {
		ERR("%s\n", Reply->str);
		freeReplyObject(Reply);
		return STATUS_UNSUCCESSFUL;
	}
	freeReplyObject(Reply);

	if (val)
		val->SetType(Type);

	//add to parent childs
	CUNICODE_STRING LocalNameW(PathLowercase);
	CUNICODE_STRING PathToParentChilds(PathLowercase);
	GetLocalNameFromPath(PathLowercase, LocalNameW);
	RemoveLastPart(PathToParentChilds);
	PathToParentChilds.Concat(CHILDS_SUFFIX);
	PathToParentChilds.WCharToUtf8( UTF8Path, MAX_PATH_LENGTH );


	char UTF8Name[MAX_PATH_LENGTH];
	LocalNameW.WCharToUtf8( UTF8Name, MAX_PATH_LENGTH );

	TRACE("LREM %s 0 %s\n", UTF8Path, UTF8Name);
	Reply = (redisReply*)redisCommand(RedisContext, "LREM %s 0 %s", UTF8Path, UTF8Name);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	freeReplyObject(Reply);

	TRACE("LPUSH %s %s\n", UTF8Path, UTF8Name);
	Reply = (redisReply*)redisCommand(RedisContext, "RPUSH %s %s", UTF8Path, UTF8Name);
	if (Reply->type == REDIS_REPLY_ERROR)
		ERR("%s\n", Reply->str);

	freeReplyObject(Reply);

	return STATUS_SUCCESS;

}

char* REGISTRY_REDIS::getRedisRepresentaiton(PVOID Data, ULONG Size, ULONG Type)
{
	switch (Type)
	{
		case REG_NONE:
		case REG_BINARY:
		case REG_SZ:
		case REG_EXPAND_SZ:
		default:
		{
			char *Utf8Data = new char[Size];
			memcpy(Utf8Data, Data, Size);
			return Utf8Data;
		}
		case REG_DWORD:
		{
			char* StringDword = new char[Size];
			memcpy(StringDword, Data, Size);

			//DWORD Dword = *(DWORD*)Data;
			//sprintf(StringDword, "%ld", Dword);
			return StringDword;
		}

	}
}

REGKEY_REDIS* REGISTRY_REDIS::GetOpenedKey(const CUNICODE_STRING& Name)
{
	std::map<CUNICODE_STRING, REGKEY_REDIS*>::iterator it = OpenedKeys.find(Name);
	if (it != OpenedKeys.end())
		return it->second;
	return NULL;
}

REGVAL_REDIS* REGISTRY_REDIS::GetOpenedValue(const CUNICODE_STRING& Name)
{
	std::map<CUNICODE_STRING, REGVAL_REDIS*>::iterator it = OpenedValues.find(Name);
	if (it != OpenedValues.end())
		return it->second;
	return NULL;
}

bool REGISTRY_REDIS::IsSubkey(const CUNICODE_STRING& Path)
{
	char UTF8Path[MAX_PATH_LENGTH];
	CUNICODE_STRING ChildValueType(Path);
	ChildValueType.Concat(TYPE_SUFFIX);
	ChildValueType.WCharToUtf8(UTF8Path, MAX_PATH_LENGTH);

	TRACE("EXISTS %s\n", UTF8Path);
	redisReply *ChildReply = (redisReply*)redisCommand(RedisContext, "EXISTS %s", UTF8Path);
	if (ChildReply->type == REDIS_REPLY_ERROR)
		ERR("error %s\n", ChildReply->str);

	bool result = ChildReply->integer;
	freeReplyObject(ChildReply);

	return !result;
}

REGVAL_REDIS::REGVAL_REDIS(const CUNICODE_STRING& _Name, ULONG _Type, ULONG _Size)
{
	m_Data = NULL;
	SetType(_Type);
	m_Size = _Size;
	m_Name = _Name;
	m_Data = new BYTE[Size()];
}

REGVAL_REDIS::REGVAL_REDIS(const CUNICODE_STRING& _Name, ULONG _Type, PVOID _Data, ULONG _Size)
{
	m_Data = NULL;
	m_Name = _Name;
	SetType(_Type);
	SetData(_Data, _Size);	
}

REGVAL_REDIS::~REGVAL_REDIS()
{
	delete[] m_Data;
}

void REGVAL_REDIS::SetData(PVOID Data, ULONG Size)
{
	if (m_Data)
		delete[] m_Data;

	m_Size = Size;

	m_Data = new BYTE[Size];
	memcpy(m_Data, Data, Size);
}

void REGVAL_REDIS::SetType(ULONG Type)
{
	m_Type = Type;
}
