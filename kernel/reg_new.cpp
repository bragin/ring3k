/*
 * new registry with Redis database
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

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <signal.h>

#include "hiredis.h"
#include "reg_new.h"
#include "reg_new_p.h"
#include "debug.h"
#include "object.h"

DEFAULT_DEBUG_CHANNEL(registry);

#include "object.inl"

redisContext *RedisContext;

REGKEYREDIS::REGKEYREDIS( const CUNICODE_STRING& path)// :
	//Name(path)
{
	Name = path;
}


//value structure:
// type [1 byte]
// data
NTSTATUS ParseRedisValue( REGKEYREDIS* key, char* str, long len )
{
	assert(len >= 1);
	BYTE type = str[0];
}

redisReply* getRedisValue( const CUNICODE_STRING& path )
{
	char key[MAX_REGKEY_LENGTH];
	LONG stored = path.WCharToUtf8(key, MAX_REGKEY_LENGTH);
	assert(stored == path.Length);

	return static_cast<redisReply*>( redisCommand( RedisContext, "GET %s", key ) );
}

NTSTATUS OpenKeyFromDB( REGKEYREDIS **out, const CUNICODE_STRING &path)
{
	NTSTATUS r;
	char key[MAX_REGKEY_LENGTH];
	LONG stored = path.WCharToUtf8(key, MAX_REGKEY_LENGTH);
	assert(stored == path.Length);

	redisReply *reply = static_cast<redisReply*>( redisCommand( RedisContext, "GET %s", key ) );

	if (!reply)
	{
		ERR("Redis error %s\n", RedisContext->errstr);
		return STATUS_UNSUCCESSFUL;
	}

	switch (reply->type)
	{
		case REDIS_REPLY_NIL: break;	//err
		case REDIS_REPLY_ERROR:
			ERR("Redis error %s\n", reply->str);
			return STATUS_UNSUCCESSFUL;
		case REDIS_REPLY_STRING:
		{
			REGKEYREDIS *key = new REGKEYREDIS(path);
			r = ParseRedisValue(key, reply->str, reply->len);
			if (r < STATUS_SUCCESS)
				return r;
		} break;
		default:
			ERR("Unhandled redis status %d\n", reply->type);


	}
}

void RemoveName(CUNICODE_STRING& str)
{
	while (str.Length && str.Buffer[str.Length-1] != L'\\')
	{
		str.Length--;
		str.Buffer = L'\0';
	}
}

NTSTATUS OpenKeyRedis( REGKEYREDIS **out, OBJECT_ATTRIBUTES *oa )
{
	NTSTATUS r;
	CUNICODE_STRING Path;
	REGKEYREDIS *key;

	if (oa->RootDirectory)
	{
		REGKEYREDIS *rootKey = NULL;
		r = ObjectFromHandle( rootKey, oa->RootDirectory, 0 );
		if (r < STATUS_SUCCESS)
			return r;
		Path = rootKey->Name;
		TRACE("root %ls\n", Path.Buffer);
	}

	if (oa->ObjectName)
	{
		if (!Path.IsEmpty())
			Path.Concat(L"\\");

		Path.Concat(*oa->ObjectName);
	}

	SkipSlashes(&Path);

	TRACE("Path %S\n", Path.Buffer);

	redisReply *reply = getRedisValue(Path);
	if (!reply)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (reply->type == REDIS_REPLY_NIL)
	{
		RemoveName(Path);
		TRACE("Value not found, trying to find root element with name %S", Path.Buffer);
		reply = getRedisValue(Path);
		if (reply->type == REDIS_REPLY_NIL)
			return STATUS_OBJECT_PATH_NOT_FOUND;
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	assert (reply->type != REDIS_REPLY_STRING);

	key = new REGKEYREDIS(Path);

	if (!key)
		return STATUS_NO_MEMORY;

	return STATUS_SUCCESS;
}


NTSTATUS CreateKeyRedis( REGKEYREDIS **out, OBJECT_ATTRIBUTES *oa, bool& opened_existing )
{
	
}


bool StartRedis()
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

		Die("execlp(\"redis-server\", NULL) returned with errno = %d", errno);
	}

	return true;
}

void InitNewRegistry( void )
{
	TRACE("Starting redis\n");
	if (!StartRedis())
		Die("Cannot start Redis\n");

	TRACE("Redis started\n");

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
	}

	TRACE("Connected to redis\n");


}

void FreeNewRegistry( void )
{
	redisFree(RedisContext);
}
