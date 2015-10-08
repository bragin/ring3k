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


#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"
#include "unicode.h"
#include "ntcall.h"

#include "file.h"
#include "objdir.h"
#include "debug.h"

class PIPE_SERVER;
class PIPE_CLIENT;
class PIPE_CONTAINER;

typedef LIST_ANCHOR<PIPE_SERVER,0> PIPE_SERVER_LIST;
typedef LIST_ELEMENT<PIPE_SERVER> PIPE_SERVER_ELEMENT;
typedef LIST_ITER<PIPE_SERVER,0> PIPE_SERVER_ITER;
typedef LIST_ANCHOR<PIPE_CLIENT,0> PIPE_CLIENT_LIST;
typedef LIST_ELEMENT<PIPE_CLIENT> PIPE_CLIENT_ELEMENT;
typedef LIST_ITER<PIPE_CLIENT,0> PIPE_CLIENT_ITER;

// the pipe device \Device\NamedPipe, contains pipes of different names
class PIPE_DEVICE : public OBJECT_DIR_IMPL, public IO_OBJECT
{
public:
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	NTSTATUS WaitServerAvailable( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length );
};

// factory to create the pipe device at startup
class PIPE_DEVICE_FACTORY : public OBJECT_FACTORY
{
public:
	NTSTATUS AllocObject(OBJECT** obj);
};

// contains all clients and servers associated with a specific pipe name
class PIPE_CONTAINER : virtual public OBJECT
{
	PIPE_SERVER_LIST servers;
	PIPE_CLIENT_LIST clients;
	ULONG num_instances;
	ULONG max_instances;
public:
	PIPE_CONTAINER( ULONG max );
	NTSTATUS CreateServer( PIPE_SERVER*& pipe, ULONG max_inst );
	NTSTATUS CreateClient( PIPE_CLIENT*& pipe );
	void Unlink( PIPE_SERVER *pipe );
	PIPE_SERVER_LIST& GetServers()
	{
		return servers;
	}
	PIPE_CLIENT_LIST& GetClients()
	{
		return clients;
	}
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	PIPE_SERVER* FindIdleServer();
};

class PIPE_MESSAGE;

typedef LIST_ANCHOR<PIPE_MESSAGE,0> PIPE_MESSAGE_LIST;
typedef LIST_ELEMENT<PIPE_MESSAGE> PIPE_MESSAGE_ELEMENT;
typedef LIST_ITER<PIPE_MESSAGE,0> PIPE_MESSAGE_ITER;

class PIPE_MESSAGE
{
protected:
	void *operator new(unsigned int count, void*&ptr)
	{
		assert( count == sizeof (PIPE_MESSAGE));
		return ptr;
	}
	PIPE_MESSAGE(ULONG _Length);
public:
	PIPE_MESSAGE_ELEMENT Entry[1];
	ULONG Length;
	static PIPE_MESSAGE* AllocPipeMessage( ULONG _Length );
	unsigned char *DataPtr();
};

// a single server instance
class PIPE_SERVER : public IO_OBJECT
{
	friend class PIPE_CONTAINER;
public:
	enum pipe_state
	{
		pipe_idle,
		pipe_wait_connect,
		pipe_connected,
		pipe_wait_disconnect,
		pipe_disconnected,
	};
	PIPE_CONTAINER *Container;
	pipe_state State;
	PIPE_CLIENT *Client;
	THREAD *Thread;
	PIPE_SERVER_ELEMENT Entry[1];
	PIPE_MESSAGE_LIST ReceivedMessages;
	PIPE_MESSAGE_LIST SentMessages;
public:
	PIPE_SERVER( PIPE_CONTAINER *container );
	~PIPE_SERVER();
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	inline bool IsConnected()
	{
		return State == pipe_connected;
	}
	inline bool IsIdle()
	{
		return State == pipe_idle;
	}
	inline bool IsAwaitingConnect()
	{
		return State == pipe_wait_connect;
	}
	bool DoConnect();
	NTSTATUS Connect();
	NTSTATUS Disconnect();
	void SetClient( PIPE_CLIENT* pipe_client );
	void QueueMessageFromClient( PIPE_MESSAGE *msg );
	void QueueMessageToClient( PIPE_MESSAGE *msg );
};

// a single client instance
class PIPE_CLIENT : public IO_OBJECT
{
	friend class PIPE_CONTAINER;
public:
	PIPE_CLIENT_ELEMENT Entry[1];
	PIPE_SERVER *Server;
	THREAD *Thread;
public:
	PIPE_CLIENT( PIPE_CONTAINER *container );
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	NTSTATUS SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	NTSTATUS Transceive(
		PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
};

// server factory, used by NtCreateNamedPipeFile
class PIPE_FACTORY : public OBJECT_FACTORY
{
	ULONG MaxInstances;
public:
	PIPE_FACTORY( ULONG _MaxInstances );
	NTSTATUS AllocObject(OBJECT** obj);
	NTSTATUS OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info );
};

NTSTATUS PIPE_DEVICE::Open( OBJECT *&out, OPEN_INFO& info )
{
	if (info.path.Length == 0)
		return OBJECT_DIR_IMPL::Open( out, info );

	// appears to be a flat namespace under the pipe device
	trace("pipe = %pus\n", &info.path );
	out = lookup( info.path, info.case_insensitive() );

	// not the NtCreateNamedPipeFile case?
	if (out && dynamic_cast<PIPE_FACTORY*>(&info) == NULL)
		return out->Open( out, info );

	return info.OnOpen( this, out, info );
}

NTSTATUS PIPE_CONTAINER::Open( OBJECT *&out, OPEN_INFO& info )
{
	trace("allocating pipe client = %pus\n", &info.path );
	PIPE_CLIENT *pipe = 0;
	NTSTATUS r = CreateClient( pipe );
	if (r < STATUS_SUCCESS)
		return r;
	out = pipe;
	return r;
}

NTSTATUS PIPE_DEVICE_FACTORY::AllocObject(OBJECT** obj)
{
	*obj = new PIPE_DEVICE;
	if (!*obj)
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

void InitPipeDevice()
{
	PIPE_DEVICE_FACTORY factory;
	unicode_string_t name;
	name.set( L"\\Device\\NamedPipe");

	NTSTATUS r;
	OBJECT *obj = 0;
	r = factory.create_kernel( obj, name );
	if (r < STATUS_SUCCESS)
		Die("failed to create named pipe\n");
}

NTSTATUS PIPE_DEVICE::Read( PVOID buffer, ULONG length, ULONG *read )
{
	return STATUS_ACCESS_DENIED;
}

NTSTATUS PIPE_DEVICE::Write( PVOID buffer, ULONG length, ULONG *written )
{
	return STATUS_ACCESS_DENIED;
}

PIPE_MESSAGE::PIPE_MESSAGE( ULONG _Length ) :
	Length( _Length )
{
}

PIPE_MESSAGE *PIPE_MESSAGE::AllocPipeMessage( ULONG _Length )
{
	ULONG sz = _Length + sizeof (PIPE_MESSAGE);
	void *mem = (void*) new unsigned char[sz];
	return new(mem) PIPE_MESSAGE(_Length);
}

unsigned char *PIPE_MESSAGE::DataPtr()
{
	return (unsigned char *) (this+1);
}

class WAIT_SERVER_INFO
{
	FILE_PIPE_WAIT_FOR_BUFFER info;
public:
	LARGE_INTEGER&  Timeout;
	ULONG&          NameLength;
	BOOLEAN&        TimeoutSpecified;
	unicode_string_t Name;
public:
	WAIT_SERVER_INFO();
	NTSTATUS CopyFromUser( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length );
	void Dump();
};

WAIT_SERVER_INFO::WAIT_SERVER_INFO() :
	Timeout( info.Timeout ),
	NameLength( info.NameLength ),
	TimeoutSpecified( info.TimeoutSpecified )
{
}

NTSTATUS WAIT_SERVER_INFO::CopyFromUser( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length )
{
	NTSTATUS r;
	ULONG sz = FIELD_OFFSET( FILE_PIPE_WAIT_FOR_BUFFER, Name );

	if (Length < sz)
		return STATUS_INVALID_PARAMETER;
	r = ::copy_from_user( &info, pwfb, sz );
	if (r < STATUS_SUCCESS)
		return r;
	if (Length < (sz + NameLength))
		return STATUS_INVALID_PARAMETER;
	return Name.copy_wstr_from_user( pwfb->Name, NameLength );
}

void WAIT_SERVER_INFO::Dump()
{
	trace("pipe server wait name=%pus\n", &Name );
}

NTSTATUS PIPE_DEVICE::WaitServerAvailable( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length )
{
	WAIT_SERVER_INFO info;

	NTSTATUS r = info.CopyFromUser( pwfb, Length );
	if (r < STATUS_SUCCESS)
		return r;

	info.Dump();

	OBJECT* obj = lookup( info.Name, true );
	if (!obj)
	{
		trace("no pipe server (%pus)\n", &info.Name );
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	PIPE_CONTAINER *container = dynamic_cast<PIPE_CONTAINER*>( obj );
	if (!container)
		return STATUS_UNSUCCESSFUL;

	PIPE_SERVER* server = container->FindIdleServer();
	if (!server)
	{
		//FIXME: timeout
		current->Wait();
	}

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_DEVICE::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
									PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	if (FsControlCode == FSCTL_PIPE_WAIT)
		return WaitServerAvailable( (PFILE_PIPE_WAIT_FOR_BUFFER) InputBuffer, InputBufferLength );

	trace("unimplemented %08lx\n", FsControlCode);

	return STATUS_NOT_IMPLEMENTED;
}

PIPE_CONTAINER::PIPE_CONTAINER( ULONG max ) :
	num_instances(0),
	max_instances(max)
{
}

void PIPE_CONTAINER::Unlink( PIPE_SERVER *pipe )
{
	servers.Unlink( pipe );
	num_instances--;
}

NTSTATUS PIPE_CONTAINER::CreateServer( PIPE_SERVER *& pipe, ULONG max_inst )
{
	trace("creating pipe server\n");
	if (max_inst != max_instances)
		return STATUS_INVALID_PARAMETER;

	if (num_instances >= max_instances )
		return STATUS_ACCESS_DENIED;
	num_instances++;

	pipe = new PIPE_SERVER( this );

	servers.Append( pipe );
	addref( this );

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CONTAINER::CreateClient( PIPE_CLIENT*& client )
{
	client = new PIPE_CLIENT( this );
	if (!client)
		return STATUS_NO_MEMORY;

	PIPE_SERVER *server = FindIdleServer();
	if (server)
	{
		server->SetClient( client );
		THREAD *t = server->Thread;
		server->Thread = NULL;
		t->Start();
	}

	return STATUS_SUCCESS;
}

void PIPE_SERVER::SetClient( PIPE_CLIENT* pipe_client )
{
	assert( pipe_client );
	Client = pipe_client;
	Client->Server = this;
	State = pipe_connected;
	trace("connect server %p to client %p\n", this, Client );
}

PIPE_SERVER* PIPE_CONTAINER::FindIdleServer()
{
	// search for an idle server
	for (PIPE_SERVER_ITER i(servers); i; i.Next())
	{
		PIPE_SERVER *ps = i;
		if (ps->IsAwaitingConnect())
			return ps;
	}
	return NULL;
}

PIPE_SERVER::PIPE_SERVER( PIPE_CONTAINER *_container ) :
	Container( _container ),
	State( pipe_idle ),
	Client( NULL ),
	Thread( NULL )
{
}

PIPE_SERVER::~PIPE_SERVER()
{
	PIPE_MESSAGE *msg;
	while ((msg = ReceivedMessages.Head()))
	{
		ReceivedMessages.Unlink( msg );
		delete msg;
	}
	Container->Unlink( this );
	release( Container );
}

NTSTATUS PIPE_SERVER::Open( OBJECT *&out, OPEN_INFO& info )
{
	// should return a pointer to a pipe client
	trace("implement\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS PIPE_SERVER::Read( PVOID buffer, ULONG length, ULONG *read )
{
	PIPE_MESSAGE *msg;

	// only allow reading in the correct state
	if (State != pipe_connected)
		return STATUS_PIPE_BROKEN;

	// only allow one reader at a time
	if (Thread)
		return STATUS_PIPE_BUSY;

	// get a message
	msg = ReceivedMessages.Head();
	if (!msg)
	{
		// wait for a message
		Thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( Thread == NULL );
		msg = ReceivedMessages.Head();
	}

	ULONG len = 0;
	if (msg)
	{
		len = min( length, msg->Length );
		NTSTATUS r = copy_to_user( buffer, msg->DataPtr(), len );
		if (r < STATUS_SUCCESS)
			return r;
		ReceivedMessages.Unlink( msg );
		delete msg;
	}
	*read = len;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::Write( PVOID buffer, ULONG length, ULONG *written )
{
	PIPE_MESSAGE *msg = PIPE_MESSAGE::AllocPipeMessage( length );

	NTSTATUS r;
	r = copy_from_user( msg->DataPtr(), buffer, length );
	if (r < STATUS_SUCCESS)
	{
		delete msg;
		return r;
	}

	QueueMessageToClient( msg );
	*written = length;
	return STATUS_SUCCESS;
}

bool PIPE_SERVER::DoConnect()
{
	for (PIPE_CLIENT_ITER i( Container->GetClients() ); i; i.Next())
	{
		PIPE_CLIENT *pipe_client = i;

		if (pipe_client->Server)
			continue;
		SetClient( pipe_client );
		return true;
	}
	return false;
}

NTSTATUS PIPE_SERVER::Connect()
{
	if (State != pipe_idle)
		return STATUS_PIPE_CONNECTED;

	State = pipe_wait_connect;
	DoConnect();
	if (!IsConnected())
	{
		Thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( Thread == NULL );
		assert( IsConnected() );
	}

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::Disconnect()
{
	if (State != pipe_connected)
		return STATUS_PIPE_BROKEN;

	Client->Server = 0;
	Client = 0;
	State = pipe_disconnected;

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
									PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	trace("PIPE_SERVER %08lx\n", FsControlCode);
	if (FsControlCode == FSCTL_PIPE_LISTEN)
		return Connect();

	if (FsControlCode == FSCTL_PIPE_DISCONNECT)
		return Disconnect();

	trace("implement\n");
	return STATUS_NOT_IMPLEMENTED;
}

void PIPE_SERVER::QueueMessageFromClient( PIPE_MESSAGE *msg )
{
	ReceivedMessages.Append( msg );

	// wakeup readers
	assert( State == pipe_connected );
	if (Thread)
	{
		THREAD *t = Thread;
		Thread = 0;
		t->Start();
	}
}

void PIPE_SERVER::QueueMessageToClient( PIPE_MESSAGE *msg )
{
	SentMessages.Append( msg );
	// wakeup readers
	assert( State == pipe_connected );
	if (Client->Thread)
	{
		THREAD *t = Client->Thread;
		Client->Thread = 0;
		t->Start();
	}
}

PIPE_CLIENT::PIPE_CLIENT( PIPE_CONTAINER *container ) :
	Server( NULL ),
	Thread( NULL )
{
}

NTSTATUS PIPE_CLIENT::Read( PVOID buffer, ULONG length, ULONG *read )
{
	PIPE_MESSAGE *msg;

	// only allow reading in the correct state
	if (Server == NULL || Server->State != PIPE_SERVER::pipe_connected)
		return STATUS_PIPE_BROKEN;

	// only allow one reader at a time
	if (Thread)
		return STATUS_PIPE_BUSY;

	// get a message
	msg = Server->SentMessages.Head();
	if (!msg)
	{
		// wait for a message
		Thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( Thread == NULL );
		msg = Server->SentMessages.Head();
	}

	ULONG len = 0;
	if (msg)
	{
		len = min( length, msg->Length );
		NTSTATUS r = copy_to_user( buffer, msg->DataPtr(), len );
		if (r < STATUS_SUCCESS)
			return r;
		Server->SentMessages.Unlink( msg );
		delete msg;
	}
	*read = len;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CLIENT::Write( PVOID buffer, ULONG length, ULONG *written )
{
	PIPE_MESSAGE *msg = PIPE_MESSAGE::AllocPipeMessage( length );

	if (Server == NULL || Server->State != PIPE_SERVER::pipe_connected)
		return STATUS_PIPE_BROKEN;

	NTSTATUS r;
	r = copy_from_user( msg->DataPtr(), buffer, length );
	if (r < STATUS_SUCCESS)
	{
		delete msg;
		return r;
	}

	Server->QueueMessageFromClient( msg );
	*written = length;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CLIENT::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
									PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	trace("PIPE_CLIENT %08lx\n", FsControlCode);

	if (FsControlCode == FSCTL_PIPE_TRANSCEIVE)
		return Transceive( InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	return STATUS_INVALID_PARAMETER;
}

NTSTATUS PIPE_CLIENT::Transceive(
	PVOID InputBuffer, ULONG InputBufferLength,
	PVOID OutputBuffer, ULONG OutputBufferLength )
{
	NTSTATUS r;
	ULONG out = 0;
	r = Write( InputBuffer, InputBufferLength, &out );
	if (r < STATUS_SUCCESS)
		return r;

	r = Read( OutputBuffer, OutputBufferLength, &out );
	if (r < STATUS_SUCCESS)
		return r;

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CLIENT::SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info )
{
	trace("%ld %ld\n", pipe_info.ReadModeMessage, pipe_info.WaitModeBlocking);
	return STATUS_SUCCESS;
}

PIPE_FACTORY::PIPE_FACTORY( ULONG _MaxInstances ) :
	MaxInstances( _MaxInstances )
{
}

NTSTATUS PIPE_FACTORY::AllocObject(OBJECT** obj)
{
	assert(0);
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_FACTORY::OnOpen( OBJECT_DIR* dir, OBJECT*& obj, OPEN_INFO& info )
{
	NTSTATUS r;

	trace("PIPE_FACTORY()\n");
	PIPE_CONTAINER *container = 0;
	if (!obj)
	{
		container = new PIPE_CONTAINER( MaxInstances );
		if (!container)
			return STATUS_NO_MEMORY;

		r = container->name.copy( &info.path );
		if (r < STATUS_SUCCESS)
			return r;

		dir->append( container );
	}
	else
	{
		container = dynamic_cast<PIPE_CONTAINER*>( obj );
		if (!container)
			return STATUS_OBJECT_TYPE_MISMATCH;
	}

	assert( container );

	PIPE_SERVER *pipe = 0;
	r = container->CreateServer( pipe, MaxInstances );
	if (r == STATUS_SUCCESS)
		obj = pipe;

	return r;
}

NTSTATUS NTAPI NtCreateNamedPipeFile(
	PHANDLE PipeHandle,
	ACCESS_MASK AccessMask,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	BOOLEAN TypeMessage,
	BOOLEAN ReadModeMessage,
	BOOLEAN NonBlocking,
	ULONG MaxInstances,
	ULONG InBufferSize,
	ULONG OutBufferSize,
	PLARGE_INTEGER DefaultTimeout)
{
	LARGE_INTEGER timeout;
	object_attributes_t oa;
	NTSTATUS r;

	if (CreateDisposition != FILE_OPEN_IF)
		return STATUS_INVALID_PARAMETER;

	if (MaxInstances == 0)
		return STATUS_INVALID_PARAMETER;

	if (ObjectAttributes == NULL)
		return STATUS_INVALID_PARAMETER;

	if (!(ShareAccess & FILE_SHARE_READ))
		return STATUS_INVALID_PARAMETER;
	if (!(ShareAccess & FILE_SHARE_WRITE))
		return STATUS_INVALID_PARAMETER;

	r = copy_from_user( &timeout, DefaultTimeout, sizeof timeout );
	if (r < STATUS_SUCCESS)
		return r;

	if (timeout.QuadPart > 0)
		return STATUS_INVALID_PARAMETER;

	r = verify_for_write( PipeHandle, sizeof *PipeHandle );
	if (r < STATUS_SUCCESS)
		return r;

	r = verify_for_write( IoStatusBlock, sizeof IoStatusBlock );
	if (r < STATUS_SUCCESS)
		return r;

	PIPE_FACTORY factory( MaxInstances );

	return factory.create( PipeHandle, AccessMask, ObjectAttributes );
}
