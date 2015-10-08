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

typedef LIST_ANCHOR<PIPE_SERVER,0> pipe_server_list_t;
typedef LIST_ELEMENT<PIPE_SERVER> pipe_server_element_t;
typedef LIST_ITER<PIPE_SERVER,0> pipe_server_iter_t;
typedef LIST_ANCHOR<PIPE_CLIENT,0> pipe_client_list_t;
typedef LIST_ELEMENT<PIPE_CLIENT> pipe_client_element_t;
typedef LIST_ITER<PIPE_CLIENT,0> pipe_client_iter_t;

// the pipe device \Device\NamedPipe, contains pipes of different names
class PIPE_DEVICE : public OBJECT_DIR_IMPL, public IO_OBJECT
{
public:
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	NTSTATUS wait_server_available( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length );
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
	pipe_server_list_t servers;
	pipe_client_list_t clients;
	ULONG num_instances;
	ULONG max_instances;
public:
	PIPE_CONTAINER( ULONG max );
	NTSTATUS create_server( PIPE_SERVER*& pipe, ULONG max_inst );
	NTSTATUS create_client( PIPE_CLIENT*& pipe );
	void unlink( PIPE_SERVER *pipe );
	pipe_server_list_t& get_servers()
	{
		return servers;
	}
	pipe_client_list_t& get_clients()
	{
		return clients;
	}
	virtual NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	PIPE_SERVER* find_idle_server();
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
	PIPE_MESSAGE_ELEMENT entry[1];
	ULONG Length;
	static PIPE_MESSAGE* alloc_pipe_message( ULONG _Length );
	unsigned char *data_ptr();
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
	PIPE_CONTAINER *container;
	pipe_state state;
	PIPE_CLIENT *client;
	THREAD *thread;
	pipe_server_element_t entry[1];
	PIPE_MESSAGE_LIST received_messages;
	PIPE_MESSAGE_LIST sent_messages;
public:
	PIPE_SERVER( PIPE_CONTAINER *container );
	~PIPE_SERVER();
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	NTSTATUS Open( OBJECT *&out, OPEN_INFO& info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	inline bool is_connected()
	{
		return state == pipe_connected;
	}
	inline bool is_idle()
	{
		return state == pipe_idle;
	}
	inline bool is_awaiting_connect()
	{
		return state == pipe_wait_connect;
	}
	bool do_connect();
	NTSTATUS connect();
	NTSTATUS disconnect();
	void set_client( PIPE_CLIENT* pipe_client );
	void queue_message_from_client( PIPE_MESSAGE *msg );
	void queue_message_to_client( PIPE_MESSAGE *msg );
};

// a single client instance
class PIPE_CLIENT : public IO_OBJECT
{
	friend class PIPE_CONTAINER;
public:
	pipe_client_element_t entry[1];
	PIPE_SERVER *server;
	THREAD *thread;
public:
	PIPE_CLIENT( PIPE_CONTAINER *container );
	virtual NTSTATUS Read( PVOID buffer, ULONG length, ULONG *read );
	virtual NTSTATUS Write( PVOID buffer, ULONG length, ULONG *written );
	NTSTATUS SetPipeInfo( FILE_PIPE_INFORMATION& pipe_info );
	virtual NTSTATUS FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
								 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength );
	NTSTATUS transceive(
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
	NTSTATUS r = create_client( pipe );
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

void init_pipe_device()
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

PIPE_MESSAGE *PIPE_MESSAGE::alloc_pipe_message( ULONG _Length )
{
	ULONG sz = _Length + sizeof (PIPE_MESSAGE);
	void *mem = (void*) new unsigned char[sz];
	return new(mem) PIPE_MESSAGE(_Length);
}

unsigned char *PIPE_MESSAGE::data_ptr()
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
	unicode_string_t name;
public:
	WAIT_SERVER_INFO();
	NTSTATUS copy_from_user( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length );
	void dump();
};

WAIT_SERVER_INFO::WAIT_SERVER_INFO() :
	Timeout( info.Timeout ),
	NameLength( info.NameLength ),
	TimeoutSpecified( info.TimeoutSpecified )
{
}

NTSTATUS WAIT_SERVER_INFO::copy_from_user( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length )
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
	return name.copy_wstr_from_user( pwfb->Name, NameLength );
}

void WAIT_SERVER_INFO::dump()
{
	trace("pipe server wait name=%pus\n", &name );
}

NTSTATUS PIPE_DEVICE::wait_server_available( PFILE_PIPE_WAIT_FOR_BUFFER pwfb, ULONG Length )
{
	WAIT_SERVER_INFO info;

	NTSTATUS r = info.copy_from_user( pwfb, Length );
	if (r < STATUS_SUCCESS)
		return r;

	info.dump();

	OBJECT* obj = lookup( info.name, true );
	if (!obj)
	{
		trace("no pipe server (%pus)\n", &info.name );
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	PIPE_CONTAINER *container = dynamic_cast<PIPE_CONTAINER*>( obj );
	if (!container)
		return STATUS_UNSUCCESSFUL;

	PIPE_SERVER* server = container->find_idle_server();
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
		return wait_server_available( (PFILE_PIPE_WAIT_FOR_BUFFER) InputBuffer, InputBufferLength );

	trace("unimplemented %08lx\n", FsControlCode);

	return STATUS_NOT_IMPLEMENTED;
}

PIPE_CONTAINER::PIPE_CONTAINER( ULONG max ) :
	num_instances(0),
	max_instances(max)
{
}

void PIPE_CONTAINER::unlink( PIPE_SERVER *pipe )
{
	servers.unlink( pipe );
	num_instances--;
}

NTSTATUS PIPE_CONTAINER::create_server( PIPE_SERVER *& pipe, ULONG max_inst )
{
	trace("creating pipe server\n");
	if (max_inst != max_instances)
		return STATUS_INVALID_PARAMETER;

	if (num_instances >= max_instances )
		return STATUS_ACCESS_DENIED;
	num_instances++;

	pipe = new PIPE_SERVER( this );

	servers.append( pipe );
	addref( this );

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CONTAINER::create_client( PIPE_CLIENT*& client )
{
	client = new PIPE_CLIENT( this );
	if (!client)
		return STATUS_NO_MEMORY;

	PIPE_SERVER *server = find_idle_server();
	if (server)
	{
		server->set_client( client );
		THREAD *t = server->thread;
		server->thread = NULL;
		t->Start();
	}

	return STATUS_SUCCESS;
}

void PIPE_SERVER::set_client( PIPE_CLIENT* pipe_client )
{
	assert( pipe_client );
	client = pipe_client;
	client->server = this;
	state = pipe_connected;
	trace("connect server %p to client %p\n", this, client );
}

PIPE_SERVER* PIPE_CONTAINER::find_idle_server()
{
	// search for an idle server
	for (pipe_server_iter_t i(servers); i; i.next())
	{
		PIPE_SERVER *ps = i;
		if (ps->is_awaiting_connect())
			return ps;
	}
	return NULL;
}

PIPE_SERVER::PIPE_SERVER( PIPE_CONTAINER *_container ) :
	container( _container ),
	state( pipe_idle ),
	client( NULL ),
	thread( NULL )
{
}

PIPE_SERVER::~PIPE_SERVER()
{
	PIPE_MESSAGE *msg;
	while ((msg = received_messages.head()))
	{
		received_messages.unlink( msg );
		delete msg;
	}
	container->unlink( this );
	release( container );
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
	if (state != pipe_connected)
		return STATUS_PIPE_BROKEN;

	// only allow one reader at a time
	if (thread)
		return STATUS_PIPE_BUSY;

	// get a message
	msg = received_messages.head();
	if (!msg)
	{
		// wait for a message
		thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( thread == NULL );
		msg = received_messages.head();
	}

	ULONG len = 0;
	if (msg)
	{
		len = min( length, msg->Length );
		NTSTATUS r = copy_to_user( buffer, msg->data_ptr(), len );
		if (r < STATUS_SUCCESS)
			return r;
		received_messages.unlink( msg );
		delete msg;
	}
	*read = len;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::Write( PVOID buffer, ULONG length, ULONG *written )
{
	PIPE_MESSAGE *msg = PIPE_MESSAGE::alloc_pipe_message( length );

	NTSTATUS r;
	r = copy_from_user( msg->data_ptr(), buffer, length );
	if (r < STATUS_SUCCESS)
	{
		delete msg;
		return r;
	}

	queue_message_to_client( msg );
	*written = length;
	return STATUS_SUCCESS;
}

bool PIPE_SERVER::do_connect()
{
	for (pipe_client_iter_t i( container->get_clients() ); i; i.next())
	{
		PIPE_CLIENT *pipe_client = i;

		if (pipe_client->server)
			continue;
		set_client( pipe_client );
		return true;
	}
	return false;
}

NTSTATUS PIPE_SERVER::connect()
{
	if (state != pipe_idle)
		return STATUS_PIPE_CONNECTED;

	state = pipe_wait_connect;
	do_connect();
	if (!is_connected())
	{
		thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( thread == NULL );
		assert( is_connected() );
	}

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::disconnect()
{
	if (state != pipe_connected)
		return STATUS_PIPE_BROKEN;

	client->server = 0;
	client = 0;
	state = pipe_disconnected;

	return STATUS_SUCCESS;
}

NTSTATUS PIPE_SERVER::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
									PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	trace("PIPE_SERVER %08lx\n", FsControlCode);
	if (FsControlCode == FSCTL_PIPE_LISTEN)
		return connect();

	if (FsControlCode == FSCTL_PIPE_DISCONNECT)
		return disconnect();

	trace("implement\n");
	return STATUS_NOT_IMPLEMENTED;
}

void PIPE_SERVER::queue_message_from_client( PIPE_MESSAGE *msg )
{
	received_messages.append( msg );

	// wakeup readers
	assert( state == pipe_connected );
	if (thread)
	{
		THREAD *t = thread;
		thread = 0;
		t->Start();
	}
}

void PIPE_SERVER::queue_message_to_client( PIPE_MESSAGE *msg )
{
	sent_messages.append( msg );
	// wakeup readers
	assert( state == pipe_connected );
	if (client->thread)
	{
		THREAD *t = client->thread;
		client->thread = 0;
		t->Start();
	}
}

PIPE_CLIENT::PIPE_CLIENT( PIPE_CONTAINER *container ) :
	server( NULL ),
	thread( NULL )
{
}

NTSTATUS PIPE_CLIENT::Read( PVOID buffer, ULONG length, ULONG *read )
{
	PIPE_MESSAGE *msg;

	// only allow reading in the correct state
	if (server == NULL || server->state != PIPE_SERVER::pipe_connected)
		return STATUS_PIPE_BROKEN;

	// only allow one reader at a time
	if (thread)
		return STATUS_PIPE_BUSY;

	// get a message
	msg = server->sent_messages.head();
	if (!msg)
	{
		// wait for a message
		thread = current;
		current->Wait();
		if (current->IsTerminated())
			return STATUS_THREAD_IS_TERMINATING;
		assert( thread == NULL );
		msg = server->sent_messages.head();
	}

	ULONG len = 0;
	if (msg)
	{
		len = min( length, msg->Length );
		NTSTATUS r = copy_to_user( buffer, msg->data_ptr(), len );
		if (r < STATUS_SUCCESS)
			return r;
		server->sent_messages.unlink( msg );
		delete msg;
	}
	*read = len;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CLIENT::Write( PVOID buffer, ULONG length, ULONG *written )
{
	PIPE_MESSAGE *msg = PIPE_MESSAGE::alloc_pipe_message( length );

	if (server == NULL || server->state != PIPE_SERVER::pipe_connected)
		return STATUS_PIPE_BROKEN;

	NTSTATUS r;
	r = copy_from_user( msg->data_ptr(), buffer, length );
	if (r < STATUS_SUCCESS)
	{
		delete msg;
		return r;
	}

	server->queue_message_from_client( msg );
	*written = length;
	return STATUS_SUCCESS;
}

NTSTATUS PIPE_CLIENT::FSControl( EVENT* event, IO_STATUS_BLOCK iosb, ULONG FsControlCode,
									PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength )
{
	trace("PIPE_CLIENT %08lx\n", FsControlCode);

	if (FsControlCode == FSCTL_PIPE_TRANSCEIVE)
		return transceive( InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength );

	return STATUS_INVALID_PARAMETER;
}

NTSTATUS PIPE_CLIENT::transceive(
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
	r = container->create_server( pipe, MaxInstances );
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
