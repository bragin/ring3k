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
#include <assert.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "mem.h"
#include "object.h"
#include "ntcall.h"
#include "section.h"
#include "object.inl"

class MESSAGE;

typedef LIST_ANCHOR<MESSAGE, 0> MESSAGE_LIST;
typedef LIST_ELEMENT<MESSAGE> MESSAGE_ENTRY;
typedef LIST_ITER<MESSAGE, 0> MESSAGE_ITER;

class MESSAGE
{
public:
	ULONG DestinationId;
protected:
	friend class LIST_ANCHOR<MESSAGE, 0>;
	friend class LIST_ITER<MESSAGE, 0>;
	MESSAGE_ENTRY Entry[1];
public:
	void *operator new(size_t n, size_t len);
	void operator delete(void* ptr);
	explicit MESSAGE();
	bool IsLinked()
	{
		return Entry[0].IsLinked();
	}
	~MESSAGE();
	void Dump();
	const char* MsgType();
public:
	LPC_MESSAGE Req;
};

struct LISTENER;
struct PORT_QUEUE;

typedef LIST_ANCHOR<LISTENER, 0> LISTENER_LIST;
typedef LIST_ELEMENT<LISTENER> LISTENER_ENTRY;
typedef LIST_ITER<LISTENER, 0> LISTENER_ITER;

struct LISTENER
{
	LISTENER_ENTRY Entry[1];
	PORT *Port;
	THREAD *Thread;
	BOOLEAN WantConnect;
	ULONG MessageId;
public:
	explicit LISTENER(PORT *p, THREAD *t, BOOLEAN wc, ULONG id);
	~LISTENER();
	bool IsLinked()
	{
		return Entry[0].IsLinked();
	}
};

struct PORT_QUEUE : public OBJECT
{
	ULONG Refs;
	ULONG MaxConnect;
	ULONG MaxData;
	MESSAGE_LIST Messages;
	LISTENER_LIST Listeners;
public:
	explicit PORT_QUEUE( ULONG max_connect, ULONG max_data );
	~PORT_QUEUE();
	MESSAGE *FindConnectionRequest();
};

struct PORT: public OBJECT
{
	PORT_QUEUE *Queue;
	BOOLEAN Server;
	THREAD *Thread;
	PORT *Other;
	SECTION *Section; // our Section
	BYTE *OtherSectionBase;	// mapped address of Other Port's Section
	BYTE *OurSectionBase;	// mapped address of Our Port's Section
	ULONG ViewSize;
	ULONG Identifier;
	MESSAGE *ReceivedMsg;
public:
	explicit PORT( BOOLEAN s, THREAD *t, PORT_QUEUE *q );
	~PORT();
	void SendMessage( MESSAGE *msg );
	void SendCloseMessage( void );
	NTSTATUS SendReply( MESSAGE *reply );
	void Listen( MESSAGE *&msg );
	NTSTATUS SendRequest( MESSAGE *msg );
	void RequestWaitReply( MESSAGE *msg, MESSAGE *&reply );
	NTSTATUS ReplyWaitReceive( MESSAGE *reply, MESSAGE *&received );
	NTSTATUS AcceptConnect( THREAD *t, MESSAGE *reply, PLPC_SECTION_WRITE server_write_sec );
};

struct EXCEPTION_MSG_DATA
{
	ULONG EventCode;
	ULONG Status;
	EXCEPTION_RECORD ExceptionRecord;
};

static int UniqueMessageId = 0x101;

void *MESSAGE::operator new(size_t msg_size, size_t extra)
{
	return new unsigned char[msg_size + extra];
}

void MESSAGE::operator delete(void* ptr)
{
	delete[] (unsigned char*) ptr;
}

MESSAGE::MESSAGE() :
	DestinationId(0)
{
	memset( &Req, 0, sizeof Req );
}

MESSAGE::~MESSAGE()
{
	assert( !IsLinked() );
}

void UnlinkAndFreeMessage( MESSAGE_LIST *list, MESSAGE *msg )
{
	assert( msg->IsLinked() );
	list->Unlink( msg );
	delete msg;
}

void MsgFreeUnlinked( MESSAGE *msg )
{
	if (!msg)
		return;
	if (msg->IsLinked())
		return;
	delete msg;
}

const char* MESSAGE::MsgType()
{
	switch (Req.MessageType)
	{
#define M(x) case x: return #x;
		M(LPC_NEW_MESSAGE)
		M(LPC_REQUEST)
		M(LPC_REPLY)
		M(LPC_DATAGRAM)
		M(LPC_LOST_REPLY)
		M(LPC_PORT_CLOSED)
		M(LPC_CLIENT_DIED)
		M(LPC_EXCEPTION)
		M(LPC_DEBUG_EVENT)
		M(LPC_ERROR_EVENT)
		M(LPC_CONNECTION_REQUEST)
#undef M
	default:
		return "unknown";
	}
}

void MESSAGE::Dump()
{
	if (!OptionTrace)
		return;
	trace("DataSize    = %d\n", Req.DataSize);
	trace("MessageSize = %d\n", Req.MessageSize);
	trace("MessageType = %d (%s)\n", Req.MessageType, MsgType());
	trace("Offset      = %d\n", Req.VirtualRangesOffset);
	trace("ClientId    = %04x, %04x\n",
		  (int)Req.ClientId.UniqueProcess, (int)Req.ClientId.UniqueThread);
	trace("MessageId   = %ld\n", Req.MessageId);
	trace("SectionSize = %08lx\n", Req.SectionSize);
	DumpMem(&Req.Data, Req.DataSize);
}

PORT *PortFromObj( OBJECT *obj )
{
	return dynamic_cast<PORT*>( obj );
}

NTSTATUS PortFromHandle( HANDLE handle, PORT *& port )
{
	return ObjectFromHandle( port, handle, 0 );
}

void SendTerminateMessage(
	THREAD *thread,
	OBJECT *terminate_port,
	LARGE_INTEGER& create_time )
{
	PORT *port = dynamic_cast<PORT*>( terminate_port );
	assert(port);
	create_time.QuadPart = 0;

	trace("Thread = %p Port = %p\n", thread, port);

	ULONG data_size = sizeof create_time;
	ULONG msg_size = FIELD_OFFSET(LPC_MESSAGE, Data) + data_size;

	MESSAGE *msg = new(msg_size) MESSAGE;

	msg->Req.MessageSize = msg_size;
	msg->Req.MessageType = LPC_CLIENT_DIED;
	msg->Req.DataSize = data_size;
	thread->GetClientID( &msg->Req.ClientId );
	msg->Req.MessageId = UniqueMessageId++;
	memcpy( &msg->Req.Data, &create_time, sizeof create_time );

	port->SendMessage( msg );
	Release(terminate_port);
}

NTSTATUS SetExceptionPort( PROCESS *process, OBJECT *obj )
{
	PORT *port = PortFromObj( obj );
	if (!port)
		return STATUS_OBJECT_TYPE_MISMATCH;
	if (process->ExceptionPort)
		return STATUS_PORT_ALREADY_SET;
	// no addref here, destructors searchs processes...
	process->ExceptionPort = port;
	return STATUS_SUCCESS;
}

bool SendException( THREAD *thread, EXCEPTION_RECORD& rec )
{
	if (!thread->Process->ExceptionPort)
		return false;

	PORT *port = static_cast<PORT*>(thread->Process->ExceptionPort);

	trace("Thread = %p Port = %p\n", thread, port);

	ULONG status = STATUS_PENDING;
	while (1)
	{
		MESSAGE *msg = new(0x78) MESSAGE;

		msg->Req.MessageSize = 0x78;
		msg->Req.MessageType = LPC_EXCEPTION;
		msg->Req.DataSize = 0x5c;
		thread->GetClientID( &msg->Req.ClientId );
		msg->Req.MessageId = UniqueMessageId++;

		EXCEPTION_MSG_DATA *x;

		x = (typeof x) &msg->Req.Data[0];
		x->Status = status;
		x->EventCode = 0;
		x->ExceptionRecord = rec;

		// send the message and block waiting for a response
		MESSAGE *reply = 0;
		port->RequestWaitReply( msg, reply );
		x = (typeof x) &reply->Req.Data[0];
		status = x->Status;
		delete reply;

		switch (status)
		{
		case DBG_CONTINUE:
		case DBG_EXCEPTION_HANDLED:
			return false;
		case DBG_TERMINATE_THREAD:
			thread->Terminate(rec.ExceptionCode);
			return true;
		case DBG_TERMINATE_PROCESS:
			thread->Process->Terminate(rec.ExceptionCode);
			return true;
		default:
			trace("status = %08lx\n", status);
			continue;
		}
	}

	return false;
}

LISTENER::LISTENER(PORT *p, THREAD *t, BOOLEAN connect, ULONG id) :
	Port(p),
	Thread(t),
	WantConnect(connect),
	MessageId(id)
{
	AddRef( t );
	Port->Queue->Listeners.Append( this );
}

LISTENER::~LISTENER()
{
	// maybe still linked if the Thread was terminated
	if (IsLinked())
		Port->Queue->Listeners.Unlink( this );
	Release( Thread );
}

static inline ULONG RoundUp( ULONG len )
{
	return (len + 3) & ~3;
}

NTSTATUS CopyMsgFromUser( MESSAGE **message, LPC_MESSAGE *Reply, ULONG max_data )
{
	LPC_MESSAGE reply_hdr;
	MESSAGE *msg;
	NTSTATUS r;

	r = CopyFromUser( &reply_hdr, Reply, sizeof reply_hdr );
	if (r < STATUS_SUCCESS)
		return r;

	if (reply_hdr.DataSize > max_data)
		return STATUS_INVALID_PARAMETER;

	if (reply_hdr.MessageSize > max_data)
		return STATUS_PORT_MESSAGE_TOO_LONG;

	ULONG len = RoundUp(reply_hdr.DataSize);
	msg = new(len) MESSAGE;
	if (!msg)
		return STATUS_NO_MEMORY;

	memcpy( &msg->Req, &reply_hdr, sizeof reply_hdr );
	r = CopyFromUser( &msg->Req.Data, &Reply->Data[0], len );
	if (r < STATUS_SUCCESS)
		delete msg;
	else
		*message = msg;

	return r;
}

NTSTATUS CopyMsgToUser( LPC_MESSAGE *addr, MESSAGE *msg )
{
	return CopyToUser( addr, &msg->Req, RoundUp(msg->Req.MessageSize) );
}

PORT_QUEUE::~PORT_QUEUE()
{
	MESSAGE *m;

	//trace("%p\n", this);

	while ((m = Messages.Head() ))
		UnlinkAndFreeMessage( &Messages, m );

	assert( Listeners.Empty() );
}

void PORT::SendCloseMessage( void )
{
	MESSAGE *msg;

	// FIXME: what's in the two words of data?
	ULONG data_size = sizeof (ULONG) * 2;
	ULONG msg_size = FIELD_OFFSET(LPC_MESSAGE, Data) + data_size;

	msg = new(data_size) MESSAGE;

	// FIXME: Should we Queue the message?
	//		What if new() fails?
	//		Should we send the message to every listener?

	msg->Req.MessageSize = msg_size;
	msg->Req.MessageType = LPC_PORT_CLOSED;
	msg->Req.DataSize = data_size;
	Current->GetClientID( &msg->Req.ClientId );
	msg->Req.MessageId = UniqueMessageId++;

	SendMessage( msg );
	//msg_free_unlinked( msg );
}

PORT::~PORT()
{
	// check if this is the exception Port for any processes
	for ( PROCESS_ITER i(Processes); i; i.Next() )
	{
		PROCESS *p = i;
		if (p->ExceptionPort == this)
			p->ExceptionPort = 0;
	}

	if (OtherSectionBase)
		Thread->Process->Vm->UnmapView( OtherSectionBase );
	if (OurSectionBase)
		Thread->Process->Vm->UnmapView( OurSectionBase );
	if (Section)
		Release(Section);
	if (Other)
	{
		Other->Other = 0;
		Other = 0;
		SendCloseMessage();
	}
	Release( Queue );
	Release( Thread );
}

PORT::PORT( BOOLEAN s, THREAD *t, PORT_QUEUE *q ) :
	Queue(q),
	Server(s),
	Thread(t),
	Other(0),
	Section(0),
	OtherSectionBase(0),
	OurSectionBase(0),
	ViewSize(0),
	Identifier(0),
	ReceivedMsg(0)
{
	if (q)
		AddRef(q);
	AddRef(Thread);
}

PORT_QUEUE::PORT_QUEUE( ULONG _max_connect, ULONG _max_data ) :
	MaxConnect( _max_connect ),
	MaxData( _max_data )
{
}

NTSTATUS CreateNamedPort(
	OBJECT **obj,
	OBJECT_ATTRIBUTES *oa,
	ULONG max_connect,
	ULONG max_data )
{
	PORT *port;
	NTSTATUS r = STATUS_SUCCESS;

	*obj = NULL;

	port = new PORT( TRUE, Current, 0 );
	if (!port)
		return STATUS_NO_MEMORY;

	port->Queue = new PORT_QUEUE( max_connect, max_data );
	if (port->Queue)
	{
		r = NameObject( port, oa );
		if (r == STATUS_SUCCESS)
		{
			AddRef( port );
			*obj = port;
		}
	}
	Release( port );

	return r;
}

MESSAGE *PORT_QUEUE::FindConnectionRequest()
{
	// check for existing connect requests
	for ( MESSAGE_ITER i(Messages); i ; i.Next() )
	{
		MESSAGE *msg = i;
		if (msg->Req.MessageType == LPC_CONNECTION_REQUEST)
			return msg;
	}
	return 0;
}

NTSTATUS PORT::SendReply( MESSAGE *reply )
{
	reply->Req.MessageType = LPC_REPLY;
	Current->GetClientID( &reply->Req.ClientId );

	reply->Dump();

	for (LISTENER_ITER i(Queue->Listeners); i; i.Next())
	{
		LISTENER *l = i;

		if (l->WantConnect)
			continue;

		if (l->MessageId == reply->Req.MessageId)
		{
			l->Port->ReceivedMsg = reply;
			Queue->Listeners.Unlink( l );
			l->Thread->Start();
			return STATUS_SUCCESS;
		}
	}
	return STATUS_REPLY_MESSAGE_MISMATCH;
}

// Wake a Thread that called NtListenPort or NtReplyWaitReceive
void PORT::SendMessage( MESSAGE *msg )
{
	msg->Dump();

	msg->DestinationId = Identifier;
	Queue->Messages.Append( msg );

	for (LISTENER_ITER i(Queue->Listeners); i; i.Next())
	{
		LISTENER *l = i;
		if (l->MessageId)
			continue;
		if (!l->WantConnect || msg->Req.MessageType == LPC_CONNECTION_REQUEST)
		{
			//trace("Queue %p has listener %p\n", Queue, l->Thread);
			Queue->Listeners.Unlink( l );
			l->Thread->Start();
			return;
		}
	}
}

void PORT::Listen( MESSAGE *&msg )
{
	msg = Queue->FindConnectionRequest();
	if (!msg)
	{
		// Block until somebody connects to this Port.
		LISTENER l( this, Current, TRUE, 0 );

		Current->Wait();
		if (Current->IsTerminated())
			return;

		msg = Queue->FindConnectionRequest();
		assert(msg);
	}
	Queue->Messages.Unlink(msg);
}

NTSTATUS ConnectPort(
	PHANDLE out_handle,
	UNICODE_STRING *name,
	MESSAGE *msg,
	MESSAGE *&reply,
	PULONG MaximumMessageLength,
	PLPC_SECTION_WRITE write_sec,
	PLPC_SECTION_READ ServerSharedMemory )
{
	OBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	OBJECT *obj = NULL;
	PORT *port;

	trace("%pus\n", name);

	oa.Length = sizeof oa;
	oa.RootDirectory = 0;
	oa.ObjectName = name;
	oa.Attributes = 0;
	oa.SecurityDescriptor = 0;
	oa.SecurityQualityOfService = 0;

	r = GetNamedObject( &obj, &oa );
	if (r < STATUS_SUCCESS)
		return r;

	// maybe the object should just be a Queue...
	// try a test using ntconnectport on a result of itself
	PORT_QUEUE *queue;

	port = PortFromObj( obj );
	if (!port)
		return STATUS_OBJECT_TYPE_MISMATCH;
	queue = port->Queue;
	Release(port);

	// check the connect data isn't too big
	if (queue->MaxConnect < msg->Req.DataSize)
		return STATUS_INVALID_PARAMETER;

	// set the Thread's MessageId so that complete_connect can find it
	Current->MessageId = msg->Req.MessageId;

	port = new PORT( FALSE, Current, queue );
	if (!port)
		return STATUS_NO_MEMORY;

	// FIXME: use the Section properly
	if (write_sec->SectionHandle)
	{
		r = ObjectFromHandle( port->Section, write_sec->SectionHandle, 0 );
		if (r < STATUS_SUCCESS)
			return r;
		AddRef(port->Section);
	}
	port->ViewSize = write_sec->ViewSize;
	port->SendMessage( msg );

	// port_t::accept_connect will set the Port->Other pointer
	assert(port->Other == 0);
	assert(port->ReceivedMsg == 0);

	// expect to be restarted by NtCompleteConnectPort when t->Port is set
	assert( 0 == Current->Port);
	Current->Port = port;
	Current->Wait();
	assert( Current->Port == 0 );
	if (port->ReceivedMsg)
	{
		reply = port->ReceivedMsg;
		port->ReceivedMsg = 0;
	}

	// failing to fill the "Other" Port is a connection refusal
	if (port->Other == 0)
	{
		Release( port );
		return STATUS_PORT_CONNECTION_REFUSED;
	}

	r = AllocUserHandle( port, 0, out_handle );
	Release( port );
	if (r < STATUS_SUCCESS)
		return r;

	trace("ServerSharedMemory = %p\n", ServerSharedMemory);
	if (ServerSharedMemory)
	{
		LPC_SECTION_READ read_sec;

		// Length seems to be always set to zero on output...
		read_sec.Length = 0;
		read_sec.ViewBase = port->OtherSectionBase;
		read_sec.ViewSize = port->Other->ViewSize;

		CopyToUser( ServerSharedMemory, &read_sec, sizeof read_sec );
	}

	write_sec->ViewBase = port->OurSectionBase;
	write_sec->TargetViewBase = port->Other->OtherSectionBase;

	if (MaximumMessageLength)
		CopyToUser( MaximumMessageLength, &port->Queue->MaxData, sizeof (ULONG));

	return STATUS_SUCCESS;
}

NTSTATUS CompleteConnectPort( PORT *port )
{
	//trace("%p\n", Port);

	if (port->Server)
		return STATUS_INVALID_PORT_HANDLE;

	if (!port->Other)
		return STATUS_INVALID_PARAMETER;

	// allow starting threads where t->Port is set
	THREAD *t = port->Other->Thread;
	if (!t->Port)
		return STATUS_INVALID_PARAMETER;

	// make sure we don't try restart the Thread twice
	t->Port = 0;

	// restart the Thread that was blocked on connect
	t->Start();

	return STATUS_SUCCESS;
}

NTSTATUS PORT::AcceptConnect(
	THREAD *t,
	MESSAGE *reply,
	PLPC_SECTION_WRITE server_write_sec )
{
	//trace("%p %p %08lx\n", req->ClientId.UniqueProcess, req->ClientId.UniqueThread, req->MessageId);

	// set the Other pointer for connect_port
	Other = t->Port;
	Other->Other = this;
	Other->ReceivedMsg = reply;

	NTSTATUS r;
	// map our section into the other process
	if (server_write_sec->SectionHandle)
	{
		r = ObjectFromHandle( Section, server_write_sec->SectionHandle, 0 );
		if (r < STATUS_SUCCESS)
			return r;
		AddRef(Section);
		ViewSize = server_write_sec->ViewSize;

		// map our Section into their process
		assert(t->Port->OtherSectionBase == 0);
		r = Section->Mapit( t->Process->Vm, t->Port->OtherSectionBase, 0,
							MEM_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;

		// map our Section into our process
		assert(OurSectionBase == 0);
		r = Section->Mapit( Current->Process->Vm, OurSectionBase, 0,
							MEM_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;

		trace("ours=%p theirs=%p\n", t->Port->OtherSectionBase, OurSectionBase);
	}

	// map the Other side's Section into our process
	if (Other->Section)
	{
		assert(OtherSectionBase == 0);
		// map their Section into our process
		r = Other->Section->Mapit( Current->Process->Vm, OtherSectionBase, 0,
								   MEM_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;

		// map their Section into their process
		r = Other->Section->Mapit( t->Process->Vm, t->Port->OurSectionBase, 0,
								   MEM_COMMIT, PAGE_READWRITE );
		if (r < STATUS_SUCCESS)
			return r;
		trace("theirs=%p ours=%p\n", OtherSectionBase, t->Port->OurSectionBase);
	}

	server_write_sec->ViewBase = OurSectionBase;
	server_write_sec->TargetViewBase = Other->OtherSectionBase;

	return STATUS_SUCCESS;
}

NTSTATUS PORT::SendRequest( MESSAGE *msg )
{
	// Queue a message into the Port
	//msg->req.MessageSize = FIELD_OFFSET(LPC_MESSAGE, Data);
	Current->GetClientID( &msg->Req.ClientId );
	msg->Req.MessageId = UniqueMessageId++;
	msg->Req.SectionSize = 0;
	msg->DestinationId = Identifier;

	Current->MessageId = msg->Req.MessageId;

	SendMessage( msg );
	// receiver frees the message

	return STATUS_SUCCESS;
}

void PORT::RequestWaitReply( MESSAGE *msg, MESSAGE *&reply )
{
	SendRequest( msg );

	LISTENER l( this, Current, FALSE, msg->Req.MessageId );

	// put the Thread to sleep while we wait for a reply
	assert( ReceivedMsg == 0 );
	Current->Wait();
	reply = ReceivedMsg;
	ReceivedMsg = 0;
	assert( !reply->IsLinked() );
}

NTSTATUS PORT::ReplyWaitReceive( MESSAGE *reply, MESSAGE *& received )
{
	trace("%p %p %p\n", this, reply, received );

	if (reply)
	{
		NTSTATUS r = SendReply( reply );
		if (r < STATUS_SUCCESS)
			return r;
	}

	received = Queue->Messages.Head();
	if (!received)
	{
		LISTENER l( this, Current, FALSE, 0 );

		Current->Wait();
		received = Queue->Messages.Head();
	}
	if (!received)
		return STATUS_THREAD_IS_TERMINATING;
	if (Current->IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	Queue->Messages.Unlink(received);
	assert( !received->IsLinked() );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreatePort(
	PHANDLE Port,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG MaxConnectInfoLength,
	ULONG MaxDataLength,
	PULONG Reserved )
{
	COBJECT_ATTRIBUTES oa;
	NTSTATUS r;
	OBJECT *p = NULL;

	trace("%p %p %lu %lu %p\n", Port, ObjectAttributes, MaxConnectInfoLength, MaxDataLength, Reserved);

	r = VerifyForWrite( Port, sizeof *Port );
	if (r < STATUS_SUCCESS)
		return r;

	r = oa.CopyFromUser( ObjectAttributes );
	if (r < STATUS_SUCCESS)
		return r;

	if (MaxDataLength > 0x148)
		return STATUS_INVALID_PARAMETER_4;

	if (MaxConnectInfoLength > 0x104)
		return STATUS_INVALID_PARAMETER_3;

	trace("root = %p Port = %pus\n", oa.RootDirectory, oa.ObjectName );

	r = CreateNamedPort( &p, &oa, MaxConnectInfoLength, MaxDataLength );
	if (r == STATUS_SUCCESS)
	{
		r = AllocUserHandle( p, 0, Port );
		Release( p );
	}

	return r;
}

NTSTATUS NTAPI NtListenPort(
	HANDLE PortHandle,
	PLPC_MESSAGE ConnectionRequest )
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p %p\n", PortHandle, ConnectionRequest);

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	if ((ULONG)ConnectionRequest&3)
		return STATUS_DATATYPE_MISALIGNMENT;

	r = VerifyForWrite( ConnectionRequest, sizeof *ConnectionRequest );
	if (r < STATUS_SUCCESS)
		return r;

	MESSAGE *msg = 0;
	port->Listen( msg );
	if (Current->IsTerminated())
		return STATUS_THREAD_IS_TERMINATING;
	r = CopyMsgToUser( ConnectionRequest, msg );
	delete msg;

	return r;
}

NTSTATUS NTAPI NtConnectPort(
	PHANDLE ClientPortHandle,
	PUNICODE_STRING ServerPortName,
	PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	PLPC_SECTION_WRITE ClientSharedMemory,
	PLPC_SECTION_READ ServerSharedMemory,
	PULONG MaximumMessageLength,
	PVOID ConnectionInfo,
	PULONG ConnectionInfoLength )
{
	trace("%p %p %p %p %p %p %p %p\n", ClientPortHandle, ServerPortName,
		  SecurityQos, ClientSharedMemory, ServerSharedMemory,
		  MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);

	return NtSecureConnectPort( ClientPortHandle, ServerPortName,
								SecurityQos, ClientSharedMemory, NULL, ServerSharedMemory,
								MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);
}

NTSTATUS NTAPI NtSecureConnectPort(
	PHANDLE ClientPortHandle,
	PUNICODE_STRING ServerPortName,
	PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	PLPC_SECTION_WRITE ClientSharedMemory,
	PSID ServerSid,
	PLPC_SECTION_READ ServerSharedMemory,
	PULONG MaximumMessageLength,
	PVOID ConnectionInfo,
	PULONG ConnectionInfoLength )
{
	CUNICODE_STRING name;
	NTSTATUS r;

	trace("%p %p %p %p %p %p %p %p %p\n", ClientPortHandle, ServerPortName,
		  SecurityQos, ClientSharedMemory, ServerSid, ServerSharedMemory,
		  MaximumMessageLength, ConnectionInfo, ConnectionInfoLength);

	r = VerifyForWrite( ClientPortHandle, sizeof (HANDLE) );
	if (r < STATUS_SUCCESS)
		return r;

	LPC_SECTION_WRITE write_sec;
	memset( &write_sec, 0, sizeof write_sec );
	if (ClientSharedMemory)
	{
		r = CopyFromUser( &write_sec, ClientSharedMemory, sizeof write_sec );
		if (r < STATUS_SUCCESS)
			return r;
		if (write_sec.Length != sizeof write_sec)
			return STATUS_INVALID_PARAMETER;
	}

	LPC_SECTION_READ read_sec;
	memset( &read_sec, 0, sizeof read_sec );
	if (ServerSharedMemory)
	{
		r = CopyFromUser( &read_sec, ServerSharedMemory, sizeof read_sec );
		if (r < STATUS_SUCCESS)
			return r;
		if (read_sec.Length != sizeof read_sec)
			return STATUS_INVALID_PARAMETER;
	}

	PSECURITY_QUALITY_OF_SERVICE qos;
	r = CopyFromUser( &qos, SecurityQos, sizeof qos );
	if (r < STATUS_SUCCESS)
		return r;

	r = name.CopyFromUser( ServerPortName );
	if (r < STATUS_SUCCESS)
		return r;

	if (!name.Buffer)
		return STATUS_OBJECT_NAME_INVALID;

	if (ClientSharedMemory)
	{
		SECTION* sec = 0;
		r = ObjectFromHandle( sec, write_sec.SectionHandle, 0 );
		if (r < STATUS_SUCCESS)
			return STATUS_INVALID_HANDLE;
	}

	// get the length
	ULONG info_length = 0;
	if (ConnectionInfoLength)
	{
		r = CopyFromUser( &info_length, ConnectionInfoLength, sizeof info_length );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (MaximumMessageLength)
	{
		r = VerifyForWrite( MaximumMessageLength, sizeof *MaximumMessageLength );
		if (r < STATUS_SUCCESS)
			return r;
	}

	// build a connect message
	MESSAGE* msg = new(info_length) MESSAGE;
	if (!msg)
		return STATUS_NO_MEMORY;

	// hack to avoid copying too much data then failing later
	if (info_length > 0x104)
		info_length = 0x108;

	msg->Req.DataSize = info_length;
	msg->Req.MessageSize = FIELD_OFFSET(LPC_MESSAGE, Data) + info_length;
	msg->Req.MessageType = LPC_CONNECTION_REQUEST;
	Current->GetClientID( &msg->Req.ClientId );
	msg->Req.MessageId = UniqueMessageId++;
	msg->Req.SectionSize = write_sec.ViewSize;

	r = CopyFromUser( msg->Req.Data, ConnectionInfo, info_length );
	if (r == STATUS_SUCCESS)
	{
		MESSAGE *reply = 0;
		r = ConnectPort( ClientPortHandle, &name, msg, reply, MaximumMessageLength, &write_sec, ServerSharedMemory );
		if (r == STATUS_SUCCESS && ClientSharedMemory)
			CopyToUser( ClientSharedMemory, &write_sec, sizeof write_sec );

		// copy the received connect info back to the caller
		if (reply)
		{
			if (ConnectionInfoLength )
			{
				// the buffer can't be assumed to be bigger info_length
				// so truncate the received data
				if (info_length > reply->Req.DataSize)
					info_length = reply->Req.DataSize;
				if (ConnectionInfo)
					CopyToUser( ConnectionInfo, reply->Req.Data, info_length );
				CopyToUser( ConnectionInfoLength, &info_length, sizeof info_length );
			}
			delete reply;
		}
	}

	return r;
}

NTSTATUS NTAPI NtReplyWaitReceivePort(
	HANDLE PortHandle,
	PULONG ReceivePortHandle,
	PLPC_MESSAGE Reply,
	PLPC_MESSAGE IncomingRequest )
{
	PORT *port = 0;
	MESSAGE *reply_msg = NULL;
	NTSTATUS r;

	trace("%p %p %p %p\n", PortHandle, ReceivePortHandle, Reply, IncomingRequest);

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	if (ReceivePortHandle)
	{
		r = VerifyForWrite( ReceivePortHandle, sizeof *ReceivePortHandle );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (Reply)
	{
		r = CopyMsgFromUser( &reply_msg, Reply, port->Queue->MaxData );
		if (r < STATUS_SUCCESS)
			return r;
	}

	r = VerifyForWrite( IncomingRequest, sizeof *IncomingRequest );
	if (r < STATUS_SUCCESS)
	{
		delete reply_msg;
		return r;
	}

	MESSAGE *received = 0;
	r = port->ReplyWaitReceive( reply_msg, received );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyMsgToUser( IncomingRequest, received );
	if (r == STATUS_SUCCESS)
	{
		if (ReceivePortHandle)
			CopyToUser( ReceivePortHandle, &received->DestinationId, sizeof (ULONG) );
		delete received;
	}

	return r;
}

NTSTATUS NTAPI NtRequestWaitReplyPort(
	HANDLE PortHandle,
	PLPC_MESSAGE Request,
	PLPC_MESSAGE Reply )
{
	MESSAGE *msg = NULL;
	PORT *port = 0;
	NTSTATUS r;

	trace("%p %p %p\n", PortHandle, Request, Reply );

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyMsgFromUser( &msg, Request, port->Queue->MaxData );
	if (r < STATUS_SUCCESS)
		return r;

	msg->Req.MessageType = LPC_REQUEST;

	MESSAGE *reply_msg = 0;
	port->RequestWaitReply( msg, reply_msg );

	r = CopyMsgToUser( Reply, reply_msg );
	if (r == STATUS_SUCCESS)
		delete reply_msg;

	return r;
}

NTSTATUS NTAPI NtAcceptConnectPort(
	PHANDLE ServerPortHandle,
	ULONG PortIdentifier,
	PLPC_MESSAGE ConnectionReply,
	BOOLEAN AcceptConnection,
	PLPC_SECTION_WRITE ServerSharedMemory,
	PLPC_SECTION_READ ClientSharedMemory )
{
	NTSTATUS r;

	trace("%p %lx %p %u %p %p\n", ServerPortHandle, PortIdentifier,
		  ConnectionReply, AcceptConnection, ServerSharedMemory, ClientSharedMemory );

	MESSAGE *reply = 0;
	r = CopyMsgFromUser( &reply, ConnectionReply, 0x148 );
	if (r < STATUS_SUCCESS)
		return r;

	r = VerifyForWrite( ServerPortHandle, sizeof *ServerPortHandle );
	if (r < STATUS_SUCCESS)
		return r;

	LPC_SECTION_WRITE write_sec;
	memset( &write_sec, 0, sizeof write_sec );
	if (ServerSharedMemory)
	{
		r = CopyFromUser( &write_sec, ServerSharedMemory, sizeof write_sec );
		if (r < STATUS_SUCCESS)
			return r;
		if (write_sec.Length != sizeof write_sec)
			return STATUS_INVALID_PARAMETER;
	}

	if (ClientSharedMemory)
	{
		LPC_SECTION_READ read_sec;
		r = CopyFromUser( &read_sec, ClientSharedMemory, sizeof read_sec );
		if (r < STATUS_SUCCESS)
			return r;
		if (read_sec.Length != sizeof read_sec)
			return STATUS_INVALID_PARAMETER;
		r = VerifyForWrite( ClientSharedMemory, sizeof *ClientSharedMemory );
		if (r < STATUS_SUCCESS)
			return r;
	}

	THREAD *t = FindThreadByClientId( &reply->Req.ClientId );
	if (!t)
		return STATUS_INVALID_CID;

	trace("%08lx %08lx\n", t->MessageId, reply->Req.MessageId);
	if (t->MessageId != reply->Req.MessageId)
	{
		trace("reply message mismatch\n");
		return STATUS_REPLY_MESSAGE_MISMATCH;
	}

	// avoid accepting the same connection twice
	if (!t->Port)
		return STATUS_REPLY_MESSAGE_MISMATCH;
	if (t->Port->Other)
		return STATUS_REPLY_MESSAGE_MISMATCH;

	if (!AcceptConnection)
	{
		// restart the Thread that was blocked on connect
		t->Port = 0;
		t->Start();
		return STATUS_SUCCESS;
	}

	assert( t->Port );
	assert( !t->Port->Other );
	assert( t->Port->Queue );

	PORT *port = new PORT( FALSE, Current, t->Port->Queue );
	if (!port)
		return STATUS_NO_MEMORY;

	// tie the ports together
	r = port->AcceptConnect( t, reply, &write_sec );
	if (r < STATUS_SUCCESS)
	{
		delete port;
		return r;
	}

	// allocate a handle
	HANDLE handle = 0;
	r = AllocUserHandle( port, 0, ServerPortHandle, &handle );

	// write out information on the sections we just created
	if (ClientSharedMemory)
	{
		LPC_SECTION_READ read_sec;

		if (port->Other->Section)
		{
			read_sec.Length = sizeof read_sec;
			read_sec.ViewBase = port->OtherSectionBase;
			read_sec.ViewSize = port->Other->ViewSize;
		}
		else
			memset( &read_sec, 0, sizeof read_sec);
		CopyToUser( ClientSharedMemory, &read_sec, sizeof read_sec );
	}

	if (ServerSharedMemory)
		CopyToUser( ServerSharedMemory, &write_sec, sizeof write_sec );

	// use the Port's handle as its identifier
	if (PortIdentifier)
		port->Other->Identifier = PortIdentifier;
	else
		port->Other->Identifier = (ULONG) handle;

	Release( port );

	return r;
}

NTSTATUS NTAPI NtCompleteConnectPort(
	HANDLE PortHandle )
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p\n", PortHandle);

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	return CompleteConnectPort( port );
}

NTSTATUS NTAPI NtReplyPort(
	HANDLE PortHandle,
	PLPC_MESSAGE reply )
{
	PORT *port = 0;
	MESSAGE *msg = NULL;
	NTSTATUS r;

	trace("%p %p\n", PortHandle, reply );

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyMsgFromUser( &msg, reply, port->Queue->MaxData );
	if (r < STATUS_SUCCESS)
		goto error;

	r = port->SendReply( msg );

error:
	if (r < STATUS_SUCCESS)
		MsgFreeUnlinked( msg );

	return r;
}

NTSTATUS NTAPI NtRegisterThreadTerminatePort(
	HANDLE PortHandle)
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p\n", PortHandle);

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	Current->RegisterTerminatePort( port );

	return r;
}

NTSTATUS NTAPI NtRequestPort(
	HANDLE PortHandle,
	PLPC_MESSAGE Request )
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p %p\n", PortHandle, Request);

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	MESSAGE *msg = 0;
	r = CopyMsgFromUser( &msg, Request, port->Queue->MaxData );
	if (r < STATUS_SUCCESS)
		return r;

	msg->Req.MessageType = LPC_DATAGRAM;
	return port->SendRequest( msg );
}

NTSTATUS NTAPI NtSetDefaultHardErrorPort(
	HANDLE PortHandle )
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p\n", PortHandle );

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	trace("does nothing\n");

	return STATUS_SUCCESS;
}

//syscall NtQueryInformationPort (9a) not implemented
NTSTATUS NTAPI NtQueryInformationPort(
	HANDLE PortHandle,
	PORT_INFORMATION_CLASS InformationClass,
	PVOID Buffer,
	ULONG Length,
	PULONG ReturnLength )
{
	PORT *port = 0;
	NTSTATUS r;

	trace("%p\n", PortHandle );

	r = PortFromHandle( PortHandle, port );
	if (r < STATUS_SUCCESS)
		return r;

	switch (InformationClass)
	{
	default:
		return STATUS_INVALID_INFO_CLASS;
	}

	return STATUS_SUCCESS;
}

