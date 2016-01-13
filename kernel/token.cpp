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

#include "debug.h"
#include "object.h"
#include "ntcall.h"
#include "token.h"

DEFAULT_DEBUG_CHANNEL(token);

#include "object.inl"

// http://blogs.msdn.com/david_leblanc/archive/2007/07/26/process-tokens-and-default-dacls.aspx
// typedef struct _ACCESS_MASK {
// WORD SpecificRights;
// BYTE StandardRights;
// BYTE AccessSystemAcl : 1;
// BYTE Reserved : 3;
// BYTE GenericAll : 1;
// BYTE GenericExecute : 1;
// BYTE GenericWrite : 1;
// BYTE GenericRead : 1;
// } ACCESS_MASK;
// typedef ACCESS_MASK *PACCESS_MASK;

class LUID_AND_PRIVILEGES;
class CTOKEN_PRIVILEGES;

typedef LIST_ANCHOR<LUID_AND_PRIVILEGES,0> LUID_AND_PRIV_LIST;
typedef LIST_ELEMENT<LUID_AND_PRIVILEGES> LUID_AND_PRIV_ENTRY;
typedef LIST_ITER<LUID_AND_PRIVILEGES,0> LUID_AND_PRIV_ITER;

class LUID_AND_PRIVILEGES : public LUID_AND_ATTRIBUTES
{
	friend class LIST_ANCHOR<LUID_AND_PRIVILEGES,0>;
	friend class LIST_ITER<LUID_AND_PRIVILEGES,0>;
protected:
	LUID_AND_PRIV_ENTRY Entry[1];
public:
	void Dump();
};

void LUID_AND_PRIVILEGES::Dump()
{
	TRACE("%08lx %08lx %08lx\n", Luid.LowPart, Luid.HighPart, Attributes );
}

class CTOKEN_PRIVILEGES
{
	ULONG PrivCount;
	LUID_AND_PRIV_LIST PrivList;
public:
	CTOKEN_PRIVILEGES();
	~CTOKEN_PRIVILEGES();
	void Dump();
	ULONG GetLength();
	NTSTATUS CopyFromUser( PTOKEN_PRIVILEGES tp );
	NTSTATUS CopyToUser( PTOKEN_PRIVILEGES tp );
	NTSTATUS Add( LUID_AND_ATTRIBUTES& la );
};

CTOKEN_PRIVILEGES::CTOKEN_PRIVILEGES() :
	PrivCount(0)
{
}

CTOKEN_PRIVILEGES::~CTOKEN_PRIVILEGES()
{
	LUID_AND_PRIVILEGES *priv;
	while ((priv = PrivList.Head()))
	{
		PrivList.Unlink( priv );
		delete priv;
	}
	PrivCount = 0;
}

void CTOKEN_PRIVILEGES::Dump()
{
	LUID_AND_PRIV_ITER i(PrivList);
	while (i)
	{
		LUID_AND_PRIVILEGES *priv = i;
		priv->Dump();
		i.Next();
	}
}

NTSTATUS CTOKEN_PRIVILEGES::Add( LUID_AND_ATTRIBUTES& la )
{
	LUID_AND_PRIVILEGES *priv = new LUID_AND_PRIVILEGES;
	if (!priv)
		return STATUS_NO_MEMORY;
	priv->Luid = la.Luid;
	priv->Attributes = la.Attributes;
	PrivList.Append( priv );
	PrivCount++;
	return STATUS_SUCCESS;
}

NTSTATUS CTOKEN_PRIVILEGES::CopyFromUser( PTOKEN_PRIVILEGES tp )
{
	NTSTATUS r;
	ULONG count = 0;

	r = ::CopyFromUser( &count, &tp->PrivilegeCount, sizeof count );
	if (r < STATUS_SUCCESS)
		return r;

	for (ULONG i=0; i<count; i++)
	{
		LUID_AND_ATTRIBUTES la;
		r = ::CopyFromUser( &la, &tp->Privileges[i], sizeof la );
		if (r < STATUS_SUCCESS)
			return r;
		r = Add( la );
		if (r < STATUS_SUCCESS)
			return r;
	}

	return r;
}

ULONG CTOKEN_PRIVILEGES::GetLength()
{
	return sizeof PrivCount + PrivCount * sizeof (LUID_AND_ATTRIBUTES);
}

NTSTATUS CTOKEN_PRIVILEGES::CopyToUser( PTOKEN_PRIVILEGES tp )
{
	NTSTATUS r;

	r = ::CopyToUser( &tp->PrivilegeCount, &PrivCount, sizeof PrivCount );
	if (r < STATUS_SUCCESS)
		return r;

	LUID_AND_PRIV_ITER i(PrivList);
	ULONG n = 0;
	while (i)
	{
		LUID_AND_PRIVILEGES *priv = i;
		LUID_AND_ATTRIBUTES* la = priv;
		r = ::CopyToUser( &tp->Privileges[n], la, sizeof *la );
		if (r < STATUS_SUCCESS)
			break;
		i.Next();
		n++;
	}

	return r;
}

class USER_COPY
{
public:
	virtual ULONG GetLength() = 0;
	virtual NTSTATUS CopyToUser(PVOID) = 0;
	virtual ~USER_COPY() = 0;
};

USER_COPY::~USER_COPY()
{
}

class CSID : public USER_COPY
{
public:
	BYTE Revision;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
protected:
	BYTE SubAuthorityCount;
	ULONG *SubAuthority;
	inline ULONG SidLen()
	{
		return FIELD_OFFSET( SID, SubAuthority );
	}
public:
	CSID();
	NTSTATUS CopyFromUser( PSID sid );
	virtual ULONG GetLength();
	virtual NTSTATUS CopyToUser( PVOID sid );
	void SetSubAuthCount( BYTE count );
	void SetSubAuth( ULONG n, ULONG subauth );
	ULONG GetSubAuthCount()
	{
		return SubAuthorityCount;
	}
	void Dump();
};

CSID::CSID() :
	Revision(1),
	SubAuthorityCount(0),
	SubAuthority(0)
{
}

void CSID::Dump()
{
	BYTE* b = IdentifierAuthority.Value;
	TRACE("sid: %02x %02x %02x-%02x-%02x-%02x-%02x-%02x\n",
		  Revision, SubAuthorityCount, b[0], b[1], b[2], b[3], b[4], b[6]);
}

void CSID::SetSubAuthCount( BYTE count )
{
	if (SubAuthority)
		delete SubAuthority;
	SubAuthorityCount = count;
	SubAuthority = new ULONG[count];
}

void CSID::SetSubAuth( ULONG n, ULONG subauth )
{
	assert(n < SubAuthorityCount);
	SubAuthority[n] = subauth;
}

ULONG CSID::GetLength()
{
	return SidLen() + SubAuthorityCount * sizeof (ULONG);
}

NTSTATUS CSID::CopyFromUser( PSID psid )
{
	NTSTATUS r;
	SID sid;

	r = ::CopyFromUser( &sid, psid, SidLen() );
	if (r < STATUS_SUCCESS)
		return r;

	Revision = sid.Revision;
	IdentifierAuthority = sid.IdentifierAuthority;
	SetSubAuthCount( sid.SubAuthorityCount );

	PISID pisid = (PISID) psid;
	r = ::CopyFromUser( SubAuthority, &pisid->SubAuthority, SubAuthorityCount * sizeof (ULONG));

	return r;
}

NTSTATUS CSID::CopyToUser( PSID psid )
{
	NTSTATUS r;
	SID sid;

	sid.Revision = Revision;
	sid.IdentifierAuthority = IdentifierAuthority;
	sid.SubAuthorityCount = SubAuthorityCount;

	r = ::CopyToUser( psid, &sid, SidLen() );
	if (r < STATUS_SUCCESS)
		return r;

	PISID pisid = (PISID) psid;
	r = ::CopyToUser( &pisid->SubAuthority, SubAuthority, SubAuthorityCount * sizeof (ULONG));

	return r;
}

// wrapper for SID_AND_ATTRIBUTES
class CSID_AND_ATTRIBUTES
{
	CSID Sid;
	ULONG Attributes;
public:
	CSID_AND_ATTRIBUTES();
	ULONG GetLength();
	NTSTATUS CopyHdrToUser( SID_AND_ATTRIBUTES* psida, ULONG ofs );
	NTSTATUS CopyToUser( SID_AND_ATTRIBUTES* sida );
	CSID &GetSid();
};

CSID_AND_ATTRIBUTES::CSID_AND_ATTRIBUTES():
	Attributes( 0 )
{
}

CSID &CSID_AND_ATTRIBUTES::GetSid()
{
	return Sid;
}

ULONG CSID_AND_ATTRIBUTES::GetLength()
{
	return sizeof (SID_AND_ATTRIBUTES) + Sid.GetLength();
}

NTSTATUS CSID_AND_ATTRIBUTES::CopyHdrToUser( SID_AND_ATTRIBUTES* psida, ULONG ofs )
{
	SID_AND_ATTRIBUTES sida;
	sida.Attributes = Attributes;
	sida.Sid = (PSID) ((BYTE*)psida + ofs);
	return ::CopyToUser( psida, &sida, sizeof sida );
}

NTSTATUS CSID_AND_ATTRIBUTES::CopyToUser( SID_AND_ATTRIBUTES* psida )
{
	NTSTATUS r;
	r = CopyHdrToUser( psida, sizeof *psida );
	if (r < STATUS_SUCCESS)
		return r;

	return Sid.CopyToUser( (PSID)(psida + 1) );
}

class CTOKEN_GROUPS
{
	ULONG Count;
	CSID_AND_ATTRIBUTES *SA;
protected:
	void Reset();
public:
	CTOKEN_GROUPS();
	~CTOKEN_GROUPS();
	ULONG GetLength();
	NTSTATUS CopyToUser( TOKEN_GROUPS *tg );
	void SetCount( ULONG n );
	CSID_AND_ATTRIBUTES& GetSA( ULONG n );
};

CTOKEN_GROUPS::CTOKEN_GROUPS() :
	Count(0),
	SA(0)
{
}

CTOKEN_GROUPS::~CTOKEN_GROUPS()
{
	Reset();
}

void CTOKEN_GROUPS::Reset()
{
	delete SA;
	SA = 0;
	Count = 0;
}

// assume this is only done once
void CTOKEN_GROUPS::SetCount( ULONG n )
{
	Reset();
	SA = new CSID_AND_ATTRIBUTES[n];
	Count = n;
}

CSID_AND_ATTRIBUTES& CTOKEN_GROUPS::GetSA( ULONG n )
{
	if (n >= Count)
		throw;
	return SA[n];
}

ULONG CTOKEN_GROUPS::GetLength()
{
	ULONG len = sizeof (ULONG);

	for (ULONG i=0; i<Count; i++)
		len += SA[i].GetLength();

	return len;
}

NTSTATUS CTOKEN_GROUPS::CopyToUser( TOKEN_GROUPS *tg )
{
	NTSTATUS r;
	r = ::CopyToUser( &tg->GroupCount, &Count, sizeof Count );
	if (r < STATUS_SUCCESS)
		return r;

	// Copying multiple SID_AND_ATTRIBUTES structs is a bit complex.
	// The SID_AND_ATTRIBUTES and the SID it points to are separated.
	// The order should be:
	//    ULONG GroupCount;
	//    SID_AND_ATTRIBUTES Groups[GroupCount];
	//    1st SID
	//    2nd SID
	//    ...
	ULONG ofs = sizeof (ULONG) + Count * sizeof (SID_AND_ATTRIBUTES);
	for (ULONG i=0; i<Count; i++)
	{
		r = SA[i].CopyHdrToUser( &tg->Groups[i], ofs );
		if (r < STATUS_SUCCESS)
			return r;
		r = SA[i].GetSid().CopyToUser( (PSID) ((BYTE*) tg + ofs) );
		if (r < STATUS_SUCCESS)
			return r;
		ofs += SA[i].GetSid().GetLength();
	}

	return r;
}

// access control entry
class ACE;

typedef LIST_ANCHOR<ACE,0> ACE_LIST;
typedef LIST_ELEMENT<ACE> ACE_ENTRY;
typedef LIST_ITER<ACE,0> ACE_ITER;

class ACE : public USER_COPY
{
	struct ACE_COMMON
	{
		ACE_HEADER Header;
		ULONG Mask;
		ULONG SidStart;
	};
	friend class LIST_ANCHOR<ACE,0>;
	friend class LIST_ITER<ACE,0>;
protected:
	ACE_ENTRY Entry[1];
	BYTE Type;
	BYTE Flags;
	ULONG Mask;
	CSID Sid;
public:
	ACE(BYTE type);
	virtual ULONG GetLength();
	virtual NTSTATUS CopyToUser( PVOID pace );
	virtual ~ACE();
	CSID& GetSid();
};

ACE::ACE(BYTE _type) :
	Type( _type ),
	Flags( 0 )
{
}

ACE::~ACE()
{
}

CSID& ACE::GetSid()
{
	return Sid;
}

ULONG ACE::GetLength()
{
	return sizeof (ACE_COMMON) + Sid.GetLength();
}

NTSTATUS ACE::CopyToUser( PVOID pace )
{
	BYTE *p = (BYTE*) pace;

	ACE_COMMON ace;

	ace.Header.AceType = Type;
	ace.Header.AceFlags = Flags;
	ace.Header.AceSize = sizeof ace + Sid.GetLength();
	ace.Mask = Mask;
	ace.SidStart = sizeof ace;

	NTSTATUS r = ::CopyToUser( pace, &ace, sizeof ace );
	if (r < STATUS_SUCCESS)
		return r;

	return Sid.CopyToUser( (PVOID) ((PBYTE) p + sizeof ace) );
}

class CACCESS_ALLOWED_ACE : public ACE
{
public:
	CACCESS_ALLOWED_ACE();
};

CACCESS_ALLOWED_ACE::CACCESS_ALLOWED_ACE() :
	ACE( ACCESS_ALLOWED_ACE_TYPE )
{
}

class CACCESS_DENIED_ACE : public ACE
{
public:
	CACCESS_DENIED_ACE();
};

CACCESS_DENIED_ACE::CACCESS_DENIED_ACE() :
	ACE( ACCESS_DENIED_ACE_TYPE )
{
}

class CSYSTEM_AUDIT_ACE : public ACE
{
public:
	CSYSTEM_AUDIT_ACE();
};

CSYSTEM_AUDIT_ACE::CSYSTEM_AUDIT_ACE() :
	ACE( SYSTEM_AUDIT_ACE_TYPE )
{
}

class CSYSTEM_ALARM_ACE : public ACE
{
public:
	CSYSTEM_ALARM_ACE();
};

CSYSTEM_ALARM_ACE::CSYSTEM_ALARM_ACE() :
	ACE( SYSTEM_ALARM_ACE_TYPE )
{
}

// access control list
class CACL : public USER_COPY, protected ACL
{
	ACE_LIST AceList;
public:
	virtual ULONG GetLength();
	virtual NTSTATUS CopyToUser( PVOID pacl );
	virtual ~CACL();
	NTSTATUS CopyFromUser( PACL pacl );
	void Add( ACE *ace );
};

CACL::~CACL()
{
	ACE *ace;
	while ((ace = AceList.Head()))
	{
		AceList.Unlink( ace );
		delete ace;
	}
}

ULONG CACL::GetLength()
{
	ULONG len = sizeof (ACL);
	ACE_ITER i(AceList);
	while (i)
	{
		ACE *ace = i;
		len += ace->GetLength();
		i.Next();
	}
	return len;
}

NTSTATUS CACL::CopyToUser( PVOID pacl )
{
	PACL acl = this;
	ULONG ofs = sizeof *acl;
	NTSTATUS r = ::CopyToUser( pacl, acl, ofs );

	ACE_ITER i(AceList);
	while (i && r == STATUS_SUCCESS)
	{
		ACE *ace = i;
		r = ace->CopyToUser( (PVOID) ((BYTE*) pacl + ofs) );
		ofs += ace->GetLength();
		i.Next();
	}
	return r;
}

void CACL::Add( ACE *ace )
{
	AceList.Append( ace );
}

class PRIVILEGES_SET
{
	ULONG Count;
	ULONG Control;
	LUID_AND_ATTRIBUTES *Privileges;
protected:
	void Reset();
	void SetCount( ULONG count );
public:
	PRIVILEGES_SET();
	~PRIVILEGES_SET();
	NTSTATUS CopyFromUser( PPRIVILEGE_SET ps );
};

PRIVILEGES_SET::PRIVILEGES_SET() :
	Count(0),
	Control(0),
	Privileges(0)
{
}

PRIVILEGES_SET::~PRIVILEGES_SET()
{
	Reset();
}

void PRIVILEGES_SET::Reset()
{
	if (Count)
	{
		delete Privileges;
		Count = 0;
	}
}

void PRIVILEGES_SET::SetCount( ULONG n )
{
	Reset();
	Privileges = new LUID_AND_ATTRIBUTES[n];
	Count = n;
}

NTSTATUS PRIVILEGES_SET::CopyFromUser( PPRIVILEGE_SET ps )
{
	struct
	{
		ULONG count;
		ULONG control;
	} x;

	NTSTATUS r = ::CopyFromUser( &x, ps, sizeof x );
	if (r < STATUS_SUCCESS)
		return r;

	SetCount( x.count );
	Control = x.control;

	r = ::CopyFromUser( Privileges, ps->Privilege, Count * sizeof Privileges[0] );

	return STATUS_SUCCESS;
}

TOKEN::~TOKEN()
{
}

class TOKEN_IMPL : public TOKEN
{
	CTOKEN_PRIVILEGES Privs;
	CSID Owner;
	CSID PrimaryGroup;
	CACL DefaultDacl;
	CSID_AND_ATTRIBUTES User;
	CTOKEN_GROUPS Groups;
	CTOKEN_GROUPS RestrictedSids;
public:
	TOKEN_IMPL();
	virtual ~TOKEN_IMPL();
	virtual CTOKEN_PRIVILEGES& GetPrivs();
	virtual CSID& GetOwner();
	virtual CSID_AND_ATTRIBUTES& GetUser();
	virtual CSID& GetPrimaryGroup();
	virtual CTOKEN_GROUPS& GetGroups();
	virtual CTOKEN_GROUPS& GetRestrictedSids();
	virtual CACL& GetDefaultDacl();
	virtual NTSTATUS Adjust(CTOKEN_PRIVILEGES& privs);
	NTSTATUS Add( LUID_AND_ATTRIBUTES& la );
};

TOKEN_IMPL::TOKEN_IMPL()
{
	// FIXME: make this a default local computer account with privileges disabled
	LUID_AND_ATTRIBUTES la;

	//la.Luid.LowPart = SECURITY_LOCAL_SYSTEM_RID;
	la.Luid.LowPart = SECURITY_LOCAL_SERVICE_RID;
	la.Luid.HighPart = 0;
	la.Attributes = 0;

	Privs.Add( la );

	static const SID_IDENTIFIER_AUTHORITY auth = {SECURITY_NT_AUTHORITY};
	memcpy( &Owner.IdentifierAuthority, &auth, sizeof auth );
	Owner.SetSubAuthCount( 1 );
	Owner.SetSubAuth( 0, SECURITY_LOCAL_SYSTEM_RID );

	memcpy( &PrimaryGroup.IdentifierAuthority, &auth, sizeof auth );
	PrimaryGroup.SetSubAuthCount( 1 );
	PrimaryGroup.SetSubAuth( 0, DOMAIN_GROUP_RID_COMPUTERS );

	CSID &user_sid = User.GetSid();
	memcpy( &user_sid.IdentifierAuthority, &auth, sizeof auth );
	user_sid.SetSubAuthCount( 1 );
	user_sid.SetSubAuth( 0, SECURITY_LOCAL_SYSTEM_RID );
}

TOKEN_IMPL::~TOKEN_IMPL()
{
}

CSID& TOKEN_IMPL::GetOwner()
{
	return Owner;
}

CSID& TOKEN_IMPL::GetPrimaryGroup()
{
	return PrimaryGroup;
}

CTOKEN_GROUPS& TOKEN_IMPL::GetGroups()
{
	return Groups;
}

CTOKEN_GROUPS& TOKEN_IMPL::GetRestrictedSids()
{
	return RestrictedSids;
}

CSID_AND_ATTRIBUTES& TOKEN_IMPL::GetUser()
{
	return User;
}

CTOKEN_PRIVILEGES& TOKEN_IMPL::GetPrivs()
{
	return Privs;
}

CACL& TOKEN_IMPL::GetDefaultDacl()
{
	return DefaultDacl;
}

NTSTATUS TOKEN_IMPL::Adjust(CTOKEN_PRIVILEGES& privs)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtOpenProcessToken(
	HANDLE Process,
	ACCESS_MASK DesiredAccess,
	PHANDLE Token )
{
	NTSTATUS r;

	TRACE("%p %08lx %p\n", Process, DesiredAccess, Token);

	r = VerifyForWrite( Token, sizeof *Token );
	if (r < STATUS_SUCCESS)
		return r;

	PROCESS *p = 0;
	r = ObjectFromHandle( p, Process, 0 );
	if (r < STATUS_SUCCESS)
		return r;

	TOKEN *token = new TOKEN_IMPL;
	if (!token)
		return STATUS_NO_MEMORY;

	r = AllocUserHandle( token, DesiredAccess, Token );
	Release( token );

	return r;
}

NTSTATUS NTAPI NtOpenThreadToken(
	HANDLE Thread,
	ACCESS_MASK DesiredAccess,
	BOOLEAN OpenAsSelf,
	PHANDLE TokenHandle )
{
	NTSTATUS r;

	TRACE("%p %08lx %u %p\n", Thread, DesiredAccess, OpenAsSelf, TokenHandle);

	r = VerifyForWrite( TokenHandle, sizeof *TokenHandle );
	if (r < STATUS_SUCCESS)
		return r;

	THREAD *t = 0;
	r = ObjectFromHandle( t, Thread, DesiredAccess );
	if (r < STATUS_SUCCESS)
		return r;

	TOKEN *tok = t->GetToken();
	if (tok == 0)
		return STATUS_NO_TOKEN;

	r = AllocUserHandle( tok, DesiredAccess, TokenHandle );

	return r;
}

NTSTATUS NTAPI NtAdjustPrivilegesToken(
	HANDLE TokenHandle,
	BOOLEAN DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	ULONG BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PULONG ReturnLength )
{
	NTSTATUS r;

	TRACE("%p %u %p %lu %p %p\n", TokenHandle, DisableAllPrivileges,
		  NewState, BufferLength, PreviousState, ReturnLength );

	if (ReturnLength)
	{
		r = VerifyForWrite( ReturnLength, sizeof *ReturnLength );
		if (r < STATUS_SUCCESS)
			return r;
	}

	if (!NewState)
		return STATUS_INVALID_PARAMETER;

	// getting the old state requires query rights
	ACCESS_MASK mask = TOKEN_ADJUST_PRIVILEGES;
	if (PreviousState)
		mask |= TOKEN_QUERY;

	TOKEN *token = 0;
	r = ObjectFromHandle( token, TokenHandle, mask );
	if (r < STATUS_SUCCESS)
		return r;

	CTOKEN_PRIVILEGES privs;
	r = privs.CopyFromUser( NewState );
	if (r < STATUS_SUCCESS)
		return r;

	// return previous state information if required
	if (PreviousState)
	{
		CTOKEN_PRIVILEGES& prev_state = token->GetPrivs();

		ULONG len = prev_state.GetLength();
		TRACE("old privs %ld bytes\n", len);
		prev_state.Dump();
		if (len > BufferLength)
			return STATUS_BUFFER_TOO_SMALL;

		r = prev_state.CopyToUser( PreviousState );
		if (r < STATUS_SUCCESS)
			return r;

		r = CopyToUser( ReturnLength, &len, sizeof len );
		assert( r == STATUS_SUCCESS );
	}

	r = token->Adjust( privs );

	TRACE("new privs\n");
	privs.Dump();

	return r;
}

static NTSTATUS CopyPtrToUser( USER_COPY& item, PVOID info, ULONG infolen, ULONG& retlen )
{
	// really screwy - have to write back a pointer to the sid, then the sid
	retlen = item.GetLength() + sizeof (PVOID);
	if (retlen > infolen)
		return STATUS_BUFFER_TOO_SMALL;

	// pointer followed by the data blob
	PVOID ptr = (PVOID) ((PVOID*) info + 1);
	NTSTATUS r = CopyToUser( info, &ptr, sizeof ptr );
	if (r < STATUS_SUCCESS)
		return r;
	return item.CopyToUser( ptr );
}

NTSTATUS NTAPI NtQueryInformationToken(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength )
{
	TOKEN *token;
	ULONG len;
	NTSTATUS r;
	TOKEN_STATISTICS stats;

	TRACE("%p %u %p %lu %p\n", TokenHandle, TokenInformationClass,
		  TokenInformation, TokenInformationLength, ReturnLength );

	r = ObjectFromHandle( token, TokenHandle, TOKEN_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	switch( TokenInformationClass )
	{
	case TokenOwner:
		TRACE("TokenOwner\n");
		r = CopyPtrToUser( token->GetOwner(), TokenInformation, TokenInformationLength, len );
		break;

	case TokenPrimaryGroup:
		TRACE("TokenPrimaryGroup\n");
		r = CopyPtrToUser( token->GetPrimaryGroup(), TokenInformation, TokenInformationLength, len );
		break;

	case TokenDefaultDacl:
		TRACE("TokenDefaultDacl\n");
		r = CopyPtrToUser( token->GetDefaultDacl(), TokenInformation, TokenInformationLength, len );
		break;

	case TokenUser:
		TRACE("TokenUser\n");
		len = token->GetUser().GetLength();
		if (len > TokenInformationLength)
		{
			r = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		r = token->GetUser().CopyToUser( (SID_AND_ATTRIBUTES*) TokenInformation );
		break;

	case TokenImpersonationLevel:
		FIXME("UNIMPLEMENTED: TokenImpersonationLevel\n");
		return STATUS_INVALID_INFO_CLASS;

	case TokenStatistics:
		TRACE("TokenStatistics\n");
		len = sizeof stats;
		if (len != TokenInformationLength)
			return STATUS_INFO_LENGTH_MISMATCH;

		memset( &stats, 0, sizeof stats );
		r = CopyToUser( TokenInformation, &stats, sizeof stats );
		if (r < STATUS_SUCCESS)
			return r;

		break;

	case TokenGroups:
		TRACE("TokenGroups\n");
		len = token->GetGroups().GetLength();
		if (len > TokenInformationLength)
		{
			r = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		r = token->GetGroups().CopyToUser( (TOKEN_GROUPS*) TokenInformation );
		break;

	case TokenRestrictedSids:
		TRACE("TokenRestrictedSids\n");
		len = token->GetRestrictedSids().GetLength();
		if (len > TokenInformationLength)
		{
			r = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		r = token->GetGroups().CopyToUser((TOKEN_GROUPS*)TokenInformation);
		break;

	default:
		FIXME("UNIMPLEMENTED: info class %d\n", TokenInformationClass);
		return STATUS_INVALID_INFO_CLASS;
	}

	if (ReturnLength)
		CopyToUser( ReturnLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtSetSecurityObject(
	HANDLE Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor )
{
	FIXME("UNIMPLEMENTED: %p %08lx %p\n", Handle, SecurityInformation, SecurityDescriptor );

	// Make sure the caller doesn't pass a NULL security descriptor
	if (!SecurityDescriptor) return STATUS_ACCESS_VIOLATION;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtDuplicateToken(
	HANDLE ExistingToken,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly,
	TOKEN_TYPE TokenType,
	PHANDLE TokenHandle)
{
	TOKEN *existing = 0;

	NTSTATUS r = ObjectFromHandle( existing, ExistingToken, TOKEN_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	TOKEN *token = new TOKEN_IMPL;
	if (!token)
		return STATUS_NO_MEMORY;

	r = AllocUserHandle( token, DesiredAccess, TokenHandle );
	Release( token );

	return r;
}

NTSTATUS NTAPI NtFilterToken(
	HANDLE ExistingTokenHandle,
	ULONG Flags,
	PTOKEN_GROUPS SidsToDisable,
	PTOKEN_PRIVILEGES PrivelegesToDelete,
	PTOKEN_GROUPS SidsToRestrict,
	PHANDLE NewTokenHandle)
{
	FIXME("\n");
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI NtAccessCheck(
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	HANDLE TokenHandle,
	ACCESS_MASK DesiredAccess,
	PGENERIC_MAPPING GenericMapping,
	PPRIVILEGE_SET PrivilegeSet,
	PULONG PrivilegeSetLength,
	PACCESS_MASK GrantedAccess,
	PBOOLEAN AccessStatus)
{
	FIXME("\n");
	return STATUS_NOT_IMPLEMENTED;
}

//NtPrivilegeCheck(00000154,0006fdc0,0006fe34) ret=77fa7082
NTSTATUS NtPrivilegeCheck(
	HANDLE TokenHandle,
	PPRIVILEGE_SET RequiredPrivileges,
	PBOOLEAN Result)
{
	TOKEN *token = 0;

	NTSTATUS r = ObjectFromHandle( token, TokenHandle, TOKEN_QUERY );
	if (r < STATUS_SUCCESS)
		return r;

	PRIVILEGES_SET ps;
	r = ps.CopyFromUser( RequiredPrivileges );
	if (r < STATUS_SUCCESS)
		return r;

	BOOLEAN ok = TRUE;
	r = CopyToUser( Result, &ok, sizeof ok );

	FIXME("\n");

	return r;
}
