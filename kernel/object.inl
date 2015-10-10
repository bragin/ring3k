#ifndef __OBJECT_INL__
#define __OBJECT_INL__

#include "ntcall.h"

template<class T> NTSTATUS NtOpenObject(
	PHANDLE Handle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes)
{
	OBJECT_ATTRIBUTES oa;
	unicode_string_t us;
	NTSTATUS r;

	r = CopyFromUser( &oa, ObjectAttributes, sizeof oa );
	if (r != STATUS_SUCCESS)
		return r;

	if (oa.ObjectName)
	{
		r = us.copy_from_user( oa.ObjectName );
		if (r != STATUS_SUCCESS)
			return r;
		oa.ObjectName = &us;
	}

	trace("object = %pus\n", oa.ObjectName );

	OBJECT *object = NULL;

	r = GetNamedObject( &object, &oa );
	if (r != STATUS_SUCCESS)
		return r;

	if (dynamic_cast<T*>( object ))
	{
		r = AllocUserHandle( object, DesiredAccess, Handle );
	}
	else
		r = STATUS_OBJECT_TYPE_MISMATCH;

	Release( object );

	return r;
}

template<typename T> NTSTATUS ObjectFromHandle(T*& out, HANDLE handle, ACCESS_MASK access)
{
	NTSTATUS r;
	OBJECT *obj = 0;

	r = Current->Process->HandleTable.ObjectFromHandle( obj, handle, access );
	if (r != STATUS_SUCCESS)
		return r;

	out = dynamic_cast<T*>(obj);
	if (!out)
		return STATUS_OBJECT_TYPE_MISMATCH;

	return STATUS_SUCCESS;
}

#endif // __OBJECT_INL__
