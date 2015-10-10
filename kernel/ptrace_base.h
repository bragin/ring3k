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

#ifndef __NTNATIVE_PTRACE_BASE_H
#define __NTNATIVE_PTRACE_BASE_H

#include "config.h"

class PTRACE_ADRESS_SPACE_IMPL: public ADDRESS_SPACE_IMPL
{
protected:
	static PTRACE_ADRESS_SPACE_IMPL *SigTarget;
	static void CancelTimer();
	static void SigitimerHandler(int signal);
	int GetContext( PCONTEXT ctx );
	int SetContext( PCONTEXT ctx );
	int PtraceRun( PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout );
	virtual pid_t GetChildPid() = 0;
	virtual void Handle( int signal );
	virtual void Run( void *TebBaseAddress, PCONTEXT ctx, int single_step, LARGE_INTEGER& timeout, EXECUTION_CONTEXT *exec );
	virtual void AlarmTimeout(LARGE_INTEGER& timeout);
	virtual int SetUserspaceFs(void *TebBaseAddress, ULONG fs);
	virtual void InitContext( CONTEXT& ctx );
	virtual unsigned short GetUserspaceFs() = 0;
	virtual unsigned short GetUserspaceDataSeg();
	virtual unsigned short GetUserspaceCodeSeg();
	virtual int GetFaultInfo( void *& addr );
	void WaitForSignal( pid_t pid, int signal );
public:
	static void SetSignals();
};


#endif // __NTNATIVE_PTRACE_BASE_H
