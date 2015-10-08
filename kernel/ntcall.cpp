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
#include <stdlib.h>
#include <stdio.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "debug.h"
#include "object.h"
#include "mem.h"
#include "ntcall.h"
#include "timer.h"

NTSTATUS CopyToUser( void *dest, const void *src, size_t len )
{
	return Current->CopyToUser( dest, src, len );
}

NTSTATUS CopyFromUser( void *dest, const void *src, size_t len )
{
	return Current->CopyFromUser( dest, src, len );
}

NTSTATUS VerifyForWrite( void *dest, size_t len )
{
	return Current->VerifyForWrite( dest, len );
}

// print with white on blue - appologies for the lame hack ;)
void ColorPrint( const char* format, ... )
{
	va_list va;
	va_start( va, format);
	// set to blue
	fprintf(stderr, "\x1b[37;44m");
	vfprintf(stderr, format, va );
	// restore the color
	fprintf(stderr, "\x1b[0m\n");
	va_end( va );
}

NTSTATUS NTAPI NtRaiseHardError(
	NTSTATUS Status,
	ULONG NumberOfArguments,
	ULONG StringArgumentsMask,
	PULONG Arguments,
	HARDERROR_RESPONSE_OPTION ResponseOption,
	PHARDERROR_RESPONSE Response)
{
	NTSTATUS r;
	ULONG i;

	trace("%08lx %lu %lu %p %u %p\n", Status, NumberOfArguments,
		  StringArgumentsMask, Arguments, ResponseOption, Response);

	if (NumberOfArguments>32)
		return STATUS_INVALID_PARAMETER;

	ColorPrint(" Blue screen of death! ");
	for (i=0; i<NumberOfArguments; i++)
	{
		void *arg;

		r = CopyFromUser( &arg, &Arguments[i], sizeof (PUNICODE_STRING) );
		if (r < STATUS_SUCCESS)
			break;

		if (StringArgumentsMask & (1<<i))
		{
			char buffer[0x100];
			unicode_string_t us;

			r = us.copy_from_user( (UNICODE_STRING*) arg );
			if (r < STATUS_SUCCESS)
				break;

			us.wchar_to_utf8( buffer, sizeof buffer );
			ColorPrint(" %s ", buffer);
		}
		else
			ColorPrint(" %08lx ", (ULONG)arg);
	}

	exit(1);

	return STATUS_SUCCESS;
}

#define SET_INFO_LENGTH(len, item) \
	do { \
		(len) = sizeof (item); \
		if ((len) < SystemInformationLength) \
			return STATUS_INFO_LENGTH_MISMATCH; \
		(len) = SystemInformationLength; \
	} while (0)

NTSTATUS NTAPI NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength )
{
	NTSTATUS r = STATUS_SUCCESS;
	union
	{
		SYSTEM_BASIC_INFORMATION basic;
		SYSTEM_CPU_INFORMATION cpu;
		SYSTEM_THREAD_INFORMATION thread;
		SYSTEM_TIME_OF_DAY_INFORMATION time_of_day;
		SYSTEM_RANGE_START_INFORMATION range_start;
		SYSTEM_GLOBAL_FLAG global_flag;
		SYSTEM_KERNEL_DEBUGGER_INFORMATION kernel_debugger_info;
		SYSTEM_PERFORMANCE_INFORMATION performance_info;
		SYSTEM_CRASH_DUMP_STATE_INFORMATION crash_dump_info;
	} info;
	ULONG len = 0;

	trace("%d %p %lu %p\n", SystemInformationClass, SystemInformation,
		  SystemInformationLength, ReturnLength);

	if (ReturnLength)
	{
		r = CopyToUser( ReturnLength, &len, sizeof len );
		if (r < STATUS_SUCCESS)
			return r;
	}

	memset( &info, 0, sizeof info );

	switch( SystemInformationClass )
	{
	case SystemBasicInformation:
		SET_INFO_LENGTH( len, info.basic );
		info.basic.dwUnknown1 = 0;
		info.basic.uKeMaximumIncrement = 0x18730;
		info.basic.uPageSize = 0x1000;
		info.basic.uMmNumberOfPhysicalPages = 0xbf6c;
		info.basic.uMmLowestPhysicalPage = 1;
		info.basic.uMmHighestPhysicalPage = 0xbfdf;
		info.basic.uAllocationGranularity = 0x1000;
		info.basic.pLowestUserAddress = (void*)0x1000;
		info.basic.pMmHighestUserAddress = (void*)0x7ffeffff;
		info.basic.uKeActiveProcessors = 1;
		info.basic.uKeNumberProcessors = 1;
		break;

	case SystemCpuInformation:
		SET_INFO_LENGTH( len, info.cpu );
		info.cpu.Architecture = 0;
		info.cpu.Level = 6;
		info.cpu.Revision = 0x0801;
		info.cpu.FeatureSet = 0x2fff;
		break;

	case SystemTimeOfDayInformation:
		SET_INFO_LENGTH( len, info.time_of_day );
		get_system_time_of_day( info.time_of_day );
		break;

	case SystemRangeStartInformation:
		SET_INFO_LENGTH( len, info.range_start );
		info.range_start.SystemRangeStart = (PVOID) 0x80000000;
		break;

	case SystemGlobalFlag:
		SET_INFO_LENGTH( len, info.global_flag );
		info.global_flag.GlobalFlag = 0;
		if (OptionTrace)
			info.global_flag.GlobalFlag |= FLG_SHOW_LDR_SNAPS | FLG_ENABLE_CSRDEBUG;
		break;

	case SystemKernelDebuggerInformation:
		SET_INFO_LENGTH( len, info.kernel_debugger_info );
		info.kernel_debugger_info.DebuggerEnabled = FALSE;
		info.kernel_debugger_info.DebuggerNotPresent = TRUE;
		break;

	case SystemPerformanceInformation:
		SET_INFO_LENGTH( len, info.performance_info );
		info.performance_info.AvailablePages = 0x80000; // 512Mb
		break;

	case SystemCrashDumpStateInformation:
		SET_INFO_LENGTH( len, info.crash_dump_info );
		info.crash_dump_info.CrashDumpSectionExists = 0;
		info.crash_dump_info.Unknown = 0;
		break;

	default:
		trace("SystemInformationClass = %d not handled\n", SystemInformationClass);
		r = STATUS_INVALID_INFO_CLASS;
	}

	r = CopyToUser( SystemInformation, &info, len );
	if (ReturnLength)
		r = CopyToUser( ReturnLength, &len, sizeof len );

	return r;
}

NTSTATUS NTAPI NtSetSystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength )
{
	trace("%d %p %lu\n", SystemInformationClass, SystemInformation, SystemInformationLength );
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtFlushInstructionCache(
	HANDLE Process,
	PVOID BaseAddress,
	SIZE_T NumberOfBytesToFlush )
{
	trace("%p %p %08lx\n", Process, BaseAddress, NumberOfBytesToFlush);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtDisplayString( PUNICODE_STRING String )
{
	unicode_string_t us;
	NTSTATUS r;

	r = us.copy_from_user( String );
	if (r < STATUS_SUCCESS)
		return r;

	trace("%pus\n", &us );

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtCreatePagingFile(
	PUNICODE_STRING FileName,
	PULARGE_INTEGER InitialSize,
	PULARGE_INTEGER MaximumSize,
	ULONG Reserved)
{
	unicode_string_t us;
	NTSTATUS r;

	r = us.copy_from_user( FileName );
	if (r < STATUS_SUCCESS)
		return r;

	ULARGE_INTEGER init_sz, max_sz;

	r = CopyFromUser( &init_sz, InitialSize, sizeof init_sz );
	if (r < STATUS_SUCCESS)
		return r;

	r = CopyFromUser( &max_sz, MaximumSize, sizeof max_sz );
	if (r < STATUS_SUCCESS)
		return r;

	trace("unimplemented - %pus %llu %llu %08lx\n",
		  &us, init_sz.QuadPart, max_sz.QuadPart, Reserved);

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI NtShutdownSystem(
	SHUTDOWN_ACTION Action)
{
	const char *action = 0;
	switch (Action)
	{
	case ShutdownNoReboot:
		action = "ShutdownNoReboot";
		break;
	case ShutdownReboot:
		action = "ShutdownReboot";
		break;
	case ShutdownPowerOff:
		action = "ShutdownPowerOff";
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}
	trace("%s\n", action);
	exit(1);
}

NTSTATUS NTAPI NtQueryPerformanceCounter(
	PLARGE_INTEGER PerformanceCount,
	PLARGE_INTEGER PerformanceFrequency)
{
	LARGE_INTEGER now = timeout_t::current_time();
	LARGE_INTEGER freq;
	NTSTATUS r;
	freq.QuadPart = 1000LL;
	r = CopyToUser( PerformanceCount, &now, sizeof now );
	if (r < STATUS_SUCCESS)
		return r;
	r = CopyToUser( PerformanceFrequency, &freq, sizeof freq );
	return r;
}

NTSTATUS NTAPI NtAllocateLocallyUniqueId(
	PLUID Luid)
{
	static LARGE_INTEGER id;
	LUID luid;
	luid.HighPart = id.QuadPart >> 32;
	luid.LowPart = id.QuadPart & 0xffffffffLL;
	NTSTATUS r = CopyToUser( Luid, &luid, sizeof luid );
	if (r == STATUS_SUCCESS)
		id.QuadPart++;
	return r;
}

NTSTATUS NTAPI NtQueryDebugFilterState(
	ULONG Component,
	ULONG Level)
{
	trace("%08lx %08lx\n", Component, Level);
	return STATUS_SUCCESS;
}
