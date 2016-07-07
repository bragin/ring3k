/* INCLUDES ******************************************************************/

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "ntcall.h"
#include "ntwin32.h"
#include "mem.h"
#include "section.h"
#include "debug.h"
#include "win32mgr.h"

DEFAULT_DEBUG_CHANNEL(ntgdi);

/* GLOBALS *******************************************************************/

// shared across all processes (in a window station)
SECTION *gdi_ht_section;
void *GdiHandleTable = 0;

gdishm_tracer GdishmTrace;
NTGDISHM_TRACER ntgdishm_trace;

SECTION *GDI_OBJECT::g_GdiSection;
BYTE *GDI_OBJECT::g_GdiSharedMemory;
ALLOCATION_BITMAP* GDI_OBJECT::g_GdiSharedBitmap;

/* INTERNAL FUNCTIONS ********************************************************/

bool NTGDISHM_TRACER::Enabled() const
{
	return TraceIsEnabled("gdishm");
}

void NTGDISHM_TRACER::OnAccess(MBLOCK *mb, BYTE *address, ULONG eip)
{
	ULONG ofs = address - mb->GetBaseAddress();
	if (ofs < MAX_GDI_HANDLE * 0x10)
	{
		char unk[16];
		const char *field = "unknown";
		switch (ofs & 15)
		{
#define gdifield(ofs,x) case ofs: field = #x; break;
			gdifield(0, kernel_info)
				gdifield(4, ProcessId)
				gdifield(6, Count)
				gdifield(8, Upper)
				gdifield(10, Type)
				gdifield(11, Type_Hi)
				gdifield(12, user_info)
#undef gdifield
default:
	field = unk;
	sprintf(unk, "unk_%04lx", ofs);
		}
		fprintf(stderr, "%lx.%lx: accessed gdi handle[%04lx]:%s from %08lx\n",
			Current->Process->Id, Current->GetID(), ofs >> 4, field, eip);
	}
	else
		fprintf(stderr, "%lx.%lx: accessed gshm[%04lx] from %08lx\n",
		Current->Process->Id, Current->GetID(), ofs, eip);
}

static inline ULONG get_gdi_type_size(ULONG type)
{
	switch (type)
	{
	case GDI_OBJECT_DC:
		return sizeof(GDI_DEVICE_CONTEXT_SHARED);
	default:
		return 0;
	}
}

ULONG object_from_memory(BYTE *address)
{
	GDI_HANDLE_TABLE_ENTRY *table = (GDI_HANDLE_TABLE_ENTRY*)GdiHandleTable;
	for (ULONG i = 0; i<MAX_GDI_HANDLE; i++)
	{
		ULONG sz = get_gdi_type_size(table[i].Type);
		if (!sz)
			continue;
		BYTE* ptr = (BYTE*)table[i].user_info;
		if (ptr > address)
			continue;
		if ((ptr + sz) > address)
			return i;
	}
	return 0;
}

void gdishm_tracer::OnAccess(MBLOCK *mb, BYTE *address, ULONG eip)
{
	ULONG n = object_from_memory(address);
	if (n)
	{
		GDI_HANDLE_TABLE_ENTRY *table = (GDI_HANDLE_TABLE_ENTRY*)GdiHandleTable;
		ULONG ofs = address - (BYTE*)table[n].user_info;
		fprintf(stderr, "%lx.%lx: accessed gdishm[%04lx][%04lx] from %08lx\n",
			Current->Process->Id, Current->GetID(), n, ofs, eip);
	}
	else
	{
		ULONG ofs = address - mb->GetBaseAddress();
		fprintf(stderr, "%lx.%lx: accessed gdishm[%04lx] from %08lx\n",
			Current->Process->Id, Current->GetID(), ofs, eip);
	}
}

bool gdishm_tracer::Enabled() const
{
	return TraceIsEnabled("gdishm");
}

GDI_OBJECT::GDI_OBJECT() :
Handle(0),
RefCount(0)
{
}

BOOL GDI_OBJECT::Release()
{
	if (RefCount)
		return FALSE;
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry(Handle);
	assert(entry);
	assert(reinterpret_cast<GDI_OBJECT*>(entry->kernel_info) == this);
	memset(entry, 0, sizeof *entry);
	delete this;
	return TRUE;
}

int FindFreeGdiHandle(void)
{
	GDI_HANDLE_TABLE_ENTRY *table = (GDI_HANDLE_TABLE_ENTRY*)GdiHandleTable;

	for (int i = 0; i<MAX_GDI_HANDLE; i++)
	{
		if (!table[i].ProcessId)
			return i;
	}
	return -1;
}

HGDIOBJ AllocGdiHandle(BOOL stock, ULONG type, void *user_info, GDI_OBJECT* obj)
{
	int index = FindFreeGdiHandle();
	if (index < 0)
		return 0;

	// strangeness: handle indicates pen, but it's a brush in the table
	ULONG reported_type = type;
	if (type == GDI_OBJECT_PEN)
		type = GDI_OBJECT_BRUSH;

	GDI_HANDLE_TABLE_ENTRY *table = (GDI_HANDLE_TABLE_ENTRY*)GdiHandleTable;
	table[index].ProcessId = Current->Process->Id;
	table[index].Type = type;
	HGDIOBJ handle = GDI_HANDLE_makeHGDIOBJ(0, stock, reported_type, index);
	table[index].Count = 0;
	table[index].Upper = (ULONG)handle >> 16;
	table[index].user_info = user_info;
	table[index].kernel_info = reinterpret_cast<void*>(obj);

	return handle;
}

HGDIOBJ GDI_OBJECT::Alloc(BOOL stock, ULONG type)
{
	GDI_OBJECT *obj = new GDI_OBJECT();
	HGDIOBJ handle = AllocGdiHandle(stock, type, 0, obj);
	if (handle)
		obj->Handle = handle;
	else
		delete obj;
	return obj->Handle;
}

void GDI_OBJECT::InitGdiSharedMem()
{
	NTSTATUS r;
	int dc_shared_memory_size = 0x10000;

	if (!g_GdiSharedMemory)
	{
		LARGE_INTEGER sz;
		sz.QuadPart = dc_shared_memory_size;
		r = CreateSection(&g_GdiSection, NULL, &sz, SEC_COMMIT, PAGE_READWRITE);
		assert(r >= STATUS_SUCCESS);

		g_GdiSharedMemory = (BYTE*)g_GdiSection->GetKernelAddress();

		assert(g_GdiSharedBitmap == NULL);
		g_GdiSharedBitmap = new ALLOCATION_BITMAP;
		g_GdiSharedBitmap->SetArea(g_GdiSharedMemory, dc_shared_memory_size);
	}

	BYTE*& dc_shared_mem = Current->Process->Win32kInfo->DcSharedMem;
	if (!dc_shared_mem)
	{
		r = g_GdiSection->Mapit(Current->Process->Vm, dc_shared_mem, 0, MEM_COMMIT, PAGE_READWRITE);
		if (r < STATUS_SUCCESS)
		{
			ERR("failed to map shared memory\n");
			assert(0);
		}

		Current->Process->Vm->SetTracer(dc_shared_mem, GdishmTrace);
	}
}

BYTE* GDI_OBJECT::GetSharedMem() const
{
	return UserToKernel(GetUserSharedMem());
}

BYTE* GDI_OBJECT::GetUserSharedMem() const
{
	GDI_HANDLE_TABLE_ENTRY *entry = GetHandleTableEntry(Handle);
	assert(entry != NULL);
	return (BYTE*)entry->user_info;
}

BYTE *GDI_OBJECT::AllocGdiSharedMemory(size_t len, BYTE** kernel_shm)
{
	InitGdiSharedMem();
	return g_GdiSharedBitmap->Alloc(len);
}

void GDI_OBJECT::FreeGdiSharedMemory(BYTE *shm)
{
	g_GdiSharedBitmap->Free(shm);
}

GDI_HANDLE_TABLE_ENTRY *GetHandleTableEntry(HGDIOBJ handle)
{
	GDI_HANDLE_TABLE_ENTRY *table = (GDI_HANDLE_TABLE_ENTRY*)GdiHandleTable;
	ULONG index = (ULONG)handle & 0xffff;
	ULONG upper = (ULONG)handle >> 16;
	if (index >= MAX_GDI_HANDLE)
		return 0;

	if (upper != table[index].Upper)
		return 0;
	return &table[index];
}

HGDIOBJ AllocGdiObject(BOOL stock, ULONG type)
{
	return GDI_OBJECT::Alloc(stock, type);
}

const char *GetObjectTypeName(HGDIOBJ object)
{
	switch (GDI_HANDLE_GET_TYPE(object))
	{
	case GDI_OBJECT_BRUSH:
		return "brush";
	case GDI_OBJECT_PEN:
		return "pen";
	case GDI_OBJECT_PALETTE:
		return "palette";
	case GDI_OBJECT_FONT:
		return "font";
	case GDI_OBJECT_BITMAP:
		return "bitmap";
	}
	return "unknown";
}
