#pragma once

class GDI_OBJECT
{
protected:
	HGDIOBJ Handle;
	ULONG RefCount;

	static SECTION *g_GdiSection;
	static BYTE *g_GdiSharedMemory;
	static ALLOCATION_BITMAP* g_GdiSharedBitmap;

	static void InitGdiSharedMem();
	static BYTE *AllocGdiSharedMemory(size_t len, BYTE** kernel_shm = NULL);
	static void FreeGdiSharedMemory(BYTE* ptr);
protected:
	GDI_OBJECT();
public:
	HGDIOBJ GetHandle()
	{
		return Handle;
	}
	virtual ~GDI_OBJECT() {};
	virtual BOOL Release();
	void Select()
	{
		RefCount++;
	}
	void Deselect()
	{
		RefCount--;
	}
	static HGDIOBJ Alloc(BOOL stock, ULONG type);
	BYTE *GetSharedMem() const;
	template<typename T> static T* KernelToUser(T* kernel_ptr)
	{
		ULONG ofs = (BYTE*)kernel_ptr - (BYTE*)g_GdiSharedMemory;
		return (T*)(Current->Process->Win32kInfo->DcSharedMem + ofs);
	}
	template<typename T> static T* UserToKernel(T* user_ptr)
	{
		ULONG ofs = (BYTE*)user_ptr - (BYTE*)Current->Process->Win32kInfo->DcSharedMem;
		return (T*)(g_GdiSharedMemory + ofs);
	}
	BYTE *GetUserSharedMem() const;
};

// Tracers
class NTGDISHM_TRACER : public BLOCK_TRACER
{
public:
	virtual void OnAccess(MBLOCK *mb, BYTE *address, ULONG eip);
	virtual bool Enabled() const;
};

class gdishm_tracer : public BLOCK_TRACER
{
public:
	virtual void OnAccess(MBLOCK *mb, BYTE *address, ULONG eip);
	virtual bool Enabled() const;
};

