/*
 * Win32 shared GDI Handle information between gdi32/win32k
 */

#pragma once

/* DEFINES *******************************************************************/

/*GDI object types */

// from FengYuan's Windows Graphics Programming Section 3.2, page 144
#define GDI_OBJECT_DC            0x01
#define GDI_OBJECT_REGION        0x04
#define GDI_OBJECT_BITMAP        0x05
#define GDI_OBJECT_CLIOBJ        0x06
#define GDI_OBJECT_PATH          0x07
#define GDI_OBJECT_PALETTE       0x08
#define GDI_OBJECT_COLORSPACE    0x09
#define GDI_OBJECT_FONT          0x0a
#define GDI_OBJECT_BRUSH         0x10
#define GDI_OBJECT_ENUMFONT      0x16
#define GDI_OBJECT_DRIVEROBJ     0x1C

/* Following object types are derived types from the above base types
use 0x001f0000 as mask to get the base type */
#define GDI_OBJECT_EMF           0x21

#define GDI_OBJECT_METAFILE      0x26
#define GDI_OBJECT_ENHMETAFILE   0x46
#define GDI_OBJECT_PEN           0x30
#define GDI_OBJECT_EXTPEN        0x50
#define GDI_OBJECT_METADC        0x66

/* GDI handles defines */
/* GDI handle table can hold 0x10000 handles */
//#define GDI_HANDLE_COUNT 0x10000
#define MAX_GDI_HANDLE 0x4000

// In ReactOS it is this way
//#define GDI_HANDLE_INDEX_MASK (GDI_HANDLE_COUNT - 1)
//#define GDI_HANDLE_TYPE_MASK  0x007f0000

#define GDI_HANDLE_INDEX_MASK 0x3fff
#define GDI_HANDLE_TYPE_MASK  0x007f

#define GDI_ENTRY_UPPER_SHIFT 16

/* GDI handles macros/inline functions */
static inline ULONG GDI_HANDLE_GET_TYPE(HGDIOBJ handle)
{
	return (((ULONG)handle) >> 16) & GDI_HANDLE_TYPE_MASK;
}

static inline ULONG GDI_HANDLE_GET_INDEX(HANDLE handle)
{
	return (((ULONG)handle) & GDI_HANDLE_INDEX_MASK);
}

static inline ULONG GDI_HANDLE_GET_TOP(HANDLE handle)
{
	return (((ULONG)handle) >> 24) & 0xff;
}

static inline ULONG GDI_HANDLE_GET_UPPER(HANDLE handle)
{
	return (((ULONG)handle) >> 16);
}

static inline HGDIOBJ GDI_HANDLE_makeHGDIOBJ(
	ULONG Top,
	BOOLEAN Stock,
	ULONG ObjectType,
	ULONG Index)
{
	return (HGDIOBJ)(((Top & 0xff) << 24) | ((Stock & 1) << 23) |
		((ObjectType & 0x7f) << 16) | (Index & 0x3fff));
}


/* TYPES *********************************************************************/

typedef struct _GDI_HANDLE_TABLE_ENTRY {
	void *kernel_info;
	USHORT ProcessId;
	USHORT Count;
	USHORT Upper;
	USHORT Type;
	void *user_info;
} GDI_HANDLE_TABLE_ENTRY;
 