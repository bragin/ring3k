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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
* Internal definitions (do not use these directly)
*/

enum __kdbp_debug_class
{
	__KDBP_DBCL_FIXME,
	__KDBP_DBCL_ERR,
	__KDBP_DBCL_WARN,
	__KDBP_DBCL_TRACE,

	__KDBP_DBCL_INIT = 7  /* lazy init flag */
};

struct __kdbp_debug_channel
{
	unsigned char flags;
	char name[15];
};

void DebugInit(void);
void DebugPrintf(const char *file, const char *func, int line, const char *fmt, ...) __attribute__((format (printf,4,5)));
void DumpMem(void *p, unsigned int len);
void Die(const char *fmt, ...) __attribute__((format (printf,1,2))) __attribute__((noreturn));
int dump_instruction(unsigned char *inst);
void print_wide_string( unsigned short *str, int len );
int DebugPrintfEx(enum __kdbp_debug_class cls, struct __kdbp_debug_channel *channel, const char *func, const char *format, ...);

extern int option_quiet;
extern int option_debug;
void DumpRegs(CONTEXT *ctx);

void Debugger( void );
void DebuggerBacktrace(PCONTEXT ctx);

#ifdef __cplusplus
}
#endif

#define kalloc( size ) _kalloc( __FILE__, __LINE__, (size) )
#define kfree( mem ) _kfree( __FILE__, __LINE__, (mem) )

#define __KDBG_GET_DEBUGGING_TRACE(dbch) ((dbch)->flags & (1 << __KDBP_DBCL_TRACE))
#define __KDBG_GET_DEBUGGING_WARN(dbch)  ((dbch)->flags & (1 << __KDBP_DBCL_WARN))
#define __KDBG_GET_DEBUGGING_FIXME(dbch) ((dbch)->flags & (1 << __KDBP_DBCL_FIXME))
#define __KDBG_GET_DEBUGGING_ERR(dbch)   ((dbch)->flags & (1 << __KDBP_DBCL_ERR))

#define __KDBG_GET_DEBUGGING(dbcl,dbch)  __KDBG_GET_DEBUGGING##dbcl(dbch)

#define __KDBG_IS_DEBUG_ON(dbcl,dbch) \
  (__KDBG_GET_DEBUGGING##dbcl(dbch) && (__KdbpDbgGetChannelFlags(dbch) & (1 << __KDBP_DBCL##dbcl)))

#define __KDBG_DPRINTF(dbcl,dbch) \
  do { if(__KDBG_GET_DEBUGGING(dbcl,(dbch))) { \
       struct __kdbp_debug_channel * const __dbch = (dbch); \
       const enum __kdbp_debug_class __dbcl = __KDBP_DBCL##dbcl; \
       __KDBG_DBG_LOG

#define __KDBG_DBG_LOG(args...) \
    DebugPrintfEx( __dbcl, __dbch, __FUNCTION__, args); } } while(0)

#define TRACE                 __KDBG_DPRINTF(_TRACE,__kdbp_dbch___default)
#define TRACE_(ch)            __KDBG_DPRINTF(_TRACE,&__kdbp_dbch_##ch)
#define TRACE_ON(ch)          __KDBG_IS_DEBUG_ON(_TRACE,&__kdbp_dbch_##ch)
#define WARN                  __KDBG_DPRINTF(_WARN,__kdbp_dbch___default)
#define WARN_(ch)             __KDBG_DPRINTF(_WARN,&__kdbp_dbch_##ch)
#define WARN_ON(ch)           __KDBG_IS_DEBUG_ON(_WARN,&__kdbp_dbch_##ch)
#define FIXME                 __KDBG_DPRINTF(_FIXME,__kdbp_dbch___default)
#define FIXME_(ch)            __KDBG_DPRINTF(_FIXME,&__kdbp_dbch_##ch)
#define FIXME_ON(ch)          __KDBG_IS_DEBUG_ON(_FIXME,&__kdbp_dbch_##ch)
#define ERR                   __KDBG_DPRINTF(_ERR,__kdbp_dbch___default)
#define ERR_(ch)              __KDBG_DPRINTF(_ERR,&__kdbp_dbch_##ch)
#define ERR_ON(ch)            __KDBG_IS_DEBUG_ON(_ERR,&__kdbp_dbch_##ch)

#define DECLARE_DEBUG_CHANNEL(ch) \
    static struct __kdbp_debug_channel __kdbp_dbch_##ch = { (unsigned char)~0, #ch }
#define DEFAULT_DEBUG_CHANNEL(ch) \
    static struct __kdbp_debug_channel __kdbp_dbch_##ch = { (unsigned char)~0, #ch }; \
    static struct __kdbp_debug_channel * const __kdbp_dbch___default = &__kdbp_dbch_##ch



#endif // _DEBUG_H_
