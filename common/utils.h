/* **********************************************************
 * Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; 
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _UTILS_H_
#define _UTILS_H_ 1

#include "hashtable.h"

#include <limits.h>

#ifdef WINDOWS
# define IF_WINDOWS(x) x
# define IF_WINDOWS_(x) x, 
# define _IF_WINDOWS(x) , x
# define IF_WINDOWS_ELSE(x,y) x
# define IF_LINUX(x)
# define IF_LINUX_ELSE(x,y) y
# define IF_LINUX_(x)
#else
# define IF_WINDOWS(x)
# define IF_WINDOWS_(x)
# define _IF_WINDOWS(x)
# define IF_WINDOWS_ELSE(x,y) y
# define IF_LINUX(x) x
# define IF_LINUX_ELSE(x,y) x
# define IF_LINUX_(x) x,
#endif

#ifdef X64
# define IF_X64(x) x
# define IF_X86_32(x) x
#else
# define IF_X64(x) 
# define IF_X86_32(x) x
#endif

#ifdef DEBUG
# define IF_DEBUG(x) x
# define _IF_DEBUG(x) , x
#else
# define IF_DEBUG(x)
# define _IF_DEBUG(x)
#endif

#ifdef VMX86_SERVER
# define IF_VMX86(x) x
#else
# define IF_VMX86(x) 
#endif

#ifdef USE_DRSYMS
# define IF_DRSYMS(x) x
# define IF_NOT_DRSYMS(x)
# define IF_DRSYMS_ELSE(x, y) x
#else
# define IF_DRSYMS(x) 
# define IF_NOT_DRSYMS(x) x
# define IF_DRSYMS_ELSE(x, y) y
#endif

#ifdef TOOL_DR_MEMORY
# define IF_DRMEM(x) x
# define IF_DRHEAP(x)
# define IF_DRMEM_ELSE(x, y) x
#else
# define IF_DRMEM(x) 
# define IF_DRHEAP(x) x
# define IF_DRMEM_ELSE(x, y) y
#endif

#define ALIGNED(x, alignment) ((((ptr_uint_t)x) & ((alignment)-1)) == 0)
#define ALIGN_BACKWARD(x, alignment) (((ptr_uint_t)x) & (~((alignment)-1)))
#define ALIGN_FORWARD(x, alignment) \
    ((((ptr_uint_t)x) + ((alignment)-1)) & (~((alignment)-1)))
#define ALIGN_MOD(addr, size, alignment) \
    ((((ptr_uint_t)addr)+(size)-1) & ((alignment)-1))
#define CROSSES_ALIGNMENT(addr, size, alignment) \
    (ALIGN_MOD(addr, size, alignment) < (size)-1)

#define TEST(mask, var) (((mask) & (var)) != 0)
#define TESTANY TEST
#define TESTALL(mask, var) (((mask) & (var)) == (mask))

#ifdef WINDOWS
# define inline __inline
# define INLINE_FORCED __forceinline
/* Use special C99 operator _Pragma to generate a pragma from a macro */
# if _MSC_VER <= 1200 /* FIXME: __pragma may work w/ vc6: then don't need #if */
#  define ACTUAL_PRAGMA(p) _Pragma ( #p )
# else
#   define ACTUAL_PRAGMA(p) __pragma ( p )
# endif
# define DO_NOT_OPTIMIZE ACTUAL_PRAGMA( optimize("g", off) )
# define END_DO_NOT_OPTIMIZE ACTUAL_PRAGMA( optimize("g", on) )
#else /* LINUX */
# define inline __inline__
# define INLINE_FORCED inline
# if 0 /* only available in gcc 4.4+ so not using: XXX: add HAVE_OPTIMIZE_ATTRIBUTE */
#   define DO_NOT_OPTIMIZE __attribute__((optimize("O0")))
# else
#   define DO_NOT_OPTIMIZE /* nothing */
# endif
# define END_DO_NOT_OPTIMIZE /* nothing */
#endif
#define INLINE_ONCE inline

#ifdef LINUX
# define DIRSEP '/'
# define NL "\n"
#else
/* we now use mixed paths with drive letter but forward slashes */
# define DIRSEP '/'
# define NL "\r\n"
#endif

#define MAX_INSTR_SIZE 17

#define sscanf  DO_NOT_USE_sscanf_directly_see_issue_344

#define INVALID_THREAD_ID 0

/* globals that affect NOTIFY* and *LOG* macros */
extern bool op_print_stderr;
extern uint op_verbose_level;
extern bool op_pause_at_assert;
extern bool op_pause_via_loop;
extern bool op_ignore_asserts;
extern file_t f_global;
#ifdef USE_DRSYMS
extern file_t f_results;
#endif

/* Workarounds for i#261 where DR can't write to cmd console.
 *
 * 1) Use drsyms, which has already loaded a private kernel32, to write to the
 * console.  This could be unsafe to do in the middle of app operations but our
 * notifications are usually at startup and shutdown only.  Writing to the
 * console involves sending a message to csrss which we hope we can treat like a
 * system call wrt atomicity so long as the message crafting via private
 * kernel32.dll is safe.
 *
 * 2) For drag-and-drop where the cmd window will disappear, we use
 * msgboxes (rather than "wait for keypress") for error messages,
 * which are good to highlight anyway (and thus we do not try to
 * distinguish existing cmd from new cmd: but we do not use msgbox for
 * rxvt or xterm or other shells since we assume that's a savvy user).
 * We only pop up msgbox for NOTIFY_ERROR() to avoid too many
 * msgboxes, esp for things like options list (for that we'd want to
 * bundle into one buffer anyway: but that exceeds dr_messagebox's
 * buffer size).
 */
#ifdef USE_DRSYMS
# define IN_CMD (drsym_using_console())
# define USE_MSGBOX (op_print_stderr && IN_CMD)
/* drsym_write_to_console works on both cmd and cygwin rxvt/xterm */
# define PRINT_CONSOLE(...) drsym_write_to_console(__VA_ARGS__)
#else
/* For non-USE_DRSYMS Windows we just don't support cmd: unfortunately this
 * includes cygwin in cmd.  With PR 561181 we'll get cygwin into USE_DRSYMS.
 */
# define USE_MSGBOX (false)
# define PRINT_CONSOLE(...) dr_fprintf(STDERR, __VA_ARGS__)
#endif

/* for notifying user 
 * FIXME: should add messagebox, controlled by option
 */
#ifdef TOOL_DR_MEMORY
# define PREFIX ":::Dr.Memory::: "
#else
# define PREFIX ":::Dr.Heapstat::: "
#endif
#define NOTIFY(...) do { \
    ELOG(0, __VA_ARGS__); \
    if (op_print_stderr) { \
        PRINT_CONSOLE("%s", PREFIX); \
        PRINT_CONSOLE(__VA_ARGS__); \
    }                                         \
} while (0)
#define NOTIFY_ERROR(...) do { \
    IF_NOT_DRSYMS(ELOG(0, "FATAL ERROR: ")); \
    NOTIFY(__VA_ARGS__); \
    IF_DRSYMS(ELOGF(0, f_results, __VA_ARGS__)); \
    if (USE_MSGBOX) \
        IF_WINDOWS(dr_messagebox(__VA_ARGS__)); \
} while (0)
#define NOTIFY_COND(cond, f, ...) do { \
    ELOGF(0, f, __VA_ARGS__); \
    if ((cond) && op_print_stderr) { \
        PRINT_CONSOLE("%s", PREFIX); \
        PRINT_CONSOLE(__VA_ARGS__); \
    }                                         \
} while (0)
#define NOTIFY_NO_PREFIX(...) do { \
    ELOG(0, __VA_ARGS__); \
    if (op_print_stderr) { \
        PRINT_CONSOLE(__VA_ARGS__); \
    }                                         \
} while (0)

/* for warning/error reporting to logfile */
#define LOGFILE(pt) ((pt) == NULL ? f_global : (pt)->f)
#define LOGFILE_LOOKUP() \
    LOGFILE((dr_get_current_drcontext() == NULL) ? NULL : \
            (per_thread_t *)dr_get_tls_field(dr_get_current_drcontext()))
/* we require a ,fmt arg but C99 requires one+ argument which we just strip */
#define ELOGF(level, f, ...) do {   \
    if (op_verbose_level >= (level) && (f) != INVALID_FILE) \
        dr_fprintf(f, __VA_ARGS__); \
} while (0)
#define ELOGPT(level, pt, ...) \
    ELOGF(level, LOGFILE(pt), __VA_ARGS__)
#define ELOG(level, ...) \
    ELOGPT(level, (dr_get_current_drcontext() == NULL) ? NULL : \
           (per_thread_t *)dr_get_tls_field(dr_get_current_drcontext()), \
           __VA_ARGS__)
/* DR's fprintf has a size limit */
#define ELOG_LARGE_F(level, f, s) do {   \
    if (op_verbose_level >= (level) && (f) != INVALID_FILE) \
        dr_write_file(f, s, strlen(s)); \
} while (0)
#define ELOG_LARGE_PT(level, pt, s) \
    ELOG_LARGE_F(level, LOGFILE(pt), s)
#define ELOG_LARGE(level, s) \
    ELOG_LARGE_PT(level, (dr_get_current_drcontext() == NULL) ? NULL : \
                  (per_thread_t *)dr_get_tls_field(dr_get_current_drcontext()), s)

#define WARN(...) ELOGF(0, f_global, __VA_ARGS__)

/* PR 427074: asserts should go to the log and not just stderr.
 * Since we don't have a vsnprintf() (i#168) we can't make this an
 * expression (w/o duplicating NOTIFY as an expression) but we only
 * use it as a statement anyway.
 */
#ifdef DEBUG
# define ASSERT(x, msg) do { \
    if (!(x)) { \
        NOTIFY_ERROR("ASSERT FAILURE (thread %d): %s:%d: %s (%s)",  \
                     (dr_get_current_drcontext() == NULL ? 0 :      \
                      dr_get_thread_id(dr_get_current_drcontext())),\
                     __FILE__,  __LINE__, #x, msg); \
        if (!op_ignore_asserts) drmemory_abort(); \
    } \
} while (0)
# define ASSERT_NOT_TESTED(msg) do { \
    static int assert_not_tested_printed = 0; \
    if (!assert_not_tested_printed) { \
        /* This singleton-like implementation has a data race. \
         * However, in the worst case this will result in printing the message \
         * twice which isn't a big deal \
         */ \
        assert_not_tested_printed = 1; \
        NOTIFY("Not tested - %s @%s:%d\n", msg, __FILE__, __LINE__); \
    } \
} while (0)
#else
# define ASSERT(x, msg) /* nothing */
# define ASSERT_NOT_TESTED(msg) /* nothing */
#endif

#ifdef DEBUG
# define LOGF ELOGF
# define LOGPT ELOGPT
# define LOG ELOG
# define LOG_LARGE_F ELOG_LARGE_F
# define LOG_LARGE_PT ELOG_LARGE_PT
# define LOG_LARGE ELOG_LARGE
# define DOLOG(level, stmt)  do {   \
    if (op_verbose_level >= (level)) \
        stmt                        \
} while (0)
# define DODEBUG(stmt)  do {   \
    stmt                       \
} while (0)
#else
# define LOGF(level, pt, fmt, ...) /* nothing */
# define LOGPT(level, pt, fmt, ...) /* nothing */
# define LOG(level, fmt, ...) /* nothing */
# define LOG_LARGE_F(level, pt, fmt, ...) /* nothing */
# define LOG_LARGE_PT(level, pt, fmt, ...) /* nothing */
# define LOG_LARGE(level, fmt, ...) /* nothing */
# define DOLOG(level, stmt) /* nothing */
# define DODEBUG(stmt) /* nothing */
#endif

/* For printing to a buffer.
 * Usage: have a size_t variable "sofar" that counts the chars used so far.
 * We take in "len" to avoid repeated locals, which some compilers won't
 * combine (grrr: xref some PR).
 * If we had i#168 dr_vsnprintf this wouldn't have to be a macro.
 */
#define BUFPRINT_NO_ASSERT(buf, bufsz, sofar, len, ...) do { \
    len = dr_snprintf((buf)+(sofar), (bufsz)-(sofar), __VA_ARGS__); \
    sofar += (len < 0 ? 0 : len); \
    /* be paranoid: though usually many calls in a row and could delay until end */ \
    (buf)[(bufsz)-1] = '\0';                                 \
} while (0)

#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    BUFPRINT_NO_ASSERT(buf, bufsz, sofar, len, __VA_ARGS__); \
    ASSERT((bufsz) > (sofar), "buffer size miscalculation"); \
} while (0)

/* Buffered file write marcos, to improve performance.  See PR 551841. */
#define FLUSH_BUFFER(fd, buf, sofar) do { \
    if ((sofar) > 0) \
        dr_write_file(fd, buf, sofar); \
} while (0)

#define BUFFERED_WRITE(fd, buf, bufsz, sofar, len, ...) do { \
    int old_sofar = sofar; \
    BUFPRINT_NO_ASSERT(buf, bufsz, sofar, len, __VA_ARGS__); \
 \
    /* Did the buffer overflow?  If so restore the buffer to before the  \
     * snprintf, flush it to the file and reprint to the buffer. \
     */ \
    if ((sofar) >= (bufsz)) { \
        (buf)[old_sofar] = '\0';  /* not needed, strictly speaking; be safe */ \
        FLUSH_BUFFER(fd, buf, old_sofar); \
        (sofar) = 0; \
        BUFPRINT_NO_ASSERT(buf, bufsz, sofar, len, __VA_ARGS__); \
        ASSERT((bufsz) > (sofar), "single write can't overflow buffer"); \
    } \
} while (0)

#ifdef STATISTICS
# define STATS_INC(stat) ATOMIC_INC32(stat)
# define STATS_DEC(stat) ATOMIC_DEC32(stat)
# define STATS_ADD(stat, val) ATOMIC_ADD32(stat, val)
#else
# define STATS_INC(stat) /* nothing */
# define STATS_DEC(stat) /* nothing */
# define STATS_ADD(stat, val) /* nothing */
#endif

#define PRE instrlist_meta_preinsert
#define PREXL8 instrlist_preinsert

#define EXPANDSTR(x) #x
#define STRINGIFY(x) EXPANDSTR(x)

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf)    (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf)  BUFFER_LAST_ELEMENT(buf) = 0

#define DWORD2BYTE(v, n) (((v) & (0xff << 8*(n))) >> 8*(n))

#ifdef X64
# define POINTER_MAX ULLONG_MAX
#else
# define POINTER_MAX UINT_MAX
#endif

/* C standard has pointer overflow as undefined so cast to unsigned (i#302) */
#define POINTER_OVERFLOW_ON_ADD(ptr, add) \
    (((ptr_uint_t)(ptr)) + (add) < ((ptr_uint_t)(ptr)))
#define POINTER_UNDERFLOW_ON_SUB(ptr, sub) \
    (((ptr_uint_t)(ptr)) - (sub) > ((ptr_uint_t)(ptr)))

#ifdef LINUX
# ifdef X64
#  define ASM_XAX "rax"
#  define ASM_XSP "rsp"
#  define ASM_SEG "gs"
#  define ASM_SYSARG1 "rdi"
#  define ASM_SYSARG2 "rsi"
#  define ASM_SYSARG3 "rdx"
#  define ASM_SYSARG4 "r10"
#  define ASM_SYSARG5 "r8"
#  define ASM_SYSARG6 "r9"
# else
#  define ASM_XAX "eax"
#  define ASM_XSP "esp"
#  define ASM_SEG "fs"
#  define ASM_SYSARG1 "ebx"
#  define ASM_SYSARG2 "ecx"
#  define ASM_SYSARG3 "edx"
#  define ASM_SYSARG4 "esi"
#  define ASM_SYSARG5 "edi"
#  define ASM_SYSARG6 "ebp"
# endif
#endif

#ifdef LINUX
# define ATOMIC_INC32(x) __asm__ __volatile__("lock incl %0" : "=m" (x) : : "memory")
# define ATOMIC_DEC32(x) __asm__ __volatile__("lock decl %0" : "=m" (x) : : "memory")
# define ATOMIC_ADD32(x, val) \
    __asm__ __volatile__("lock addl %1, %0" : "=m" (x) : "r" (val) : "memory")

static inline int
atomic_add32_return_sum(volatile int *x, int val)
{
    int cur;
    __asm__ __volatile__("lock xaddl %1, %0" : "=m" (*x), "=r" (cur)
                         : "1" (val) : "memory");
    return (cur + val);
}
#else
# define ATOMIC_INC32(x) _InterlockedIncrement((volatile LONG *)&(x))
# define ATOMIC_DEC32(x) _InterlockedDecrement((volatile LONG *)&(x))
# define ATOMIC_ADD32(x, val) _InterlockedExchangeAdd((volatile LONG *)&(x), val)

static inline int
atomic_add32_return_sum(volatile int *x, int val)
{
    return (ATOMIC_ADD32(*x, val) + val);
}
#endif

/* racy: should be used only for diagnostics */
#define DO_ONCE(stmt) {     \
    static int do_once = 0; \
    if (!do_once) {         \
        do_once = 1;        \
        stmt;               \
    }                       \
}

#define MIN(x,y) ((x) < (y) ? (x) : (y))

/***************************************************************************
 * UTILITY ROUTINES
 */

void *
memset(void *dst, int val, size_t size);

void
wait_for_user(const char *message);

void
drmemory_abort(void);

bool
safe_read(void *base, size_t size, void *out_buf);

/* if returns false, calls instr_free() on inst first */
bool
safe_decode(void *drcontext, app_pc pc, instr_t *inst, app_pc *next_pc /*OPTIONAL OUT*/);

#ifdef USE_DRSYMS
app_pc
lookup_symbol(const module_data_t *mod, const char *symname);

app_pc
lookup_internal_symbol(const module_data_t *mod, const char *symname);

/* iterates over symbols matching modname!sym_pattern until
 * callback returns false
 */
bool
lookup_all_symbols(const module_data_t *mod, const char *sym_pattern,
                   bool (*callback)(const char *name, size_t modoffs, void *data),
                   void *data);
#endif

#ifdef DEBUG
void
print_mcontext(file_t f, dr_mcontext_t *mc);
#endif

#if defined(WINDOWS) && defined (USE_DRSYMS)
# ifdef DEBUG
/* check that peb isolation is consistently applied (xref i#324) */
bool
using_private_peb(void);
# endif

HANDLE
get_private_heap_handle(void);
#endif /* WINDOWS && USE_DRSYMS */

void
hashtable_delete_with_stats(hashtable_t *table, const char *name);

/***************************************************************************
 * WINDOWS SYSCALLS
 */

#ifdef WINDOWS
# include "windefs.h"

TEB *
get_TEB(void);

TEB *
get_TEB_from_handle(HANDLE h);

thread_id_t
get_tid_from_handle(HANDLE h);

TEB *
get_TEB_from_tid(thread_id_t tid);

PEB *
get_app_PEB(void);

bool
is_current_process(HANDLE h);

bool
is_wow64_process(void);

bool
opc_is_in_syscall_wrapper(uint opc);

int
syscall_num(void *drcontext, byte *entry);

int
sysnum_from_name(void *drcontext, const module_data_t *info, const char *name);

bool
running_on_Win7_or_later(void);

bool
running_on_Vista_or_later(void);

dr_os_version_t
get_windows_version(void);

app_pc
get_highest_user_address(void);
#endif /* WINDOWS */

/***************************************************************************
 * LINUX SYSCALLS
 */

#ifdef LINUX
ptr_int_t
raw_syscall_1arg(uint sysnum, ptr_int_t arg);

ptr_int_t
raw_syscall_5args(uint sysnum, ptr_int_t arg1, ptr_int_t arg2, ptr_int_t arg3,
                  ptr_int_t arg4, ptr_int_t arg5);
#endif

/***************************************************************************
 * HEAP WITH STATS
 */

/* PR 423757: heap accounting */
typedef enum {
    HEAPSTAT_SHADOW,
    HEAPSTAT_PERBB,
#ifdef TOOL_DR_HEAPSTAT
    HEAPSTAT_SNAPSHOT,
    HEAPSTAT_STALENESS,
#endif
    HEAPSTAT_CALLSTACK,
    HEAPSTAT_HASHTABLE,
    HEAPSTAT_GENCODE,
    HEAPSTAT_RBTREE,
    HEAPSTAT_REPORT,
    HEAPSTAT_MISC,
    /* when you add here, add to heapstat_names in utils.c */
    HEAPSTAT_NUMTYPES,
} heapstat_t;

/* wrappers around dr_ versions to track heap accounting stats */
void *
global_alloc(size_t size, heapstat_t type);

void
global_free(void *p, size_t size, heapstat_t type);

void *
thread_alloc(void *drcontext, size_t size, heapstat_t type);

void
thread_free(void *drcontext, void *p, size_t size, heapstat_t type);

void *
nonheap_alloc(size_t size, uint prot, heapstat_t type);

void
nonheap_free(void *p, size_t size, heapstat_t type);

void
heap_dump_stats(file_t f);

#define dr_global_alloc DO_NOT_USE_use_global_alloc
#define dr_global_free  DO_NOT_USE_use_global_free
#define dr_thread_alloc DO_NOT_USE_use_thread_alloc
#define dr_thread_free  DO_NOT_USE_use_thread_free
#define dr_nonheap_alloc DO_NOT_USE_use_nonheap_alloc
#define dr_nonheap_free  DO_NOT_USE_use_nonheap_free

char *
drmem_strdup(const char *src, heapstat_t type);

char *
drmem_strndup(const char *src, size_t max, heapstat_t type);

/***************************************************************************
 * OPTIONS
 */

#define MAX_OPTION_LEN MAXIMUM_PATH

const char *
get_option_word(const char *s, char buf[MAX_OPTION_LEN]);

/***************************************************************************
 * HASHTABLE
 *
 * hashtable was moved and generalized so we need to initialize it
 */

void
utils_init(void);

void
utils_exit(void);

#endif /* _UTILS_H_ */
