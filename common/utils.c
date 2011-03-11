/* **********************************************************
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

#ifdef WINDOWS
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include "dr_api.h"
#include "per_thread.h"
#include "utils.h"
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif
#ifdef WINDOWS
# include "windefs.h"
#else
# include <string.h>
#endif
#include <stddef.h> /* for offsetof */

/* globals that affect NOTIFY* and *LOG* macros */
bool op_print_stderr = true;
uint op_verbose_level;
bool op_pause_at_assert;
bool op_pause_via_loop;
bool op_ignore_asserts;
file_t f_global = INVALID_FILE;

#if defined(DEBUG) && defined(WINDOWS)
static PEB *orig_peb;
#endif

/***************************************************************************
 * UTILITIES
 */

/* FIXME: VC8 uses intrinsic memset yet has it call out, so /nodefaultlib
 * gets a link error missing _memset.  This does not help, nor does /Oi:
 *   #pragma intrinsic ( memset)
 * So have to provide our own memset:
 * But with /O2 it actually uses the intrinsic.
 */
#ifndef NDEBUG /* cmake Release build type */
void *
memset(void *dst, int val, size_t size)
{
    register unsigned char *ptr = (unsigned char *) dst;
    while (size-- > 0)
        *ptr++ = val;
    return dst;
}
#endif

void
wait_for_user(const char *message)
{
#ifdef WINDOWS
    dr_messagebox(message);
#else
    if (op_pause_via_loop) {
        /* PR 406725: on Linux, infinite loop rather than waiting for stdin */
        bool forever = true; /* make it easy to break out in gdb */
        dr_fprintf(STDERR, "%s\n", message);
        dr_fprintf(STDERR, "<in infinite loop>\n");
        while (forever) {
            dr_thread_yield();
        }
    } else {
        char keypress;
        dr_fprintf(STDERR, "%s\n", message);
        dr_fprintf(STDERR, "<press enter to continue>\n");
        dr_read_file(stdin->_fileno, &keypress, sizeof(keypress));
    }
#endif
}

void
drmemory_abort(void)
{
    if (op_pause_at_assert)
        wait_for_user("paused at assert");
    dr_abort();
}

bool
safe_read(void *base, size_t size, void *out_buf)
{
    /* DR now provides dr_safe_read so we don't need to call
     * NtReadVirtualMemory anymore; plus this works on Linux too.
     */
#ifdef WINDOWS
    /* For all of our uses, a failure is rare, so we do not want
     * to pay the cost of the syscall (i#265).
     * Xref the same problem with leak_safe_read_heap (PR 570839).
     * XXX: perf: have caller pass in drcontext
     */
    bool res = true;
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        memcpy(out_buf, base, size);
    }, { /* EXCEPT */
        res = false;
    });
    return res;
#else
    /* dr_safe_read() uses try/except */
    size_t bytes_read = 0;
    return (dr_safe_read(base, size, out_buf, &bytes_read) &&
            bytes_read == size);
#endif
}

/* if returns false, calls instr_free() on inst first */
bool
safe_decode(void *drcontext, app_pc pc, instr_t *inst, app_pc *next_pc /*OPTIONAL OUT*/)
{
    app_pc nxt;
    DR_TRY_EXCEPT(drcontext, {
        nxt = decode(drcontext, pc, inst);
    }, { /* EXCEPT */
        /* in case decode filled something in before crashing */
        instr_free(drcontext, inst);
        return false;
    });
    if (next_pc != NULL)
        *next_pc = nxt;
    return true;
}

#ifdef USE_DRSYMS
/* default cb used when we want first match */
static bool
search_syms_cb(const char *name, size_t modoffs, void *data)
{
    size_t *ans = (size_t *) data;
    LOG(3, "sym lookup cb: %s @ offs "PIFX"\n", name, modoffs);
    ASSERT(ans != NULL, "invalid param");
    *ans = modoffs;
    return false; /* stop iterating: we want first match */
}

static app_pc
lookup_symbol_common(const module_data_t *mod, const char *sym_pattern,
                     bool full, drsym_enumerate_cb callback, void *data)
{
    /* We have to specify the module via "modname!symname".
     * We must use the same modname as in full_path.
     */
# define MAX_SYM_WITH_MOD_LEN 256
    char sym_with_mod[MAX_SYM_WITH_MOD_LEN];
    size_t modoffs;
    drsym_error_t symres;
    char *fname = NULL, *c;

    if (mod->full_path == NULL)
        return NULL;

    for (c = mod->full_path; *c != '\0'; c++) {
        if (*c == DIRSEP IF_WINDOWS(|| *c == '\\'))
            fname = c + 1;
    }
    ASSERT(fname != NULL, "unable to get fname for module");
    if (fname == NULL)
        return NULL;
    /* now get rid of extension */
    for (; c > fname && *c != '.'; c--)
        ; /* nothing */

    ASSERT(c - fname < BUFFER_SIZE_ELEMENTS(sym_with_mod), "sizes way off");
    modoffs = dr_snprintf(sym_with_mod, c - fname, "%s", fname);
    ASSERT(modoffs > 0, "error printing modname!symname");
    modoffs = dr_snprintf(sym_with_mod + modoffs,
                          BUFFER_SIZE_ELEMENTS(sym_with_mod) - modoffs,
                          "!%s", sym_pattern);
    ASSERT(modoffs > 0, "error printing modname!symname");
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));

    /* We rely on drsym_init() having been called during init */
    if (full) {
        /* A SymSearch full search is slower than SymFromName */
        symres = drsym_lookup_symbol(mod->full_path, sym_with_mod, &modoffs);
    } else {
        /* drsym_search_symbols() is faster than either drsym_lookup_symbol() or
         * drsym_enumerate_symbols() (i#313)
         */
        modoffs = 0;
        symres = drsym_search_symbols(mod->full_path, sym_with_mod, false,
                                      callback == NULL ? search_syms_cb : callback,
                                      callback == NULL ? &modoffs : data);
    }
    LOG(2, "sym lookup of %s in %s => %d "PFX"\n", sym_with_mod, mod->full_path,
        symres, modoffs);
    if (symres == DRSYM_SUCCESS) {
        if (callback == NULL) {
            if (modoffs == 0) /* using as sentinel: assuming no sym there */
                return NULL;
            else
                return mod->start + modoffs;
        } else /* non-null to indicate success */
            return mod->start;
    } else
        return NULL;
}

app_pc
lookup_symbol(const module_data_t *mod, const char *symname)
{
    return lookup_symbol_common(mod, symname, false, NULL, NULL);
}

app_pc
lookup_internal_symbol(const module_data_t *mod, const char *symname)
{
    return lookup_symbol_common(mod, symname, true, NULL, NULL);
}

bool
lookup_all_symbols(const module_data_t *mod, const char *sym_pattern,
                   drsym_enumerate_cb callback, void *data)
{
    return (lookup_symbol_common(mod, sym_pattern, false, callback, data) != NULL);
}
#endif

/***************************************************************************
 * OPTION PARSING
 *
 */

#ifdef LINUX
/* FIXME: i#30: provide safe libc routines like we do on Windows */
static int
isspace(int c)
{
    return (c == ' ' || c == '\t');
}
#endif

const char *
get_option_word(const char *s, char buf[MAX_OPTION_LEN])
{
    int i = 0;
    bool quoted = false;
    char endquote = '\0';
    while (*s != '\0' && isspace(*s))
        s++;
    if (*s == '\"' || *s == '\'' || *s == '`') {
        quoted = true;
        endquote = *s;
        s++;
    }
    while (*s != '\0' && ((!quoted && !isspace(*s)) || (quoted && *s != endquote)) &&
           i < MAX_OPTION_LEN-1)
        buf[i++] = *s++;
    if (quoted && *s == endquote)
        s++;
    buf[i] = '\0';
    if (i == 0)
        return NULL;
    else
        return s;
}

/***************************************************************************
 * WINDOWS SYSTEM CALLS
 */

#ifdef WINDOWS
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    /* added after XP+ */
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessResourceManagement,
    ProcessCookie,
    ProcessImageInformation,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef LONG KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION { // Information Class 0
    NTSTATUS ExitStatus;
    PNT_TIB TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

#define OBJ_CASE_INSENSITIVE    0x00000040L

GET_NTDLL(NtQueryInformationThread, (IN HANDLE ThreadHandle,
                                     IN THREADINFOCLASS ThreadInformationClass,
                                     OUT PVOID ThreadInformation,
                                     IN ULONG ThreadInformationLength,
                                     OUT PULONG ReturnLength OPTIONAL));

GET_NTDLL(NtOpenThread, (OUT PHANDLE ThreadHandle,
                         IN ACCESS_MASK DesiredAccess,
                         IN POBJECT_ATTRIBUTES ObjectAttributes,
                         IN PCLIENT_ID ClientId));

GET_NTDLL(NtClose, (IN HANDLE Handle));


TEB *
get_TEB(void)
{
    return (TEB *) __readfsdword(offsetof(TEB, Self));
}

TEB *
get_TEB_from_handle(HANDLE h)
{
    uint pid, got;
    THREAD_BASIC_INFORMATION info;
    NTSTATUS res;
    memset(&info, 0, sizeof(THREAD_BASIC_INFORMATION));
    res = NtQueryInformationThread(h, ThreadBasicInformation,
                                   &info, sizeof(THREAD_BASIC_INFORMATION), &got);
    if (!NT_SUCCESS(res) || got != sizeof(THREAD_BASIC_INFORMATION)) {
        ASSERT(false, "internal error");
        return NULL;
    }
    return (TEB *) info.TebBaseAddress;
}

TEB *
get_TEB_from_tid(thread_id_t tid)
{
    HANDLE h;
    TEB *teb = NULL;
    NTSTATUS res;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    /* these aren't really HANDLEs */
    cid.UniqueProcess = (HANDLE) dr_get_process_id();
    cid.UniqueThread = (HANDLE) tid;
    InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE, NULL, NULL);
    res = NtOpenThread(&h, THREAD_QUERY_INFORMATION, &oa, &cid);
    if (NT_SUCCESS(res)) {
        teb = get_TEB_from_handle(h);
        /* avoid DR's hook on NtClose: dr_close_file() calls the raw version */
        dr_close_file(h);
    }
    return teb;
}

static uint
getpid(void)
{
    return (uint) get_TEB()->ClientId.UniqueProcess;
}

GET_NTDLL(NtQueryInformationProcess, (IN HANDLE ProcessHandle,
                                      IN PROCESSINFOCLASS ProcessInformationClass,
                                      OUT PVOID ProcessInformation,
                                      IN ULONG ProcessInformationLength,
                                      OUT PULONG ReturnLength OPTIONAL));

PEB *
get_app_PEB(void)
{
    /* With i#249, in DrMem code the PEB pointed at by the TEB is DR's private
     * copy, so we query DR to get the app's PEB.
     * Note that NtQueryInformationProcess, disturbingly, returns the pointer
     * in the TEB, so we can't use that!
     */
    return (PEB *) dr_get_app_PEB();
}

#if defined(DEBUG) && defined(WINDOWS)
/* check that peb isolation is consistently applied (xref i#324) */
bool
using_private_peb(void)
{
    TEB *teb = get_TEB();
    return (teb != NULL && teb->ProcessEnvironmentBlock == orig_peb);
}
#endif

bool
is_current_process(HANDLE h)
{
    uint pid, got;
    PROCESS_BASIC_INFORMATION info;
    NTSTATUS res;
    if (h == NT_CURRENT_PROCESS)
        return true;
    memset(&info, 0, sizeof(PROCESS_BASIC_INFORMATION));
    res = NtQueryInformationProcess(h, ProcessBasicInformation,
                                    &info, sizeof(PROCESS_BASIC_INFORMATION), &got);
    if (!NT_SUCCESS(res) || got != sizeof(PROCESS_BASIC_INFORMATION)) {
        ASSERT(false, "internal error");
        return false; /* better to have false positives than negatives? */
    }
    return (info.UniqueProcessId == getpid());
}

bool
is_wow64_process(void)
{
    /* Another feature DR now provides for us */
    return dr_is_wow64();
}


bool
opc_is_in_syscall_wrapper(uint opc)
{
    return (opc == OP_mov_imm || opc == OP_lea || opc == OP_xor /*wow64*/ ||
            opc == OP_int || opc == OP_call_ind ||
            /* w/ DR Ki hooks before dr_init we have to walk over the
             * native_exec_syscall hooks */
            opc == OP_jmp);
}

/* Takes in any Nt syscall wrapper entry point.
 * FIXME: deal with hooks
 */
int
syscall_num(void *drcontext, byte *entry)
{
    int num = -1;
    byte *pc = entry;
    uint opc;
    instr_t instr;
    instr_init(drcontext, &instr);
    do {
        instr_reset(drcontext, &instr);
        pc = decode(drcontext, pc, &instr);
        ASSERT(instr_valid(&instr), "unknown system call sequence");
        opc = instr_get_opcode(&instr);
        ASSERT(opc_is_in_syscall_wrapper(opc), "unknown system call sequence");
        /* safety check: should only get 11 or 12 bytes in */
        if (pc - entry > 20) {
            ASSERT(false, "unknown system call sequence");
            instr_free(drcontext, &instr);
            return -1;
        }
        /* FIXME: what if somebody has hooked the wrapper? */
        if (opc == OP_mov_imm && opnd_is_reg(instr_get_dst(&instr, 0)) &&
            opnd_get_reg(instr_get_dst(&instr, 0)) == REG_EAX) {
            ASSERT(opnd_is_immed_int(instr_get_src(&instr, 0)), "internal error");
            num = opnd_get_immed_int(instr_get_src(&instr, 0));
            break;
        }
        /* stop at call to vsyscall or at int itself */
    } while (opc != OP_call_ind && opc != OP_int);
    instr_free(drcontext, &instr);
    ASSERT(num > -1, "unknown system call number");
    return num;
}

# ifdef TOOL_DR_MEMORY
extern const char *get_syscall_name(int sysnum);
# endif

/* Returns -1 on failure */
int
sysnum_from_name(void *drcontext, app_pc ntdll_base, const char *name)
{
    int num;
    app_pc entry = (app_pc) dr_get_proc_address(ntdll_base, name);
    if (entry == NULL)
        return -1;
    num = syscall_num(drcontext, entry);
    ASSERT(num != -1, "error finding key syscall number");
# ifdef TOOL_DR_MEMORY
    /* good sanity check */
    ASSERT(stri_eq(get_syscall_name(num), name), "sysnum mismatch");
# endif
    return num;
}

/* We want DR to provide a get_windows_version() routine: PR 367157 */
bool
running_on_Vista_or_later(void)
{
    TEB *teb = get_TEB();
    PEB *peb = get_app_PEB();
    if (peb->OSPlatformId == VER_PLATFORM_WIN32_NT && peb->OSMajorVersion >= 6) {
        return true;
    }
    return false;
}

#endif /* WINDOWS */

/***************************************************************************
 * LINUX SYSTEM CALLS
 */

#ifdef LINUX
ptr_int_t
raw_syscall_1arg(uint sysnum, ptr_int_t arg)
{
    /* FIXME i#199: should DR provide a general raw_syscall interface? */
    ptr_int_t res;
    __asm("pushl %"ASM_SYSARG1);
    /* we do not mark as clobbering ASM_SYSARG1 to avoid error about
     * clobbering pic register for 32-bit
     */
    __asm("mov %0, %%"ASM_SYSARG1 : : "g"(arg));
    __asm("mov %0, %%eax" : : "g"(sysnum) : "eax");
    __asm("int $0x80");
    __asm("mov %%"ASM_XAX", %0" : "=m"(res));
    __asm("popl %"ASM_SYSARG1);
    return res;
}

ptr_int_t
raw_syscall_5args(uint sysnum, ptr_int_t arg1, ptr_int_t arg2, ptr_int_t arg3,
                  ptr_int_t arg4, ptr_int_t arg5)
{
    /* FIXME i#199: should DR provide a general raw_syscall interface? */
    ptr_int_t res;
    __asm("pusha");
    /* we do not mark as clobbering ASM_SYSARG1 to avoid error about
     * clobbering pic register for 32-bit
     */
    __asm("mov %0, %%"ASM_SYSARG5 : : "g"(arg5));
    __asm("mov %0, %%"ASM_SYSARG4 : : "g"(arg4));
    __asm("mov %0, %%"ASM_SYSARG3 : : "g"(arg3));
    __asm("mov %0, %%"ASM_SYSARG2 : : "g"(arg2));
    __asm("mov %0, %%"ASM_SYSARG1 : : "g"(arg1));
    __asm("mov %0, %%eax" : : "g"(sysnum) : "eax");
    __asm("int $0x80");
    __asm("mov %%"ASM_XAX", %0" : "=m"(res));
    __asm("popa");
    return res;
}
#endif

/***************************************************************************
 * HEAP WITH STATS
 *
 */

#ifdef STATISTICS
/* We could have each client define this to avoid ifdefs in common/,
 * but the shared hashtable code needs a shared define, so going w/
 * ifdefs.
 */
static const char * heapstat_names[] = {
    "shadow",
    "perbb",
# ifdef TOOL_DR_HEAPSTAT
    "snapshot",
    "staleness",
# endif
    "callstack",
    "hashtable",
    "gencode",
    "rbtree",
    "misc",
};

static uint heap_usage[HEAPSTAT_NUMTYPES];  /* cur usage  */
static uint heap_max[HEAPSTAT_NUMTYPES];    /* peak usage */
static uint heap_count[HEAPSTAT_NUMTYPES];  /* # allocs   */

static void
heap_usage_inc(heapstat_t type, size_t size)
{
    uint usage;
    ATOMIC_ADD32(heap_usage[type], size);
    /* racy: if a problem in practice we can switch to per-thread stats */
    usage = heap_usage[type];
    if (usage > heap_max[type])
        heap_max[type] = usage;
    ATOMIC_INC32(heap_count[type]);
}

static void
heap_usage_dec(heapstat_t type, size_t size)
{
    ATOMIC_ADD32(heap_usage[type], -(ssize_t)size);
    ATOMIC_DEC32(heap_count[type]);
}

void
heap_dump_stats(file_t f)
{
    int i;
    dr_fprintf(f, "\nHeap usage:\n");
    for (i = 0; i < HEAPSTAT_NUMTYPES; i++) {
        dr_fprintf(f, "\t%11s: count=%8u, cur=%6u KB, max=%6u KB\n",
                   heapstat_names[i], heap_count[i],
                   heap_usage[i]/1024, heap_max[i]/1024);
    }
}
#endif /* STATISTICS */

#undef dr_global_alloc
#undef dr_global_free
#undef dr_thread_alloc
#undef dr_thread_free
#undef dr_nonheap_alloc
#undef dr_nonheap_free

void *
global_alloc(size_t size, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_inc(type, size);
#endif
    /* Note that the recursive lock inside DR is a perf hit for
     * malloc-intensive apps: we're already holding the malloc_lock,
     * so could use own heap alloc, or add option to DR to not use
     * lock yet still use thread-shared heap.
     */
    return dr_global_alloc(size);
}

void
global_free(void *p, size_t size, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_dec(type, size);
#endif
    dr_global_free(p, size);
}

void *
thread_alloc(void *drcontext, size_t size, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_inc(type, size);
#endif
    return dr_thread_alloc(drcontext, size);
}

void
thread_free(void *drcontext, void *p, size_t size, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_dec(type, size);
#endif
    dr_thread_free(drcontext, p, size);
}

void *
nonheap_alloc(size_t size, uint prot, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_inc(type, size);
#endif
    return dr_nonheap_alloc(size, prot);
}

void
nonheap_free(void *p, size_t size, heapstat_t type)
{
#ifdef STATISTICS
    heap_usage_dec(type, size);
#endif
    dr_nonheap_free(p, size);
}

#define dr_global_alloc DO_NOT_USE_use_global_alloc
#define dr_global_free  DO_NOT_USE_use_global_free
#define dr_thread_alloc DO_NOT_USE_use_thread_alloc
#define dr_thread_free  DO_NOT_USE_use_thread_free
#define dr_nonheap_alloc DO_NOT_USE_use_nonheap_alloc
#define dr_nonheap_free  DO_NOT_USE_use_nonheap_free

char *
drmem_strdup(const char *src, heapstat_t type)
{
    char *dup = NULL;
    if (src != NULL) {
        dup = global_alloc(strlen(src)+1, type);
        strncpy(dup, src, strlen(src)+1);
    }
    return dup;
}

/***************************************************************************
 * HASHTABLE
 */

/* hashtable was moved and generalized */

static void *
hashwrap_alloc(size_t size)
{
    return global_alloc(size, HEAPSTAT_HASHTABLE);
}

static void
hashwrap_free(void *ptr, size_t size)
{
    global_free(ptr, size, HEAPSTAT_HASHTABLE);
}

static void
hashwrap_assert_fail(const char *msg)
{
    /* The reported file+line won't be the hashtable.c source but we
     * don't want the complexity of snprintf, and msg should identify
     * the source
     */
    ASSERT(false, msg);
}

void
utils_init(void)
{
#if defined(DEBUG) && defined(WINDOWS)
    /* store private peb and check later that it's the same (xref i#324) */
    ASSERT(get_TEB() != NULL, "can't get TEB");
    orig_peb = get_TEB()->ProcessEnvironmentBlock;
#endif

    hashtable_global_config(hashwrap_alloc, hashwrap_free, hashwrap_assert_fail);
}

