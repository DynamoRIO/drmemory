/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
#include "drmgr.h"
#include "utils.h"
#ifdef USE_DRSYMS
# include "drsyms.h"
# include "symcache.h"
#endif
#ifdef WINDOWS
# include "windefs.h"
# include "../wininc/ndk_extypes.h" /* for SYSTEM_INFORMATION_CLASS */
#else
# include <string.h>
#endif
#include <stddef.h> /* for offsetof */
#include <ctype.h> /* for tolower */

/* globals that affect NOTIFY* and *LOG* macros */
int tls_idx_util = -1;
bool op_print_stderr = true;
uint op_verbose_level;
bool op_pause_at_assert;
bool op_pause_via_loop;
bool op_ignore_asserts;
file_t f_global = INVALID_FILE;
#ifdef USE_DRSYMS
bool op_use_symcache;
# ifdef STATISTICS
uint symbol_lookups;
uint symbol_searches;
uint symbol_lookup_cache_hits;
uint symbol_search_cache_hits;
uint symbol_address_lookups;
# endif
#endif

#ifdef WINDOWS
static dr_os_version_info_t os_version = {sizeof(os_version),};
#endif

#if defined(WINDOWS) && defined (USE_DRSYMS)
/* for ensuring library isolation */
static PEB *priv_peb;
#endif

static thread_id_t primary_thread = INVALID_THREAD_ID;

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
    if (op_pause_at_assert) {
        char buf[64];
        /* very useful to have the pid */
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                    "Dr. Memory is paused at an assert in pid=%d",
                    dr_get_process_id());
        wait_for_user(buf);
    }
    dr_abort();
}

bool
safe_read(void *base, size_t size, void *out_buf)
{
    /* DR's dr_safe_read() is now faster than try/except.
     * History: this routine pre-dates dr_safe_read() itself, and
     * even once that was available it was too slow on Windows
     * as it involved an NtReadVirtualMemory syscall.
     * For all of our uses, a failure is rare, so we would rather
     * have low overhead on non-failure and have no syscall or
     * setjmp overhead (i#265).
     * Xref the same problem with leak_safe_read_heap (PR 570839).
     */
    size_t bytes_read = 0;
    return (dr_safe_read(base, size, out_buf, &bytes_read) &&
            bytes_read == size);
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
bool
lookup_has_fast_search(const module_data_t *mod)
{
    drsym_debug_kind_t kind;
    drsym_error_t res = drsym_get_module_debug_kind(mod->full_path, &kind);
    return TEST(DRSYM_PDB, kind);
}

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

typedef struct _search_regex_t {
    const char *regex;
    drsym_enumerate_cb orig_cb;
    void *orig_data;
} search_regex_t;

/* cb used when we need to do our own regex matching
 * XXX: would be better for drsyms to do this for us instead of
 * returning NYI on search, although we'd still have
 * multiple loops: for efficiency might need to pool together
 * what we're interested in from all modules and do one loop.
 * maybe each module registers pattern and gets callback from
 * some central module event code.
 */
static bool
search_syms_regex_cb(const char *name, size_t modoffs, void *data)
{
    search_regex_t *sr = (search_regex_t *) data;
    const char *sym = strchr(sr->regex, '!');
    LOG(3, "%s: comparing %s to pattern %s\n", __FUNCTION__,
        name, sym == NULL ? sr->regex : sym + 1);
    if (sr->regex[0] == '\0' ||
        text_matches_pattern(name, sym == NULL ? sr->regex : sym + 1, false)) {
        return sr->orig_cb(name, modoffs, sr->orig_data);
    }
    return true; /* keep iterating */
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
    int len;
    drsym_error_t symres;
    char *fname = NULL, *c;

    if (mod->full_path == NULL)
        return NULL;
    if (callback == NULL) {
        if (op_use_symcache) {
            uint count;
            /* if there are multiple we just return the first one */
            if (symcache_lookup(mod, sym_pattern, 0, &modoffs, &count)) {
                STATS_INC(symbol_lookup_cache_hits);
                if (modoffs == 0)
                    return NULL;
                else
                    return mod->start + modoffs;
            }
        }
        STATS_INC(symbol_lookups); /* not total, rather un-cached */
    } else
        STATS_INC(symbol_searches);

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
    len = dr_snprintf(sym_with_mod, c - fname, "%s", fname);
    ASSERT(len == -1, "error printing modname!symname");
    len = dr_snprintf(sym_with_mod + (c - fname),
                      BUFFER_SIZE_ELEMENTS(sym_with_mod) - (c - fname),
                      "!%s", sym_pattern);
    ASSERT(len > 0, "error printing modname!symname");
    IF_WINDOWS(ASSERT(using_private_peb(), "private peb not preserved"));

    /* We rely on drsym_init() having been called during init */
    if (full && callback == NULL) {
        /* A SymSearch full search is slower than SymFromName */
        symres = drsym_lookup_symbol(mod->full_path, sym_with_mod, &modoffs,
                                     DRSYM_DEMANGLE);
    } else {
        /* drsym_search_symbols() is faster than either drsym_lookup_symbol() or
         * drsym_enumerate_symbols() (i#313)
         */
        modoffs = 0;
        symres = drsym_search_symbols(mod->full_path, sym_with_mod, full,
                                      callback == NULL ? search_syms_cb : callback,
                                      callback == NULL ? &modoffs : data);
        if (symres == DRSYM_ERROR_NOT_IMPLEMENTED) {
            /* ELF or PECOFF where regex search is NYI
             * XXX: better for caller to do single walk though: should we
             * return failure and have caller call back with "" and its own
             * pattern-matching callback?
             */
            search_regex_t *sr = (search_regex_t *)
                global_alloc(sizeof(*sr), HEAPSTAT_MISC);
            sr->regex = sym_with_mod;
            sr->orig_cb = callback == NULL ? search_syms_cb : callback;
            sr->orig_data = callback == NULL ? &modoffs : data;
            symres = drsym_enumerate_symbols(mod->full_path, search_syms_regex_cb,
                                             (void *) sr, DRSYM_DEMANGLE);
            global_free(sr, sizeof(*sr), HEAPSTAT_MISC);
        }
    }
    LOG(2, "sym lookup of %s in %s => %d "PFX"\n", sym_with_mod, mod->full_path,
        symres, modoffs);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        if (callback == NULL) {
            if (op_use_symcache)
                symcache_add(mod, sym_pattern, modoffs);
            if (modoffs == 0) /* using as sentinel: assuming no sym there */
                return NULL;
            else
                return mod->start + modoffs;
        } else /* non-null to indicate success */
            return mod->start;
    } else {
        if (symres == DRSYM_ERROR_SYMBOL_NOT_FOUND && op_use_symcache)
            symcache_add(mod, sym_pattern, 0);
        return NULL;
    }
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

/* Iterates over symbols matching modname!sym_pattern until
 * callback returns false.
 * N.B.: if you add a call to this routine, or modify an existing call,
 * bump SYMCACHE_VERSION and add symcache checks.
 */
bool
lookup_all_symbols(const module_data_t *mod, const char *sym_pattern, bool full,
                   drsym_enumerate_cb callback, void *data)
{
    return (lookup_symbol_common(mod, sym_pattern, full, callback, data) != NULL);
}
#endif

#ifdef DEBUG
void
print_mcontext(file_t f, dr_mcontext_t *mc)
{
    dr_fprintf(f, "\txax="PFX", xbx="PFX", xcx="PFX", xdx="PFX"\n"
               "\txsi="PFX", xdi="PFX", xbp="PFX", xsp="PFX"\n",
               mc->xax, mc->xbx, mc->xcx, mc->xdx,
               mc->xsi, mc->xdi, mc->xbp, mc->xsp);
}
#endif

void
hashtable_delete_with_stats(hashtable_t *table, const char *name)
{
    LOG(1, "final %s table size: %u bits, %u entries\n", name,
        table->table_bits, table->entries);
    /* XXX: add collision data: though would want those stats mid-run
     * for tables that have entries freed during exit before here
     */
    hashtable_delete(table);
}

#ifdef STATISTICS
void
hashtable_cluster_stats(hashtable_t *table, const char *name)
{
    uint max_cluster = 0, tot_cluster = 0, count_cluster = 0;
    uint i;
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        hash_entry_t *he;
        uint cluster = 0;
        if (table->table[i] != NULL)
            count_cluster++;
        for (he = table->table[i]; he != NULL; he = he->next)
            cluster++;
        if (cluster > max_cluster)
            max_cluster = cluster;
        tot_cluster += cluster;
    }
    /* we don't want to use floating point so we print count and tot */
    LOG(0, "%s table: clusters=%u max=%u tot=%u\n",
        name, count_cluster, max_cluster, tot_cluster);
}
#endif

void
print_prefix_to_buffer(char *buf, size_t bufsz, size_t *sofar)
{
    void *drcontext = dr_get_current_drcontext();
    ssize_t len;
    if (drcontext != NULL) {
        thread_id_t tid = dr_get_thread_id(drcontext);
        if (primary_thread != INVALID_THREAD_ID/*initialized?*/ &&
            tid != primary_thread) {
            /* no-assert since used for errors, etc. in fragile contexts */
            BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, "~~%d~~ ", tid);
            return;
        }
    }
    /* no-assert since used for errors, etc. in fragile contexts */
    BUFPRINT_NO_ASSERT(buf, bufsz, *sofar, len, "%s", PREFIX_MAIN_THREAD);
}

void
print_prefix_to_console(void)
{
    char buf[16];
    size_t sofar = 0;
    print_prefix_to_buffer(buf, BUFFER_SIZE_ELEMENTS(buf), &sofar);
    PRINT_CONSOLE("%s", buf);
}

#if defined(WINDOWS) && defined(USE_DRSYMS)
bool
print_to_cmd(char *buf)
{
    /* we avoid buffer size limits in dr_fprintf by directly
     * talking to kernel32 ourselves
     */
    uint written;
    if (!WriteFile(GetStdHandle(STD_ERROR_HANDLE),
                   buf, (DWORD) strlen(buf), (LPDWORD) &written, NULL))
        return false;
    return true;
}
#endif

/***************************************************************************
 * STRING PARSING
 *
 */

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
    if (i == 0 && *s == '\0')
        return NULL;
    else
        return s;
}

bool
text_matches_pattern(const char *text, const char *pattern,
                     bool ignore_case)
{
    /* Match text with pattern and return the result.
     * The pattern may contain '*' and '?' wildcards.
     */
    const char *cur_text = text,
               *text_last_asterisk = NULL,
               *pattern_last_asterisk = NULL;
    char cmp_cur, cmp_pat;
    while (*cur_text != '\0') {
        cmp_cur = *cur_text;
        cmp_pat = *pattern;
        if (ignore_case) {
            cmp_cur = (char) tolower(cmp_cur);
            cmp_pat = (char) tolower(cmp_pat);
        }
        if (*pattern == '*') {
            while (*++pattern == '*') {
                /* Skip consecutive '*'s */
            }
            if (*pattern == '\0') {
                /* the pattern ends with a series of '*' */
                LOG(5, "    text_matches_pattern \"%s\" == \"%s\"\n", text, pattern);
                return true;
            }
            text_last_asterisk = cur_text;
            pattern_last_asterisk = pattern;
        } else if ((cmp_cur == cmp_pat) || (*pattern == '?')) {
            ++cur_text;
            ++pattern;
        } else if (text_last_asterisk != NULL) {
            /* No match. But we have seen at least one '*', so go back
             * and try at the next position.
             */
            pattern = pattern_last_asterisk;
            cur_text = text_last_asterisk++;
        } else {
            LOG(5, "    text_matches_pattern \"%s\" != \"%s\"\n", text, pattern);
            return false;
        }
    }
    while (*pattern == '*')
        ++pattern;
    LOG(4, "    text_matches_pattern \"%s\": end at \"%.5s\"\n", text, pattern);
    return *pattern == '\0';
}

/* patterns is a null-separated, double-null-terminated list of strings */
bool
text_matches_any_pattern(const char *text, const char *patterns, bool ignore_case)
{
    const char *c = patterns;
    while (*c != '\0') {
        if (text_matches_pattern(text, c, ignore_case))
            return true;
        c += strlen(c) + 1;
    }
    return false;
}

/* not available in ntdll CRT so we supply our own */
static const char *
strcasestr(const char *text, const char *pattern)
{
    const char *cur_text, *cur_pattern, *root;
    cur_text = text;
    root = text;
    cur_pattern = pattern;
    while (true) {
        if (*cur_pattern == '\0')
            return root;
        if (*cur_text == '\0')
            return NULL;
        if ((char)tolower(*cur_text) == (char)tolower(*cur_pattern)) {
            cur_text++;
            cur_pattern++;
        } else {
            root++;
            cur_text = root;
            cur_pattern = pattern;
        }
    }
}

/* patterns is a null-separated, double-null-terminated list of strings */
const char *
text_contains_any_string(const char *text, const char *patterns, bool ignore_case,
                         const char **matched)
{
    const char *c = patterns;
    while (*c != '\0') {
        const char *match =
            ignore_case ? strcasestr(text, c) : strstr(text, c);
        if (match != NULL) {
            if (matched != NULL)
                *matched = c;
            return match;
        }
        c += strlen(c) + 1;
    }
    return NULL;
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

GET_NTDLL(NtAllocateVirtualMemory, (IN HANDLE ProcessHandle,
                                    IN OUT PVOID *BaseAddress,
                                    IN ULONG ZeroBits,
                                    IN OUT PULONG AllocationSize,
                                    IN ULONG AllocationType,
                                    IN ULONG Protect));

GET_NTDLL(NtFreeVirtualMemory, (IN HANDLE ProcessHandle,
                                IN OUT PVOID *BaseAddress,
                                IN OUT PULONG FreeSize,
                                IN ULONG FreeType));

TEB *
get_TEB(void)
{
#ifdef X64
    return (TEB *) __readgsqword(offsetof(TEB, Self));
#else
    return (TEB *) __readfsdword(offsetof(TEB, Self));
#endif
}

TEB *
get_TEB_from_handle(HANDLE h)
{
    uint got;
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

thread_id_t
get_tid_from_handle(HANDLE h)
{
    uint got;
    THREAD_BASIC_INFORMATION info;
    NTSTATUS res;
    memset(&info, 0, sizeof(THREAD_BASIC_INFORMATION));
    res = NtQueryInformationThread(h, ThreadBasicInformation,
                                   &info, sizeof(THREAD_BASIC_INFORMATION), &got);
    if (!NT_SUCCESS(res) || got != sizeof(THREAD_BASIC_INFORMATION)) {
        ASSERT(false, "internal error");
        return INVALID_THREAD_ID;
    }
    return (thread_id_t) info.ClientId.UniqueThread;
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
    } else {
        WARN("WARNING: get_TEB_from_tid tid=%d failed "PFX"\n", tid, res);
    }
    return teb;
}

void
set_app_error_code(void *drcontext, uint val)
{
    TEB *teb;
    bool swapped = false;
    if (!dr_using_app_state(drcontext)) {
        swapped = true;
        dr_switch_to_app_state(drcontext);
    }
    teb = get_TEB();
    teb->LastErrorValue = val;
    if (swapped)
        dr_switch_to_dr_state(drcontext);
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
     * Update: I'm not seeing NtQueryInformationProcess do that: for i#5
     * it returns the system PEB, not TEB->ProcessEnvironmentBlock.
     * Does it do different things at different times, or was I measuring on
     * different OS's?  The latter is on xp64.
     */
    return (PEB *) dr_get_app_PEB();
}

#ifdef USE_DRSYMS
# ifdef DEBUG
/* check that peb isolation is consistently applied (xref i#324) */
bool
using_private_peb(void)
{
    TEB *teb = get_TEB();
    return (teb != NULL && teb->ProcessEnvironmentBlock == priv_peb);
}
# endif

HANDLE
get_private_heap_handle(void)
{
    return (HANDLE) priv_peb->ProcessHeap;
}
#endif /* DEBUG */

HANDLE
get_process_heap_handle(void)
{
    return (HANDLE) get_app_PEB()->ProcessHeap;
}

bool
is_current_process(HANDLE h)
{
    uint pid, got;
    PROCESS_BASIC_INFORMATION info;
    NTSTATUS res;
    if (h == NT_CURRENT_PROCESS)
        return true;
    if (h == NULL)
        return false;
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

const wchar_t *
get_app_commandline(void)
{
    PEB *peb = get_app_PEB();
    if (peb != NULL) {
        RTL_USER_PROCESS_PARAMETERS *param = (RTL_USER_PROCESS_PARAMETERS *)
            peb->ProcessParameters;
        if (param != NULL) {
            return param->CommandLine.Buffer;
        }
    }
    return L"";
}

bool
opc_is_in_syscall_wrapper(uint opc)
{
    return (opc == OP_mov_imm || opc == OP_lea || opc == OP_xor /*wow64*/ ||
            opc == OP_int || opc == OP_call_ind ||
            /* 64-bit Windows:
             * ntdll!NtMapViewOfSection:
             * 77941590 4c8bd1          mov     r10,rcx
             * 77941593 b825000000      mov     eax,25h
             * 77941598 0f05            syscall
             */
            IF_X64(opc == OP_mov_ld ||)
            /* w/ DR Ki hooks before dr_init we have to walk over the
             * native_exec_syscall hooks */
            opc == OP_jmp);
}

/* Takes in any Nt syscall wrapper entry point.
 * Will accept other entry points (e.g., we call it for gdi32!GetFontData)
 * and return -1 for them: up to caller to assert if that shouldn't happen.
 *
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
        if (!opc_is_in_syscall_wrapper(opc))
            break;
        /* safety check: should only get 11 or 12 bytes in */
        if (pc - entry > 20)
            break;
        /* FIXME: what if somebody has hooked the wrapper? */
        if (opc == OP_mov_imm && opnd_is_reg(instr_get_dst(&instr, 0)) &&
            opnd_get_reg(instr_get_dst(&instr, 0)) == REG_EAX) {
            ASSERT(opnd_is_immed_int(instr_get_src(&instr, 0)), "internal error");
            num = opnd_get_immed_int(instr_get_src(&instr, 0));
            break;
        }
        /* stop at call to vsyscall or at int itself */
    } while (opc != OP_call_ind && opc != OP_int &&
             opc != OP_sysenter && opc != OP_syscall);
    instr_free(drcontext, &instr);
    return num;
}

# ifdef TOOL_DR_MEMORY
extern const char *get_syscall_name(int sysnum);
extern int get_syscall_num(void *drcontext, const module_data_t *info, const char *name);
# endif

/* Returns -1 on failure */
int
sysnum_from_name(void *drcontext, const module_data_t *info, const char *name)
{
    int num;
# ifdef TOOL_DR_MEMORY
    /* drmem has extra info via tables for when no syms are avail (i#388) */
    num = get_syscall_num(drcontext, info, name);
    /* good sanity check */
    DOLOG(1, {
        if (num != -1) {
            const char *sysname = get_syscall_name(num);
            ASSERT(stri_eq(sysname, name) ||
                   /* account for NtUser*, etc. prefix differences */
                   strstr(sysname, name) != NULL , "sysnum mismatch");
        }
    });
# else
    app_pc entry = (app_pc) dr_get_proc_address(info->handle, name);
#  ifdef USE_DRSYMS
    if (entry == NULL) {
        /* Some kernel32 and user32 syscall wrappers are not exported.
         * For Windows drmem (the only place so far where we need
         * non-exported syscall nums) we use get_syscall_num() above.
         */
        entry = lookup_internal_symbol(info, name);
    }
#  endif
    if (entry == NULL)
        return -1;
    /* look for partial map (i#730) */
    if (entry >= info->end) /* XXX: syscall_num will decode a few instrs in */
        return -1;
    num = syscall_num(drcontext, entry);
    ASSERT(num != -1, "error finding key syscall number");
# endif /* TOOL_DR_MEMORY */
    return num;
}

static void
init_os_version(void)
{
    if (!dr_get_os_version(&os_version)) {
        ASSERT(false, "unable to get Windows version");
        /* assume latest just to make progress: good chance of working */
        os_version.version = DR_WINDOWS_VERSION_7;
        os_version.service_pack_major = 1;
        os_version.service_pack_minor = 0;
    }
}

bool
running_on_Win7_or_later(void)
{
    if (os_version.version == 0)
        init_os_version();
    return (os_version.version >= DR_WINDOWS_VERSION_7);
}

bool
running_on_Win7SP1_or_later(void)
{
    if (os_version.version == 0)
        init_os_version();
    return (os_version.version >= DR_WINDOWS_VERSION_7 &&
            os_version.service_pack_major >= 1);
}

bool
running_on_Vista_or_later(void)
{
    if (os_version.version == 0)
        init_os_version();
    return (os_version.version >= DR_WINDOWS_VERSION_VISTA);
}

dr_os_version_t
get_windows_version(void)
{
    if (os_version.version == 0)
        init_os_version();
    return os_version.version;
}

GET_NTDLL(NtQuerySystemInformation, (IN  SYSTEM_INFORMATION_CLASS info_class,
                                     OUT PVOID  info, 
                                     IN  ULONG  info_size, 
                                     OUT PULONG bytes_received));
   
app_pc
get_highest_user_address(void)
{
    static app_pc highest_user_address;
    if (highest_user_address == NULL) {
        SYSTEM_BASIC_INFORMATION info;
        ULONG got;
        NTSTATUS res = NtQuerySystemInformation(SystemBasicInformation, &info,
                                                sizeof(info), &got);
        if (NT_SUCCESS(res) && got == sizeof(info))
            highest_user_address = (app_pc) info.HighestUserAddress;
        else
            highest_user_address = (app_pc) POINTER_MAX;
    }
    return highest_user_address;
}

bool
virtual_alloc(void **base, size_t size, uint memtype, uint prot)
{
    NTSTATUS res;
    ULONG actual_size;
    ASSERT_TRUNCATE(actual_size, ULONG, size);
    actual_size = (ULONG)size;
    ASSERT(base != NULL && ALIGNED(*base, PAGE_SIZE), "base not page-aligned");
    res = NtAllocateVirtualMemory(NT_CURRENT_PROCESS, base, 0, &actual_size,
                                  memtype, prot);
    LOG(2, "%s size=%d => "PFX" "PIFX"\n", __FUNCTION__, size, *base, res);
    return NT_SUCCESS(res);
}

bool
virtual_free(void *base)
{
    NTSTATUS res;
    ULONG size = 0; /* must be 0 for MEM_RELEASE */
    res = NtFreeVirtualMemory(NT_CURRENT_PROCESS, &base, &size, MEM_RELEASE);
    LOG(2, "%s "PFX" => "PIFX"\n", __FUNCTION__, base, res);
    return NT_SUCCESS(res);
}

/* XXX DRi#877: should we add an import iterator to DR's API? */
bool
module_imports_from_msvc(const module_data_t *mod)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *) mod->start;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *) (mod->start + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_IMPORT_DESCRIPTOR *imports, *imports_end;
# ifdef DEBUG
    const char *modname = dr_module_preferred_name(mod);
    if (modname == NULL)
        modname = "";
# endif
    ASSERT(nt != NULL && nt->Signature == IMAGE_NT_SIGNATURE, "invalid mod header");

    /* Could be paranoid and de-ref this (and dos and nt) inside a TRY
     * but these should be present: I'm actually more nervous about making
     * a too-big DR_TRY_EXCEPT b/c it can't nest
     */
    dir = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ?
           (nt->OptionalHeader.DataDirectory) :
           (((IMAGE_NT_HEADERS64 *)nt)->OptionalHeader.DataDirectory))
        + IMAGE_DIRECTORY_ENTRY_IMPORT;
    if (dir == NULL || dir->Size <= 0)
        return false;
    imports = (IMAGE_IMPORT_DESCRIPTOR *) (mod->start + dir->VirtualAddress);
    imports_end = (IMAGE_IMPORT_DESCRIPTOR *)
        (mod->start + dir->VirtualAddress + dir->Size);

    while (imports->OriginalFirstThunk != 0 && imports < imports_end) {
        IMAGE_THUNK_DATA *lookup;
        IMAGE_THUNK_DATA *address;
        const char *impname;
        bool matches = false, partial = false;
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            impname = (const char *) (mod->start + imports->Name);
            LOG(3, "module %s imports from %s\n", modname, impname);
            if (text_matches_pattern(impname, "msvc*.dll", true/*ignore case*/))
                matches = true;
        }, {
            partial = true; /* partial map */
        });
        /* Can't return out of DR_TRY_EXCEPT */
        if (matches)
            return true;
        if (partial)
            return false;
        imports++;
    }
    return false;
}
#endif /* WINDOWS */

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
    "suppress",
    "misc",
};

static uint heap_usage[HEAPSTAT_NUMTYPES];  /* cur usage  */
static uint heap_max[HEAPSTAT_NUMTYPES];    /* peak usage */
static uint heap_count[HEAPSTAT_NUMTYPES];  /* # allocs   */

static void
heap_usage_inc(heapstat_t type, size_t size)
{
    uint usage;
    uint delta;
    ASSERT_TRUNCATE(delta, uint, size);
    delta = (uint)size;
    ATOMIC_ADD32(heap_usage[type], delta);
    /* racy: if a problem in practice we can switch to per-thread stats */
    usage = heap_usage[type];
    if (usage > heap_max[type])
        heap_max[type] = usage;
    ATOMIC_INC32(heap_count[type]);
}

static void
heap_usage_dec(heapstat_t type, size_t size)
{
    int delta;
    ASSERT_TRUNCATE(delta, int, size);
    delta = (int)size;
    ATOMIC_ADD32(heap_usage[type], -delta);
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

char *
drmem_strndup(const char *src, size_t max, heapstat_t type)
{
    char *dup = NULL;
    /* deliberately not calling strlen on src since may be quite long */
    const char *c;
    size_t sz;
    for (c = src; c != '\0' && (c - src < max); c++)
        ; /* nothing */
    sz = (c - src < max) ? c -src : max;
    if (src != NULL) {
        dup = global_alloc(sz + 1, type);
        strncpy(dup, src, sz);
        dup[sz] = '\0';
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

/***************************************************************************
 * INIT/EXIT
 */

void
utils_init(void)
{
    tls_idx_util = drmgr_register_tls_field();
    ASSERT(tls_idx_util > -1, "failed to obtain TLS slot");

#ifdef WINDOWS
    if (os_version.version == 0)
        init_os_version();
#endif

#ifdef USE_DRSYMS
    if (drsym_init(NULL) != DRSYM_SUCCESS) {
        LOG(1, "WARNING: unable to initialize symbol translation\n");
    }
#endif

#if defined(WINDOWS) && defined (USE_DRSYMS)
    /* store private peb and check later that it's the same (xref i#324) */
    ASSERT(get_TEB() != NULL, "can't get TEB");
    priv_peb = get_TEB()->ProcessEnvironmentBlock;
#endif

    hashtable_global_config(hashwrap_alloc, hashwrap_free, hashwrap_assert_fail);

    primary_thread = dr_get_thread_id(dr_get_current_drcontext());
}

void
utils_exit(void)
{
#ifdef USE_DRSYMS
    if (drsym_exit() != DRSYM_SUCCESS) {
        LOG(1, "WARNING: error cleaning up symbol library\n");
    }
#endif
    drmgr_unregister_tls_field(tls_idx_util);
}

void
utils_thread_init(void *drcontext)
{
    tls_util_t *pt = (tls_util_t *) thread_alloc(drcontext, sizeof(*pt), HEAPSTAT_MISC);
    memset(pt, 0, sizeof(*pt));
    drmgr_set_tls_field(drcontext, tls_idx_util, (void *) pt);
}

void
utils_thread_exit(void *drcontext)
{
    tls_util_t *pt = (tls_util_t *) drmgr_get_tls_field(drcontext, tls_idx_util);
    /* with PR 536058 we do have dcontext in exit event so indicate explicitly
     * that we've cleaned up the per-thread data
     */
    drmgr_set_tls_field(drcontext, tls_idx_util, NULL);
    thread_free(drcontext, pt, sizeof(*pt), HEAPSTAT_MISC);
}

void
utils_thread_set_file(void *drcontext, file_t f)
{
    tls_util_t *pt = (tls_util_t *) drmgr_get_tls_field(drcontext, tls_idx_util);
    pt->f = f;
}
