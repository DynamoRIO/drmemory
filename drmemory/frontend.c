/* **********************************************************
 * Copyright (c) 2010-2013 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
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

/* Dr. Memory: the memory debugger
 * a.k.a. DRMemory == DynamoRIO Memory checker
 *
 * This is the front end for launching applications under Dr. Memory on
 * Windows when using online symbols via the drsyms DynamoRIO Extension.
 * PR 540913 was the original PR for online symbol processing.
 * Versus perl-based sideline processing:
 * - Cygwin uses a separate build b/c drsyms doesn't support its symbols
 *   yet (PR 561181 covers adding cygwin symbol support to drsyms)
 * - Not supporting these features that are in postprocess.pl:
 *   o groups: just going to eliminate the feature
 *   o during-run summary + counts: just going to eliminate the feature
 *   o -aggregate: not supporting on Windows
 *   o -srcfilter: not supporting on Windows; now replaced with -src_whitelist.
 * - Very large symbol files that do not fit in the app address space
 *   are not yet supported: drsyms will eventually have symbol server
 *   support for those (PR 243532).
 */

/* For unicode support, we must use wide-char versions of main(), argv[],
 * and all of the windows library routines like GetEnvironmentVariable(),
 * _access(), and GetFullPathName().  Yet we must use UTF-8 for the DR
 * API routines.  We could go two routes: one is to have everything be UTF-16
 * and only convert before calling DR routines; the other is to have everything
 * be UTF-8 and convert when calling Windows routines.  We pick the latter
 * because we expect to port this to Linux.
 */
#ifdef WINDOWS
# define UNICODE
# define _UNICODE
#endif

#include "dr_api.h" /* for the types */
#include "dr_inject.h"
#include "dr_config.h"
#include "utils.h"
#include "frontend.h"
#include <assert.h>
#include <dbghelp.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#if _MSC_VER <= 1400 /* VS2005- */
/* These aren't present in VS2005 DbgHelp.h */
BOOL IMAGEAPI
SymInitializeW(__in HANDLE hProcess, __in_opt PCWSTR UserSearchPath,
               __in BOOL fInvadeProcess);

BOOL IMAGEAPI
SymSetSearchPathW(__in HANDLE hProcess, __in_opt PCWSTR SearchPath);

DWORD64 IMAGEAPI
SymLoadModuleExW(__in HANDLE hProcess, __in_opt HANDLE hFile, __in_opt PCWSTR ImageName,
                 __in_opt PCWSTR ModuleName, __in DWORD64 BaseOfDll, __in DWORD DllSize,
                 __in_opt PMODLOAD_DATA Data, __in_opt DWORD Flags);
#endif

/* XXX: we may want to share this with DR's libutil/our_tchar.h b/c we'll
 * want something similar for drdeploy and drinject libs and tools
 */
#ifdef WINDOWS
# include <tchar.h>
#else
# define TCHAR char
# define _tmain main
# define _tcslen strlen
# define _tcsstr strstr
# define _tcscmp strcmp
# define _tcsnicmp strnicmp
# define _tcsncpy strncpy
# define _tcscat_s strcat
# define _tcsrchr strrchr
# define _sntprintf snprintf
# define _ftprintf fprintf
# define _tfopen fopen
# define _T(s) s
#endif
#ifdef _UNICODE
# define TSTR_FMT "%S"
#else
# define TSTR_FMT "%s"
#endif

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)
#define MAX_APP_CMDLINE 4096

#ifdef X64
# define LIB_ARCH "lib64"
# define BIN_ARCH "bin64"
#else
# define LIB_ARCH "lib32"
# define BIN_ARCH "bin"
#endif

/* -shared_slowpath requires -disable_traces
 * freeing stringop data also requires -disable_traces (i#391)
 * to save space we use -bb_single_restore_prefix
 * PR 415155: our code expansion causes us to exceed max bb size sometimes
 * PR 561775: drsyms (esp newer versions) uses a lot of stack, which
 *   caused DR 20K stack to overlow, so upping to 36K (biggest callstack
 *   is module load event where DR has already used a bunch of stack,
 *   and PR 486382 does name-to-addr symbol lookup).
 *   update: DR's default is now 56K so this is no longer needed.
 * i#1263: on larger apps our shadow memory routinely exceeds DR's
 *   default 128MB reservation.  DR is more efficient when all its
 *   allocations are inside its reservation.
 * DRi#1081: we disable reset until the DR bug is fixed.
 */
#define DEFAULT_DR_OPS \
    "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256 -vm_size 256M -no_enable_reset"

#define DRMEM_CLIENT_ID 0

static bool verbose;
static bool quiet;
static bool results_to_stderr = true;
static bool batch; /* no popups */
static bool no_resfile; /* no results file expected */
static bool top_stats;
static bool fetch_symbols = false;  /* Off by default for 1.5.0 release. */
static bool fetch_crt_syms_only = true;

static dr_os_version_info_t win_ver;

enum {
    /* _NT_SYMBOL_PATH typically has a local path and a URL. */
    MAX_SYMSRV_PATH = 2 * MAXIMUM_PATH
};

/* Symbol search path. */
/* XXX: it may be simpler to have this be TCHAR and avoid extra conversions
 * if we created BUFPRINT for TCHAR to simplify set_symbol_search_path().
 */
static char symsrv_path[MAX_SYMSRV_PATH];

/* URL of the MS symbol server. */
static const char ms_symsrv[] = "http://msdl.microsoft.com/download/symbols";

static const char *prefix = PREFIX_DEFAULT_MAIN_THREAD;

static bool
on_vista_or_later(void)
{
    return (win_ver.version >= DR_WINDOWS_VERSION_VISTA);
}

static bool
on_win8_or_later(void)
{
    return (win_ver.version >= DR_WINDOWS_VERSION_8);
}

static bool
on_supported_version(void)
{
    return (win_ver.version <= DR_WINDOWS_VERSION_8_1);
}

static void
pause_if_in_cmd(void)
{
#ifdef WINDOWS
    if (dr_using_console() ||
        /* i#1157: on win8 dr_using_console() always returns false, so we
         * always pause unless -batch
         */
        (on_win8_or_later() && !batch)) {
        /* If someone double-clicked drmemory.exe, ensure the message
         * stays up instead of the cmd window disappearing (i#1129).
         * Yes, someone already in cmd will have to hit a key, but
         * that's ok.
         */
        fprintf(stderr, "\n<press enter>\n");
        fflush(stderr);
        getchar();
    }
#endif
}

#define fatal(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", __VA_ARGS__);    \
    fflush(stderr); \
    /* for drag-and-drop we'd better make fatal errors visible */ \
    pause_if_in_cmd(); \
    exit(1); \
} while (0)

#define warn(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "WARNING: " msg "\n", __VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#define warn_prefix(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "%s", prefix); \
        fprintf(stderr, "WARNING: " msg "\n", __VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#define info(msg, ...) do { \
    if (verbose) { \
        fprintf(stderr, "INFO: " msg "\n", __VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

/* Fetching symbols can create the appearance of a hang, so we want to print
 * these messages without -v.
 */
#define sym_info(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "%s", prefix); \
        fprintf(stderr, msg "\n", __VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

/* XXX: share w/ options.c */
enum {
    SCOPE_IS_PUBLIC_front    = true,
    SCOPE_IS_PUBLIC_side     = true,
    SCOPE_IS_PUBLIC_post     = true,
    SCOPE_IS_PUBLIC_script   = true,
    SCOPE_IS_PUBLIC_client   = true,
    SCOPE_IS_PUBLIC_internal = false,
};

enum {
    TYPE_IS_BOOL_bool       = true,
    TYPE_IS_BOOL_opstring_t = false,
    TYPE_IS_BOOL_multi_opstring_t = false,
    TYPE_IS_BOOL_uint       = false,
    TYPE_IS_BOOL_int        = false,
    TYPE_IS_STRING_bool       = false,
    TYPE_IS_STRING_opstring_t = true,
    TYPE_IS_STRING_multi_opstring_t = false,
    TYPE_IS_STRING_uint       = false,
    TYPE_IS_STRING_int        = false,
    TYPE_HAS_RANGE_bool       = false,
    TYPE_HAS_RANGE_opstring_t = false,
    TYPE_HAS_RANGE_multi_opstring_t = false,
    TYPE_HAS_RANGE_uint       = true,
    TYPE_HAS_RANGE_int        = true,
};

static const char * const bool_string[2] = {
    "false",
    "true",
};

static void
print_usage(bool full)
{
    fprintf(stderr, "Usage: drmemory.exe [options] -- <app and args to run>\n");
    if (!full) {
        fprintf(stderr, "Run with --help for full option list.\n");
        fprintf(stderr, "See http://drmemory.org/docs/ for more information.\n");
        pause_if_in_cmd();
        return;
    }
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    if (SCOPE_IS_PUBLIC_##scope) {                                      \
        if (TYPE_IS_BOOL_##type) { /* turn "(0)" into "false" */        \
            fprintf(stderr, "  -%-28s [%6s]  %s\n", #name,              \
                    bool_string[(int)defval], short);                   \
        } else if (TYPE_HAS_RANGE_##type)                               \
            fprintf(stderr, "  -%-28s [%6s]  %s\n", #name" <int>", #defval, short); \
        else                                                            \
            fprintf(stderr, "  -%-28s [%6s]  %s\n", #name" <string>", #defval, short); \
    }
#define OPTION_FRONT OPTION_CLIENT
#include "optionsx.h"
#undef OPTION_CLIENT
#undef OPTION_FRONT
}

#define usage(msg, ...) do {                                    \
    fprintf(stderr, "\n");                                      \
    fprintf(stderr, "ERROR: " msg "\n\n", __VA_ARGS__);         \
    print_usage(false);                                         \
    exit(1);                                                    \
} while (0)

#undef BUFPRINT /* XXX: we could redefine ASSERT to use utils.h BUFPRINT here */
/* must use dr_snprintf here to support %S converting UTF-16<->UTF-8 */
#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    len = dr_snprintf((buf)+(sofar), (bufsz)-(sofar), __VA_ARGS__); \
    sofar += (len < 0 ? 0 : len); \
    assert((bufsz) > (sofar)); \
    /* be paranoid: though usually many calls in a row and could delay until end */ \
    (buf)[(bufsz)-1] = '\0';                                 \
} while (0)

/* always null-terminates */
static void
tchar_to_char(const TCHAR *wstr, char *buf, size_t buflen/*# elements*/)
{
    int res = WideCharToMultiByte(CP_UTF8, 0, wstr, -1/*null-term*/,
                                  buf, buflen, NULL, NULL);
    /* XXX: propagate to caller?  or make fatal error? */
    assert(res > 0);
    buf[buflen - 1] = '\0';
}

/* includes the terminating null */
static size_t
tchar_to_char_size_needed(const TCHAR *wstr)
{
    return WideCharToMultiByte(CP_UTF8, 0, wstr, -1/*null-term*/, NULL, 0, NULL, NULL);
}

/* always null-terminates */
static void
char_to_tchar(const char *str, TCHAR *wbuf, size_t wbuflen/*# elements*/)
{
    int res = MultiByteToWideChar(CP_UTF8, 0/*=>MB_PRECOMPOSED*/, str, -1/*null-term*/,
                                  wbuf, wbuflen);
    /* XXX: propagate to caller?  or make fatal error? */
    assert(res > 0);
    wbuf[wbuflen - 1] = L'\0';
}

/* On failure returns INVALID_HANDLE_VALUE.
 * On success returns a file handle which must be closed via CloseHandle()
 * by the caller.
 */
static HANDLE
read_nt_headers(const char *exe, IMAGE_NT_HEADERS *nt)
{
    HANDLE f;
    DWORD offs;
    DWORD read;
    IMAGE_DOS_HEADER dos;
    TCHAR wexe[MAXIMUM_PATH];
    char_to_tchar(exe, wexe, BUFFER_SIZE_ELEMENTS(wexe));
    f = CreateFile(wexe, GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        goto read_nt_headers_error;
    if (!ReadFile(f, &dos, sizeof(dos), &read, NULL) ||
        read != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE)
        goto read_nt_headers_error;
    offs = SetFilePointer(f, dos.e_lfanew, NULL, FILE_BEGIN);
    if (offs == INVALID_SET_FILE_POINTER)
        goto read_nt_headers_error;
    if (!ReadFile(f, nt, sizeof(*nt), &read, NULL) ||
        read != sizeof(*nt) ||
        nt->Signature != IMAGE_NT_SIGNATURE)
        goto read_nt_headers_error;
    return f;
 read_nt_headers_error:
    if (f != INVALID_HANDLE_VALUE)
        CloseHandle(f);
    return INVALID_HANDLE_VALUE;
}

static bool
is_graphical_app(const char *exe)
{
    /* reads the PE headers to see whether the given image is a graphical app */
    bool res = false; /* err on side of console */
    IMAGE_NT_HEADERS nt;
    HANDLE f = read_nt_headers(exe, &nt);
    if (f == INVALID_HANDLE_VALUE)
        return res;
    res = (nt.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
    CloseHandle(f);
    return res;
}

static bool
is_64bit_app(const char *exe)
{
    bool res = false;
    IMAGE_NT_HEADERS nt;
    HANDLE f = read_nt_headers(exe, &nt);
    if (f == INVALID_HANDLE_VALUE)
        return res;
    res = (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    CloseHandle(f);
    return res;
}

/* Replace occurences of old_char with new_char in str.  Typically used to
 * canonicalize Windows paths into using forward slashes.
 */
void
string_replace_character(char *str, char old_char, char new_char)
{
    while (*str != '\0') {
        if (*str == old_char) {
            *str = new_char;
        }
        str++;
    }
}

void
string_replace_character_wide(TCHAR *str, TCHAR old_char, TCHAR new_char)
{
    while (*str != _T('\0')) {
        if (*str == old_char) {
            *str = new_char;
        }
        str++;
    }
}

static bool
ends_in_exe(const char *s)
{
    /* really we want caseless strstr */
    size_t len = strlen(s);
    return (len > 4 && s[len-4] == '.' &&
            (s[len-3] == 'E' || s[len-3] == 'e') &&
            (s[len-2] == 'X' || s[len-2] == 'x') &&
            (s[len-1] == 'E' || s[len-1] == 'e'));
}

static bool
file_is_writable(char *path)
{
    TCHAR wbuf[MAXIMUM_PATH];
    char_to_tchar(path, wbuf, BUFFER_SIZE_ELEMENTS(wbuf));
    return (_taccess(wbuf, 2/*write*/) == 0);
}

static bool
file_is_readable(char *path)
{
    TCHAR wbuf[MAXIMUM_PATH];
    char_to_tchar(path, wbuf, BUFFER_SIZE_ELEMENTS(wbuf));
    return (_taccess(wbuf, 4/*read*/) == 0);
}

static bool
get_env_var(const TCHAR *name, char *buf, size_t buflen/*# elements*/)
{
    TCHAR wbuf[MAXIMUM_PATH];
    int len = GetEnvironmentVariable(name, wbuf, BUFFER_SIZE_ELEMENTS(wbuf));
    if (len > 0) {
        tchar_to_char(wbuf, buf, buflen);
        return true;
    }
    return false;
}

/* Takes in UTF-16 and returns UTF-8 when _UNICODE is set */
static void
get_absolute_path_wide(const TCHAR *wsrc, char *buf, size_t buflen/*# elements*/)
{
    TCHAR wdst[MAXIMUM_PATH];
    int res = GetFullPathName(wsrc, BUFFER_SIZE_ELEMENTS(wdst), wdst, NULL);
    assert(res > 0);
    NULL_TERMINATE_BUFFER(wdst);
    tchar_to_char(wdst, buf, buflen);
}

static void
get_absolute_path(const char *src, char *buf, size_t buflen/*# elements*/)
{
    TCHAR wsrc[MAXIMUM_PATH];
    char_to_tchar(src, wsrc, BUFFER_SIZE_ELEMENTS(wsrc));
    get_absolute_path_wide(wsrc, buf, buflen);
}

static void
get_full_path(const char *app, char *buf, size_t buflen/*# elements*/)
{
    int res;
    TCHAR wbuf[MAXIMUM_PATH];
    TCHAR wapp[MAXIMUM_PATH];
    char_to_tchar(app, wapp, BUFFER_SIZE_ELEMENTS(wapp));
    _tsearchenv(wapp, _T("PATH"), wbuf);
    NULL_TERMINATE_BUFFER(wbuf);
    if (wbuf[0] == _T('\0')) {
        /* may need to append .exe, FIXME : other executable types */
        TCHAR tmp_buf[MAXIMUM_PATH];
        _sntprintf(tmp_buf, BUFFER_SIZE_ELEMENTS(tmp_buf), _T("%s%s"), wapp, _T(".exe"));
        NULL_TERMINATE_BUFFER(wbuf);
        _tsearchenv(tmp_buf, _T("PATH"), wbuf);
    }
    if (wbuf[0] == _T('\0')) {
        /* last try: expand w/ cur dir */
        GetFullPathName(wapp, BUFFER_SIZE_ELEMENTS(wbuf), wbuf, NULL);
        NULL_TERMINATE_BUFFER(wbuf);
    }
    tchar_to_char(wbuf, buf, buflen);
}

/* i#200/PR 459481: communicate child pid via file */
static void
write_pid_to_file(const char *pidfile, process_id_t pid)
{
    TCHAR wpidfile[MAXIMUM_PATH];
    HANDLE f;
    char_to_tchar(pidfile, wpidfile, BUFFER_SIZE_ELEMENTS(wpidfile));
    f = CreateFile(wpidfile, GENERIC_WRITE, FILE_SHARE_READ,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        warn("cannot open %s: %d", pidfile, GetLastError());
    } else {
        char pidbuf[16];
        BOOL ok;
        DWORD written;
        _snprintf(pidbuf, BUFFER_SIZE_ELEMENTS(pidbuf), "%d\n", pid);
        NULL_TERMINATE_BUFFER(pidbuf);
        ok = WriteFile(f, pidbuf, (DWORD)strlen(pidbuf), &written, NULL);
        assert(ok && written == strlen(pidbuf));
        CloseHandle(f);
    }
}

/* Sets up _NT_SYMBOL_PATH for drsyms symbol lookup and saves a copy in
 * symsrv_path for downloading missing pdbs later.  If the user set
 * _NT_SYMBOL_PATH, we use that and add the Microsoft symbol server if it's
 * missing.
 *
 * DR's private loader does *not* support loading symsrv.dll, and if
 * _NT_SYMBOL_PATH has any symbol servers, dbghelp will fail to load any
 * symbols.  Therefore, we strip all servers when setting _NT_SYMBOL_PATH for
 * the app.
 */
static void
set_symbol_search_path(const char *logdir, bool ignore_env)
{
    char app_symsrv_path[MAX_SYMSRV_PATH];
    TCHAR wapp_symsrv_path[MAX_SYMSRV_PATH];
    char tmp_srv_path[MAX_SYMSRV_PATH];
    char *cur;
    char *end;
    size_t sofar;
    ssize_t len;
    bool has_srv;
    bool has_ms_symsrv;

    /* If the user set a non-empty _NT_SYMBOL_PATH, then we use that.
     * Otherwise, we set it to logs/symbols and make sure it exists.
     */
    if (ignore_env ||
        get_env_var(_T("_NT_SYMBOL_PATH"), symsrv_path,
                    BUFFER_SIZE_ELEMENTS(symsrv_path)) == 0 ||
        strlen(symsrv_path) == 0) {
        char pdb_dir[MAXIMUM_PATH];
        _snprintf(pdb_dir, BUFFER_SIZE_ELEMENTS(pdb_dir), "%s/symbols", logdir);
        NULL_TERMINATE_BUFFER(pdb_dir);
        string_replace_character(pdb_dir, ALT_DIRSEP, DIRSEP); /* canonicalize */
        dr_create_dir(pdb_dir);
        if (!dr_directory_exists(pdb_dir)) {
            warn("Failed to create directory for symbols: %s", pdb_dir);
        }
        strncpy(symsrv_path, pdb_dir, BUFFER_SIZE_ELEMENTS(symsrv_path));
        NULL_TERMINATE_BUFFER(symsrv_path);
    }

    /* Prepend "srv*" if it isn't there, and append the MS symbol server if it
     * isn't there.
     */
    has_srv = (_strnicmp("srv*", symsrv_path, 4) == 0);
    has_ms_symsrv = (strstr(symsrv_path, ms_symsrv) != NULL);
    _snprintf(tmp_srv_path, BUFFER_SIZE_ELEMENTS(tmp_srv_path),
              "%s%s%s%s",
              (has_srv ? "" : "srv*"),
              symsrv_path,
              (has_ms_symsrv ? "" : "*"),
              (has_ms_symsrv ? "" : ms_symsrv));
    NULL_TERMINATE_BUFFER(tmp_srv_path);
    strncpy(symsrv_path, tmp_srv_path, BUFFER_SIZE_ELEMENTS(symsrv_path));
    NULL_TERMINATE_BUFFER(symsrv_path);

    /* For app_symsrv_path, split symsrv_path on '*' and filter out all the
     * non-directory elements.
     */
    strncpy(tmp_srv_path, symsrv_path, BUFFER_SIZE_ELEMENTS(tmp_srv_path));
    NULL_TERMINATE_BUFFER(tmp_srv_path);
    cur = tmp_srv_path;
    end = strchr(tmp_srv_path, '\0');
    string_replace_character(tmp_srv_path, '*', '\0');
    sofar = 0;
    app_symsrv_path[0] = '\0';
    while (cur < end) {
        char *next = strchr(cur, '\0');
        if (dr_directory_exists(cur)) {
            BUFPRINT(app_symsrv_path, BUFFER_SIZE_ELEMENTS(app_symsrv_path),
                     sofar, len, "%s*", cur);
        }
        cur = next + 1;
    }
    if (sofar > 0)
        app_symsrv_path[sofar-1] = '\0';  /* Cut trailing '*'. */
    if (app_symsrv_path[0] == '\0') {
        if (!ignore_env) {
            warn("_NT_SYMBOL_PATH incorrect: using local location instead");
            /* Easiest to recurse.  Bool prevents 2nd recursion. */
            set_symbol_search_path(logdir, true);
            return;
        } else {
            warn("error parsing _NT_SYMBOL_PATH: may fail to fetch symbols");
        }
    }
    info("using symbol path %s as the local store", app_symsrv_path);
    info("using symbol path %s to fetch symbols", symsrv_path);

    /* Set _NT_SYMBOL_PATH for dbghelp in the app. */
    char_to_tchar(app_symsrv_path, wapp_symsrv_path,
                  BUFFER_SIZE_ELEMENTS(wapp_symsrv_path));
    if (!SetEnvironmentVariable(_T("_NT_SYMBOL_PATH"), wapp_symsrv_path)) {
        warn("SetEnvironmentVariable failed: %d", GetLastError());
    }
}

static BOOL
fetch_module_symbols(HANDLE proc, const char *modpath)
{
    DWORD64 base;
    IMAGEHLP_MODULEW64 mod_info;
    BOOL got_pdbs = FALSE;
    TCHAR wmodpath[MAXIMUM_PATH];
    char_to_tchar(modpath, wmodpath, BUFFER_SIZE_ELEMENTS(wmodpath));

    /* XXX: If we port the C frontend to Linux, we can make this shell out to a
     * bash script that uses apt/yum to install debug info.
     * XXX: We could push the fetching logic into drsyms to make the frontend
     * portable.  We'd have to link the frontend against drmemorylib because we
     * use DR_EXT_DRSYMS_STATIC.
     */

    /* The SymSrv* API calls are complicated.  It's easier to set the symbol
     * path to point at a server and rely on SymLoadModuleEx to fetch symbols.
     */

    /* We must use SymLoadModuleEx as there's no wide version of SymLoadModule64 */
    base = SymLoadModuleExW(proc, NULL, wmodpath, NULL, 0, 0, NULL, 0);
    if (base == 0) {
        warn("SymLoadModuleEx error: %d", GetLastError());
        return got_pdbs;
    }

    /* Check that we actually got pdbs. */
    memset(&mod_info, 0, sizeof(mod_info));
    mod_info.SizeOfStruct = sizeof(mod_info);
    if (SymGetModuleInfoW64(proc, base, &mod_info)) {
        switch (mod_info.SymType) {
        case SymPdb:
        case SymDeferred:
            if (verbose) {
                sym_info("  pdb for %s stored at %S",
                     modpath, mod_info.LoadedPdbName);
            }
            got_pdbs = TRUE;
            break;
        case SymExport:
            if (verbose) {
                sym_info("  failed to fetch pdb for %s, exports only", modpath);
            }
            break;
        default:
            if (verbose) {
                sym_info("  failed to fetch pdb for %s, got SymType %d",
                         modpath, mod_info.SymType);
            }
            break;
        }
    } else {
        warn("SymGetModuleInfoEx failed: %d", GetLastError());
    }

    /* Unload it. */
    if (!SymUnloadModule64(proc, base)) {
        warn("SymUnloadModule64 error %d", GetLastError());
    }

    return got_pdbs;
}

/* Return true if we should fetch this symbol file.  Modifies modpath to make it
 * a long path and assumes it is MAXIMUM_PATH bytes long.
 */
static bool
should_fetch_symbols(const TCHAR *system_root, char *modpath)
{
    TCHAR wmodpath[MAXIMUM_PATH];
    bool r;
    string_replace_character(modpath, '\n', '\0');  /* Trailing newline. */
    /* Convert to a long path to compare with $SystemRoot.  These paths are
     * already absolute, but some of them, like sophos-detoured.dll, are
     * 8.3 style paths.
     */
    char_to_tchar(modpath, wmodpath, BUFFER_SIZE_ELEMENTS(wmodpath));
    if (GetLongPathName(wmodpath, wmodpath, BUFFER_SIZE_ELEMENTS(wmodpath)) == 0) {
        warn("GetLongPathName failed: %d", GetLastError());
    }
    /* We only fetch pdbs for system libraries.  Everything else was
     * probably built on the user's machine, so if the pdbs aren't there,
     * attempting to fetch them will be futile.
     */
    r = (_tcsnicmp(system_root, wmodpath, _tcslen(system_root)) == 0);
    /* By default, we only fetch CRT symbols. */
    if (r && fetch_crt_syms_only) {
        const TCHAR *basename;
        basename = _tcsrchr(wmodpath, _T('\\'));  /* GetLongPathName uses \ only. */
        basename = (basename == NULL ? wmodpath : basename + 1);
        r = (_tcsnicmp(_T("msvc"), basename, 4) == 0);
    }
    info("%s: modpath %s => %d", __FUNCTION__, modpath, r);
    return r;
}

static void
fetch_missing_symbols(const char *logdir, const TCHAR *resfile)
{
    TCHAR missing_symbols[MAXIMUM_PATH];
    char line[MAXIMUM_PATH];
    FILE *stream;
    TCHAR *last_slash;
    HANDLE proc = GetCurrentProcess();
    int num_files;
    int cur_file;
    int files_fetched;
    TCHAR system_root[MAXIMUM_PATH];
    DWORD len;
    TCHAR wsymsrv_path[MAX_SYMSRV_PATH];

    /* Get %SystemRoot%. */
    len = GetWindowsDirectory(system_root, BUFFER_SIZE_ELEMENTS(system_root));
    if (len == 0) {
        _tcsncpy(system_root, _T("C:\\Windows"), BUFFER_SIZE_ELEMENTS(system_root));
        NULL_TERMINATE_BUFFER(system_root);
    }
    _tcsncpy(missing_symbols, resfile, BUFFER_SIZE_ELEMENTS(missing_symbols));
    NULL_TERMINATE_BUFFER(missing_symbols);
    string_replace_character_wide(missing_symbols, _T(ALT_DIRSEP), _T(DIRSEP));
    last_slash = _tcsrchr(missing_symbols, _T(DIRSEP));
    if (last_slash == NULL) {
        warn(TSTR_FMT" is not an absolute path", missing_symbols);
        return;
    }
    *last_slash = _T(DIRSEP);
    *(last_slash+1) = _T('\0'); /* safe, since was null-terminated prior to _tcsrchr */
    _tcscat_s(missing_symbols, BUFFER_SIZE_ELEMENTS(missing_symbols),
              _T("missing_symbols.txt"));
    NULL_TERMINATE_BUFFER(missing_symbols);

    stream = _tfopen(missing_symbols, _T("r"));
    if (stream == NULL) {
        warn("can't open "TSTR_FMT" to fetch missing symbols", missing_symbols);
        return;
    }

    /* Count the number of files we intend to fetch up front.  Each line is a
     * module path, so MAXIMUM_PATH is always enough.
     */
    num_files = 0;
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
        if (should_fetch_symbols(system_root, line))
            num_files++;
    }
    fseek(stream, 0, SEEK_SET);  /* Back to beginning. */

    /* Don't initialize dbghelp and symsrv if there are no syms to fetch. */
    if (num_files == 0)
        goto stream_cleanup;

    /* Initializing dbghelp can be slow, so print something to the user. */
    sym_info("Fetching %d symbol files...", num_files);

    char_to_tchar(symsrv_path, wsymsrv_path, BUFFER_SIZE_ELEMENTS(wsymsrv_path));
    if (!SymInitializeW(proc, wsymsrv_path, FALSE)) {
        warn("SymInitialize error %d", GetLastError());
        goto stream_cleanup;
    }
    SymSetSearchPathW(proc, wsymsrv_path);

    cur_file = 0;
    files_fetched = 0;
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
        if (should_fetch_symbols(system_root, line)) {
            cur_file++;
            sym_info("[%d/%d] Fetching symbols for %s",
                     cur_file, num_files, line);
            if (fetch_module_symbols(proc, line))
                files_fetched++;
        }
    }
    if (!SymCleanup(proc))
        warn("SymCleanup error %d", GetLastError());

stream_cleanup:
    fclose(stream);
    if (num_files > 0) {
        sym_info("Fetched %d symbol files successfully", files_fetched);
    }
}

/* Rather than iterating to find the most recent dir w/ pid in name,
 * or risk running into the client option length limit by passing in a
 * file to write the results to, the client always writes to
 * <logdir>/resfile.<pid>.  There is a race here since we're reading
 * it after the app exited and another app of same pid could start up,
 * but we live with it since extremely unlikely.
 */
static void
process_results_file(const char *logdir, process_id_t pid, const char *app)
{
    HANDLE f;
    TCHAR fname[MAXIMUM_PATH];
    char resfile[MAXIMUM_PATH];
    TCHAR wresfile[MAXIMUM_PATH];
    DWORD read;
    if (no_resfile || (quiet && batch))
        return;
    dr_snwprintf(fname, BUFFER_SIZE_ELEMENTS(fname), _T(TSTR_FMT)_T("/resfile.%d"),
                 logdir, pid);
    NULL_TERMINATE_BUFFER(fname);
    f = CreateFile(fname, GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        warn("unable to locate results file since can't open "TSTR_FMT": %d",
             fname, GetLastError());
        return;
    }
    if (!ReadFile(f, resfile, BUFFER_SIZE_ELEMENTS(resfile), &read, NULL)) {
        warn("unable to locate results file since can't read "TSTR_FMT": %d",
             fname, GetLastError());
        CloseHandle(f);
        return;
    }
    assert(read < BUFFER_SIZE_ELEMENTS(resfile));
    resfile[read] = '\0';
    CloseHandle(f);
    /* We are now done with the file */
    if (!DeleteFile(fname)) {
        warn("unable to delete temp file "TSTR_FMT": %d", fname, GetLastError());
    }
    char_to_tchar(resfile, wresfile, BUFFER_SIZE_ELEMENTS(wresfile));

    if (!quiet &&
        /* On vista, or win7+ with i#440, output works from client, even during exit */
        !on_vista_or_later()) {
        /* Even with console-writing support from DR, the client cannot write
         * to a cmd console from the exit event: nor can it write for a graphical
         * application (xref i#261/PR 562198).  Thus when within cmd we always
         * paste the results from the file here.
         *
         * Identifying cmd: for a Windows app, env vars do not help us: even
         * when launched from a cygwin shell, ComSpec is set and SHELL,
         * etc. are not.  So we check whether the bottom 2 bits of the std
         * handles are set: if so, these are handled by csrss, and thus
         * we're in cmd.
         */
        bool in_cmd = ((((ptr_int_t)GetStdHandle(STD_OUTPUT_HANDLE)) & 0x10000003)
                       == 0x3);
        /* Don't show leaks for graphical app, since won't have other errors */
        bool show_leaks = !quiet && results_to_stderr && !is_graphical_app(app);
        if (in_cmd) {
            FILE *stream;
            char line[100];
            bool found_summary = false, in_leak = false;
            if ((stream = _tfopen(wresfile, _T("r"))) != NULL) {
                while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
                    if (!found_summary) {
                        found_summary = (strstr(line, "ERRORS FOUND:") == line ||
                                         strstr(line, "NO ERRORS FOUND:") == line);
                        if (found_summary)
                            fprintf(stderr, "%s\r\n", prefix);
                    }
                    if (!in_leak && show_leaks) {
                        in_leak = (strstr(line, ": LEAK") != NULL) ||
                            (strstr(line, ": POSSIBLE LEAK") != NULL) ||
                            (strstr(line, ": REACHABLE LEAK") != NULL);
                        if (in_leak)
                            fprintf(stderr, "%s\r\n", prefix);
                    } else {
                        if (line[0] == '\r' || line[0] == '\n')
                            in_leak = false;
                    }
                    if (found_summary || in_leak)
                        fprintf(stderr, "%s%s", prefix, line);
                }
                fclose(stream);
            }
        }
    }

    if (!batch) {
        /* Pop up notepad in background w/ results file */
        PROCESS_INFORMATION pi;
        STARTUPINFO si;
        TCHAR cmd[MAXIMUM_PATH*2];
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        _tsearchenv(_T("notepad.exe"), _T("PATH"), fname);
        NULL_TERMINATE_BUFFER(fname);
        /* Older notepad can't handle forward slashes (i#1123) */
        string_replace_character_wide(wresfile, _T('/'), _T('\\'));
        _sntprintf(cmd, BUFFER_SIZE_ELEMENTS(cmd), _T("%s %s"), fname, wresfile);
        NULL_TERMINATE_BUFFER(cmd);
        if (!CreateProcess(fname, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            warn("cannot run \"%s\": %d", cmd, GetLastError());
        } else {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    /* We provide an option to allow the user to turn this feature off. */
    if (fetch_symbols || fetch_crt_syms_only) {
        info("fetching symbols");
        fetch_missing_symbols(logdir, wresfile);
    } else {
        info("skipping symbol fetching");
    }
}

int
_tmain(int argc, TCHAR *targv[])
{
    char **argv;
    char *process = NULL;
    char *dr_root = NULL;
    char *drmem_root = NULL;
    char default_dr_root[MAXIMUM_PATH];
    char default_drmem_root[MAXIMUM_PATH];
    char client_path[MAXIMUM_PATH];

    char client_ops[MAX_DR_CMDLINE];
    size_t cliops_sofar = 0; /* for BUFPRINT to client_ops */
    char dr_ops[MAX_DR_CMDLINE];
    size_t drops_sofar = 0; /* for BUFPRINT to dr_ops */
    ssize_t len; /* shared by all BUFPRINT */

    /* passed through to client but first we make absolute and check existence.
     * we also use logdir to find results.txt and launch notepad.
     */
    char logdir[MAXIMUM_PATH];
    char suppress[MAXIMUM_PATH];
    char scratch[MAXIMUM_PATH];
    char persist_dir[MAXIMUM_PATH];

    bool use_dr_debug = false;
    bool use_drmem_debug = false;
    char *pidfile = NULL;
    process_id_t nudge_pid = 0;
    bool native_parent = false;
    size_t native_parent_pos = 0; /* holds cliops_sofar of "-native_parent" */

    char *app_name;
    char full_app_name[MAXIMUM_PATH];
    char **app_argv;

    int errcode;
    void *inject_data;
    int i;
    char *c;
    char buf[MAXIMUM_PATH];
    process_id_t pid;
    bool have_logdir = false;
    bool persisting = false;
    bool exit0 = false;
    bool dr_logdir_specified = false;
    bool doubledash_present = false;

    time_t start_time, end_time;

    if (dr_standalone_init() == NULL) {
        /* We assume this is due to a new version of Windows */
        fatal("this version of Windows is not supported by Dr. Memory.");
    }

    /* i#1377: we can't trust GetVersionEx() b/c it pretends 6.3 (Win8.1) is 
     * 6.2 (Win8)!  Thus we use DR's version.
     */
    win_ver.size = sizeof(win_ver);
    if (!dr_get_os_version(&win_ver))
        fatal("unable to determine Windows version");
    /* This will likely be caught by the DR failure, but we allow a separate
     * check in case DrMem has a different version requirement from DR.
     */
    if (!on_supported_version())
        fatal("this version of Windows is not supported by Dr. Memory.");

#ifdef _UNICODE
    /* To simplify our (soon-to-be) cross-platform code we convert to utf8 up front.
     * We need to do this for app_argv in any case so there's not much extra
     * work here.
     */
    argv = (char **) malloc((argc + 1/*null*/)*sizeof(*argv));
    for (i = 0; i < argc; i++) {
        size_t len = tchar_to_char_size_needed(targv[i]);
        argv[i] = (char *) malloc(len); /* len includes terminating null */
        tchar_to_char(targv[i], argv[i], len);
    }
    argv[i] = NULL;
#else
# ifdef _MBCS
#  error _MBCS not supported: only _UNICODE or ascii
# endif
    argv = targv;
#endif

    /* Default root: we assume this exe is <root>/bin/drmemory.exe */
    get_full_path(argv[0], buf, BUFFER_SIZE_ELEMENTS(buf));
    c = buf + strlen(buf) - 1;
    while (*c != DIRSEP && *c != ALT_DIRSEP && c > buf)
        c--;
    _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "../dynamorio");
    NULL_TERMINATE_BUFFER(buf);
    get_absolute_path(buf, default_dr_root, BUFFER_SIZE_ELEMENTS(default_dr_root));
    NULL_TERMINATE_BUFFER(default_dr_root);
    dr_root = default_dr_root;

    /* assuming we're in bin/ (mainly due to CPack NSIS limitations) */
    _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "..");
    NULL_TERMINATE_BUFFER(buf);
    get_absolute_path(buf, default_drmem_root, BUFFER_SIZE_ELEMENTS(default_drmem_root));
    NULL_TERMINATE_BUFFER(default_drmem_root);
    drmem_root = default_drmem_root;
    string_replace_character(drmem_root, ALT_DIRSEP, DIRSEP); /* canonicalize */

    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "%s ", DEFAULT_DR_OPS);
    /* FIXME i#699: early injection crashes the child on 32-bit or on wow64 vista+.
     * We work around it here.  Should remove this once the real bug is fixed.
     */
    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "-no_early_inject ");

    /* default logdir */
    if (strstr(drmem_root, "Program Files") != NULL) {
        /* On Vista+ we can't write to Program Files; plus better to not store
         * logs there on 2K or XP either.
         */
        bool have_env = get_env_var(_T("APPDATA"), buf, BUFFER_SIZE_ELEMENTS(buf));
        if (have_env) {
            _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s/Dr. Memory", buf);
            NULL_TERMINATE_BUFFER(logdir);
        } else {
            have_env = get_env_var(_T("USERPROFILE"), buf, BUFFER_SIZE_ELEMENTS(buf));
            if (have_env) {
                _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), 
                          "%s/Application Data/Dr. Memory", buf);
                NULL_TERMINATE_BUFFER(logdir);
            }
        }
        if (have_env) {
            if (dr_create_dir(logdir) || dr_directory_exists(logdir)) {
                have_logdir = true;
            }
        }
    } else {
        _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s%cdrmemory%clogs",
                  drmem_root, DIRSEP, DIRSEP);
        NULL_TERMINATE_BUFFER(logdir);
        if (!file_is_writable(logdir)) {
            /* try w/o the drmemory */
            _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s%clogs",
                      drmem_root, DIRSEP);
            NULL_TERMINATE_BUFFER(logdir);
            if (file_is_writable(logdir))
                have_logdir = true;
        } else
            have_logdir = true;
    }
    if (!have_logdir) {
        /* try logs in cur dir */
        get_absolute_path("./logs", logdir, BUFFER_SIZE_ELEMENTS(logdir));
        NULL_TERMINATE_BUFFER(logdir);
        if (!file_is_writable(logdir)) {
            /* try cur dir */
            get_absolute_path(".", logdir, BUFFER_SIZE_ELEMENTS(logdir));
            NULL_TERMINATE_BUFFER(logdir);
        }
    }

    persist_dir[0] = '\0';

    /* parse command line */
    /* FIXME PR 487993: use optionsx.h to construct this parsing code */
    for (i=1; i<argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            doubledash_present = true;
            break;
        }
    }
    for (i=1; i<argc; i++) {

        /* note that we pass unknown args to client, until -- */
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
	}
        /* drag-and-drop does not include "--" so we try to identify the app.
         * we explicitly parse -logdir and -suppress, and all the other
         * client ops that take args take numbers so this should be safe.
         */
        else if (argv[i][0] != '-' && !doubledash_present && ends_in_exe(argv[i])) {
            /* leave i alone: this is the app itself */
            break;
	}
        else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
            continue;
        }
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            print_usage(true/*full*/);
            exit(0);
        }
        else if (strcmp(argv[i], "-quiet") == 0) {
            /* -quiet is also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "%s ", argv[i]);
            quiet = true;
            continue;
        }
        else if (strcmp(argv[i], "-no_results_to_stderr") == 0) {
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "%s ", argv[i]);
            results_to_stderr = false;
            continue;
        }
        else if (strcmp(argv[i], "-batch") == 0) {
            batch = true;
            continue;
        }
        else if (strcmp(argv[i], "-visual_studio") == 0) {
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "%s ", argv[i]);
            /* XXX: share this logic w/ the client */
            batch = true;
            prefix = PREFIX_BLANK;
            continue;
        }
        else if (strcmp(argv[i], "-prefix_style") == 0) {
            int style;
            if (i >= argc - 1)
                usage("invalid arguments");
            style = atoi(argv[++i]);
            if (style == PREFIX_STYLE_NONE)
                prefix = "";
            else if (style == PREFIX_STYLE_BLANK)
                prefix = PREFIX_BLANK;
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "%s %s ", argv[i-1], argv[i]);
            continue;
        }
        else if (strcmp(argv[i], "-fetch_symbols") == 0) {
            fetch_symbols = true;
            fetch_crt_syms_only = false;
            continue;
        }
        else if (strcmp(argv[i], "-no_fetch_symbols") == 0) {
            fetch_symbols = false;
            fetch_crt_syms_only = false;
            continue;
        }
        else if (strcmp(argv[i], "-top_stats") == 0) {
            top_stats = true;
            continue;
        }
        else if (strcmp(argv[i], "-dr_debug") == 0) {
            use_dr_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-dr_release") == 0) {
            use_dr_debug = false;
            continue;
        }
        else if (strcmp(argv[i], "-debug") == 0) {
            use_drmem_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-release") == 0) {
            use_drmem_debug = false;
            continue;
        }
        else if (!strcmp(argv[i], "-version")) {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
          printf("Dr. Memory version %s -- build %d\n", VERSION_STRING, BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
          printf("Dr. Memory custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#elif defined(VERSION_NUMBER)
          printf("Dr. Memory version %s -- custom build %s, %s\n",
                 VERSION_STRING, __DATE__, __TIME__);
#else
          printf("Dr. Memory custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
          exit(0);
        }
        else if (strcmp(argv[i], "-dr") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            dr_root = argv[++i];
        }
        else if (strcmp(argv[i], "-drmemory") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            drmem_root = argv[++i];
        }
        else if (strcmp(argv[i], "-follow_children") == 0 ||
                 strcmp(argv[i], "-no_follow_children") == 0) {
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "%s ", argv[i]);
        }
        else if (strcmp(argv[i], "-nudge") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            nudge_pid = strtoul(argv[++i], NULL, 10);
        }        
        else if (strcmp(argv[i], "-native_parent") == 0) {
            native_parent = true;
            native_parent_pos = cliops_sofar;
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "-native_parent ");
        }
        else if (strcmp(argv[i], "-dr_ops") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* Slight risk of some other option containing "-logdir " but
             * -dr_ops is really only be used by Dr. Memory developers anyway.
             */
            if (strstr(argv[i+1], "-logdir ") != NULL)
                dr_logdir_specified = true;
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "%s ", argv[++i]);
        }
        else if (strcmp(argv[i], "-pid_file") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            pidfile = argv[++i];
        }
        else if (strcmp(argv[i], "-logdir") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* make absolute */
            get_absolute_path(argv[++i], logdir, BUFFER_SIZE_ELEMENTS(logdir));
            NULL_TERMINATE_BUFFER(logdir);
            /* added to client ops below */
        }
        else if (strcmp(argv[i], "-symcache_dir") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* make absolute */
            get_absolute_path(argv[++i], scratch, BUFFER_SIZE_ELEMENTS(scratch));
            NULL_TERMINATE_BUFFER(scratch);
            if (!file_is_writable(scratch)) {
                fatal("invalid -symcache_dir: cannot find/write %s", scratch);
                goto error; /* actually won't get here */
            }
            info("symcache_dir is \"%s\"", scratch);
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "-symcache_dir `%s` ", scratch);
        }
        else if (strcmp(argv[i], "-persist_code") == 0) {
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "-persist ");
            /* also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "-persist_code ");
            persisting = true;
        }
        else if (strcmp(argv[i], "-persist_dir") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* make absolute */
            get_absolute_path(argv[++i], persist_dir,
                              BUFFER_SIZE_ELEMENTS(persist_dir));
            NULL_TERMINATE_BUFFER(persist_dir);
            /* further processed below */
        }
        else if (strcmp(argv[i], "-suppress") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* front-end provides relative-to-absolute and existence check */
            /* make absolute */
            get_absolute_path(argv[++i], suppress, BUFFER_SIZE_ELEMENTS(suppress));
            NULL_TERMINATE_BUFFER(suppress);
            if (!file_is_readable(suppress)) {
                fatal("cannot find -suppress file %s", suppress);
                goto error; /* actually won't get here */
            }
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "-suppress `%s` ", suppress);
        }
        else if (strcmp(argv[i], "-exit0") == 0) {
            exit0 = TRUE;
        }
        else {
            if (strcmp(argv[i], "-perturb_only") == 0)
                no_resfile = true;
            /* pass to client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "`%s` ", argv[i]);
        }
    }

    if (nudge_pid != 0) {
        dr_config_status_t res;
        if (i < argc)
            usage("%s", "-nudge does not take an app to run");
        /* could also complain about other client or app specific ops */
        res = dr_nudge_pid(nudge_pid, DRMEM_CLIENT_ID, NUDGE_LEAK_SCAN, INFINITE);
        if (res != DR_SUCCESS) {
            fatal("error nudging %d%s", nudge_pid,
                  (res == DR_NUDGE_PID_NOT_INJECTED) ? ": no such Dr. Memory process"
                  : "");
            assert(false); /* shouldn't get here */
        }
        exit(0);
    }

    if (i >= argc)
        usage("%s", "no app specified");
    app_name = argv[i];
    get_full_path(app_name, full_app_name, BUFFER_SIZE_ELEMENTS(full_app_name));
    if (full_app_name[0] != '\0')
        app_name = full_app_name;
    info("targeting application: \"%s\"", app_name);

    /* note that we want target app name as part of cmd line
     * (FYI: if we were using WinMain, the pzsCmdLine passed in
     *  does not have our own app name in it)
     * it's easier to construct than to call GetCommandLine() and then
     * remove our own args.
     */
    app_argv = &argv[i];
    if (verbose) {
        int j;
        c = buf;
        for (j = 0; app_argv[j] != NULL; j++) {
            c += _snprintf(c, BUFFER_SIZE_ELEMENTS(buf) - (c - buf),
                           "\"%s\" ", app_argv[j]);
        }
        NULL_TERMINATE_BUFFER(buf);
        assert(c - buf < BUFFER_SIZE_ELEMENTS(buf));
        info("app cmdline: %s", buf);
    }

#ifndef X64
    /* Currently our builds and test suite are all single-arch and we don't
     * have a 64-bit build in the release package, so for a 32-bit frontend
     * we supply this useful message up front.  Once we do add 64-bit we'll
     * want to solve i#1037 and then get rid of or modify this message.
     */
    if (is_64bit_app(app_name)) {
        fatal("This Dr. Memory release does not support 64-bit applications.");
        goto error; /* actually won't get here */
    }
#endif

    if (!file_is_readable(dr_root)) {
        fatal("invalid -dr_root %s", dr_root);
        goto error; /* actually won't get here */
    }
    if (dr_root != default_dr_root) {
        /* Workaround for DRi#1082 where DR root path can't have ".." */
        get_absolute_path(dr_root, default_dr_root,
                          BUFFER_SIZE_ELEMENTS(default_dr_root));
        NULL_TERMINATE_BUFFER(default_dr_root);
        dr_root = default_dr_root;
    }
    _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), 
              "%s/"LIB_ARCH"/%s/dynamorio.dll", dr_root,
              use_dr_debug ? "debug" : "release");
    NULL_TERMINATE_BUFFER(buf);
    if (!file_is_readable(buf)) {
        /* support debug build w/ integrated debug DR build and so no release */
        if (!use_dr_debug) {
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), 
                      "%s/"LIB_ARCH"/%s/dynamorio.dll", dr_root, "debug");
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf)) {
                fatal("cannot find DynamoRIO library %s", buf);
                goto error; /* actually won't get here */
            }
            warn("using debug DynamoRIO since release not found");
            use_dr_debug = true;
        }
    }

    /* once we have 64-bit we'll need to address the NSIS "bin/" requirement */
    _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
              "%s%c"BIN_ARCH"%c%s%cdrmemorylib.dll", drmem_root, DIRSEP, DIRSEP,
              use_drmem_debug ? "debug" : "release", DIRSEP);
    NULL_TERMINATE_BUFFER(client_path);
    if (!file_is_readable(client_path)) {
        if (!use_drmem_debug) {
            _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s%c"BIN_ARCH"%c%s%cdrmemorylib.dll", drmem_root,
                      DIRSEP, DIRSEP, "debug", DIRSEP);
            NULL_TERMINATE_BUFFER(client_path);
            if (!file_is_readable(client_path)) {
                fatal("invalid -drmem_root: cannot find %s", client_path);
                goto error; /* actually won't get here */
            }
            /* try to avoid warning for devs running from build dir */
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s%cCMakeCache.txt", drmem_root, DIRSEP);
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf))
                warn("using debug Dr. Memory since release not found");
            use_drmem_debug = true;
        }
    }

    string_replace_character(logdir, ALT_DIRSEP, DIRSEP); /* canonicalize */
    if (!file_is_writable(logdir)) {
        fatal("invalid -logdir: cannot find/write %s", logdir);
        goto error; /* actually won't get here */
    }
    info("logdir is \"%s\"", logdir);
    BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
             cliops_sofar, len, "-logdir `%s` ", logdir);

    /* Put DR logs inside drmem logdir (i#874).
     * XXX DRi#886: if deployment API let us set the default logdir
     * we'd prefer that to avoid adding to option string length
     * for every run.
     */
    if (!dr_logdir_specified) { /* don't override user-specified DR logdir */
        _snprintf(scratch, BUFFER_SIZE_ELEMENTS(scratch), "%s%cdynamorio", logdir, DIRSEP);
        NULL_TERMINATE_BUFFER(scratch);
        /* Default dir is created at install/config time but if user specifies
         * a new base logdir we need to create the subdir.
         */
        if (!dr_directory_exists(scratch)) {
            if (!dr_create_dir(scratch)) {
                /* check again in case of a race */
                if (!dr_directory_exists(scratch)) {
                    fatal("cannot create %s", scratch);
                    goto error; /* actually won't get here */
                }
            }
        }
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-logdir `%s` ", scratch);
    }

    if (persisting) {
        /* default -persist_dir is not DR's default so we have to set it */
        if (persist_dir[0] == '\0') { /* not set by user */
            _snprintf(persist_dir, BUFFER_SIZE_ELEMENTS(persist_dir),
                      "%s%ccodecache", logdir, DIRSEP);
            NULL_TERMINATE_BUFFER(persist_dir);
            /* create it if not specified by user.
             * using dr_ API here since available and perhaps we'll want this
             * same frontend on linux someday.
             */
            if (!dr_directory_exists(persist_dir)) {
                if (!dr_create_dir(persist_dir)) {
                    /* check again in case of a race */
                    if (!dr_directory_exists(persist_dir)) {
                        fatal("cannot create %s", persist_dir);
                        goto error; /* actually won't get here */
                    }
                }
            }
        }
        string_replace_character(persist_dir, ALT_DIRSEP, DIRSEP); /* canonicalize */
        if (!file_is_writable(persist_dir)) {
            fatal("invalid -persist_dir: cannot find/write %s", persist_dir);
            goto error; /* actually won't get here */
        }
        info("persist_dir is \"%s\"", persist_dir);
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-persist_dir `%s` ", persist_dir);
    }

    /* Easier for the front-end to get the $SYSTEMROOT env var, so we set the
     * default value here.  We add ` to rule out -lib_blacklist_frames.
     */
    if (strstr(client_ops, "-lib_blacklist`") == NULL) {
        bool ok = get_env_var(_T("SYSTEMROOT"), buf, BUFFER_SIZE_ELEMENTS(buf));
        if (ok) {
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     /* Add .d?? to still report errors in app .exe but not
                      * in *.dll or *.drv.
                      */
                     cliops_sofar, len,
                     "-lib_blacklist %s*.d?? ",
                     buf);
        }
    }

    /* Set _NT_SYMBOL_PATH for the app. */
    set_symbol_search_path(logdir, false);

    errcode = dr_inject_process_create(app_name, app_argv, &inject_data);
    if (errcode != 0) {
        int sofar = _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                              "failed to create process for \"%s\": ", app_name);
        if (sofar > 0) {
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                          (LPTSTR) buf + sofar,
                          BUFFER_SIZE_ELEMENTS(buf) - sofar*sizeof(char), NULL);
        }
        NULL_TERMINATE_BUFFER(buf);
        fatal("%s", buf);
        goto error; /* actually won't get here */
    }

    pid = dr_inject_get_process_id(inject_data);
    if (pidfile != NULL)
        write_pid_to_file(pidfile, pid);

    /* we need to locate the results file, but only for top-level process (i#328) */
    BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
             cliops_sofar, len, "-resfile %d ", pid);

    process = dr_inject_get_image_name(inject_data);
    /* we don't care if this app is already registered for DR b/c our
     * this-pid config will override
     */
    info("configuring %s pid=%d dr_ops=\"%s\"", process, pid, dr_ops);
    if (dr_register_process(process, pid,
                            false/*local*/, dr_root,  DR_MODE_CODE_MANIPULATION,
                            use_dr_debug, DR_PLATFORM_DEFAULT, dr_ops) != DR_SUCCESS) {
        fatal("failed to register DynamoRIO configuration");
        goto error; /* actually won't get here */
    }
    info("configuring client \"%s\" ops=\"%s\"", client_path, client_ops);
    if (dr_register_client(process, pid,
                           false/*local*/, DR_PLATFORM_DEFAULT, DRMEM_CLIENT_ID,
                           0, client_path, client_ops) != DR_SUCCESS) {
        fatal("failed to register DynamoRIO client configuration");
        goto error; /* actually won't get here */
    }

    if (native_parent) {
        /* Create a regular config file without -native_parent so the children will
         * run normally.
         */
        info("configuring child processes");
        if (dr_process_is_registered(process, 0, false/*local*/, DR_PLATFORM_DEFAULT,
                                     NULL, NULL, NULL, NULL)) {
            if (dr_unregister_process(process, 0, false/*local*/, DR_PLATFORM_DEFAULT)
                == DR_SUCCESS)
                warn("overriding existing registration");
            else {
                fatal("failed to override existing registration");
                goto error; /* actually won't get here */
            }
        }
        if (dr_register_process(process, 0, false/*local*/, dr_root,
                                DR_MODE_CODE_MANIPULATION, use_dr_debug,
                                DR_PLATFORM_DEFAULT, dr_ops) != DR_SUCCESS) {
            fatal("failed to register child DynamoRIO configuration");
            goto error; /* actually won't get here */
        }
        /* clear out "-native_parent" */
        memset(client_ops + native_parent_pos, ' ', strlen("-native_parent"));
        if (dr_register_client(process, 0, false/*local*/, DR_PLATFORM_DEFAULT,
                               DRMEM_CLIENT_ID, 0, client_path, client_ops)
            != DR_SUCCESS) {
            fatal("failed to register child DynamoRIO client configuration");
            goto error; /* actually won't get here */
        }
    }

    if (!dr_inject_process_inject(inject_data, false/*!force*/, NULL)) {
        fatal("unable to inject");
        goto error; /* actually won't get here */
    }

    if (top_stats)
        start_time = time(NULL);
    dr_inject_process_run(inject_data);
    info("waiting for app to exit...");
    errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data), INFINITE);
    if (errcode != WAIT_OBJECT_0)
        info("failed to wait for app: %d\n", errcode);
    if (top_stats) {
        double wallclock;
        end_time = time(NULL);
        wallclock = difftime(end_time, start_time);
        dr_inject_print_stats(inject_data, (int) wallclock, true/*time*/, true/*mem*/);
    }
    if (native_parent) {
        if (dr_unregister_process(process, 0, false/*local*/, DR_PLATFORM_DEFAULT)
            != DR_SUCCESS)
            warn("failed to unregister child processes");
    }
    errcode = dr_inject_process_exit(inject_data, false/*don't kill process*/);
    process_results_file(logdir, pid, app_name);
    goto cleanup;
 error:
    dr_inject_process_exit(inject_data, false);
    errcode = 1;
 cleanup:
#ifdef _UNICODE
    for (i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
#endif
    if (errcode != 0) {
        /* We use a prefix to integrate better with tool output, esp inside
         * the VS IDE as an External Tool.
         */
        warn_prefix("application exited with abnormal code 0x%x", errcode);
    }
    return (exit0 ? 0 : errcode);
}
