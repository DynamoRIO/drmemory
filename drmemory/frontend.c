/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
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
 *   o -srcfilter: not supporting on Windows
 * - Very large symbol files that do not fit in the app address space
 *   are not yet supported: drsyms will eventually have symbol server
 *   support for those (PR 243532).
 */

#include "dr_api.h" /* for the types */
#include "dr_inject.h"
#include "dr_config.h"
#include "frontend.h"
#include <assert.h>
#include <dbghelp.h>
#include <stdio.h>
#include <time.h>

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)
#define MAX_APP_CMDLINE 4096

/* maybe DR should export these */
#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof(buf[0]))
#define BUFFER_LAST_ELEMENT(buf)    buf[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf)  BUFFER_LAST_ELEMENT(buf) = 0

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
 */
#define DEFAULT_DR_OPS \
    "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256"

#define DRMEM_CLIENT_ID 0

static bool verbose;
static bool quiet;
static bool results_to_stderr = true;
static bool batch; /* no popups */
static bool no_resfile; /* no results file expected */
static bool top_stats;

enum {
    /* _NT_SYMBOL_PATH typically has a local path and a URL. */
    MAX_SYMSRV_PATH = 2 * MAXIMUM_PATH
};

/* Symbol search path. */
static char symsrv_path[MAX_SYMSRV_PATH];

/* URL of the MS symbol server. */
static const char ms_symsrv[] = "http://msdl.microsoft.com/download/symbols";

#define prefix "~~Dr.M~~ "

#define fatal(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", __VA_ARGS__);    \
    fflush(stderr); \
    exit(1); \
} while (0)

#define warn(msg, ...) do { \
    if (!quiet) { \
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
        fprintf(stderr, prefix msg "\n", __VA_ARGS__); \
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
print_usage(void)
{
    fprintf(stderr, "usage: Dr. Memory [options] -- <app and args to run>\n");
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
    print_usage();                                              \
    exit(1);                                                    \
} while (0)

#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    len = _snprintf((buf)+(sofar), (bufsz)-(sofar), __VA_ARGS__); \
    sofar += (len < 0 ? 0 : len); \
    assert((bufsz) > (sofar)); \
    /* be paranoid: though usually many calls in a row and could delay until end */ \
    (buf)[(bufsz)-1] = '\0';                                 \
} while (0)

static bool
on_vista_or_later(void)
{
    OSVERSIONINFO version;
    version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    return (GetVersionEx(&version) &&
            version.dwPlatformId == VER_PLATFORM_WIN32_NT && 
            version.dwMajorVersion >= 6 &&
            version.dwMinorVersion >= 0);
}

static bool
is_graphical_app(const char *exe)
{
    /* reads the PE headers to see whether the given image is a graphical app */
    HANDLE f;
    DWORD offs;
    DWORD read;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    bool res = false; /* err on side of console */
    f = CreateFile(exe, GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return res;
    if (!ReadFile(f, &dos, sizeof(dos), &read, NULL) ||
        read != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE)
        goto is_graphical_app_done;
    offs = SetFilePointer(f, dos.e_lfanew, NULL, FILE_BEGIN);
    if (offs == INVALID_SET_FILE_POINTER)
        goto is_graphical_app_done;
    if (!ReadFile(f, &nt, sizeof(nt), &read, NULL) ||
        read != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE)
        goto is_graphical_app_done;
    res = (nt.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI);
 is_graphical_app_done:
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

static void
get_full_path(const char *app, char *buf, size_t buflen/*# elements*/)
{
    _searchenv(app, "PATH", buf);
    buf[buflen - 1] = '\0';
    if (buf[0] == '\0') {
        /* may need to append .exe, FIXME : other executable types */
        char tmp_buf[MAXIMUM_PATH];
        _snprintf(tmp_buf, BUFFER_SIZE_ELEMENTS(tmp_buf), "%s%s", app, ".exe");
        buf[buflen - 1] = '\0';
        _searchenv(tmp_buf, "PATH", buf);
    }
    if (buf[0] == '\0') {
        /* last try: expand w/ cur dir */
        GetFullPathName(app, buflen, buf, NULL);
        buf[buflen - 1] = '\0';
    }
}

/* i#200/PR 459481: communicate child pid via file */
static void
write_pid_to_file(const char *pidfile, process_id_t pid)
{
    HANDLE f = CreateFile(pidfile, GENERIC_WRITE, FILE_SHARE_READ,
                          NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        warn("cannot open %s: %d", pidfile, GetLastError());
    } else {
        TCHAR pidbuf[16];
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
set_symbol_search_path(const char *logdir)
{
    char app_symsrv_path[MAX_SYMSRV_PATH];
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
    if (GetEnvironmentVariable("_NT_SYMBOL_PATH", symsrv_path,
                               BUFFER_SIZE_ELEMENTS(symsrv_path)) == 0 ||
        strlen(symsrv_path) == 0) {
        char pdb_dir[MAXIMUM_PATH];
        _snprintf(pdb_dir, BUFFER_SIZE_ELEMENTS(pdb_dir), "%s/symbols", logdir);
        NULL_TERMINATE_BUFFER(pdb_dir);
        string_replace_character(pdb_dir, '\\', '/');
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
    info("using symbol path %s as the local store", app_symsrv_path);
    info("using symbol path %s to fetch symbols", symsrv_path);

    /* Set _NT_SYMBOL_PATH for dbghelp in the app. */
    if (!SetEnvironmentVariable("_NT_SYMBOL_PATH", app_symsrv_path)) {
        warn("SetEnvironmentVariable failed: %d", GetLastError());
    }
}

static BOOL
fetch_module_symbols(HANDLE proc, const char *modpath)
{
    DWORD64 base;
    IMAGEHLP_MODULE64 mod_info;
    BOOL got_pdbs = FALSE;

    /* XXX: If we port the C frontend to Linux, we can make this shell out to a
     * bash script that uses apt/yum to install debug info.
     * XXX: We could push the fetching logic into drsyms to make the frontend
     * portable.  We'd have to link the frontend against drmemorylib because we
     * use DR_EXT_DRSYMS_STATIC.
     */

    /* The SymSrv* API calls are complicated.  It's easier to set the symbol
     * path to point at a server and rely on SymLoadModule64 to fetch symbols.
     */
    base = SymLoadModule64(proc, NULL, (char *)modpath, NULL, 0, 0);
    if (base == 0) {
        warn("SymLoadModule64 error: %d", GetLastError());
        return got_pdbs;
    }

    /* Check that we actually got pdbs. */
    memset(&mod_info, 0, sizeof(mod_info));
    mod_info.SizeOfStruct = sizeof(mod_info);
    if (SymGetModuleInfo64(proc, base, &mod_info)) {
        switch (mod_info.SymType) {
        case SymPdb:
        case SymDeferred:
            if (verbose) {
                sym_info("  pdb for %s stored at %s",
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
        warn("SymGetModuleInfo64 failed: %d", GetLastError());
    }

    /* Unload it. */
    if (!SymUnloadModule64(proc, base)) {
        warn("SymUnloadModule64 error %d", GetLastError());
    }

    return got_pdbs;
}

static void
fetch_missing_symbols(const char *logdir, const char *resfile)
{
    char missing_symbols[MAXIMUM_PATH];
    char line[MAXIMUM_PATH];
    FILE *stream;
    char *last_slash;
    HANDLE proc = GetCurrentProcess();
    int num_files;
    int cur_file;
    int files_fetched;
    char system_root[MAXIMUM_PATH];
    DWORD len;

    /* Get %SystemRoot%. */
    len = GetWindowsDirectory(system_root, BUFFER_SIZE_ELEMENTS(system_root));
    if (len == 0) {
        strncpy(system_root, "C:\\Windows", sizeof(system_root));
        NULL_TERMINATE_BUFFER(system_root);
    }

    strncpy(missing_symbols, resfile, BUFFER_SIZE_ELEMENTS(missing_symbols));
    NULL_TERMINATE_BUFFER(missing_symbols);
    string_replace_character(missing_symbols, '\\', '/');
    last_slash = strrchr(missing_symbols, '/');
    if (last_slash == NULL) {
        warn("%s is not an absolute path", missing_symbols);
        return;
    }
    *last_slash = '\0';
    strcat_s(missing_symbols, sizeof(missing_symbols), "/missing_symbols.txt");
    NULL_TERMINATE_BUFFER(missing_symbols);

    stream = fopen(missing_symbols, "r");
    if (stream == NULL) {
        warn("can't open %s to fetch missing symbols", missing_symbols);
        return;
    }

    /* Count the number of files we intend to fetch up front.  Each line is a
     * module path, so MAXIMUM_PATH is always enough.
     */
    num_files = 0;
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
        if (_strnicmp(system_root, line, strlen(system_root)) == 0)
            num_files++;
    }
    fseek(stream, 0, SEEK_SET);  /* Back to beginning. */

    /* Don't initialize dbghelp and symsrv if there are no syms to fetch. */
    if (num_files == 0)
        goto stream_cleanup;

    /* Initializing dbghelp can be slow, so print something to the user. */
    sym_info("Fetching %d symbol files...", num_files);

    if (!SymInitialize(proc, symsrv_path, FALSE)) {
        warn("SymInitialize error %d", GetLastError());
        goto stream_cleanup;
    }
    SymSetSearchPath(proc, symsrv_path);

    cur_file = 0;
    files_fetched = 0;
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
        string_replace_character(line, '\n', '\0');  /* Trailing newline. */
        /* Convert to a long path to compare with $SystemRoot.  These paths are
         * already absolute, but some of them, like sophos-detoured.dll, are
         * 8.3 style paths.
         */
        if (GetLongPathName(line, line, BUFFER_SIZE_ELEMENTS(line)) == 0) {
            warn("GetLongPathName failed: %d", GetLastError());
        }
        /* We only fetch pdbs for system libraries.  Everything else was
         * probably built on the user's machine, so if the pdbs aren't there,
         * attempting to fetch them will be futile.
         */
        if (_strnicmp(system_root, line, strlen(system_root)) == 0) {
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
    char fname[MAXIMUM_PATH];
    char resfile[MAXIMUM_PATH];
    DWORD read;
    if (no_resfile || (quiet && batch))
        return;
    _snprintf(fname, BUFFER_SIZE_ELEMENTS(fname), "%s/resfile.%d", logdir, pid);
    NULL_TERMINATE_BUFFER(fname);
    f = CreateFile(fname, GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        warn("unable to locate results file since can't open %s: %d",
             fname, GetLastError());
        return;
    }
    if (!ReadFile(f, resfile, BUFFER_SIZE_ELEMENTS(resfile), &read, NULL)) {
        warn("unable to locate results file since can't read %s: %d",
             fname, GetLastError());
        CloseHandle(f);
        return;
    }
    assert(read < BUFFER_SIZE_ELEMENTS(resfile));
    resfile[read] = '\0';
    CloseHandle(f);
    /* We are now done with the file */
    if (!DeleteFile(fname)) {
        warn("unable to delete temp file %s: %d", fname, GetLastError());
    }

    if (!quiet &&
        /* on vista, or win7+ with i#440, output works from client, even during exit */
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
            if ((stream = fopen(resfile, "r" )) != NULL) {
                while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
                    if (!found_summary) {
                        found_summary = (strstr(line, "ERRORS FOUND:") == line);
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
        char cmd[MAXIMUM_PATH*2];
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        _searchenv("notepad.exe", "PATH", fname);
        NULL_TERMINATE_BUFFER(fname);
        _snprintf(cmd, BUFFER_SIZE_ELEMENTS(cmd), "%s %s", fname, resfile);
        NULL_TERMINATE_BUFFER(cmd);
        if (!CreateProcess(fname, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            warn("cannot run \"%s\": %d", cmd, GetLastError());
        } else {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    fetch_missing_symbols(logdir, resfile);
}

int main(int argc, char *argv[])
{
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

    char *app_name;
    char full_app_name[MAXIMUM_PATH];
    char app_cmdline[MAX_APP_CMDLINE];

    int errcode;
    void *inject_data;
    int i;
    char *c;
    char buf[MAXIMUM_PATH];
    process_id_t pid;
    bool have_logdir = false;
    bool persisting = false;
    bool exit0 = false;

    time_t start_time, end_time;

    dr_standalone_init();

    /* Default root: we assume this exe is <root>/bin/drmemory.exe */
    get_full_path(argv[0], buf, BUFFER_SIZE_ELEMENTS(buf));
    c = buf + strlen(buf) - 1;
    while (*c != '\\' && *c != '/' && c > buf)
        c--;
    _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "../dynamorio");
    NULL_TERMINATE_BUFFER(buf);
    GetFullPathName(buf, BUFFER_SIZE_ELEMENTS(default_dr_root), default_dr_root, NULL);
    NULL_TERMINATE_BUFFER(default_dr_root);
    dr_root = default_dr_root;

    /* assuming we're in bin/ (mainly due to CPack NSIS limitations) */
    _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "..");
    NULL_TERMINATE_BUFFER(buf);
    GetFullPathName(buf, BUFFER_SIZE_ELEMENTS(default_drmem_root),
                    default_drmem_root, NULL);
    NULL_TERMINATE_BUFFER(default_drmem_root);
    drmem_root = default_drmem_root;

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
        int len = GetEnvironmentVariableA("APPDATA", buf, BUFFER_SIZE_ELEMENTS(buf));
        bool have_env = false;
        if (len > 0) {
            _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s/Dr. Memory", buf);
            NULL_TERMINATE_BUFFER(logdir);
            have_env = true;
        } else {
            len = GetEnvironmentVariableA("USERPROFILE", buf, BUFFER_SIZE_ELEMENTS(buf));
            if (len > 0) {
                _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), 
                          "%s/Application Data/Dr. Memory", buf);
                NULL_TERMINATE_BUFFER(logdir);
                have_env = true;
            }
        }
        if (have_env) {
            if (CreateDirectoryA(logdir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
                have_logdir = true;
            }
        }
    } else {
        _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s/drmemory/logs", drmem_root);
        NULL_TERMINATE_BUFFER(logdir);
        if (_access(logdir, 2/*write*/) == -1) {
            /* try w/o the drmemory */
            _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s/logs", drmem_root);
            NULL_TERMINATE_BUFFER(logdir);
            if (_access(logdir, 2/*write*/) > -1)
                have_logdir = true;
        } else
            have_logdir = true;
    }
    if (!have_logdir) {
        /* try logs in cur dir */
        GetFullPathName("./logs", BUFFER_SIZE_ELEMENTS(logdir), logdir, NULL);
        NULL_TERMINATE_BUFFER(logdir);
        if (_access(logdir, 2/*write*/) == -1) {
            /* try cur dir */
            GetFullPathName(".", BUFFER_SIZE_ELEMENTS(logdir), logdir, NULL);
            NULL_TERMINATE_BUFFER(logdir);
        }
    }

    persist_dir[0] = '\0';

    /* parse command line */
    /* FIXME PR 487993: use optionsx.h to construct this parsing code */
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
        else if (argv[i][0] != '-' && ends_in_exe(argv[i])) {
            /* leave i alone: this is the app itself */
            break;
	}
        else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
            continue;
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
        else if (strcmp(argv[i], "-dr_ops") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
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
            GetFullPathName(argv[++i], BUFFER_SIZE_ELEMENTS(logdir), logdir, NULL);
            NULL_TERMINATE_BUFFER(logdir);
            /* added to client ops below */
        }
        else if (strcmp(argv[i], "-symcache_dir") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* make absolute */
            GetFullPathName(argv[++i], BUFFER_SIZE_ELEMENTS(scratch), scratch, NULL);
            NULL_TERMINATE_BUFFER(scratch);
            if (_access(scratch, 2/*write*/) == -1) {
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
            GetFullPathName(argv[++i], BUFFER_SIZE_ELEMENTS(persist_dir),
                            persist_dir, NULL);
            NULL_TERMINATE_BUFFER(persist_dir);
            /* further processed below */
        }
        else if (strcmp(argv[i], "-suppress") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            /* front-end provides relative-to-absolute and existence check */
            /* make absolute */
            GetFullPathName(argv[++i], BUFFER_SIZE_ELEMENTS(suppress), suppress, NULL);
            NULL_TERMINATE_BUFFER(suppress);
            if (_access(suppress, 4/*read*/) == -1) {
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
    app_name = argv[i++];
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
    c = app_cmdline;
    c += _snprintf(c, BUFFER_SIZE_ELEMENTS(app_cmdline) - (c - app_cmdline),
                   "\"%s\"", app_name);
    for (; i < argc; i++) {
        c += _snprintf(c, BUFFER_SIZE_ELEMENTS(app_cmdline) - (c - app_cmdline),
                       " \"%s\"", argv[i]);
    }
    NULL_TERMINATE_BUFFER(app_cmdline);
    assert(c - app_cmdline < BUFFER_SIZE_ELEMENTS(app_cmdline));
    info("app cmdline: %s", app_cmdline);

    if (_access(dr_root, 4/*read*/) == -1) {
        fatal("invalid -dr_root %s", dr_root);
        goto error; /* actually won't get here */
    }
    _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), 
              "%s/"LIB_ARCH"/%s/dynamorio.dll", dr_root,
              use_dr_debug ? "debug" : "release");
    NULL_TERMINATE_BUFFER(buf);
    if (_access(buf, 4/*read*/) == -1) {
        /* support debug build w/ integrated debug DR build and so no release */
        if (!use_dr_debug) {
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), 
                      "%s/"LIB_ARCH"/%s/dynamorio.dll", dr_root, "debug");
            NULL_TERMINATE_BUFFER(buf);
            if (_access(buf, 4/*read*/) == -1) {
                fatal("cannot find DynamoRIO library %s", buf);
                goto error; /* actually won't get here */
            }
            warn("using debug DynamoRIO since release not found");
            use_dr_debug = true;
        }
    }

    /* once we have 64-bit we'll need to address the NSIS "bin/" requirement */
    _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
              "%s/"BIN_ARCH"/%s/drmemorylib.dll", drmem_root,
              use_drmem_debug ? "debug" : "release");
    NULL_TERMINATE_BUFFER(client_path);
    if (_access(client_path, 4/*read*/) == -1) {
        if (!use_drmem_debug) {
            _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s/"BIN_ARCH"/%s/drmemorylib.dll", drmem_root, "debug");
            NULL_TERMINATE_BUFFER(client_path);
            if (_access(client_path, 4/*read*/) == -1) {
                fatal("invalid -drmem_root: cannot find %s", client_path);
                goto error; /* actually won't get here */
            }
            /* try to avoid warning for devs running from build dir */
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s/CMakeCache.txt", drmem_root);
            NULL_TERMINATE_BUFFER(buf);
            if (_access(buf, 4/*read*/) == -1)
                warn("using debug Dr. Memory since release not found");
            use_drmem_debug = true;
        }
    }

    if (_access(logdir, 2/*write*/) == -1) {
        fatal("invalid -logdir: cannot find/write %s", logdir);
        goto error; /* actually won't get here */
    }
    info("logdir is \"%s\"", logdir);
    BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
             cliops_sofar, len, "-logdir `%s` ", logdir);

    if (persisting) {
        /* default -persist_dir is not DR's default so we have to set it */
        if (persist_dir[0] == '\0') { /* not set by user */
            _snprintf(persist_dir, BUFFER_SIZE_ELEMENTS(persist_dir),
                      "%s/codecache", logdir);
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
        if (_access(persist_dir, 2/*write*/) == -1) {
            fatal("invalid -persist_dir: cannot find/write %s", persist_dir);
            goto error; /* actually won't get here */
        }
        info("persist_dir is \"%s\"", persist_dir);
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-persist_dir `%s` ", persist_dir);
    }

    /* Set _NT_SYMBOL_PATH for the app. */
    set_symbol_search_path(logdir);

    errcode = dr_inject_process_create(app_name, app_cmdline, &inject_data);
    if (errcode != 0) {
        int sofar = _snprintf(app_cmdline, BUFFER_SIZE_ELEMENTS(app_cmdline), 
                              "failed to create process for \"%s\": ", app_name);
        if (sofar > 0) {
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                          (LPTSTR) app_cmdline + sofar,
                          BUFFER_SIZE_ELEMENTS(app_cmdline) - sofar*sizeof(char), NULL);
        }
        NULL_TERMINATE_BUFFER(app_cmdline);
        fatal("%s", app_cmdline);
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
    errcode = dr_inject_process_exit(inject_data, false/*don't kill process*/);
    process_results_file(logdir, pid, app_name);
    return (exit0 ? 0 : errcode);
 error:
    dr_inject_process_exit(inject_data, false);
    return (exit0 ? 0 : 1);
}

