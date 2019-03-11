/* **********************************************************
 * Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
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
 * be UTF-8 and convert when calling Windows routines.  We pick the latter,
 * which works better for Linux and Mac.  That's the model that
 * drfrontendlib uses.
 */
#ifdef WINDOWS
# define UNICODE
# define _UNICODE
#endif

#include "dr_api.h" /* for the types */
#include "dr_inject.h"
#include "dr_config.h"
#include "dr_frontend.h"
#include "utils.h"
#include "frontend.h"
#include "options.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#ifdef MACOS
# include <sys/utsname.h>
#endif

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)
#define MAX_APP_CMDLINE 4096

#define LIB64_ARCH "lib64"
#define BIN64_ARCH "bin64"
#define LIB32_ARCH "lib32"
#define BIN32_ARCH "bin"

#ifdef WINDOWS
# define DR_LIB_NAME "dynamorio.dll"
# define DRMEM_LIB_NAME "drmemorylib.dll"
# define FRONTEND_NAME "drmemory.exe"
#elif defined(LINUX)
# define DR_LIB_NAME "libdynamorio.so"
# define DRMEM_LIB_NAME "libdrmemorylib.so"
# define FRONTEND_NAME "drmemory"
#elif defined(MACOS)
# define DR_LIB_NAME "libdynamorio.dylib"
# define DRMEM_LIB_NAME "libdrmemorylib.dylib"
# define FRONTEND_NAME "drmemory"
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
 * i#2083: disable hard-to-reach tables via -no_vm_base_near_app until a long-term
 *   fix is in place that loads tables via an extra scratch reg.
 */
#define DEFAULT_DR_OPS \
    "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256 -vm_size 256M "\
    "-no_enable_reset -no_vm_base_near_app"

#define DRMEM_CLIENT_ID 0

static bool verbose;
static bool quiet;
static bool results_to_stderr = true;
static bool no_resfile; /* no results file expected */

#ifdef WINDOWS
static bool top_stats;
static bool batch; /* no popups */
static bool fetch_symbols = false;  /* Off by default for 1.5.0 release. */
static bool fetch_crt_syms_only = true;

static dr_os_version_info_t win_ver;

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
    return (win_ver.version <= DR_WINDOWS_VERSION_10_1803);
}
#elif defined(MACOS)
static bool
on_supported_version(void)
{
    struct utsname uinfo;
    int kernel_major;
    if (uname(&uinfo) != 0)
        return false;
#   define MIN_DARWIN_VERSION_SUPPORTED 11  /* OSX 10.7.x */
#   define MAX_DARWIN_VERSION_SUPPORTED 15  /* OSX 10.11.x */
    return (dr_sscanf(uinfo.release, "%d", &kernel_major) == 1 &&
            kernel_major <= MAX_DARWIN_VERSION_SUPPORTED &&
            kernel_major >= MIN_DARWIN_VERSION_SUPPORTED);
}
#endif /* WINDOWS */

static const char *prefix = PREFIX_DEFAULT_MAIN_THREAD;

static void
pause_if_in_cmd(void)
{
#ifdef WINDOWS
    if (!batch &&
        (dr_using_console() ||
         /* i#1157: on win8 dr_using_console() always returns false, so we
          * always pause unless -batch
          */
         on_win8_or_later())) {
        /* If someone double-clicked drmemory.exe, ensure the message
         * stays up instead of the cmd window disappearing (i#1129).
         * Yes, someone already in cmd will have to hit a key, but
         * that's ok.
         */
        fprintf(stderr, "\n<press enter to dismiss>\n");
        fflush(stderr);
        getchar();
    }
#endif
}

#define fatal(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
    /* for drag-and-drop we'd better make fatal errors visible */ \
    pause_if_in_cmd(); \
    exit(1); \
} while (0)

#define warn(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#define warn_prefix(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "%s", prefix); \
        fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#define info(msg, ...) do { \
    if (verbose) { \
        fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

/* Fetching symbols can create the appearance of a hang, so we want to print
 * these messages without -v.
 */
#define sym_info(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "%s", prefix); \
        fprintf(stderr, msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

static void
print_usage(bool full)
{
    fprintf(stderr, "Usage: drmemory [options] -- <app and args to run>\n");
    if (!full) {
        fprintf(stderr, "Run with -help for full option list.\n");
#ifdef WINDOWS
        fprintf(stderr, "If running from the Start Menu or desktop icon, you must drag\n"
                "your application onto drmemory.exe.  To pass arguments you must\n"
                "instead invoke drmemory.exe from an existing shell.\n");
#endif
        fprintf(stderr, "See http://drmemory.org/docs/ for more information.\n");
        pause_if_in_cmd();
        return;
    }
    options_print_usage();
}

#define usage(msg, ...) do {                                    \
    fprintf(stderr, "\n");                                      \
    fprintf(stderr, "ERROR: " msg "\n\n", ##__VA_ARGS__);         \
    print_usage(false);                                         \
    exit(1);                                                    \
} while (0)

#undef BUFPRINT
#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    drfront_status_t sc = drfront_bufprint(buf, bufsz, &(sofar), &(len), __VA_ARGS__); \
    if (sc != DRFRONT_SUCCESS) \
        fatal("failed (status=%d) to append to buffer", sc); \
} while (0)

#ifdef WINDOWS
/* always null-terminates */
static void
char_to_tchar(const char *str, TCHAR *wbuf, size_t wbuflen/*# elements*/)
{
    drfront_status_t sc = drfront_char_to_tchar(str, wbuf, wbuflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed (status=%d) to convert UTF-8 to UTF-16", sc);
}
#endif

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
    bool ret = false;
    return (drfront_access(path, DRFRONT_WRITE, &ret) == DRFRONT_SUCCESS && ret);
}

static bool
file_is_readable(char *path)
{
    bool ret = false;
    return (drfront_access(path, DRFRONT_READ, &ret) == DRFRONT_SUCCESS && ret);
}

static void
get_absolute_path(const char *src, char *buf, size_t buflen/*# elements*/)
{
    drfront_status_t sc = drfront_get_absolute_path(src, buf, buflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed (status=%d) to convert %s to an absolute path", sc, src);
}

static void
get_full_path(const char *app, char *buf, size_t buflen/*# elements*/)
{
    drfront_status_t sc = drfront_get_app_full_path(app, buf, buflen);
    if (sc != DRFRONT_SUCCESS)
        warn("failed (status=%d) to find application %s", sc, app);
}

static bool
create_dir_if_necessary(const char *dir, const char *option)
{
    /* Using dr_ API here since available and perhaps we'll want this
     * same frontend on linux someday.
     */
    if (!dr_directory_exists(dir)) {
        if (!dr_create_dir(dir)) {
            /* check again in case of a race */
            if (!dr_directory_exists(dir)) {
                fatal("cannot create %s! Use %s to set proper path", dir, option);
                return false;
            }
        }
    }
    return true;
}

/* i#200/PR 459481: communicate child pid via file.
 * We don't need this on unix b/c we use exec.
 */
#ifdef WINDOWS
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

/* Return true if we should fetch this symbol file.  Modifies modpath to make it
 * a long path and assumes it is MAXIMUM_PATH bytes long.
 */
static bool
should_fetch_symbols(const TCHAR *system_root, char *modpath)
{
    TCHAR wmodpath[MAXIMUM_PATH];
    bool r;
    drfront_string_replace_character(modpath, '\n', '\0');  /* Trailing newline. */
    /* Convert to a long path to compare with $SystemRoot.  These paths are
     * already absolute, but some of them, like sophos-detoured.dll, are
     * 8.3 style paths.
     */
    char_to_tchar(modpath, wmodpath, BUFFER_SIZE_ELEMENTS(wmodpath));
    if (GetLongPathName(wmodpath, wmodpath, BUFFER_SIZE_ELEMENTS(wmodpath)) == 0) {
        warn("GetLongPathName failed for %s: %d", modpath, GetLastError());
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
fetch_missing_symbols(const char *symdir, const TCHAR *resfile)
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

    /* Get %SystemRoot%. */
    len = GetWindowsDirectory(system_root, BUFFER_SIZE_ELEMENTS(system_root));
    if (len == 0) {
        _tcsncpy(system_root, _T("C:\\Windows"), BUFFER_SIZE_ELEMENTS(system_root));
        NULL_TERMINATE_BUFFER(system_root);
    }
    _tcsncpy(missing_symbols, resfile, BUFFER_SIZE_ELEMENTS(missing_symbols));
    NULL_TERMINATE_BUFFER(missing_symbols);
    drfront_string_replace_character_wide(missing_symbols, _T(ALT_DIRSEP), _T(DIRSEP));
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

    cur_file = 0;
    files_fetched = 0;
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), stream) != NULL) {
        if (should_fetch_symbols(system_root, line)) {
            cur_file++;
            sym_info("[%d/%d] Fetching symbols for %s",
                     cur_file, num_files, line);
            if (drfront_fetch_module_symbols(line, NULL, 0) == DRFRONT_SUCCESS)
                files_fetched++;
        }
    }

    if (drfront_sym_exit() != DRFRONT_SUCCESS)
        warn("drfront_sym_exit failed %d", GetLastError());

stream_cleanup:
    fclose(stream);
    if (num_files > 0) {
        sym_info("Fetched %d symbol files successfully", files_fetched);
    }
}

/* List of libs we might find inside drmemory.exe */
static const TCHAR * const known_libs[] = {
    L"ntdll.dll",
    L"kernelbase.dll",
    L"kernel32.dll",
    L"user32.dll",
    L"gdi32.dll",
    L"shell32.dll",
    L"comctl32.dll",
    L"apphelp.dll",
    L"cryptbase.dll",
    L"bcryptprimitives.dll",
    L"sspicli.dll",
    L"rpcrt4.dll",
    L"advapi32.dll",
    L"sechost.dll",
    L"msvcrt.dll",
    L"ucrtbase.dll",
    L"drmemory.exe",
    L"dynamorio.dll",
    L"dbghelp.dll",
    L"drinjectlib.dll",
    L"drconfiglib.dll",
};
#define NUM_KNOWN_LIBS (sizeof(known_libs)/sizeof(known_libs[0]))

static void
analyze_loaded_modules(void)
{
    /* i#1713: look for "suspicious" libraries in the frontend itself. */
    PBYTE pb = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    TCHAR libname[MAXIMUM_PATH];
    ssize_t len;
    char msg[MAXIMUM_PATH*10];
    size_t sofar = 0;
    uint libs_printed = 0;
    BUFPRINT(msg, BUFFER_SIZE_ELEMENTS(msg), sofar, len,
             "Examine the following unusual libraries in this process to help identify\n"
             "invasive software that may have affected the target application:\n\n");
    while (VirtualQuery(pb, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.Type == MEM_IMAGE &&
            mbi.AllocationBase == mbi.BaseAddress) {
            len = GetModuleFileNameW((HINSTANCE) mbi.AllocationBase, libname,
                                     BUFFER_SIZE_ELEMENTS(libname));
            if (len > 0) {
                int i;
                bool print = true;
                const TCHAR *basename = libname + wcslen(libname) - 1;
                while (*basename != L'/' && *basename != L'\\' && basename > libname)
                    basename--;
                basename++;
                for (i = 0; i < NUM_KNOWN_LIBS; i++) {
                    if (_wcsicmp(basename, known_libs[i]) == 0) {
                        print = false;
                        break;
                    }
                }
                if (print) {
                    BUFPRINT(msg, BUFFER_SIZE_ELEMENTS(msg), sofar, len,
                             "\t%S\n", libname);
                    libs_printed++;
                }
            }
        }
        pb += mbi.RegionSize;
    }
    if (libs_printed > 0)
        warn("%s\nPlease file a bug about this at http://drmemory.org/issues", msg);
}

/* Rather than iterating to find the most recent dir w/ pid in name,
 * or risk running into the client option length limit by passing in a
 * file to write the results to, the client always writes to
 * <logdir>/resfile.<pid>.  There is a race here since we're reading
 * it after the app exited and another app of same pid could start up,
 * but we live with it since extremely unlikely.
 */
static void
process_results_file(const char *logdir, const char *symdir,
                     process_id_t pid, const char *app, int errcode)
{
    HANDLE f;
    char fname[MAXIMUM_PATH];
    TCHAR wfname[MAXIMUM_PATH];
    char resfile[MAXIMUM_PATH];
    TCHAR wresfile[MAXIMUM_PATH];
    DWORD read;
    bool is_graphical = true;

    if (no_resfile || (quiet && batch))
        return;
    dr_snwprintf(wfname, BUFFER_SIZE_ELEMENTS(wfname), _T(TSTR_FMT)_T("/resfile.%d"),
                 logdir, pid);
    NULL_TERMINATE_BUFFER(wfname);
    f = CreateFile(wfname, GENERIC_READ, FILE_SHARE_READ,
                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        if (errcode == STATUS_DLL_NOT_FOUND) {
            warn_prefix("libraries needed by the application are missing.  Check that it "
                        "runs successfully on its own and check that all needed "
                        "libraries are in its directory or on the PATH.");
            return;
        }
        warn_prefix("unable to locate results file: can't open "TSTR_FMT" (code=%d).\n"
                    "Dr. Memory failed to start the target application, perhaps due to\n"
                    "interference from invasive security software.\n"
                    "Try disabling other software or running in a virtual machine.",
                    wfname, GetLastError());
        IF_WINDOWS(analyze_loaded_modules());
        return;
    }
    if (!ReadFile(f, resfile, BUFFER_SIZE_ELEMENTS(resfile), &read, NULL)) {
        warn("unable to locate results file since can't read "TSTR_FMT": %d",
             wfname, GetLastError());
        CloseHandle(f);
        return;
    }
    assert(read < BUFFER_SIZE_ELEMENTS(resfile));
    resfile[read] = '\0';
    CloseHandle(f);
    /* We are now done with the file */
    if (!DeleteFile(wfname)) {
        warn("unable to delete temp file "TSTR_FMT": %d", wfname, GetLastError());
    }
    char_to_tchar(resfile, wresfile, BUFFER_SIZE_ELEMENTS(wresfile));

    if (drfront_is_graphical_app(app, &is_graphical) != DRFRONT_SUCCESS)
        warn("unable to determine whether app is graphical");

    if (!quiet &&
        /* On vista, or win7+ with i#440, output works from client, even during exit,
         * for non-graphical apps
         */
        (is_graphical || !on_vista_or_later()) &&
        /* Win7 output from client works even for graphical app since DR r2325 */
        /* Win8+ output from client works even for graphical app since DR 3db7e90 */
        win_ver.version < DR_WINDOWS_VERSION_7) {
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
        bool show_leaks = !quiet && results_to_stderr && !is_graphical;
        /* i#1503: on win8+ in_cmd is false, but graphical apps have no output.
         * Recent cygwins in their modified cmd window do have output, so we
         * print the summary unless we're in bash.  We do get a double summary
         * if in cmd run from within rxvt, but we can live with that.
         */
        if (is_graphical && win_ver.version >= DR_WINDOWS_VERSION_8) {
            if (drfront_get_env_var("SHELL", fname,
                                    BUFFER_SIZE_ELEMENTS(fname)) != DRFRONT_SUCCESS ||
                strlen(fname) == 0)
                in_cmd = true;
        }
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
        drfront_status_t sc;
        bool res;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        sc = drfront_searchenv("notepad.exe", "PATH", fname,
                               BUFFER_SIZE_ELEMENTS(fname), &res);
        if (sc == DRFRONT_SUCCESS && res) {
            char_to_tchar(fname, wfname, BUFFER_SIZE_ELEMENTS(wfname));
            /* Older notepad can't handle forward slashes (i#1123) */
            drfront_string_replace_character_wide(wresfile, _T('/'), _T('\\'));
            _sntprintf(cmd, BUFFER_SIZE_ELEMENTS(cmd), _T("%s %s"), wfname, wresfile);
            NULL_TERMINATE_BUFFER(cmd);
            if (!CreateProcess(wfname, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                warn("cannot run \"%s\": %d", cmd, GetLastError());
            } else {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        } else {
            warn("unable to find notepad (error %d)\n", sc);
        }
    }

    /* We provide an option to allow the user to turn this feature off. */
    if (fetch_symbols || fetch_crt_syms_only) {
        info("fetching symbols");
        fetch_missing_symbols(symdir, wresfile);
    } else {
        info("skipping symbol fetching");
    }
}

static bool
generate_sysnum_file(const char *symdir)
{
    int i;
    size_t lib_count = 0;
    char **sysnum_lib_paths;
    void *drcontext = dr_standalone_init();
    if (drcontext == NULL)
        return false;
    char outfile[MAXIMUM_PATH];
    _snprintf(outfile, BUFFER_SIZE_ELEMENTS(outfile), "%s%c%s",
              symdir, DIRSEP, dr_is_wow64() ? SYSNUM_FILE_WOW64 : SYSNUM_FILE);
    NULL_TERMINATE_BUFFER(outfile);
    drmf_status_t res = drsys_find_sysnum_libs(NULL, &lib_count);
    if (res != DRMF_ERROR_INVALID_SIZE)
        return false;
    sysnum_lib_paths = malloc(lib_count * sizeof(sysnum_lib_paths[0]));
    if (sysnum_lib_paths == NULL)
        return false;
    for (i = 0; i < lib_count; ++i) {
        sysnum_lib_paths[i] = malloc(MAXIMUM_PATH);
        if (sysnum_lib_paths[i] == NULL)
            return false;
    }
    res = drsys_find_sysnum_libs(sysnum_lib_paths, &lib_count);
    if (res != DRMF_SUCCESS)
        return false;
    if (drcontext == NULL)
        return false;
    res = drsys_generate_sysnum_file
        (drcontext, sysnum_lib_paths, lib_count, outfile, symdir);
    for (i = 0; i < lib_count; ++i)
        free(sysnum_lib_paths[i]);
    free(sysnum_lib_paths);
    return (res == DRMF_SUCCESS);
}
#endif /* WINDOWS */

/* check client options and abort on an option error */
static void
check_client_options(const char * client_ops)
{
    /* we share options_init with Dr. Memory to check the option setting */
    options_init(client_ops);
}

char app_path[MAXIMUM_PATH]; /* shared in options.c */

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

    const char *lib_arch = IF_X64_ELSE(LIB64_ARCH, LIB32_ARCH);
    const char *bin_arch = IF_X64_ELSE(BIN64_ARCH, BIN32_ARCH);

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
    char symdir[MAXIMUM_PATH];
#ifdef WINDOWS
    char symsrv_dir[MAXIMUM_PATH];
#endif

    bool use_dr_debug = false;
    bool use_drmem_debug = false;
    bool use_root_for_logdir;
#ifdef WINDOWS
    char *pidfile = NULL;
    bool tried_generating_syscall_file = false;
#endif
#ifndef MACOS /* XXX i#1286: implement nudge on MacOS */
    process_id_t nudge_pid = 0;
#endif
    bool native_parent = false;
    size_t native_parent_pos = 0; /* holds cliops_sofar of "-native_parent" */

    char *app_name;
    char **app_argv;

    int errcode;
    void *inject_data = NULL;
    int i;
    char *c;
    char buf[MAXIMUM_PATH];
    process_id_t pid;
    bool have_logdir = false;
    bool persisting = false;
    bool exit0 = false;
    bool dr_logdir_specified = false;
    bool doubledash_present = false;

#ifdef WINDOWS
    time_t start_time, end_time;
# ifdef DEBUG
    /* Avoid stderr printing in debug build from version init on new win10
     * (otherwise we get 2 prints, one here and in the client).
     */
    if (!SetEnvironmentVariable(L"DYNAMORIO_OPTIONS", L"-stderr_mask 0"))
        info("Failed to quiet frontend DR messages");
# endif
#endif

    drfront_status_t sc;
    bool is64, is32;
    dr_config_status_t status;

    if (dr_standalone_init() == NULL) {
        /* We assume this is due to a new version of Windows.
         * The user could work around it by setting -max_supported_os_version
         * in DYNAMORIO_OPTIONS env var.
         */
        fatal("this version of Windows is not supported by Dr. Memory.");
    }
#ifdef WINDOWS
    if (drfront_sym_init(NULL, "dbghelp.dll") != DRFRONT_SUCCESS) {
        warn("symbol initialization error");
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
#elif defined(MACOS)
    /* For Mac we just warn, as there's a decent chance it will work */
    if (!on_supported_version())
        warn("this version of Mac OSX is not officially supported by Dr. Memory.");
#endif

#if defined(WINDOWS) && !defined(_UNICODE)
# error _UNICODE must be defined
#else
    /* Convert to UTF-8 if necessary */
    sc = drfront_convert_args((const TCHAR **)targv, &argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to process args: %d", sc);
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
#ifdef UNIX
    /* All the dirs look cleaner without the "bin/../logs", etc., which only happens
     * on unix b/c the Windows GetFullPathName removes "..".
     */
    if (default_drmem_root[strlen(default_drmem_root)-1] == '.') {
        int len = strlen(default_drmem_root);
        char *c = default_drmem_root + len - 1;
        if (len > 4 && *c == '.' && *(c-1) == '.' && *(c-2) == '/') {
            c -= 3;
            while (*c != '/' && c > default_drmem_root)
                c--;
            *c = '\0';
        }
    }
#endif
    drmem_root = default_drmem_root;
    drfront_string_replace_character(drmem_root, ALT_DIRSEP, DIRSEP); /* canonicalize */

    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "%s ", DEFAULT_DR_OPS);
#ifdef WINDOWS
    /* FIXME i#699: early injection crashes the child on 32-bit or on wow64 vista+.
     * We work around it here.  Should remove this once the real bug is fixed.
     */
    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "-no_early_inject ");
#endif

    /* default logdir */
    if (drfront_appdata_logdir(drmem_root, "Dr. Memory", &use_root_for_logdir,
                               logdir, BUFFER_SIZE_ELEMENTS(logdir)) == DRFRONT_SUCCESS
        && !use_root_for_logdir) {
        if ((dr_create_dir(logdir) || dr_directory_exists(logdir)) &&
            file_is_writable(logdir))
            have_logdir = true;
    }
    if (!have_logdir) {
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
            if (use_root_for_logdir) {
                /* Our root was writable but not our logs subdir(s): go back to
                 * a good temp value, as cwd may not work later.
                 */
                if (drfront_appdata_logdir(logdir, "Dr. Memory", &use_root_for_logdir,
                                           logdir, BUFFER_SIZE_ELEMENTS(logdir)) ==
                    DRFRONT_SUCCESS && !use_root_for_logdir) {
                    if ((dr_create_dir(logdir) || dr_directory_exists(logdir)) &&
                        file_is_writable(logdir))
                        have_logdir = true;
                }
            }
        } else
            have_logdir = true;
    } else
        have_logdir = true;
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
    symdir[0] = '\0';

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
            /* Enable verbosity in pdf2sysfile.cpp */
            op_verbose_level = 1;
            drfront_set_verbose(op_verbose_level);
            continue;
        }
        else if (strcmp(argv[i], "-vv") == 0) {
            verbose = true;
            /* Enable verbosity in pdf2sysfile.cpp */
            op_verbose_level = 2;
            drfront_set_verbose(op_verbose_level);
            continue;
        }
        else if (strcmp(argv[i], "-vvv") == 0) {
            verbose = true;
            /* Enable extra verbosity in pdf2sysfile.cpp */
            op_verbose_level = 3;
            drfront_set_verbose(op_verbose_level);
            continue;
        }
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "-help") == 0 ||
                 strcmp(argv[i], "--help") == 0) {
            print_usage(true/*full*/);
            exit(0);
        }
        else if (strcmp(argv[i], "-quiet") == 0) {
            /* -quiet is also parsed by the client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "%s ", argv[i]);
            /* now that DR has these by default we have to explicitly turn off */
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "-msgbox_mask 0 -stderr_mask 0 ");
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
#ifdef WINDOWS
        else if (strcmp(argv[i], "-batch") == 0) {
            batch = true;
            /* now that DR has msgboxes by default we have to explicitly turn off */
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "-msgbox_mask 0 ");
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
#endif
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
#ifdef WINDOWS
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
#endif
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
#ifndef MACOS /* XXX i#1286: implement nudge on MacOS */
        else if (strcmp(argv[i], "-nudge") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            nudge_pid = strtoul(argv[++i], NULL, 10);
        }
#endif
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
#ifdef WINDOWS
        else if (strcmp(argv[i], "-pid_file") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            pidfile = argv[++i];
        }
#endif
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
            get_absolute_path(argv[++i], symdir, BUFFER_SIZE_ELEMENTS(symdir));
            NULL_TERMINATE_BUFFER(symdir);
            /* further processed below */
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
            exit0 = true;
        }
        else {
            if (strcmp(argv[i], "-perturb_only") == 0)
                no_resfile = true;
            /* pass to client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "`%s` ", argv[i]);
        }
    }

#ifndef MACOS /* XXX i#1286: implement nudge on MacOS */
    if (nudge_pid != 0) {
        if (i < argc)
            usage("%s", "-nudge does not take an app to run");
        /* could also complain about other client or app specific ops */
        status = dr_nudge_pid(nudge_pid, DRMEM_CLIENT_ID, NUDGE_LEAK_SCAN, INFINITE);
        if (status != DR_SUCCESS) {
            const char *err_msg = dr_config_status_code_to_string(status);
            fatal("error nudging %d, error code %d (%s)", nudge_pid, status, err_msg);
            assert(false); /* shouldn't get here */
        }
        exit(0);
    }
#endif

    if (i >= argc)
        usage("%s", "no app specified");
    app_name = argv[i];
    get_full_path(app_name, app_path, BUFFER_SIZE_ELEMENTS(app_path));
    if (app_path[0] != '\0')
        app_name = app_path;
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

    if (drfront_is_64bit_app(app_name, &is64, &is32) == DRFRONT_SUCCESS &&
        IF_X64_ELSE(!is64, is64 && !is32)) {
#ifdef MACOS
        /* XXX DRi#1568: DR does not yet support 64-bit MacOS */
        fatal("This Dr. Memory release does not support 64-bit applications on OSX.");
        goto error; /* actually won't get here */
#endif
        /* We launch the other frontend b/c drinjectlib doesn't support cross-arch
         * injection (DRi#803).
         */
        char *orig_argv0 = argv[0];
        lib_arch = IF_X64_ELSE(LIB32_ARCH, LIB64_ARCH);
        bin_arch = IF_X64_ELSE(BIN32_ARCH, BIN64_ARCH);
        _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                  "%s%c%s%c%s", drmem_root, DIRSEP, bin_arch, DIRSEP, FRONTEND_NAME);
        NULL_TERMINATE_BUFFER(buf);
        if (!file_is_readable(buf)) {
            fatal("unable to find frontend %s to match target app bitwidth: "
                  "is this an incomplete installation?", buf);
        }
        argv[0] = buf;
        info("launching frontend %s to match target app bitwidth", buf);
        /* XXX DRi#943: this lib routine currently doesn't handle int18n */
#ifdef WINDOWS
        errcode = dr_inject_process_create(buf, (const char **)argv, &inject_data);
#else
        errcode = dr_inject_prepare_to_exec(buf, (const char **)argv, &inject_data);
#endif
        /* Mismatch is just a warning */
        if (errcode == 0 || errcode == WARN_IMAGE_MACHINE_TYPE_MISMATCH_EXE) {
            dr_inject_process_run(inject_data);
#ifdef WINDOWS
            /* If we don't wait, the prompt comes back, which is confusing */
            info("waiting for other frontend...");
            errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data),
                                          INFINITE);
            if (errcode != WAIT_OBJECT_0)
                info("failed to wait for frontend: %d\n", errcode);
            dr_inject_process_exit(inject_data, false);
#else
            fatal("failed to exec frontend to match target app bitwidth");
#endif
            argv[0] = orig_argv0;
            goto cleanup;
        } else {
            fatal("unable to launch frontend to match target app bitwidth: code=%d",
                  errcode);
        }
    }

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
              "%s%c%s%c%s%c%s", dr_root, DIRSEP, lib_arch, DIRSEP,
              use_dr_debug ? "debug" : "release", DIRSEP, DR_LIB_NAME);
    NULL_TERMINATE_BUFFER(buf);
    if (!file_is_readable(buf)) {
        /* support debug build w/ integrated debug DR build and so no release */
        if (!use_dr_debug) {
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                      "%s%c%s%c%s%c%s", dr_root, DIRSEP, lib_arch, DIRSEP,
                      "debug", DIRSEP, DR_LIB_NAME);
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
              "%s%c%s%c%s%c%s", drmem_root, DIRSEP, bin_arch, DIRSEP,
              use_drmem_debug ? "debug" : "release", DIRSEP, DRMEM_LIB_NAME);
    NULL_TERMINATE_BUFFER(client_path);
    if (!file_is_readable(client_path)) {
        if (!use_drmem_debug) {
            _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path),
                      "%s%c%s%c%s%c%s", drmem_root, DIRSEP, bin_arch,
                      DIRSEP, "debug", DIRSEP, DRMEM_LIB_NAME);
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

    drfront_string_replace_character(logdir, ALT_DIRSEP, DIRSEP); /* canonicalize */
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
                    fatal("cannot create %s! Use -logdir to set proper path", scratch);
                    goto error; /* actually won't get here */
                }
            }
        }
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-logdir `%s` ", scratch);
    }

    if (symdir[0] == '\0') { /* not set by user */
        _snprintf(symdir, BUFFER_SIZE_ELEMENTS(symdir), "%s%csymcache", logdir, DIRSEP);
        NULL_TERMINATE_BUFFER(symdir);
        /* Users need change -logdir if the default symcache dir creation failed. */
        if (!create_dir_if_necessary(symdir, "-logdir"))
            goto error; /* actually won't get here */
    }
    if (!file_is_writable(symdir)) {
        fatal("invalid -symcache_dir: cannot find/write %s", symdir);
        goto error; /* actually won't get here */
    }
    info("symcache_dir is \"%s\"", symdir);
    /* also parsed by the client */
    BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
             cliops_sofar, len, "-symcache_dir `%s` ", symdir);

    if (persisting) {
        /* default -persist_dir is not DR's default so we have to set it */
        if (persist_dir[0] == '\0') { /* not set by user */
            _snprintf(persist_dir, BUFFER_SIZE_ELEMENTS(persist_dir),
                      "%s%ccodecache", logdir, DIRSEP);
            NULL_TERMINATE_BUFFER(persist_dir);
            /* Users need change -logdir if the default persist_dir creation failed. */
            if (!create_dir_if_necessary(persist_dir, "-logdir"))
                goto error; /* actually won't get here */
        }
        drfront_string_replace_character(persist_dir, ALT_DIRSEP,
                                         DIRSEP); /* canonicalize */
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
        if (drfront_get_env_var("SYSTEMROOT", buf, BUFFER_SIZE_ELEMENTS(buf)) ==
            DRFRONT_SUCCESS) {
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops), cliops_sofar, len,
                     /* Add .d?? to still report errors in app .exe but not
                      * in *.dll or *.drv.
                      */
                     "-lib_blacklist `%s*.d??",
                     buf);
            /* i#1755: consider "C:\Program Files\Common Files\Microsoft Shared" to
             * be on the blacklist.
             */
# define    MS_SHARED_DIRNAME "Microsoft Shared"
            if (drfront_get_env_var("CommonProgramFiles", buf, BUFFER_SIZE_ELEMENTS(buf))
                == DRFRONT_SUCCESS) {
                BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops), cliops_sofar, len,
                         ",%s%c%s*.d??", buf, DIRSEP, MS_SHARED_DIRNAME);
            }
            if (drfront_get_env_var("CommonProgramFiles(x86)", buf,
                                    BUFFER_SIZE_ELEMENTS(buf)) == DRFRONT_SUCCESS) {
                BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops), cliops_sofar, len,
                         ",%s%c%s*.d??", buf, DIRSEP, MS_SHARED_DIRNAME);
            }
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops), cliops_sofar, len,
                     "` ");
        }
    }
#ifdef WINDOWS
    /* Set _NT_SYMBOL_PATH for the app. */
    if (drfront_set_client_symbol_search_path(symdir, false, symsrv_dir,
                                              BUFFER_SIZE_ELEMENTS(symsrv_dir)) !=
        DRFRONT_SUCCESS ||
        drfront_set_symbol_search_path(symsrv_dir) != DRFRONT_SUCCESS)
        warn("Can't set symbol search path. Symbol lookup may fail.");

    /* XXX i#2164: Until DR supports the delay-load features needed for timezone
     * utilities used by dbghelp loading symbols, we work around a crash when
     * the "TZ" environment variable is unset by setting it.  This is a
     * transparency violation so we should remove this once DR's private loader
     * is improved.
     */
    if (drfront_get_env_var("TZ", buf, BUFFER_SIZE_ELEMENTS(buf)) != DRFRONT_SUCCESS ||
        strlen(buf) == 0) {
        TIME_ZONE_INFORMATION tzinfo;
        if (GetTimeZoneInformation(&tzinfo) != TIME_ZONE_ID_INVALID) {
            info("Setting TZ to %S for i#2164 workaround", tzinfo.StandardName);
            if (!SetEnvironmentVariable(L"TZ", tzinfo.StandardName))
                info("Failed to set TZ for i#2164 workaround");
        }
    }
#endif

    /* i#1638: fall back to temp dirs if there's no HOME/USERPROFILE set */
    dr_get_config_dir(false/*local*/, true/*use temp*/, buf, BUFFER_SIZE_ELEMENTS(buf));
    info("DynamoRIO configuration directory is %s", buf);

    do {
#ifdef UNIX
        errcode = dr_inject_prepare_to_exec(app_name, (const char **)app_argv,
                                            &inject_data);
#else
        errcode = dr_inject_process_create(app_name, (const char **)app_argv,
                                           &inject_data);
#endif
        if (errcode != 0) {
#ifdef WINDOWS
            int sofar =
#endif
                _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                          "failed to create process (err=%d) for \"%s\": ",
                          errcode, app_name);
#ifdef WINDOWS
            if (sofar > 0) {
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                              NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                              (LPTSTR) buf + sofar,
                              BUFFER_SIZE_ELEMENTS(buf) - sofar*sizeof(char), NULL);
            }
#endif
            NULL_TERMINATE_BUFFER(buf);
            fatal("%s", buf);
            goto error; /* actually won't get here */
        }

        pid = dr_inject_get_process_id(inject_data);
#ifdef WINDOWS
        if (pidfile != NULL)
            write_pid_to_file(pidfile, pid);
#endif

        /* we need to locate the results file, but only for top-level process (i#328) */
        BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                 cliops_sofar, len, "-resfile %d ", pid);

        process = dr_inject_get_image_name(inject_data);
        /* we don't care if this app is already registered for DR b/c our
         * this-pid config will override
         */
        info("configuring %s pid=%d dr_ops=\"%s\"", process, pid, dr_ops);
        status = dr_register_process(process, pid,
                                     false/*local*/, dr_root,  DR_MODE_CODE_MANIPULATION,
                                     use_dr_debug, DR_PLATFORM_DEFAULT, dr_ops);
        if (status != DR_SUCCESS) {
            const char *err_msg = dr_config_status_code_to_string(status);
            fatal("failed to register DynamoRIO configuration for \"%s\"(%d) "
                  "dr_ops=\"%s\".\n"
                  "Error code %d (%s)",
                  process, pid, dr_ops, status, err_msg);
            goto error; /* actually won't get here */
        }
        info("configuring client \"%s\" ops=\"%s\"", client_path, client_ops);
        /* check client options and abort on an option error */
        check_client_options(client_ops);
        status = dr_register_client(process, pid,
                                    false/*local*/, DR_PLATFORM_DEFAULT, DRMEM_CLIENT_ID,
                                    0, client_path, client_ops);
        if (status != DR_SUCCESS) {
            const char *err_msg = dr_config_status_code_to_string(status);
            fatal("failed to register DynamoRIO client configuration for \"%s\","
                  " ops=\"%s\"\n"
                  "Error code %d (%s)",
                  client_path, client_ops, status, err_msg);
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

#ifdef WINDOWS
        if (top_stats)
            start_time = time(NULL);
#endif
        dr_inject_process_run(inject_data);
#ifdef UNIX
        fatal("Failed to exec application");
#else
        info("waiting for app to exit...");
        errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data),
                                      INFINITE);
        if (errcode != WAIT_OBJECT_0)
            info("failed to wait for app: %d\n", errcode);
        if (top_stats) {
            double wallclock;
            end_time = time(NULL);
            wallclock = difftime(end_time, start_time);
            dr_inject_print_stats(inject_data, (int) wallclock, true/*time*/,
                                  true/*mem*/);
        }
#endif
        if (native_parent) {
            if (dr_unregister_process(process, 0, false/*local*/, DR_PLATFORM_DEFAULT)
                != DR_SUCCESS)
                warn("failed to unregister child processes");
        }
        errcode = dr_inject_process_exit(inject_data, false/*don't kill process*/);
#ifdef WINDOWS
        if (errcode == STATUS_INVALID_KERNEL_INFO_VERSION &&
            !tried_generating_syscall_file) {
            warn("Running on an unsupported operating system version.  Attempting to "
                 "auto-generate system call information...");
            tried_generating_syscall_file = true;
            /* Give the user some visible feedback. */
            if (op_verbose_level < 1)
                op_verbose_level = 1;
            if (generate_sysnum_file(symdir)) {
                sym_info("Auto-generation succeeded.  Re-launching the application.");
                /* Some options change values and then complain (e.g.,
                 * check_stack_bounds).
                 */
                options_reset_to_defaults();
                continue; /* restart app */
            }
        }
#endif
        break;
    } while (true);
#ifdef WINDOWS
    process_results_file(logdir, symdir, pid, app_name, errcode);
#endif
    goto cleanup;
 error:
    if (inject_data != NULL)
        dr_inject_process_exit(inject_data, false);
    errcode = 1;
 cleanup:
    sc = drfront_cleanup_args(argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to free memory for args: %d", sc);
    if (errcode != 0) {
        /* We use a prefix to integrate better with tool output, esp inside
         * the VS IDE as an External Tool.
         */
        warn_prefix("application exited with abnormal code 0x%x", errcode);
    }
    return (exit0 ? 0 : errcode);
}
