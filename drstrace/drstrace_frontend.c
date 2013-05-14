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

/* front end for drstrace tool */

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
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

/* XXX i#1079: share as much of this code as possible with drmem's frontend.c.
 * Currently this is all a copy based on frontend.c.
 *
 * Perhaps we should build a library with a common set of front-end
 * options and features: utf8, path search and absolute conversion
 * and canonicalization, DR location, client lib location, DR and client
 * lib debug vs release, DR and client options, etc.
 */

/* XXX i#1079: share this with DR's libutil/our_tchar.h and drmem's frontend.c */
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

#define BIN32_ARCH "bin"
#define BIN64_ARCH "bin64"
#define LIB32_ARCH "lib32"
#define LIB64_ARCH "lib64"

#define DEFAULT_DR_OPS ""

#define CLIENT_ID 0

#define prefix ""

static bool verbose;
static bool quiet;
static bool results_to_stderr = true;
static bool batch; /* no popups */
static bool no_resfile; /* no results file expected */
static bool top_stats;
static bool fetch_symbols = false;  /* Off by default for 1.5.0 release. */
static bool fetch_crt_syms_only = true;

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

static void
print_usage(void)
{
    fprintf(stderr, "usage: drstrace [options] -- <app and args to run>\n");
    /* FIXME: have an optionsx.h or what?  Shared frontend lib (i#1079) could help
     * solve that by providing usage and options parsing for its provided
     * options.
     */
    fprintf(stderr, "NYI: option list not here yet\n");
}

#define usage(msg, ...) do {                                    \
    fprintf(stderr, "\n");                                      \
    fprintf(stderr, "ERROR: " msg "\n\n", __VA_ARGS__);         \
    print_usage();                                              \
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

int
_tmain(int argc, TCHAR *targv[])
{
    char **argv;
    char *process = NULL;
    char *dr_root = NULL;
    char *drstrace_root = NULL;
    char default_dr_root[MAXIMUM_PATH];
    char default_drstrace_root[MAXIMUM_PATH];
    char client_path[MAXIMUM_PATH];

    const char *bin_arch = IF_X64_ELSE(BIN64_ARCH, BIN32_ARCH);
    const char *lib_arch = IF_X64_ELSE(LIB64_ARCH, LIB32_ARCH);

    char client_ops[MAX_DR_CMDLINE];
    size_t cliops_sofar = 0; /* for BUFPRINT to client_ops */
    char dr_ops[MAX_DR_CMDLINE];
    size_t drops_sofar = 0; /* for BUFPRINT to dr_ops */
    ssize_t len; /* shared by all BUFPRINT */

    bool use_dr_debug = false;
    bool use_drstrace_debug = false;

    char *app_name;
    char full_app_name[MAXIMUM_PATH];
    char **app_argv;

    int errcode;
    void *inject_data;
    int i;
    char *c;
    char buf[MAXIMUM_PATH];
    process_id_t pid;
    bool exit0 = false;

    time_t start_time, end_time;

    dr_standalone_init();

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

    /* Default root: we assume this exe is <root>/bin/drstrace.exe */
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
    get_absolute_path(buf, default_drstrace_root,
                      BUFFER_SIZE_ELEMENTS(default_drstrace_root));
    NULL_TERMINATE_BUFFER(default_drstrace_root);
    drstrace_root = default_drstrace_root;
    string_replace_character(drstrace_root, ALT_DIRSEP, DIRSEP); /* canonicalize */

    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "%s ", DEFAULT_DR_OPS);

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
        else if (strcmp(argv[i], "-dr_debug") == 0) {
            use_dr_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-dr_release") == 0) {
            use_dr_debug = false;
            continue;
        }
        else if (strcmp(argv[i], "-debug") == 0) {
            use_drstrace_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-release") == 0) {
            use_drstrace_debug = false;
            continue;
        }
        else if (!strcmp(argv[i], "-version")) {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
          printf("Dr. Memory drstrace version %s -- build %d\n",
                 VERSION_STRING, BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
          printf("Dr. Memory drstrace custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#elif defined(VERSION_NUMBER)
          printf("Dr. Memory drstrace version %s -- custom build %s, %s\n",
                 VERSION_STRING, __DATE__, __TIME__);
#else
          printf("Dr. Memory drstrace custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
          exit(0);
        }
        else if (strcmp(argv[i], "-dr") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            dr_root = argv[++i];
        }
        else if (strcmp(argv[i], "-drstrace") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            drstrace_root = argv[++i];
        }
        else if (strcmp(argv[i], "-follow_children") == 0 ||
                 strcmp(argv[i], "-no_follow_children") == 0) {
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "%s ", argv[i]);
        }
        else if (strcmp(argv[i], "-dr_ops") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "%s ", argv[++i]);
        }
        else if (strcmp(argv[i], "-exit0") == 0) {
            exit0 = TRUE;
        }
        else {
            /* pass to client */
            BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                     cliops_sofar, len, "`%s` ", argv[i]);
        }
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

#ifdef X64
    if (!is_64bit_app(app_name)) {
        bin_arch = BIN32_ARCH;
        lib_arch = LIB32_ARCH;
    }
#else
    if (is_64bit_app(app_name)) {
        bin_arch = BIN64_ARCH;
        lib_arch = LIB64_ARCH;
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
              "%s/%s/%s/dynamorio.dll", dr_root, lib_arch,
              use_dr_debug ? "debug" : "release");
    NULL_TERMINATE_BUFFER(buf);
    if (!file_is_readable(buf)) {
        /* support debug build w/ integrated debug DR build and so no release */
        if (!use_dr_debug) {
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), 
                      "%s/%s/%s/dynamorio.dll", dr_root, lib_arch, "debug");
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf)) {
                fatal("cannot find DynamoRIO library %s", buf);
                goto error; /* actually won't get here */
            }
            warn("using debug DynamoRIO since release not found");
            use_dr_debug = true;
        }
    }

    /* XXX: for x64 installation we need to address the NSIS "bin/" requirement.
     * The 32-bit frontend correctly picks the x64 lib, so we should perhaps
     * just remove the 64-bit frontend in the final package (keep in build
     * dirs b/c hard to build w/ both compilers).
     */
    _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
              "%s%c%s%c%s%cdrstracelib.dll", drstrace_root, DIRSEP, bin_arch, DIRSEP,
              use_drstrace_debug ? "debug" : "release", DIRSEP);
    NULL_TERMINATE_BUFFER(client_path);
    if (!file_is_readable(client_path)) {
        if (!use_drstrace_debug) {
            _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s%c%s%c%s%cdrstracelib.dll", drstrace_root,
                      DIRSEP, bin_arch, DIRSEP, "debug", DIRSEP);
            NULL_TERMINATE_BUFFER(client_path);
            if (!file_is_readable(client_path)) {
                fatal("invalid -drstrace_root: cannot find %s", client_path);
                goto error; /* actually won't get here */
            }
            /* try to avoid warning for devs running from build dir */
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(client_path), 
                      "%s%cCMakeCache.txt", drstrace_root, DIRSEP);
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf))
                warn("using debug Dr. Memory since release not found");
            use_drstrace_debug = true;
        }
    }

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
                           false/*local*/, DR_PLATFORM_DEFAULT, CLIENT_ID,
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
    return (exit0 ? 0 : errcode);
}
