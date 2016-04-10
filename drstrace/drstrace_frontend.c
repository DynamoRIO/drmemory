/* **********************************************************
 * Copyright (c) 2010-2016 Google, Inc.  All rights reserved.
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
#include "dr_frontend.h"
#include "utils.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

/* XXX DRi#1079: can we put even more into drfrontendlib?  DR location, client
 * lib location, DR and client lib debug vs release, DR and client options, etc.
 */

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)
#define MAX_APP_CMDLINE 4096

#define BIN32_ARCH "bin"
#define BIN64_ARCH "bin64"
#define LIB32_ARCH "lib32"
#define LIB64_ARCH "lib64"

/* As this is a Windows tool, we tune it for startup and not steady-state perf.
 * -fast_client_decode relies on drmgr, drx, and drsyscall support.
 */
/* FIXME i#1876: -fast_client_decode is causing app crashes on big Java apps.
 * We disable for now but it would be nice to fix the bug and re-enable.
 */
#define DEFAULT_DR_OPS "-disable_traces -nop_initial_bblock"

#define CLIENT_ID 0

#define prefix ""

static bool verbose;
static bool quiet;
static bool results_to_stderr = true;
static bool no_resfile; /* no results file expected */
static bool top_stats;

#define fatal(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
    exit(1); \
} while (0)

#define warn(msg, ...) do { \
    if (!quiet) { \
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

static void
print_usage(void)
{
    fprintf(stderr, "usage: drstrace [options] -- <app and args to run>\n");
    /* XXX: have an optionsx.h?  Shared frontend lib (i#1079) could help
     * solve that by providing usage and options parsing for its provided
     * options.
     */
    fprintf(stderr, "-logdir <dir>   Specify log directory where system call data\n");
    fprintf(stderr, "                will be written, in a separate file per process.\n");
    fprintf(stderr, "                The default value is \".\" (current dir).\n");
    fprintf(stderr, "                If set to \"-\", data for all processes are\n");
    fprintf(stderr, "                printed to stderr (warning: this can be slow).\n");
    fprintf(stderr, "-symcache_path <path>   Specify absolute path where symbol data\n");
    fprintf(stderr, "                should be cached. If not set, _NT_SYMBOL_PATH\n");
    fprintf(stderr, "                environment variable will be used, if set; else\n");
    fprintf(stderr, "                a local directory will be used.\n");
    fprintf(stderr, "-[no_]load_symbols  Enables or disables loading of symbols over\n");
    fprintf(stderr, "                the network.  This option is enabled by default.\n");
    fprintf(stderr, "-no_follow_children   Do not trace child processes (overrides\n");
    fprintf(stderr, "                the default, which is to trace all children).\n");
    fprintf(stderr, "-version        Print version number.\n");
    fprintf(stderr, "-verbose <N>    Change verbosity (default 1).\n");
}

#define usage(msg, ...) do {                                    \
    fprintf(stderr, "\n");                                      \
    fprintf(stderr, "ERROR: " msg "\n\n", ##__VA_ARGS__);         \
    print_usage();                                              \
    exit(1);                                                    \
} while (0)

#undef BUFPRINT /* XXX: we could redefine ASSERT to use utils.h BUFPRINT here */
/* must use dr_snprintf here to support %S converting UTF-16<->UTF-8 */
#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    drfront_status_t sc = drfront_bufprint(buf, bufsz, &(sofar), &(len), ##__VA_ARGS__); \
    if (sc != DRFRONT_SUCCESS) \
        fatal("drfront_bufprint failed: %d\n", sc); \
} while (0)

/* always null-terminates */
static void
char_to_tchar(const char *str, TCHAR *wbuf, size_t wbuflen/*# elements*/)
{
    drfront_status_t sc = drfront_char_to_tchar(str, wbuf, wbuflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("drfront_char_to_tchar failed: %d\n", sc);
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
    bool ret = false;
    return (drfront_access(path, DRFRONT_READ, &ret) == DRFRONT_SUCCESS && ret);
}

static void
get_absolute_path(const char *src, char *buf, size_t buflen/*# elements*/)
{
    drfront_status_t sc = drfront_get_absolute_path(src, buf, buflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("drfront_get_absolute_path failed: %d\n", sc);
}

static void
get_full_path(const char *app, char *buf, size_t buflen/*# elements*/)
{
    drfront_status_t sc = drfront_get_app_full_path(app, buf, buflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("drfront_get_app_full_path failed: %d\n", sc);
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
    char sym_path[MAXIMUM_PATH];
    char symsrv_path[MAXIMUM_PATH];
    char pdb_path[MAXIMUM_PATH];
    char dr_logdir[MAXIMUM_PATH];
    char symdll_path[MAXIMUM_PATH];

    size_t drops_sofar = 0; /* for BUFPRINT to dr_ops */
    ssize_t len; /* shared by all BUFPRINT */

    bool use_dr_debug = false;
    bool use_drstrace_debug = false;
    bool dr_logdir_specified = false;
    bool sym_path_specified = false;
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

    drfront_status_t sc;
    bool res;
    bool is64, is32;
    bool load_symbols = true;

    dr_standalone_init();

#if defined(WINDOWS) && !defined(_UNICODE)
# error _UNICODE must be defined
#else
    /* Convert to UTF-8 if necessary */
    sc = drfront_convert_args((const TCHAR **)targv, &argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to process args: %d\n", sc);
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

    client_ops[0] = '\0';

    /* parse command line */
    /* FIXME PR 487993: use optionsx.h to construct this parsing code */
    for (i=1; i<argc; i++) {

        /* note that we pass unknown args to client, until -- */
        if (strcmp(argv[i], "--") == 0) {
            i++;
            break;
        }
        /* drag-and-drop does not include "--" so we try to identify the app. */
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
            if (strstr(argv[i+1], "-logdir ") != NULL)
                dr_logdir_specified = true;
            BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                     drops_sofar, len, "%s ", argv[++i]);
        }
        else if (strcmp(argv[i], "-exit0") == 0) {
            exit0 = true;
        }
        else if (strcmp(argv[i], "-symcache_path") == 0) {
            _snprintf(sym_path, BUFFER_SIZE_ELEMENTS(sym_path),
                      "%s", argv[++i]);
            NULL_TERMINATE_BUFFER(sym_path);
            string_replace_character(sym_path, '\\', '/');
            sym_path_specified = true;
        }
        else if (strcmp(argv[i], "-load_symbols") == 0) {
            load_symbols = true;
        }
        else if (strcmp(argv[i], "-no_load_symbols") == 0) {
            load_symbols = false;
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

    /* Cross-arch injection (i#1506) */
    if (drfront_is_64bit_app(app_name, &is64, &is32) == DRFRONT_SUCCESS &&
        IF_X64_ELSE(!is64, is64 && !is32)) {
        /* While I'd love to just set bin_arch and lib_arch differently,
         * drinjectlib doesn't support cross-arch injection (DRi#803).
         * Thus, to provide single-front-end support, we launch the other
         * frontend.
         */
        char *orig_argv0 = argv[0];
        _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                  "%s%c%s%cdrstrace.exe", drstrace_root, DIRSEP,
                  IF_X64_ELSE(BIN32_ARCH, BIN64_ARCH), DIRSEP);
        NULL_TERMINATE_BUFFER(buf);
        if (!file_is_readable(buf)) {
            fatal("unable to find frontend %s to match target app bitwidth: "
                  "is this an incomplete installation?", buf);
        }
        argv[0] = buf;
        info("launching frontend %s to match target app bitwidth", buf);
        /* XXX DRi#943: this lib routine currently doesn't handle int18n */
        errcode = dr_inject_process_create(buf, argv, &inject_data);
        /* Mismatch is just a warning */
        if (errcode == 0 || errcode == WARN_IMAGE_MACHINE_TYPE_MISMATCH_EXE) {
            dr_inject_process_run(inject_data);
            /* If we don't wait, the prompt comes back, which is confusing */
            info("waiting for other frontend...");
            errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data),
                                          INFINITE);
            if (errcode != WAIT_OBJECT_0)
                info("failed to wait for frontend: %d\n", errcode);
            dr_inject_process_exit(inject_data, false);
            argv[0] = orig_argv0;
            goto cleanup;
        } else {
            fatal("unable to launch frontend to match target app bitwidth: code=%d",
                  errcode);
        }
    }

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
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                      "%s%cCMakeCache.txt", drstrace_root, DIRSEP);
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf))
                warn("using debug Dr. Memory since release not found");
            use_drstrace_debug = true;
        }
    }

    /* If we're installed into Program Files, we have to pick a different
     * DR logdir to avoid popup msgs (i#1499).  We don't want to use the
     * same logdir as for drstrace as the latter supports "-" (stderr).
     */
    if (!dr_logdir_specified) { /* don't override user-specified DR logdir */
        bool use_root;
        /* XXX: ideally we would share DrMem's "/dynamorio/" subdir, but that would
         * require creating both subdirs separately if drstrace is run before drmem.
         * See comment below as well.
         */
        if (drfront_appdata_logdir(dr_root, "Dr. Memory", &use_root,
                                   dr_logdir, BUFFER_SIZE_ELEMENTS(dr_logdir)) !=
            DRFRONT_SUCCESS ||
            use_root ||
            (!dr_create_dir(dr_logdir) && !dr_directory_exists(dr_logdir))) {
            /* A similar situation: we'd prefer to share DrMem's local install
             * "drmemory/logs/dynamorio" but that gets complex to support both
             * in a package and in a dev's local build dir.  Since DR logs
             * are going to be rare w/ drstrace (only for debugging the tool
             * itself) we just go w/ simplicity.
             */
            get_absolute_path(".", dr_logdir, BUFFER_SIZE_ELEMENTS(dr_logdir));
        }
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-logdir `%s` ", dr_logdir);
    }

    if (!sym_path_specified) {
        /* Default location for local symbol cache: if our install dir is
         * writable, we want logs/symbols/.  Else just symbols/ inside
         * AppData Dr. Memory dir.
         * drfront_set_client_symbol_search_path() adds symbols/ for us.
         */
        bool use_root;
        sc = drfront_appdata_logdir(drstrace_root, "Dr. Memory", &use_root,
                                    sym_path, BUFFER_SIZE_ELEMENTS(sym_path));
        if (sc == DRFRONT_SUCCESS) {
            if (use_root) {
                _snprintf(sym_path, BUFFER_SIZE_ELEMENTS(sym_path),
                          "%s%clogs", drstrace_root, DIRSEP);
                NULL_TERMINATE_BUFFER(sym_path);
            }
            if (!dr_create_dir(sym_path) && !dr_directory_exists(sym_path))
                sc = DRFRONT_ERROR;
        }
        if (sc != DRFRONT_SUCCESS) {
            get_absolute_path(".", sym_path, BUFFER_SIZE_ELEMENTS(sym_path));
        }
    }

    /* fetch wintypes.pdb (if not exists) to symcache_path */
    if (drfront_sym_init(NULL, "dbghelp.dll") == DRFRONT_SUCCESS) {
        sc = drfront_set_client_symbol_search_path
            (sym_path, sym_path_specified,
             symsrv_path, BUFFER_SIZE_ELEMENTS(symsrv_path));
        if (sc == DRFRONT_SUCCESS) {
            /* symfetch.dll is in our dir */
            get_full_path(argv[0], buf, BUFFER_SIZE_ELEMENTS(buf));
            c = buf + strlen(buf) - 1;
            while (*c != DIRSEP && *c != ALT_DIRSEP && c > buf)
                c--;
            _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "%s", SYMBOL_DLL_NAME);
            NULL_TERMINATE_BUFFER(buf);
            get_absolute_path(buf, symdll_path, BUFFER_SIZE_ELEMENTS(symdll_path));
            NULL_TERMINATE_BUFFER(symdll_path);
            /* before we add the MS symsrv, see whether we have local symbols */
            sc = drfront_fetch_module_symbols(symdll_path, pdb_path,
                                              BUFFER_SIZE_ELEMENTS(pdb_path));
            if (sc != DRFRONT_SUCCESS && load_symbols) {
                warn("fetching symbol information (procedure may take some time).");
                sc = drfront_set_symbol_search_path(symsrv_path);
                /* We use a special fake dll to obtain symbolic info from MS Symbol
                 * server. PTAL i#1540 for details.
                 */
                if (sc == DRFRONT_SUCCESS) {
                    sc = drfront_fetch_module_symbols(symdll_path, pdb_path,
                                                      BUFFER_SIZE_ELEMENTS(pdb_path));
                    if (sc == DRFRONT_SUCCESS)
                        info("symbol file successfully fetched");
                }
            }
            if (sc == DRFRONT_SUCCESS) {
                /* pass to client */
                BUFPRINT(client_ops, BUFFER_SIZE_ELEMENTS(client_ops),
                         cliops_sofar, len, "-symcache_path `%s` ", pdb_path);
            } else if (!load_symbols) {
                warn("symbol fetching was disabled via -no_load_symbols.");
            } else {
                warn("symbol fetching failed.  Symbol lookup will be disabled.");
            }
        } else {
            warn("failed to set symbol search path.  Symbol lookup will be disabled.");
        }
    } else {
        warn("symbol initialization error.  Symbol lookup will be disabled.");
    }

    /* i#1638: fall back to temp dirs if there's no HOME/USERPROFILE set */
    dr_get_config_dir(false/*local*/, true/*use temp*/, buf, BUFFER_SIZE_ELEMENTS(buf));
    info("DynamoRIO configuration directory is %s", buf);

#ifdef UNIX
    errcode = dr_inject_prepare_to_exec(app_name, (const char **)app_argv, &inject_data);
#else
    errcode = dr_inject_process_create(app_name, (const char **)app_argv, &inject_data);
#endif
    /* Mismatch is just a warning */
    if (errcode != 0 && errcode != WARN_IMAGE_MACHINE_TYPE_MISMATCH_EXE) {
#ifdef WINDOWS
        int sofar =
#endif
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                      "failed to create process for \"%s\": ", app_name);
#ifdef WINDOWS
        if (sofar > 0) {
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                          (LPTSTR) buf + sofar,
                          BUFFER_SIZE_ELEMENTS(buf) - sofar*sizeof(char), NULL);
        }
        NULL_TERMINATE_BUFFER(buf);
#endif
        fatal("%s", buf);
        goto error; /* actually won't get here */
    }

    pid = dr_inject_get_process_id(inject_data);

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
#ifdef UNIX
    fatal("failed to exec application");
#else
    info("waiting for app to exit...");
    errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data), INFINITE);
    if (errcode != WAIT_OBJECT_0)
        info("failed to wait for app: %d\n", errcode);
#endif
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
    sc = drfront_cleanup_args(argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("drfront_cleanup_args failed: %d\n", sc);
    return (exit0 ? 0 : errcode);
}
