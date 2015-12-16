/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
 * **********************************************************

 * Dr. Memory: the memory debugger
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

 /* front end for drheapstat tool */

 #ifdef WINDOWS
 # define UNICODE
 # define _UNICODE
 #endif

#include "dr_api.h" /* for the types */
#include "dr_inject.h"
#include "dr_config.h"
#include "dr_frontend.h"
#include "utils.h"
#include "../drmemory/frontend.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)
#define MAX_APP_CMDLINE 4096

#ifdef X64
# define LIB_ARCH "lib64"
# define BIN_ARCH "bin64"
#else
# define LIB_ARCH "lib32"
# define BIN_ARCH "bin"
#endif

#ifdef WINDOWS
# define DR_LIB_NAME "dynamorio.dll"
# define DRHEAPSTAT_LIB_NAME "drheapstatlib.dll"
#elif defined(LINUX)
# define DR_LIB_NAME "libdynamorio.so"
# define DRHEAPSTAT_LIB_NAME "libdrheapstatlib.so"
#elif defined(MACOS)
# define DR_LIB_NAME "libdynamorio.dylib"
# define DRHEAPSTAT_LIB_NAME "libdrheapstatlib.dylib"
#endif

/* -shared_slowpath requires -disable_traces
 * to save space we use -bb_single_restore_prefix
 * PR 415155: our code expansion causes us to exceed max bb size sometimes
 */
#define DEFAULT_DR_OPS "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256"

#define CLIENT_ID 0

#define prefix ""

static bool verbose;
static bool quiet;

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

/* XXX: share w/ options.c and drmemory/frontend.c */
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
    TYPE_IS_BOOL_uint64     = false,
    TYPE_IS_STRING_bool       = false,
    TYPE_IS_STRING_opstring_t = true,
    TYPE_IS_STRING_multi_opstring_t = false,
    TYPE_IS_STRING_uint       = false,
    TYPE_IS_STRING_int        = false,
    TYPE_IS_STRING_uint64     = false,
    TYPE_HAS_RANGE_bool       = false,
    TYPE_HAS_RANGE_opstring_t = false,
    TYPE_HAS_RANGE_multi_opstring_t = false,
    TYPE_HAS_RANGE_uint       = true,
    TYPE_HAS_RANGE_int        = true,
    TYPE_HAS_RANGE_uint64     = true,
};

static const char * const bool_string[2] = {
    "false",
    "true",
};

static void
print_usage(bool full)
{
    fprintf(stderr, "Usage: drheapstat [options] -- <app and args to run>\n");
    if (!full) {
        fprintf(stderr, "Run with --help for full option list.\n");
#ifdef WINDOWS
        fprintf(stderr, "If running from the Start Menu or desktop icon, you must drag\n"
                "your application onto drheapstat.exe.  To pass arguments you must\n"
                "instead invoke drheapstat.exe from an existing shell.\n");
#endif
        fprintf(stderr, "See http://drmemory.org/docs/ for more information.\n");
        return;
    }
#define OPTION_CLIENT(scope, name, type, defval, min, max, short, long) \
    if (SCOPE_IS_PUBLIC_##scope) {                                      \
        if (TYPE_IS_BOOL_##type) { /* turn "(0)" into "false" */        \
            fprintf(stderr, "  -%-28s [%6s]  %s\n", #name,              \
                    bool_string[(ptr_int_t)defval >= 1 ? 1 : 0], short);\
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
    fprintf(stderr, "ERROR: " msg "\n\n", ##__VA_ARGS__);         \
    print_usage(false);                                         \
    exit(1);                                                    \
} while (0)

#undef BUFPRINT /* XXX: we could redefine ASSERT to use utils.h BUFPRINT here */
/* must use dr_snprintf here to support %S converting UTF-16<->UTF-8 */
#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    drfront_status_t sc = drfront_bufprint(buf, bufsz, &(sofar), &(len), ##__VA_ARGS__); \
    if (sc != DRFRONT_SUCCESS) \
        fatal("drfront_bufprint failed: %d\n", sc); \
} while (0)

/* XXX: Much of the following utils are identical between the front-ends.
 * We should consider adding a common/utils_frontend.c or similar.
 */

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
file_is_readable(char *path)
{
    bool ret = false;
    return (drfront_access(path, DRFRONT_READ, &ret) == DRFRONT_SUCCESS && ret);
}

static bool
file_is_writable(char *path)
{
    bool ret = false;
    return (drfront_access(path, DRFRONT_WRITE, &ret) == DRFRONT_SUCCESS && ret);
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


#ifdef WINDOWS
 /* always null-terminates */
static void
char_to_tchar(const char *str, TCHAR *wbuf, size_t wbuflen/*# elements*/)
{
    drfront_status_t sc = drfront_char_to_tchar(str, wbuf, wbuflen);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed (status=%d) to convert UTF-8 to UTF-16", sc);
}

/* i#200/PR 459481: communicate child pid via file.
 * We don't need this on unix b/c we use exec.
 */
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
#endif /* WINDOWS */

int
_tmain(int argc, TCHAR *targv[])
{
    char **argv;
    char *process = NULL;
    char *dr_root = NULL;
    char *drheapstat_root = NULL;
    char default_dr_root[MAXIMUM_PATH];
    char default_drheapstat_root[MAXIMUM_PATH];
    char client_path[MAXIMUM_PATH];

    char client_ops[MAX_DR_CMDLINE];
    size_t cliops_sofar = 0; /* for BUFPRINT to client_ops */
    char dr_ops[MAX_DR_CMDLINE];
    size_t drops_sofar = 0; /* for BUFPRINT to dr_ops */
    ssize_t len; /* shared by all BUFPRINT */

    char logdir[MAXIMUM_PATH];
    bool have_logdir = false;
    bool use_root_for_logdir;

#ifdef WINDOWS
    char *pidfile = NULL;
#endif
#ifndef MACOS /* XXX i#1286: implement nudge on MacOS */
    process_id_t nudge_pid = 0;
#endif
    bool use_dr_debug = false;
    bool use_drheapstat_debug = false;

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
    bool dr_logdir_specified = false;
    bool doubledash_present = false;

    drfront_status_t sc;
    bool res;
#ifndef X64
    bool is64, is32;
#endif

    dr_standalone_init();

#if defined(WINDOWS) && !defined(_UNICODE)
# error _UNICODE must be defined
#else
    /* Convert to UTF-8 if necessary */
    sc = drfront_convert_args((const TCHAR **)targv, &argv, argc);
    if (sc != DRFRONT_SUCCESS)
        fatal("failed to process args: %d\n", sc);
#endif
    /* Default root: we assume this exe is <root>/bin/drheapstat.exe */
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
    get_absolute_path(buf, default_drheapstat_root,
                      BUFFER_SIZE_ELEMENTS(default_drheapstat_root));
    NULL_TERMINATE_BUFFER(default_drheapstat_root);
    drheapstat_root = default_drheapstat_root;
    string_replace_character(drheapstat_root, ALT_DIRSEP, DIRSEP); /* canonicalize */

    BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
             drops_sofar, len, "%s ", DEFAULT_DR_OPS);

    client_ops[0] = '\0';

    /* default logdir */
    if (drfront_appdata_logdir(drheapstat_root, "Dr. Heapstat", &use_root_for_logdir,
                               logdir, BUFFER_SIZE_ELEMENTS(logdir)) == DRFRONT_SUCCESS
        && !use_root_for_logdir) {
        if ((dr_create_dir(logdir) || dr_directory_exists(logdir)) &&
            file_is_writable(logdir))
            have_logdir = true;
    }
    if (!have_logdir) {
        _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s%cdrheapstat%clogs",
                  drheapstat_root, DIRSEP, DIRSEP);
        NULL_TERMINATE_BUFFER(logdir);
        if (!file_is_writable(logdir)) {
            _snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s%clogs",
                      drheapstat_root, DIRSEP);
            NULL_TERMINATE_BUFFER(logdir);
            if (file_is_writable(logdir))
                have_logdir = true;
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
        else if (strcmp(argv[i], "-dr_debug") == 0) {
            use_dr_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-dr_release") == 0) {
            use_dr_debug = false;
            continue;
        }
        else if (strcmp(argv[i], "-debug") == 0) {
            use_drheapstat_debug = true;
            continue;
        }
        else if (strcmp(argv[i], "-release") == 0) {
            use_drheapstat_debug = false;
            continue;
        }
        else if (!strcmp(argv[i], "-version")) {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
          printf("Dr. Heapstat version %s -- build %d\n", VERSION_STRING, BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
          printf("Dr. Heapstat custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#elif defined(VERSION_NUMBER)
          printf("Dr. Heapstat version %s -- custom build %s, %s\n",
                 VERSION_STRING, __DATE__, __TIME__);
#else
          printf("Dr. Heapstat custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
          exit(0);
        }
        else if (strcmp(argv[i], "-dr") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            dr_root = argv[++i];
        }
        else if (strcmp(argv[i], "-drheapstat") == 0) {
            if (i >= argc - 1)
                usage("invalid arguments");
            drheapstat_root = argv[++i];
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
        else if (strcmp(argv[i], "-exit0") == 0) {
            exit0 = true;
        } /* FIXME i#1653: add support for options the old perl frontend supported */
        else {
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
        res = dr_nudge_pid(nudge_pid, CLIENT_ID, NUDGE_LEAK_SCAN, INFINITE);
        if (res != DR_SUCCESS) {
            fatal("error nudging %d%s", nudge_pid,
                  (res == DR_NUDGE_PID_NOT_INJECTED) ? ": no such Dr. Heapstat process"
                  : "");
            assert(false); /* shouldn't get here */
        }
        exit(0);
    }
#endif

    if (i >= argc)
        usage("%s", "no app specified");
    app_name = argv[i];
    get_full_path(app_name, full_app_name, BUFFER_SIZE_ELEMENTS(full_app_name));
    if (full_app_name[0] != '\0')
        app_name = full_app_name;
    info("targeting application: \"%s\"", app_name);

    /* XXX: See drmemory/frontend.c for notes about our argv processing. */
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
    /* XXX: See drmemory/frontend.c for notes about 64-bit support. */
    if (drfront_is_64bit_app(app_name, &is64, &is32) == DRFRONT_SUCCESS &&
        is64 && !is32) {
        fatal("This Dr. Heapstat release does not support 64-bit applications.");
        goto error; /* actually won't get here */
    }
#endif

    if (!file_is_readable(dr_root)) {
        fatal("invalid -dr %s", dr_root);
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
              "%s/"LIB_ARCH"/%s/%s", dr_root,
              use_dr_debug ? "debug" : "release", DR_LIB_NAME);
    NULL_TERMINATE_BUFFER(buf);
    if (!file_is_readable(buf)) {
        /* support debug build w/ integrated debug DR build and so no release */
        if (!use_dr_debug) {
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                      "%s/"LIB_ARCH"/%s/%s", dr_root, "debug", DR_LIB_NAME);
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
              "%s%c"BIN_ARCH"%c%s%c%s", drheapstat_root, DIRSEP, DIRSEP,
              use_drheapstat_debug ? "debug" : "release", DIRSEP, DRHEAPSTAT_LIB_NAME);
    NULL_TERMINATE_BUFFER(client_path);
    if (!file_is_readable(client_path)) {
        if (!use_drheapstat_debug) {
            _snprintf(client_path, BUFFER_SIZE_ELEMENTS(client_path),
                      "%s%c"BIN_ARCH"%c%s%c%s", drheapstat_root,
                      DIRSEP, DIRSEP, "debug", DIRSEP, DRHEAPSTAT_LIB_NAME);
            NULL_TERMINATE_BUFFER(client_path);
            if (!file_is_readable(client_path)) {
                fatal("invalid -drheapstat_root: cannot find %s", client_path);
                goto error; /* actually won't get here */
            }
            /* try to avoid warning for devs running from build dir */
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(client_path),
                      "%s%cCMakeCache.txt", drheapstat_root, DIRSEP);
            NULL_TERMINATE_BUFFER(buf);
            if (!file_is_readable(buf))
                warn("using debug Dr. Heapstat since release not found");
            use_drheapstat_debug = true;
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

    /* Put DR logs inside drheapstat logdir */
    if (!dr_logdir_specified) {
        _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%s%cdynamorio", logdir, DIRSEP);
        NULL_TERMINATE_BUFFER(buf);
        if (!dr_directory_exists(buf)) {
            if (!dr_create_dir(buf)) {
                /* check again in case of a race */
                if (!dr_directory_exists(buf)) {
                    fatal("cannot create %s", buf);
                    goto error; /* actually won't get here */
                }
            }
        }
        BUFPRINT(dr_ops, BUFFER_SIZE_ELEMENTS(dr_ops),
                 drops_sofar, len, "-logdir `%s` ", buf);
    }

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
#ifdef WINDOWS
    if (pidfile != NULL)
        write_pid_to_file(pidfile, pid);
#endif

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
    dr_inject_process_run(inject_data);
#ifdef UNIX
    fatal("Failed to exec application");
#else
    info("waiting for app to exit...");
    errcode = WaitForSingleObject(dr_inject_get_process_handle(inject_data), INFINITE);
    if (errcode != WAIT_OBJECT_0)
        info("failed to wait for app: %d\n", errcode);
#endif
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
