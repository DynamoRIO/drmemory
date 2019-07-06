/* ***************************************************************************
 * Copyright (c) 2017-2019 Google, Inc.  All rights reserved.
 * ***************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* front end for drltrace tool */

#ifdef WINDOWS
# define UNICODE
# define _UNICODE
#endif

#include "dr_api.h"
#include "dr_inject.h"
#include "dr_config.h"
#include "dr_frontend.h"
#include "drltrace_options.h"
#undef TESTANY
#include "utils.h"
#include <string.h>

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)

#define DRLTRACE_ERROR(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
    exit(1); \
} while (0)

#define DRLTRACE_WARN(msg, ...) do { \
    fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
} while (0)

#define DRLTRACE_INFO(level, msg, ...) do { \
    if (op_verbose.get_value() >= level) {\
        fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__);    \
        fflush(stderr); \
    }\
} while (0)

#undef BUFPRINT
#define BUFPRINT(buf, bufsz, sofar, len, ...) do { \
    drfront_status_t sc = drfront_bufprint(buf, bufsz, &(sofar), &(len), ##__VA_ARGS__); \
    if (sc != DRFRONT_SUCCESS) \
        DRLTRACE_ERROR("drfront_bufprint failed: %d\n", sc); \
    NULL_TERMINATE_BUFFER(buf); \
} while (0)

/* check that drltracelib.dll, dynamorio.dll and target executable exist */
static void
check_input_files(const char *target_app_full_name, char *dr_root, char *drltrace_path) {
    bool result = false;

    /* check that the target application exists */
    if (target_app_full_name[0] == '\0')
        DRLTRACE_ERROR("target application is not specified");

    if (drfront_access(target_app_full_name, DRFRONT_READ, &result) != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("cannot find target application at %s", target_app_full_name);
    if (!result) {
        DRLTRACE_ERROR("cannot open target application for read at %s",
                       target_app_full_name);
    }

    /* check that dynamorio's root dir exists and is accessible */
    if (drfront_access(dr_root, DRFRONT_READ, &result) != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("cannot find DynamoRIO's root dir at %s", dr_root);
    if (!result)
        DRLTRACE_ERROR("cannot open DynamoRIO's root dir for read at %s", dr_root);

    /* check that drfrontendlib exist */
    if (drfront_access(drltrace_path, DRFRONT_READ, &result) != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("cannot find drltracelib at %s", drltrace_path);
    if (!result)
        DRLTRACE_ERROR("cannot open drltracelib for read at %s", drltrace_path);
}

static void
print_version() {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
    printf("drltrace version %s -- build %d\n", STRINGIFY(VERSION_NUMBER), BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
    printf(TOOLNAME" custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#else
    printf(TOOLNAME" custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
    exit(0);
}

static void
configure_application(char *app_name, char **app_argv, void **inject_data,
                      const char *dr_root, const char *lib_path, const char *log_dir,
                      const char *config_file, const char *sysnum_file)
{
    bool is_debug = false;
#ifdef DEBUG
    is_debug = true;
#endif
    int errcode;
    drfront_status_t sc;
    ssize_t len;
    size_t sofar = 0;
    char *process;
    process_id_t pid;
    char dr_option[MAX_DR_CMDLINE];
    char drltrace_option[MAX_DR_CMDLINE];
    dr_option[0] = '\0';

    if (!op_follow_children.get_value())
        dr_snprintf(dr_option, BUFFER_SIZE_ELEMENTS(dr_option), "-no_follow_children");
    NULL_TERMINATE_BUFFER(dr_option);

    BUFPRINT(drltrace_option, BUFFER_SIZE_ELEMENTS(drltrace_option), sofar, len, "%s ",
             op_ltracelib_ops.get_value().c_str());

    if (log_dir[0] != '\0') {
        BUFPRINT(drltrace_option, BUFFER_SIZE_ELEMENTS(drltrace_option), sofar, len,
                 "-logdir `%s` ", log_dir);
    }
    if (config_file[0] != '\0') {
        BUFPRINT(drltrace_option, BUFFER_SIZE_ELEMENTS(drltrace_option), sofar, len,
                 "-config `%s` ", config_file);
    }
    if (sysnum_file[0] != '\0') {
        BUFPRINT(drltrace_option, BUFFER_SIZE_ELEMENTS(drltrace_option), sofar, len,
                 "-sysnum_file `%s` ", sysnum_file);
    }

#ifdef UNIX
    errcode = dr_inject_prepare_to_exec(app_name, (const char **)app_argv, inject_data);
#else
    errcode = dr_inject_process_create(app_name, (const char **)app_argv, inject_data);
#endif
    if (errcode != 0 && errcode != WARN_IMAGE_MACHINE_TYPE_MISMATCH_EXE) {
        std::string msg =
            std::string("failed to create process for \"") + app_name + "\"";
#ifdef WINDOWS
        char buf[MAXIMUM_PATH];
        int sofar = dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%s", msg.c_str());
        NULL_TERMINATE_BUFFER(buf);
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR) buf + sofar,
                      BUFFER_SIZE_ELEMENTS(buf) - sofar*sizeof(char), NULL);
#endif
        DRLTRACE_ERROR("%s", msg.c_str());
    }

    pid = dr_inject_get_process_id(*inject_data);

    process = dr_inject_get_image_name(*inject_data);
    if (dr_register_process(process, pid,
                            false, dr_root,
                            DR_MODE_CODE_MANIPULATION,
                            is_debug, DR_PLATFORM_DEFAULT,
                            dr_option) != DR_SUCCESS) {
        DRLTRACE_ERROR("failed to register DynamoRIO configuration");
    }

    if (dr_register_client(process, pid, false, DR_PLATFORM_DEFAULT, 0, 0, lib_path,
                           drltrace_option) != DR_SUCCESS) {
        DRLTRACE_ERROR("failed to register DynamoRIO client configuration");
    }
}

static void
check_logdir_path(char *logdir, size_t logdir_len) {
    drfront_status_t sc;
    char absolute_logdir_path[MAXIMUM_PATH];
    char alter_logdir_path[MAXIMUM_PATH];
    bool result, use_root;

    if (strcmp(logdir, "-") == 0)
        return; /* logdir is stderr */

    sc = drfront_get_absolute_path(logdir, absolute_logdir_path,
                                   BUFFER_SIZE_ELEMENTS(absolute_logdir_path));
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_get_absolute_path failed, error code = %d\n", sc);

    if (!dr_directory_exists(absolute_logdir_path))
        DRLTRACE_ERROR("specified logdir doesn't exist");

    sc = drfront_appdata_logdir(absolute_logdir_path, "Dr. LTrace", &use_root,
                                alter_logdir_path,
                                BUFFER_SIZE_ELEMENTS(alter_logdir_path));
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_appdata_logdir failed, error code = %d\n", sc);
    if (!use_root) {
        DRLTRACE_WARN("cannot write log file into %s, writing log into %s instead",
                      absolute_logdir_path, alter_logdir_path);
        dr_snprintf(logdir, logdir_len, "%s", alter_logdir_path);
        /* if folder doesn't exist, create it */
        if (!dr_directory_exists(alter_logdir_path) && !dr_create_dir(alter_logdir_path))
            DRLTRACE_ERROR("failed to create a folder at %s", alter_logdir_path);
    }
    else {
        dr_snprintf(logdir, logdir_len, "%s", absolute_logdir_path);
    }
    logdir[logdir_len - 1] = '\0';
}

#ifdef WINDOWS
/* XXX: Can we share this code with Dr. Memory?  Make it part of DRMF? */
static bool
generate_sysnum_file(const char *outfile, const char *cache_dir)
{
    int i;
    size_t lib_count = 0;
    char **lib_paths;
    void *drcontext = dr_standalone_init();
    if (drcontext == NULL)
        return false;
    drmf_status_t res = drsys_find_sysnum_libs(NULL, &lib_count);
    if (res != DRMF_ERROR_INVALID_SIZE)
        return false;
    lib_paths = reinterpret_cast<char**>(malloc(lib_count * sizeof(lib_paths[0])));
    if (lib_paths == NULL)
        return false;
    for (i = 0; i < lib_count; ++i) {
        lib_paths[i] = reinterpret_cast<char*>(malloc(MAXIMUM_PATH));
        if (lib_paths[i] == NULL)
            return false;
    }
    res = drsys_find_sysnum_libs(lib_paths, &lib_count);
    if (res != DRMF_SUCCESS)
        return false;
    res = drsys_generate_sysnum_file(drcontext, const_cast<const char**>(lib_paths),
                                     lib_count, outfile, cache_dir);
    for (i = 0; i < lib_count; ++i)
        free(lib_paths[i]);
    free(lib_paths);
    return (res == DRMF_SUCCESS);
}
#endif

int
_tmain(int argc, const TCHAR *targv[])
{
    char drlibpath[MAXIMUM_PATH];
#ifdef WINDOWS
    static const char *libname = "drltracelib.dll";
#elif MACOS
    static const char *libname = "libdrltracelib.dylib";
#elif LINUX
    static const char *libname = "libdrltracelib.so";
#endif
#ifdef DEBUG
    dr_snprintf(drlibpath, BUFFER_SIZE_ELEMENTS(drlibpath), "debug/%s", libname);
#else
    dr_snprintf(drlibpath, BUFFER_SIZE_ELEMENTS(drlibpath), "release/%s", libname);
#endif
    NULL_TERMINATE_BUFFER(drlibpath);

    void *inject_data;
    int exitcode;
    char **argv;
    char *tmp;
    const char *target_app_name;

    char full_target_app_path[MAXIMUM_PATH];
    char tmp_path[MAXIMUM_PATH];
    char full_frontend_path[MAXIMUM_PATH];
    char full_dr_root_path[MAXIMUM_PATH];
    char full_drlibtrace_path[MAXIMUM_PATH];
    char logdir[MAXIMUM_PATH];
    char config_file[MAXIMUM_PATH];

    int last_index;
    std::string parse_err;
    drfront_status_t sc;
#ifdef WINDOWS
    bool tried_generating_sysnum_file = false;
#endif

#if defined(WINDOWS) && !defined(_UNICODE)
# error _UNICODE must be defined
#else
    /* Convert to UTF-8 if necessary */
    sc = drfront_convert_args((const TCHAR **)targv, &argv, argc);
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("failed to process args, error code = %d\n", sc);
#endif

    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_FRONTEND, argc, (const char **)argv,
                                       &parse_err, &last_index) || argc < 2) {
        DRLTRACE_ERROR("Usage error: %s\n Usage:\n%s\n", parse_err.c_str(),
                       droption_parser_t::usage_short(DROPTION_SCOPE_ALL).c_str());
    }
    op_verbose_level = op_verbose.get_value();

    if (op_version.get_value()) {
        print_version();
        return 0;
    }
    if (op_help.get_value()) {
        printf("Usage:\n%s", droption_parser_t::usage_long(DROPTION_SCOPE_ALL).c_str());
        return 0;
    }

    target_app_name = argv[last_index];
    if (target_app_name == NULL) {
        DRLTRACE_ERROR("Usage error, target application is not specified.\n Usage:\n%s\n",
                       droption_parser_t::usage_short(DROPTION_SCOPE_ALL).c_str());
    }
    sc = drfront_get_app_full_path(target_app_name, full_target_app_path,
                                   BUFFER_SIZE_ELEMENTS(full_target_app_path));
    if (sc != DRFRONT_SUCCESS) {
        DRLTRACE_ERROR("drfront_get_app_full_path failed on %s, error code = %d\n",
                       target_app_name, sc);
    }

    /* get DR's root directory and drltrace.exe full path */
    sc = drfront_get_app_full_path(argv[0], full_frontend_path,
                                   BUFFER_SIZE_ELEMENTS(full_frontend_path));
    if (sc != DRFRONT_SUCCESS) {
        DRLTRACE_ERROR("drfront_get_app_full_path failed on %s, error code = %d\n",
                       argv[0], sc);
    }

    tmp = full_frontend_path + strlen(full_frontend_path) - 1;

    /* we assume that default root for our executable is <root>/bin/drltrace.exe */
    while (*tmp != DIRSEP && *tmp != ALT_DIRSEP && tmp > full_frontend_path)
        tmp--;
    *(tmp+1) = '\0';

    /* in case of default config option, we use drltrace's frontend path */
    if (op_config_file_default.get_value()) {
        dr_snprintf(tmp_path, BUFFER_SIZE_ELEMENTS(tmp_path), "%s/drltrace.config",
                    full_frontend_path /* binary path */);
        NULL_TERMINATE_BUFFER(tmp_path);
        sc = drfront_get_absolute_path(tmp_path, config_file,
                                       BUFFER_SIZE_ELEMENTS(config_file));
        if (sc != DRFRONT_SUCCESS)
            DRLTRACE_ERROR("drfront_get_absolute_path failed, error code = %d\n", sc);
    } else {
        dr_snprintf(config_file, BUFFER_SIZE_ELEMENTS(config_file), "%s",
                    op_config_file.get_value().c_str());
    }
    NULL_TERMINATE_BUFFER(config_file);

    dr_snprintf(tmp_path, BUFFER_SIZE_ELEMENTS(tmp_path), "%s../dynamorio",
                full_frontend_path);
    NULL_TERMINATE_BUFFER(tmp_path);

    sc = drfront_get_absolute_path(tmp_path, full_dr_root_path,
                                   BUFFER_SIZE_ELEMENTS(full_dr_root_path));
    NULL_TERMINATE_BUFFER(full_dr_root_path);

    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_get_absolute_path failed, error code = %d\n", sc);

    dr_snprintf(full_drlibtrace_path, BUFFER_SIZE_ELEMENTS(full_drlibtrace_path),
                "%s%s", full_frontend_path, drlibpath);
    NULL_TERMINATE_BUFFER(full_drlibtrace_path);

    check_input_files(full_target_app_path, full_dr_root_path, full_drlibtrace_path);

    if (op_logdir.get_value().c_str() != NULL) {
        dr_snprintf(logdir, BUFFER_SIZE_ELEMENTS(logdir), "%s",
                    op_logdir.get_value().c_str());
        NULL_TERMINATE_BUFFER(logdir);
        /* check logdir access rights, convert in absolute path and replace if it is
         * required.
         */
        check_logdir_path(logdir, BUFFER_SIZE_ELEMENTS(logdir));
        NULL_TERMINATE_BUFFER(logdir); /* logdir has been replaced */
    } else {
        logdir[0] = '\0';
    }

#ifdef WINDOWS
    if (op_sysnum_file.get_value().empty() || op_symcache_dir.get_value().empty()) {
        bool use_root;
        char local_root_dir[MAXIMUM_PATH];
        char root_dir[MAXIMUM_PATH];
        char drmem_dir[MAXIMUM_PATH];
        char cache_dir[MAXIMUM_PATH];
        char sysnum_file[MAXIMUM_PATH];
        /* We assume we're in a bin/ subdir */
        _snprintf(local_root_dir, BUFFER_SIZE_ELEMENTS(local_root_dir), "%s%c..",
                  full_frontend_path, DIRSEP);
        NULL_TERMINATE_BUFFER(local_root_dir);
        drfront_status_t res = drfront_get_absolute_path(local_root_dir, root_dir,
                                                         BUFFER_SIZE_ELEMENTS(root_dir));
        if (res != DRFRONT_SUCCESS)
            DRLTRACE_ERROR("failed to locate root directory");
        NULL_TERMINATE_BUFFER(root_dir);

        sc = drfront_appdata_logdir(root_dir, "Dr. Memory", &use_root,
                                    drmem_dir, BUFFER_SIZE_ELEMENTS(drmem_dir));
        if (sc == DRFRONT_SUCCESS) {
            /* Try to use Dr. Memory's dir. */
            if (use_root) {
                /* A zip install has drmemory/logs/symcache, though it has to be created
                 * (which we try to do just below if another tool has not yet run).
                 */
                _snprintf(cache_dir, BUFFER_SIZE_ELEMENTS(cache_dir),
                          "%s%cdrmemory%clogs%csymcache", root_dir, DIRSEP, DIRSEP,
                          DIRSEP);
                NULL_TERMINATE_BUFFER(cache_dir);
                /* A local build has logs/symcache */
                if (!dr_directory_exists(cache_dir) && !dr_create_dir(cache_dir)) {
                    _snprintf(cache_dir, BUFFER_SIZE_ELEMENTS(cache_dir),
                              "%s%clogs%csymcache", root_dir, DIRSEP, DIRSEP);
                    NULL_TERMINATE_BUFFER(cache_dir);
                }
                /* Fall back to logs if it's there. */
                if (!dr_directory_exists(cache_dir) && !dr_create_dir(cache_dir)) {
                    _snprintf(cache_dir, BUFFER_SIZE_ELEMENTS(cache_dir),
                              "%s%clogs", root_dir, DIRSEP);
                    NULL_TERMINATE_BUFFER(cache_dir);
                }
            } else {
                _snprintf(cache_dir, BUFFER_SIZE_ELEMENTS(cache_dir),
                          "%s%csymcache", drmem_dir, DIRSEP);
                NULL_TERMINATE_BUFFER(cache_dir);
            }
            if (!dr_directory_exists(cache_dir) && !dr_create_dir(cache_dir)) {
                /* Fall back to specified log dir. */
                _snprintf(cache_dir, BUFFER_SIZE_ELEMENTS(cache_dir),
                          "%s", logdir);
                NULL_TERMINATE_BUFFER(cache_dir);
            }
            op_symcache_dir.set_value(cache_dir);

            _snprintf(sysnum_file, BUFFER_SIZE_ELEMENTS(sysnum_file),
                      "%s%c%s", cache_dir, DIRSEP,
                      dr_is_wow64() ? SYSNUM_FILE_WOW64 : SYSNUM_FILE);
            NULL_TERMINATE_BUFFER(sysnum_file);
            op_sysnum_file.set_value(sysnum_file);
        }
    }
#endif

    dr_standalone_init();

    do {
        configure_application(full_target_app_path, &argv[last_index], &inject_data,
                              full_dr_root_path, full_drlibtrace_path, logdir,
                              config_file, op_sysnum_file.get_value().c_str());

        if (!dr_inject_process_inject(inject_data, false/*!force*/, NULL))
            DRLTRACE_ERROR("unable to inject");

        if (!dr_inject_process_run(inject_data))
            DRLTRACE_ERROR("unable to execute target application");

        DRLTRACE_INFO(1, "%s sucessfully started, waiting app for exit",
                      full_target_app_path);

        dr_inject_wait_for_child(inject_data, 0/*wait forever*/);

        exitcode = dr_inject_process_exit(inject_data, false);
#ifdef WINDOWS
        if (exitcode == STATUS_INVALID_KERNEL_INFO_VERSION) {
            DRLTRACE_WARN("Missing system call information for this operating system "
                          "version.");
            if (tried_generating_sysnum_file)
                DRLTRACE_ERROR("Failed to auto-generate information.  Aborting.");
            DRLTRACE_INFO(0, "Attempting to auto-generate system call information...");
            DRLTRACE_INFO(1, "Target file is %s", op_sysnum_file.get_value().c_str());
            tried_generating_sysnum_file = true;
            /* Give the user some visible feedback. */
            int prior_verbose = op_verbose_level;
            if (op_verbose_level <= 0)
                op_verbose_level = 1;
            if (generate_sysnum_file(op_sysnum_file.get_value().c_str(),
                                     op_symcache_dir.get_value().c_str())) {
                DRLTRACE_INFO(0, "Auto-generation succeeded. "
                              "Re-launching the application.");
                op_verbose_level = prior_verbose;
                continue; /* restart app */
            }
            op_verbose_level = prior_verbose;
        }
#endif
        break;
    } while (true);

    sc = drfront_cleanup_args(argv, argc);
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_cleanup_args error, error code = %d", sc);

    return exitcode;
}
