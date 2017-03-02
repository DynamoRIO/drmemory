/* ***************************************************************************
 * Copyright (c) 2017 Google, Inc.  All rights reserved.
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
#include "droption.h"
#undef TESTANY
#include "utils.h"
#include <string.h>

#define MAX_DR_CMDLINE (MAXIMUM_PATH*6)

#define DRLTRACE_ERROR(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
    exit(1); \
} while (0)

#define DRLTRACE_INFO(level, msg, ...) do { \
    if (op_verbose.get_value() >= level) {\
        fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__);    \
        fflush(stderr); \
    }\
} while (0)

static droption_t<std::string> op_logdir
(DROPTION_SCOPE_ALL, "logdir", ".", "Log directory to print library call data",
 "Specify log directory where library call data will be written, in a separate file per "
 "process.  The default value is \".\" (current dir).  If set to \"-\", data for all "
 "processes are printed to stderr (warning: this can be slow).");

static droption_t<bool> op_only_from_app
(DROPTION_SCOPE_CLIENT, "only_from_app", false, "Reports only library calls from the app",
 "Only reports library calls from the application itself, as opposed to all calls even "
 "from other libraries or within the same library.");

static droption_t<bool> op_follow_children
(DROPTION_SCOPE_FRONTEND, "follow_children", true, "Trace child processes",
 "(overrides the default, which is to trace all children).");

static droption_t<bool> op_ignore_underscore
(DROPTION_SCOPE_CLIENT, "ignore_underscore", false, "Ignores library routine names "
 "starting with \"_\".", "Ignores library routine names starting with \"_\".");

static droption_t<bool> op_help
(DROPTION_SCOPE_FRONTEND, "help", false, "Print this message.", "Print this message");

static droption_t<bool> op_version
(DROPTION_SCOPE_FRONTEND, "version", 0, "Print version number.", "Print version number.");

static droption_t<unsigned int> op_verbose
(DROPTION_SCOPE_ALL, "verbose", 1, "Change verbosity.", "Change verbosity.");

static droption_t<std::string> op_ltracelib_ops
(DROPTION_SCOPE_CLIENT, "ltracelib_ops",
 DROPTION_FLAG_SWEEP | DROPTION_FLAG_ACCUMULATE | DROPTION_FLAG_INTERNAL,
 "", "(For internal use: sweeps up drltracelib options)",
 "This is an internal option that sweeps up other options to pass to the drltracelib.");

/* check that drltracelib.dll, dynamorio.dll and target executable exist */
static void
check_input_files(const char *target_app_full_name, char *dr_root, char *drltrace_path) {
    bool result = false;

    /* check that the target application exists */
    if (target_app_full_name[0] == '\0')
        DRLTRACE_ERROR("target application is not specified");

    /* FIXME i#1944: We need to use drfront_appdata_logdir to handle specific situations
     * when we can't write log in specific dirs (such as root dir on Android or Program
     * Files in Windows).
     */
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
                      const char *dr_root, const char *lib_path)
{
    bool is_debug = false;
#ifdef DEBUG
    is_debug = true;
#endif
    int errcode;
    char *process;
    process_id_t pid;
    char dr_option[MAX_DR_CMDLINE];
    dr_option[0] = '\0';

    if (op_follow_children.get_value() == false)
        dr_snprintf(dr_option, BUFFER_SIZE_ELEMENTS(dr_option), "-no_follow_children");
    NULL_TERMINATE_BUFFER(dr_option);

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
                           op_ltracelib_ops.get_value().c_str()) != DR_SUCCESS) {
        DRLTRACE_ERROR("failed to register DynamoRIO client configuration");
    }
}

static void
check_logdir_path(const char *logdir) {
    drfront_status_t sc;
    char absolute_logdir_path[MAXIMUM_PATH];
    bool result;

    sc = drfront_get_absolute_path(logdir, absolute_logdir_path,
                                   BUFFER_SIZE_ELEMENTS(absolute_logdir_path));
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_get_absolute_path failed, error code = %d\n", sc);

    if (drfront_access(absolute_logdir_path, DRFRONT_WRITE, &result) != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("cannot find logdir %s", absolute_logdir_path);
    if (!result)
        DRLTRACE_ERROR("cannot write log file into %s", absolute_logdir_path);
}

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

    int last_index;
    std::string parse_err;
    drfront_status_t sc;

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

    /* get DR's root directory and drltracelib.dll full path */
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

    dr_snprintf(tmp_path, BUFFER_SIZE_ELEMENTS(tmp_path), "%s../dynamorio",
                full_frontend_path);

    sc = drfront_get_absolute_path(tmp_path, full_dr_root_path,
                                   BUFFER_SIZE_ELEMENTS(tmp_path));
    NULL_TERMINATE_BUFFER(full_dr_root_path);

    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_get_absolute_path failed, error code = %d\n", sc);

    dr_snprintf(full_drlibtrace_path, BUFFER_SIZE_ELEMENTS(full_drlibtrace_path),
                "%s%s", full_frontend_path, drlibpath);
    NULL_TERMINATE_BUFFER(full_drlibtrace_path);

    if (op_logdir.get_value().c_str() != NULL) {
        /* check access to logdir */
        check_logdir_path(op_logdir.get_value().c_str());
    }

    check_input_files(full_target_app_path, full_dr_root_path, full_drlibtrace_path);

    dr_standalone_init();

    configure_application(full_target_app_path, &argv[last_index],
                          &inject_data, full_dr_root_path, full_drlibtrace_path);

    if (!dr_inject_process_inject(inject_data, false/*!force*/, NULL))
        DRLTRACE_ERROR("unable to inject");

    if (!dr_inject_process_run(inject_data))
        DRLTRACE_ERROR("unable to execute target application");

    DRLTRACE_INFO(1, "%s sucessfully started, waiting app for exit", full_target_app_path);

    dr_inject_wait_for_child(inject_data, 0/*wait forever*/);

    exitcode = dr_inject_process_exit(inject_data, false);

    sc = drfront_cleanup_args(argv, argc);
    if (sc != DRFRONT_SUCCESS)
        DRLTRACE_ERROR("drfront_cleanup_args error, error code = %d", sc);

    return exitcode;
}
