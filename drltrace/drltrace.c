/* ***************************************************************************
 * Copyright (c) 2013-2017 Google, Inc.  All rights reserved.
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

/* Library Tracing Tool: drltrace
 *
 * Records calls to exported library routines.
 *
 * The runtime options for this client include:
 *
 * -logdir <dir>       Sets log directory, which by default is "-".
 *                     If set to "-", the tool prints to stderr.
 * -only_from_app      Only reports library calls from the application itself.
 * -only_to_lib <lib>  Only reports calls to the library <lib>.
 * -ignore_underscore  Ignores library routine names starting with "_".
 * -all_args <N>       Prints N arg values for every library call.
 *                     Set to 2 by default.
 * -verbose <N>        For debugging the tool itself.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drx.h"
#include "utils.h"
#include "drcovlib.h"
#include <string.h>

/* XXX i#1349: features to add:
 *
 * + Add filtering of which library routines to trace.
 *   This would likely be via a configuration file.
 *   Currently we have a simple -only_to_lib option.
 *
 * + Add argument values and return values.  The number and type of each
 *   argument and return would likely come from the filter configuration
 *   file, or from querying debug information.
 *   Today we have simple type-blind printing via -num_unknown_args and
 *   usage of drsyscall to print symbolic arguments for known library calls.
 *
 * + Add 2 more modes, both gathering statistics rather than a full
 *   trace: one mode that counts total calls, and one that just
 *   records whether each library routine was ever called.  For these,
 *   we'll probably want to insert custom instrumentation rather than
 *   a clean call via drwrap, and so we'll want our own hashtable of
 *   the library entries.
 */

static uint verbose;

#define VNOTIFY(level, ...) do {          \
    NOTIFY_COND(verbose >= level, f_global, __VA_ARGS__); \
} while (0)

/* Checks for both debug and release builds: */
#define USAGE_CHECK(x, msg) DR_ASSERT_MSG(x, msg)

#define OPTION_MAX_LENGTH MAXIMUM_PATH

typedef struct _drltrace_options_t {
    char logdir[MAXIMUM_PATH];
    bool only_from_app;
    bool ignore_underscore;
    char only_to_lib[MAXIMUM_PATH];
    uint num_unknown_args;
    uint max_args;
    bool print_ret_addr;
} drltrace_options_t;

static drltrace_options_t options;

/* Where to write the trace */
static file_t outf;

/* Avoid exe exports, as on Linux many apps have a ton of global symbols. */
static app_pc exe_start;

/* runtest.cmake assumes this is the prefix, so update both when changing it */
#define STDERR_PREFIX "~~~~ "

/* XXX i#1978: The functions print_simple_value and print_arg were taken from drstrace.
 * It would be better to move them in drsyscall and import in drstrace and here.
 */
static void
print_simple_value(drsys_arg_t *arg, bool leading_zeroes)
{
    bool pointer = !TEST(DRSYS_PARAM_INLINED, arg->mode);
    dr_fprintf(outf, pointer ? PFX : (leading_zeroes ? PFX : PIFX), arg->value);
    if (pointer && ((arg->pre && TEST(DRSYS_PARAM_IN, arg->mode)) ||
                    (!arg->pre && TEST(DRSYS_PARAM_OUT, arg->mode)))) {
        ptr_uint_t deref = 0;
        ASSERT(arg->size <= sizeof(deref), "too-big simple type");
        /* We assume little-endian */
        if (dr_safe_read((void *)arg->value, arg->size, &deref, NULL))
            dr_fprintf(outf, (leading_zeroes ? " => " PFX : " => " PIFX), deref);
    }
}

static void
print_arg(drsys_arg_t *arg)
{
    dr_fprintf(outf, "\n    arg %d: ", arg->ordinal);
    switch (arg->type) {
    case DRSYS_TYPE_VOID:         print_simple_value(arg, true); break;
    case DRSYS_TYPE_POINTER:      print_simple_value(arg, true); break;
    case DRSYS_TYPE_BOOL:         print_simple_value(arg, false); break;
    case DRSYS_TYPE_INT:          print_simple_value(arg, false); break;
    case DRSYS_TYPE_SIGNED_INT:   print_simple_value(arg, false); break;
    case DRSYS_TYPE_UNSIGNED_INT: print_simple_value(arg, false); break;
    case DRSYS_TYPE_HANDLE:       print_simple_value(arg, false); break;
    case DRSYS_TYPE_NTSTATUS:     print_simple_value(arg, false); break;
    case DRSYS_TYPE_ATOM:         print_simple_value(arg, false); break;
    default: {
        if (arg->value == 0)
            dr_fprintf(outf, "<null>");
        else
            dr_fprintf(outf, PFX, arg->value);
    }
    }

    dr_fprintf(outf, " (%s%s%stype=%s%s, size=" PIFX ")",
              (arg->arg_name == NULL) ? "" : "name=",
              (arg->arg_name == NULL) ? "" : arg->arg_name,
              (arg->arg_name == NULL) ? "" : ", ",
              (arg->type_name == NULL) ? "\"\"" : arg->type_name,
              (arg->type_name == NULL ||
              TESTANY(DRSYS_PARAM_INLINED|DRSYS_PARAM_RETVAL, arg->mode)) ? "" : "*",
              arg->size);
}

static bool
drlib_iter_arg_cb(drsys_arg_t *arg, void *wrapcxt)
{
    if (arg->ordinal == -1)
        return true;
    if (arg->ordinal >= options.max_args)
        return false; /* limit number of arguments to be printed */

    arg->value = (ptr_uint_t)drwrap_get_arg(wrapcxt, arg->ordinal);

    print_arg(arg);
    return true; /* keep going */
}

static void
print_args_unknown_call(app_pc func, void *wrapcxt)
{
    uint i;
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    DR_TRY_EXCEPT(drcontext, {
        for (i = 0; i < options.num_unknown_args; i++) {
            dr_fprintf(outf, "\n    arg %d: " PFX, i,
                       drwrap_get_arg(wrapcxt, i));
        }
    }, {
        dr_fprintf(outf, "<invalid memory>");
        /* Just keep going */
    });
    /* all args have been sucessfully printed */
    dr_fprintf(outf, options.print_ret_addr ? "\n   ": "");
}

static void
print_symbolic_args(const char *name, void *wrapcxt, app_pc func)
{
    drmf_status_t res;
    drsys_syscall_t *syscall;

    if (options.max_args == 0)
        return;

    res = drsys_name_to_syscall(name, &syscall);
    if (res == DRMF_SUCCESS) {
        res = drsys_iterate_arg_types(syscall, drlib_iter_arg_cb, wrapcxt);
        if (res != DRMF_SUCCESS && res != DRMF_ERROR_DETAILS_UNKNOWN)
            ASSERT(false, "drsys_iterate_arg_types failed in print_symbolic_args");
        /* all args have been sucessfully printed */
        dr_fprintf(outf, options.print_ret_addr ? "\n   ": "");
        return;
    } else {
        /* use standard type-blind scheme */
        if (options.num_unknown_args > 0)
            print_args_unknown_call(func, wrapcxt);
    }
}

/****************************************************************************
 * Library entry wrapping
 */

static void
lib_entry(void *wrapcxt, INOUT void **user_data)
{
    const char *name = (const char *) *user_data;
    const char *modname = NULL;
    app_pc func = drwrap_get_func(wrapcxt);
    module_data_t *mod;
    thread_id_t tid;
    uint mod_id;
    app_pc mod_start, ret_addr;
    drcovlib_status_t res;

    void *drcontext = drwrap_get_drcontext(wrapcxt);

    if (options.only_from_app) {
        /* For just this option, the modxfer approach might be better */
        app_pc retaddr =  NULL;
        DR_TRY_EXCEPT(drcontext, {
            retaddr = drwrap_get_retaddr(wrapcxt);
        }, { /* EXCEPT */
            retaddr = NULL;
        });
        if (retaddr != NULL) {
            mod = dr_lookup_module(retaddr);
            if (mod != NULL) {
                bool from_exe = (mod->start == exe_start);
                dr_free_module_data(mod);
                if (!from_exe)
                    return;
            }
        } else {
            /* Nearly all of these cases should be things like KiUserCallbackDispatcher
             * or other abnormal transitions.
             * If the user really wants to see everything they can not pass
             * -only_from_app.
             */
            return;
        }
    }
    /* XXX: it may be better to heap-allocate the "module!func" string and
     * pass in, to avoid this lookup.
     */
    mod = dr_lookup_module(func);
    if (mod != NULL)
        modname = dr_module_preferred_name(mod);

    tid = dr_get_thread_id(drcontext);
    if (tid != INVALID_THREAD_ID)
        dr_fprintf(outf, "~~%d~~ ", tid);
    else
        dr_fprintf(outf, "~~Dr.L~~ ");

    dr_fprintf(outf, "%s%s%s%s", (outf == STDERR ? STDERR_PREFIX : ""),
               modname == NULL ? "" : modname,
               modname == NULL ? "" : "!", name);

    /* XXX: We employ two schemes of arguments printing. drsyscall is used
     * to get a symbolic representation of arguments for known library calls.
     * For the rest of library calls we use type-blind printing and -num_unknown_args
     * to get a count of arguments to print.
     */
    print_symbolic_args(name, wrapcxt, func);

    if (options.print_ret_addr) {
        ret_addr = drwrap_get_retaddr(wrapcxt);
        res = drmodtrack_lookup(drcontext, ret_addr, &mod_id, &mod_start);
        if (res == DRCOVLIB_SUCCESS) {
            dr_fprintf(outf,
                       options.print_ret_addr ? " and return to module id:%d, offset:" PIFX : "",
                       mod_id, ret_addr - mod_start);
        }
    }
    dr_fprintf(outf, "\n");
    if (mod != NULL)
        dr_free_module_data(mod);
}

static void
iterate_exports(const module_data_t *info, bool add)
{
    dr_symbol_export_iterator_t *exp_iter =
        dr_symbol_export_iterator_start(info->handle);
    while (dr_symbol_export_iterator_hasnext(exp_iter)) {
        dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
        app_pc func = NULL;
        if (sym->is_code)
            func = sym->addr;
#ifdef LINUX
        else if (sym->is_indirect_code) {
            /* Invoke the export to get the real entry: */
            app_pc (*indir)(void) = (app_pc (*)(void)) cast_to_func(sym->addr);
            void *drcontext = dr_get_current_drcontext();
            DR_TRY_EXCEPT(drcontext, {
                func = (*indir)();
            }, { /* EXCEPT */
                func = NULL;
            });
            VNOTIFY(2, "export %s indirected from " PFX " to " PFX NL,
                   sym->name, sym->addr, func);
        }
#endif
        if (options.ignore_underscore && strstr(sym->name, "_") == sym->name)
            func = NULL;
        if (func != NULL) {
            if (add) {
                IF_DEBUG(bool ok =)
                    drwrap_wrap_ex(func, lib_entry, NULL, (void *) sym->name, 0);
                ASSERT(ok, "wrap request failed");
                VNOTIFY(2, "wrapping export %s!%s @" PFX NL,
                       dr_module_preferred_name(info), sym->name, func);
            } else {
                IF_DEBUG(bool ok =)
                    drwrap_unwrap(func, lib_entry, NULL);
                ASSERT(ok, "unwrap request failed");
            }
        }
    }
    dr_symbol_export_iterator_stop(exp_iter);
}

static bool
library_matches_filter(const module_data_t *info)
{
    if (options.only_to_lib[0] != '\0') {
        const char *libname = dr_module_preferred_name(info);
        return (libname != NULL && strstr(libname, options.only_to_lib) != NULL);
    }
    return true;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    if (info->start != exe_start && library_matches_filter(info))
        iterate_exports(info, true/*add*/);
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    if (info->start != exe_start && library_matches_filter(info))
        iterate_exports(info, false/*remove*/);
}

/****************************************************************************
 * Init and exit
 */

static void
open_log_file(void)
{
    char buf[MAXIMUM_PATH];
    if (strcmp(options.logdir, "-") == 0)
        outf = STDERR;
    else {
        outf = drx_open_unique_appid_file(options.logdir, dr_get_process_id(),
                                          "drltrace", "log",
#ifndef WINDOWS
                                          DR_FILE_CLOSE_ON_FORK |
#endif
                                          DR_FILE_ALLOW_LARGE,
                                          buf, BUFFER_SIZE_ELEMENTS(buf));
        ASSERT(outf != INVALID_FILE, "failed to open log file");
        VNOTIFY(0, "drltrace log file is %s"NL, buf);

    }
}

#ifndef WINDOWS
static void
event_fork(void *drcontext)
{
    /* The old file was closed by DR b/c we passed DR_FILE_CLOSE_ON_FORK */
    open_log_file();
}
#endif

static void
event_exit(void)
{
    if (options.max_args > 0)
        drsys_exit();

    if (outf != STDERR) {
        if (options.print_ret_addr)
            drmodtrack_dump(outf);
        dr_close_file(outf);
    }
    drx_exit();
    drwrap_exit();
    drmgr_exit();
    if (options.print_ret_addr)
        drmodtrack_exit();
}

static void
options_init(client_id_t id)
{
    const char *opstr = dr_get_options(id);
    const char *s;
    char token[OPTION_MAX_LENGTH];
    /* default values */
    dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), "-");
    options.max_args = 6;
    options.num_unknown_args = 2;
    op_print_stderr = true;
    /* XXX: we have to use droption here instead of manual parsing */
    for (s = dr_get_token(opstr, token, BUFFER_SIZE_ELEMENTS(token));
         s != NULL;
         s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token))) {
        if (strcmp(token, "-logdir") == 0) {
            s = dr_get_token(s, options.logdir,
                             BUFFER_SIZE_ELEMENTS(options.logdir));
            USAGE_CHECK(s != NULL, "missing logdir path");
        } else if (strcmp(token, "-only_from_app") == 0) {
            options.only_from_app = true;
        } else if (strcmp(token, "-only_to_lib") == 0) {
            s = dr_get_token(s, options.only_to_lib,
                             BUFFER_SIZE_ELEMENTS(options.only_to_lib));
            USAGE_CHECK(s != NULL, "missing library name");
        } else if (strcmp(token, "-ignore_underscore") == 0) {
            options.ignore_underscore = true;
        } else if (strcmp(token, "-num_unknown_args") == 0) {
            s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token));
            USAGE_CHECK(s != NULL, "missing -num_unknown_args number");
            if (s != NULL) {
                int res = dr_sscanf(token, "%u", &options.num_unknown_args);
                USAGE_CHECK(res == 1, "invalid -num_unknown_args number");
            }
        } else if (strcmp(token, "-num_max_args") == 0) {
            s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token));
            USAGE_CHECK(s != NULL, "missing -num_max_args number");
            if (s != NULL) {
                int res = dr_sscanf(token, "%u", &options.max_args);
                USAGE_CHECK(res == 1, "invalid -num_max_args number");
            }
        } else if (strcmp(token, "-verbose") == 0) {
            s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token));
            USAGE_CHECK(s != NULL, "missing -verbose number");
            if (s != NULL) {
                int res = dr_sscanf(token, "%u", &verbose);
                USAGE_CHECK(res == 1, "invalid -verbose number");
            }
        } else if (strcmp(token, "-print_ret_addr") == 0)
            options.print_ret_addr = true;
        else {
            NOTIFY("UNRECOGNIZED OPTION: \"%s\""NL, token);
            USAGE_CHECK(false, "invalid option");
        }
    }
}

DR_EXPORT void
dr_init(client_id_t id)
{
    module_data_t *exe;
    drsys_options_t ops = { sizeof(ops), 0, };
    IF_DEBUG(bool ok;)

    dr_set_client_name("Dr. LTrace", "http://drmemory.org/issues");

    options_init(id);

    IF_DEBUG(ok = )
        drmgr_init();
    ASSERT(ok, "drmgr failed to initialize");
    IF_DEBUG(ok = )
        drwrap_init();
    ASSERT(ok, "drwrap failed to initialize");
    IF_DEBUG(ok = )
        drx_init();
    ASSERT(ok, "drx failed to initialize");
    if (options.print_ret_addr) {
        IF_DEBUG(ok = )
            drmodtrack_init();
        ASSERT(ok == DRCOVLIB_SUCCESS, "drmodtrack failed to initialize");
    }

    exe = dr_get_main_module();
    if (exe != NULL)
        exe_start = exe->start;
    dr_free_module_data(exe);

    /* No-frills is safe b/c we're the only module doing wrapping, and
     * we're only wrapping at module load and unwrapping at unload.
     * Fast cleancalls is safe b/c we're only wrapping func entry and
     * we don't care about the app context.
     */
    drwrap_set_global_flags(DRWRAP_NO_FRILLS | DRWRAP_FAST_CLEANCALLS);

    dr_register_exit_event(event_exit);
#ifdef UNIX
    dr_register_fork_init_event(event_fork);
#endif
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);

#ifdef WINDOWS
    dr_enable_console_printing();
#endif
    if (options.max_args > 0)
        drsys_init(id, &ops);

    open_log_file();
}
