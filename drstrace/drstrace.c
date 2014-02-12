/* **********************************************************
 * Copyright (c) 2013-2014 Google, Inc.  All rights reserved.
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

/* strace: system call tracing tool based on the Dr. Syscall Extension.
 *
 * XXX: add more features, such as:
 * + named constants for flags
 * + callstacks
 * + timestamps
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drsyscall.h"
#include "windefs.h"
#include "utils.h"
#include <string.h>
#ifdef WINDOWS
# include <windows.h>
#endif

/* Where to write the trace */
static file_t outf;

/* We buffer the output via a stack-allocated buffer.  We flush prior to
 * each system call.
 */
#define OUTBUF_SIZE 2048

typedef struct _buf_info_t {
    char buf[OUTBUF_SIZE];
    size_t sofar;
    ssize_t len;
} buf_info_t;

#define OUTPUT(buf_info, fmt, ...) \
    BUFFERED_WRITE(outf, (buf_info)->buf, BUFFER_SIZE_ELEMENTS((buf_info)->buf), \
                   (buf_info)->sofar, (buf_info)->len, fmt, __VA_ARGS__)

static uint verbose = 1;

#define ALERT(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, __VA_ARGS__); \
} while (0)

/* Checks for both debug and release builds: */
#define USAGE_CHECK(x, msg) DR_ASSERT_MSG(x, msg)

#undef ASSERT /* we don't want msgbox */
#define ASSERT(cond, msg) \
    ((void)((!(cond)) ? \
     (dr_fprintf(STDERR, "ASSERT FAILURE: %s:%d: %s (%s)", \
                 __FILE__,  __LINE__, #cond, msg),         \
      dr_abort(), 0) : 0))

#define OPTION_MAX_LENGTH MAXIMUM_PATH

typedef struct _drstrace_options_t {
    char logdir[MAXIMUM_PATH];
} drstrace_options_t;

static drstrace_options_t options;

static void
print_unicode_string(buf_info_t *buf, UNICODE_STRING *us)
{
    if (us == NULL)
        OUTPUT(buf, "<null>");
    else {
        OUTPUT(buf, "%d/%d \"%.*S\"", us->Length, us->MaximumLength,
               us->Length/sizeof(wchar_t),
               (us->Buffer == NULL) ? L"<null>" : us->Buffer);
    }
}

print_simple_value(buf_info_t *buf, drsys_arg_t *arg, bool leading_zeroes)
{
    bool pointer = !TEST(DRSYS_PARAM_INLINED, arg->mode);
    OUTPUT(buf, pointer ? PFX : (leading_zeroes ? PFX : PIFX), arg->value);
    if (pointer && ((arg->pre && TEST(DRSYS_PARAM_IN, arg->mode)) ||
                    (!arg->pre && TEST(DRSYS_PARAM_OUT, arg->mode)))) {
        ptr_uint_t deref = 0;
        ASSERT(arg->size <= sizeof(deref), "too-big simple type");
        /* We assume little-endian */
        if (dr_safe_read((void *)arg->value, arg->size, &deref, NULL))
            OUTPUT(buf, (leading_zeroes ? " => "PFX : " => "PIFX), deref);
    }
}

static void
print_arg(buf_info_t *buf, drsys_arg_t *arg)
{
    if (arg->ordinal == -1)
        OUTPUT(buf, "\tretval: ");
    else
        OUTPUT(buf, "\targ %d: ", arg->ordinal);
    /* XXX: add return value to dr_fprintf so we can more easily align
     * after PFX vs PIFX w/o having to print to buffer
     */
    switch (arg->type) {
    case DRSYS_TYPE_VOID:         print_simple_value(buf, arg, true); break;
    case DRSYS_TYPE_POINTER:      print_simple_value(buf, arg, true); break;
    case DRSYS_TYPE_BOOL:         print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_INT:          print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_SIGNED_INT:   print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_UNSIGNED_INT: print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_HANDLE:       print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_NTSTATUS:     print_simple_value(buf, arg, false); break;
    case DRSYS_TYPE_ATOM:         print_simple_value(buf, arg, false); break;
    default: {
        if (arg->value == 0) {
            OUTPUT(buf, "<null>");
        } else if (arg->pre && !TEST(DRSYS_PARAM_IN, arg->mode)) {
            OUTPUT(buf, PFX, arg->value);
        } else {
            switch (arg->type) {
            case DRSYS_TYPE_UNICODE_STRING: {
                print_unicode_string(buf, (UNICODE_STRING *) arg->value);
                break;
            }
            case DRSYS_TYPE_OBJECT_ATTRIBUTES: {
                OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES *) arg->value;
                OUTPUT(buf, "len="PIFX", root="PIFX", name=",
                       oa->Length, oa->RootDirectory);
                print_unicode_string(buf, oa->ObjectName);
                OUTPUT(buf, ", att="PIFX", sd="PFX", sqos="PFX,
                       oa->Attributes, oa->SecurityDescriptor,
                       oa->SecurityQualityOfService);
                break;
            }
            case DRSYS_TYPE_IO_STATUS_BLOCK: {
                IO_STATUS_BLOCK *io = (IO_STATUS_BLOCK *) arg->value;
                OUTPUT(buf, "status="PIFX", info="PIFX"", io->StatusPointer.Status,
                       io->Information);
                break;
            }
            case DRSYS_TYPE_LARGE_INTEGER: {
                LARGE_INTEGER *li = (LARGE_INTEGER *) arg->value;
                OUTPUT(buf, "0x"HEX64_FORMAT_STRING, li->QuadPart);
                break;
            }
            default: {
                /* FIXME i#1089: add the other types */
                OUTPUT(buf, "<NYI>");
            }
            }
            /* XXX: we want KEY_VALUE_PARTIAL_INFORMATION, etc. like in
             * syscall_diagnostics.  Add drsyscall types for those, or hardcode here?
             */
        }
    }
    }

    OUTPUT(buf, " (%s%s%stype=%s%s, size="PIFX")\n",
           (arg->arg_name == NULL) ? "" : "name=",
           (arg->arg_name == NULL) ? "" : arg->arg_name,
           (arg->arg_name == NULL) ? "" : ", ",
           (arg->type_name == NULL) ? "\"\"" : arg->type_name,
           (arg->type_name == NULL ||
            TESTANY(DRSYS_PARAM_INLINED|DRSYS_PARAM_RETVAL, arg->mode)) ? "" : "*",
           arg->size);
}

static bool
drsys_iter_arg_cb(drsys_arg_t *arg, void *user_data)
{
    buf_info_t *buf = (buf_info_t *) user_data;
    ASSERT(arg->valid, "no args should be invalid");

    if ((arg->pre && !TEST(DRSYS_PARAM_RETVAL, arg->mode)) ||
        (!arg->pre && TESTANY(DRSYS_PARAM_OUT|DRSYS_PARAM_RETVAL, arg->mode)))
        print_arg(buf, arg);

    return true; /* keep going */
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    drsys_syscall_t *syscall;
    bool known;
    drsys_param_type_t ret_type;
    const char *name;
    drmf_status_t res;
    buf_info_t buf;
    buf.sofar = 0;

    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall failed");

    if (drsys_syscall_name(syscall, &name) != DRMF_SUCCESS)
        ASSERT(false, "drsys_syscall_name failed");

    if (drsys_syscall_is_known(syscall, &known) != DRMF_SUCCESS)
        ASSERT(false, "failed to find whether known");

    OUTPUT(&buf, "%s%s\n", name, known ? "" : " (details not all known)");

    res = drsys_iterate_args(drcontext, drsys_iter_arg_cb, &buf);
    if (res != DRMF_SUCCESS && res != DRMF_ERROR_DETAILS_UNKNOWN)
        ASSERT(false, "drsys_iterate_args failed pre-syscall");

    /* Flush prior to potentially waiting in the kernel */
    FLUSH_BUFFER(outf, buf.buf, buf.sofar);

    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    drsys_syscall_t *syscall;
    bool success = false;
    drmf_status_t res;
    buf_info_t buf;
    buf.sofar = 0;

    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall failed");

    if (drsys_syscall_succeeded(syscall, dr_syscall_get_result(drcontext), &success) !=
        DRMF_SUCCESS)
        ASSERT(false, "drsys_syscall_succeeded failed");

    OUTPUT(&buf, "    %s =>\n", success ? "succeeded" : "failed");
    res = drsys_iterate_args(drcontext, drsys_iter_arg_cb, &buf);
    if (res != DRMF_SUCCESS && res != DRMF_ERROR_DETAILS_UNKNOWN)
        ASSERT(false, "drsys_iterate_args failed post-syscall");
    FLUSH_BUFFER(outf, buf.buf, buf.sofar);
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true; /* intercept everything */
}

static void
open_log_file(void)
{
    char buf[MAXIMUM_PATH];
    if (strcmp(options.logdir, "-") == 0)
        outf = STDERR;
    else {
        outf = drx_open_unique_appid_file(options.logdir, dr_get_process_id(),
                                          "drstrace", "log",
#ifndef WINDOWS
                                          DR_FILE_CLOSE_ON_FORK |
#endif
                                          DR_FILE_ALLOW_LARGE,
                                          buf, BUFFER_SIZE_ELEMENTS(buf));
        ASSERT(outf != INVALID_FILE, "failed to open log file");
        ALERT(1, "<drstrace log file is %s>\n", buf);
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

static
void exit_event(void)
{
    if (outf != STDERR)
        dr_close_file(outf);
    if (drsys_exit() != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to exit");
    drx_exit();
    drmgr_exit();
}

static void
options_init(client_id_t id)
{
    const char *opstr = dr_get_options(id);
    const char *s;
    char token[OPTION_MAX_LENGTH];

    /* default values */
    dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), ".");

    for (s = dr_get_token(opstr, token, BUFFER_SIZE_ELEMENTS(token));
         s != NULL;
         s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token))) {
        if (strcmp(token, "-logdir") == 0) {
            s = dr_get_token(s, options.logdir,
                             BUFFER_SIZE_ELEMENTS(options.logdir));
            USAGE_CHECK(s != NULL, "missing logdir path");
        } else if (strcmp(token, "-verbose") == 0) {
            s = dr_get_token(s, token, BUFFER_SIZE_ELEMENTS(token));
            USAGE_CHECK(s != NULL, "missing -verbose number");
            if (s != NULL) {
                int res = dr_sscanf(token, "%u", &verbose);
                USAGE_CHECK(res == 1, "invalid -verbose number");
            }
        } else {
            ALERT(0, "UNRECOGNIZED OPTION: \"%s\"\n", token);
            USAGE_CHECK(false, "invalid option");
        }
    }
}

DR_EXPORT
void dr_init(client_id_t id)
{
    drsys_options_t ops = { sizeof(ops), 0, };

#ifdef WINDOWS
    dr_enable_console_printing();
#endif

    options_init(id);

    drmgr_init();
    drx_init();
    if (drsys_init(id, &ops) != DRMF_SUCCESS)
        ASSERT(false, "drsys failed to init");
    dr_register_exit_event(exit_event);

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    if (drsys_filter_all_syscalls() != DRMF_SUCCESS)
        ASSERT(false, "drsys_filter_all_syscalls should never fail");

    open_log_file();
}
