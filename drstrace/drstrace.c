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
 *
 * XXX i#1497: port to Linux
 * XXX i#1498: port to MacOS
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drsyscall.h"
#include "drstrace_named_consts.h"
#include "utils.h"
#include <string.h>
#ifdef WINDOWS
# include "windefs.h"
# include <windows.h>
#endif

extern size_t get_const_arrays_num(void);

/* Where to write the trace */
static file_t outf;
#ifndef DRSTRACE_UNIT_TESTS
static
#endif
hashtable_t nconsts_table;

/* We buffer the output via a stack-allocated buffer.  We flush prior to
 * each system call.
 */
#define OUTBUF_SIZE 2048
#define TYPE_OUTPUT_SIZE 2048
#define HASHTABLE_BITSIZE 10 /* 512 < entries # < 1024 */

typedef struct _buf_info_t {
    char buf[OUTBUF_SIZE];
    size_t sofar;
    ssize_t len;
} buf_info_t;

#define OUTPUT(buf_info, fmt, ...) \
    BUFFERED_WRITE(outf, (buf_info)->buf, BUFFER_SIZE_ELEMENTS((buf_info)->buf), \
                   (buf_info)->sofar, (buf_info)->len, fmt, ##__VA_ARGS__)

static uint verbose = 1;

#define ALERT(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, ##__VA_ARGS__); \
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
    char sympath[MAXIMUM_PATH];
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

void
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

static bool
drstrace_print_enum_const_name(buf_info_t *buf, drsys_arg_t *arg)
{
    /* The routine returns false when can't
     * find symbolic name in the hashtable.
     */
    int iterator = 0;
    const_values_t *named_consts;
    const_values_t *named_consts_save;
    bool has_out = false;
    /* Trying to find enum_name in the hashtable */
    named_consts = (const_values_t *)
        hashtable_lookup(&nconsts_table, (void *) arg->enum_name);
    if (named_consts == NULL) {
        OUTPUT(buf, PIFX, arg->value);
        return false;
    }
    /* There are a lot of named constants with incremental values
     * (e.g. REG_NONE 0, REG_SZ 1, REG_EXPAND_SZ 2, REG_BINARY 3).
     * So, firstly, we're trying to determine such cases.
     */
    named_consts_save = named_consts;
    while (named_consts_save->const_name != NULL) {
        if (arg->value == named_consts_save->value) {
            if (has_out)
                OUTPUT(buf, " or ");
            OUTPUT(buf, "%s", named_consts_save->const_name);
            has_out = true;
        }
        named_consts_save++;
    }
    if (has_out)
        return true;
   /* If not, we perform linear search for composite named constants
    * (e.g. FILE_SHARE_READ | FILE_SHARE_WRITE). We're using linear
    * search instead of random access b/c current table entries may
    * contain the same values for different named constants as well as
    * combination values, which make it difficult, such as:
    * ...
    * {0x00800000, "FILE_OPEN_FOR_FREE_SPACE_QUERY"},
    * {0x00ffffff, "FILE_VALID_OPTION_FLAGS"},
    * ...
    */
    has_out = false;
    while (named_consts->const_name != NULL) {
        if (TESTALL(named_consts->value, arg->value)) {
            if (has_out)
                OUTPUT(buf, "|");
            /* FIXME i#1550: We don't perform additional search to
             * include entries with the same values in the output.
             * Ideally the tables shouldn't contain such entries.
             */
            OUTPUT(buf, "%s", named_consts->const_name);
            has_out = true;
        }
        named_consts++;
    }
    if (!has_out) {
        OUTPUT(buf, PIFX, arg->value);
        return false;
    }

    return true;
}

/* NOTE: the routine returns up to 64 bit memory values */
static int64
safe_read_field(buf_info_t *buf, void *addr_to_resolve, size_t addr_size,
                bool print_value)
{
    int64 mem_value = 0;
    ASSERT(addr_size <= sizeof(mem_value), "too-big mem value to read");
    if (!dr_safe_read(addr_to_resolve, addr_size, &mem_value, NULL)) {
        OUTPUT(buf, "<field unreadable>");
        return 0;
    }
    if (print_value)
        OUTPUT(buf, "0x"HEX64_FORMAT_STRING, mem_value);
    return mem_value;
}

static bool
print_known_compound_type(buf_info_t *buf, drsys_param_type_t type, void *start_addr)
{
    switch (type) {
    case DRSYS_TYPE_UNICODE_STRING: {
        print_unicode_string(buf, (UNICODE_STRING *) start_addr);
        break;
    }
    case DRSYS_TYPE_OBJECT_ATTRIBUTES: {
        OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES *) start_addr;
        OUTPUT(buf, "len="PIFX", root="PIFX", name=",
                oa->Length, oa->RootDirectory);
        print_unicode_string(buf, oa->ObjectName);
        OUTPUT(buf, ", att="PIFX", sd="PFX", sqos="PFX,
                oa->Attributes, oa->SecurityDescriptor,
                oa->SecurityQualityOfService);
        break;
    }
    case DRSYS_TYPE_IO_STATUS_BLOCK: {
        IO_STATUS_BLOCK *io = (IO_STATUS_BLOCK *) start_addr;
        OUTPUT(buf, "status="PIFX", info="PIFX"", io->StatusPointer.Status,
                io->Information);
        break;
    }
    case DRSYS_TYPE_LARGE_INTEGER: {
        LARGE_INTEGER *li = (LARGE_INTEGER *) start_addr;
        OUTPUT(buf, "0x"HEX64_FORMAT_STRING, li->QuadPart);
        break;
    }
    default: {
        /* FIXME i#1089: add the other types */
        return false;
    }
    }
    /* XXX: we want KEY_VALUE_PARTIAL_INFORMATION, etc. like in
     * syscall_diagnostics.  Add drsyscall types for those, or hardcode here?
     */
    return true;
}

static bool
identify_known_compound_type(buf_info_t *buf, char *name, void *start_addr)
{
    /* XXX i#1607 There are two reasons why we're trying to determine types
     * by name here. Firstly, we can't simply parse types with unions in the
     * print_structure since this routine increases memory address by field
     * size after each field which we don't want to do with unions. We make
     * temporarly solution here *only* for LARGE_INTEGER. So we're still need
     * to resolve union problem.
     * The second one is that we want extra information (e.g. field names)
     * for already known common structures.
     */
    drsys_param_type_t type = DRSYS_TYPE_UNKNOWN;
    if (strcmp(name, "_LARGE_INTEGER") == 0) {
        type = DRSYS_TYPE_LARGE_INTEGER;
    } else if (strcmp(name, "_UNICODE_STRING") == 0) {
        type = DRSYS_TYPE_UNICODE_STRING;
    } else if (strcmp(name, "_OBJECT_ATTRIBUTES") == 0) {
        type = DRSYS_TYPE_OBJECT_ATTRIBUTES;
    } else if (strcmp(name, "_IO_STATUS_BLOCK") == 0) {
        type = DRSYS_TYPE_IO_STATUS_BLOCK;
    } else {
        return false;
    }
    return print_known_compound_type(buf, type, start_addr);
}

static uint
get_total_size_of_fields(drsym_compound_type_t *compound_type)
{
    int i;
    uint total_size = 0;
    for (i = 0; i < compound_type->num_fields; i++)
        total_size += compound_type->field_types[i]->size;
    return total_size;
}

static void
print_structure(buf_info_t *buf, drsym_type_t *type, drsys_arg_t *arg, void *addr)
{
    int i;
    bool type_union = false;
    if (type->kind == DRSYM_TYPE_COMPOUND) {
        drsym_compound_type_t *compound_type =
            (drsym_compound_type_t *)type;
        OUTPUT(buf, "%s {", compound_type->name);
        if (identify_known_compound_type(buf, compound_type->name, addr)) {
            OUTPUT(buf, "}");
            return;
        }
        /* i#1607: We need to print properly parent structures when they are
         * actually unions (e.g. LARGE_INTEGER).
         */
        if (get_total_size_of_fields(compound_type) > compound_type->type.size)
            type_union = true;
        for (i = 0; i < compound_type->num_fields; i++) {
            print_structure(buf, compound_type->field_types[i], arg, addr);
            if (!type_union)
                addr = (char *)addr + compound_type->field_types[i]->size;
            /* we don't want comma after last field */
            if (i+1 != compound_type->num_fields)
                OUTPUT(buf, ", ");
        }
        OUTPUT(buf, "}");
    } else {
        /* Print type fields */
        if (type->kind == DRSYM_TYPE_VOID) {
            OUTPUT(buf, "void=");
            safe_read_field(buf, addr, type->size, true);
            return;
        } else if (type->kind == DRSYM_TYPE_PTR) {
            drsym_ptr_type_t *ptr_type = (drsym_ptr_type_t *)type;
            /* We're expecting an address here. So we truncate int64 to void* */
            void *mem_value = (void *)safe_read_field(buf, addr, ptr_type->type.size,
                                                      false);
            print_structure(buf, ptr_type->elt_type, arg, mem_value);
            OUTPUT(buf, "*");
            return;
        } else if (type->kind == DRSYM_TYPE_ARRAY) {
            OUTPUT(buf, "array(%d)={", type->size);
            /* only print up to the first 4 bytes of the array */
            safe_read_field(buf, addr, 0x1, true);
            for (i = 1; i < type->size && i < 4; i++) {
                OUTPUT(buf, ", ");
                safe_read_field(buf, (byte *)addr + i, 0x1, true);
            }
            if (i < type->size)
                OUTPUT(buf, ", ...");
            OUTPUT(buf, "}");
            return;
        } else {
            /* Print integer base types */
            switch (type->size) {
            case 1:
                OUTPUT(buf, "byte|bool=");
                break;
            case 2:
                OUTPUT(buf,"short=");
                break;
            case 4:
                OUTPUT(buf, "int=");
                break;
            case 8:
                OUTPUT(buf, "long long=");
                break;
            default:
                OUTPUT(buf, "unknown type=");
                break;
            }
            safe_read_field(buf, addr, type->size, true);
            return;
        }
    }
    return;
}

static bool
type_has_unknown_components(drsym_type_t *type)
{
    int i;
    if (type->kind == DRSYM_TYPE_COMPOUND) {
        drsym_compound_type_t *compound_type = (drsym_compound_type_t *)type;
        drsym_type_t **field_types = compound_type->field_types;
        for (i = 0; i < compound_type->num_fields; i++) {
            if (field_types[i]->kind == DRSYM_TYPE_PTR) {
                drsym_ptr_type_t *ptr_type = (drsym_ptr_type_t *)field_types[i];
                if (ptr_type->elt_type->size == 0)
                    return false;
            }
            /* recursively check type fields */
            if (!type_has_unknown_components(field_types[i]))
                return false;
        }
    } else if (type->size == 0) {
        return false;
    }
    return true;
}

static bool
drstrace_print_info_class_struct(buf_info_t *buf, drsys_arg_t *arg)
{
    char buf_tmp[TYPE_OUTPUT_SIZE];
    drsym_type_t *type;
    drsym_type_t *expand_type;
    drsym_error_t r;

    r = drsym_get_type_by_name(options.sympath, arg->enum_name,
                               buf_tmp, BUFFER_SIZE_BYTES(buf_tmp),
                               &type);
    if (r != DRSYM_SUCCESS) {
        NOTIFY("Value to symbol %s lookup failed", arg->enum_name);
        return false;
    }

    r = drsym_expand_type(options.sympath, type->id, UINT_MAX,
                          buf_tmp, BUFFER_SIZE_BYTES(buf_tmp),
                          &expand_type);
    if (r != DRSYM_SUCCESS) {
        NOTIFY("%s structure expanding failed", arg->enum_name);
        return false;
    }
    if (!type_has_unknown_components(expand_type)) {
        NOTIFY("%s structure has unknown types", arg->enum_name);
        return false;
    }

    if (arg->valid && !arg->pre) {
        if (arg->value64 == 0) {
            OUTPUT(buf, "NULL");
            /* We return true since we already printed for this value */
            return true;
        }
        /* We're expecting an address here. So we truncate int64 to void*. */
        print_structure(buf, expand_type, arg, (void *)arg->value64);
    } else {
        return false;
    }

    return true;
}

static bool
drstrace_get_arg_symname(buf_info_t *buf, drsys_arg_t *arg)
{
    if (arg->type >= DRSYS_TYPE_STRUCT) {
        if (drstrace_print_info_class_struct(buf, arg)) {
            OUTPUT(buf, " (type=<struct>*, size="PIFX")\n",
                   arg->size);
            return true;
        } else {
            return false;
        }
    } else if (arg->enum_name != NULL) {
        if (drstrace_print_enum_const_name(buf, arg)) {
            OUTPUT(buf, " (type=named constant, value="PIFX", size="PIFX")\n",
                   arg->value,
                   arg->size);
        } else {
            OUTPUT(buf, " (type=named constant, size="PIFX")\n",
                   arg->size);
        }
        return true;
    }
    return false;
}

static void
print_arg(buf_info_t *buf, drsys_arg_t *arg)
{
    if (arg->ordinal == -1)
        OUTPUT(buf, "\tretval: ");
    else
        OUTPUT(buf, "\targ %d: ", arg->ordinal);

    if (arg->enum_name != NULL) {
        if (drstrace_get_arg_symname(buf, arg))
            return;
    }
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
            if (!print_known_compound_type(buf, arg->type, (void *) arg->value))
                OUTPUT(buf, "<NYI>");
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
    uint errno;
    drmf_status_t res;
    buf_info_t buf;
    buf.sofar = 0;

    if (drsys_cur_syscall(drcontext, &syscall) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall failed");

    if (drsys_cur_syscall_result(drcontext, &success, NULL, &errno) != DRMF_SUCCESS)
        ASSERT(false, "drsys_cur_syscall_result failed");

    if (success)
        OUTPUT(&buf, "    succeeded =>\n");
    else
        OUTPUT(&buf, "    failed (error="IF_WINDOWS_ELSE(PIFX, "%d")") =>\n", errno);
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
    drsym_exit();
    drx_exit();
    drmgr_exit();
    hashtable_delete(&nconsts_table);
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
        } else if (strcmp(token, "-symcache_path") == 0) {
            s = dr_get_token(s, options.sympath,
                             BUFFER_SIZE_ELEMENTS(options.sympath));
            USAGE_CHECK(s != NULL, "missing symcache dir path");
            ALERT(2, "<drstrace symbol source is %s>\n", options.sympath);
        } else {
            ALERT(0, "UNRECOGNIZED OPTION: \"%s\"\n", token);
            USAGE_CHECK(false, "invalid option");
        }
    }
}

DR_EXPORT
void dr_init(client_id_t id)
{
    uint i = 0;
    uint const_arrays_num;
    drsys_options_t ops = { sizeof(ops), 0, };

    dr_set_client_name("Dr. STrace", "http://drmemory.org/issues");

#ifdef WINDOWS
    dr_enable_console_printing();
#endif

    options_init(id);
    drsym_init(0);
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

    const_arrays_num = get_const_arrays_num();
    hashtable_init(&nconsts_table, HASHTABLE_BITSIZE, HASH_STRING, false);
    while (i < const_arrays_num) {
        const_values_t *named_consts = const_struct_array[i];
        bool res = hashtable_add(&nconsts_table,
                                 (void *) named_consts[0].const_name,
                                 (void *) named_consts);
        if (!res)
            ASSERT(false, "drstrace failed to add to hashtable");
        i++;
    }

}

/****************************************************************************
 * Unit tests group of functions
 */

#ifdef DRSTRACE_UNIT_TESTS
bool
drstrace_unit_test_syscall_exit()
{
    if (drsym_exit() != DRSYM_SUCCESS)
        return false;
    hashtable_delete(&nconsts_table);
    return true;
}

bool
drstrace_unit_test_syscall_init()
{
    uint const_arrays_num;
    uint i = 0;

    dr_standalone_init();

    if (drsym_init(0) != DRSYM_SUCCESS)
        return false;

    const_arrays_num = get_const_arrays_num();
    hashtable_init(&nconsts_table, HASHTABLE_BITSIZE, HASH_STRING, false);
    while (i < const_arrays_num) {
        const_values_t *named_consts = const_struct_array[i];
        bool res = hashtable_add(&nconsts_table,
                                 (void *) named_consts[0].const_name,
                                 (void *) named_consts);
        if (!res)
            return false;
        i++;
    }
    return true;
}

void
drstrace_set_symbol_path(const char *pdb_dir) {
    _snprintf(options.sympath, BUFFER_SIZE_ELEMENTS(options.sympath), "%s", pdb_dir);
}

void
drstrace_unit_test_syscall_arg_iteration(drsys_arg_t arg, void *user_data)
{
    drsys_iter_arg_cb(&arg, user_data);
    return;
}

#endif /* DRSTRACE_UNIT_TESTS */
/***************************************************************************/
